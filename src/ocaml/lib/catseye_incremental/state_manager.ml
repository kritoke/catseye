(* lib/catseye_incremental/state_manager.ml
   Incremental state management for diff scanning. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

module SM = Stdlib.Map.Make(String)

(* Simple file state record *)
type file_state = {
  path : string;
  lang : string;
  cksum : string;
  mtime : float;
  ast_json : string;
  nodes : Catseye_types.Security_node.t list;
  analyzed_at : float;
}

let make_file_state ~path ~lang ~cksum ~mtime ~ast_json ~nodes = {
  path; lang; cksum; mtime; ast_json; nodes;
  analyzed_at = Unix.gettimeofday ();
}

let file_key (f : file_state) = f.path

(* Field access with explicit equality to avoid Base shadowing *)
let file_changed (s : file_state) (new_hash : string) (new_mtime : float) =
  let open Stdlib in
  (<>) s.cksum new_hash ||
  Float.(abs (s.mtime -. new_mtime)) > 0.001

(* File map module using Stdlib.Map *)
module File_map : sig
  type t
  val create : unit -> t
  val get : string -> t -> file_state option
  val set : t -> string -> file_state -> t
  val remove : string -> t -> t
  val merge : t -> (string * file_state) list -> t
  val iter : (string -> file_state -> unit) -> t -> unit
  val mem : string -> t -> bool
end = struct
  type t = file_state SM.t
  let create () : t = SM.empty
  let get key map = SM.find_opt key map
  let set map k v = SM.add k v map
  let remove key map = SM.remove key map
  let merge initial pairs =
    let rec loop acc = function
      | [] -> acc
      | (k, v) :: rest -> loop (set acc k v) rest
    in
    loop initial pairs
  let iter f m = SM.iter f m
  let mem key m = SM.mem key m
end

(* Engine state - immutable for safe incremental updates *)
type engine_state = {
  previous_map : File_map.t;
  added_files : string list;
  modified_files : string list;
}

(* Global incremental state - placeholder for real Incremental.Var *)
module Global = struct
  let state_var : File_map.t option ref = ref None
  
  let get_var () = match !state_var with
    | Some v -> v
    | None -> 
      let v = File_map.create () in
      state_var := Some v;
      v
  
  let set (m : File_map.t) = 
    state_var := Some m
  
  let value () = get_var ()
end

module Engine = struct
  type t = engine_state

  let file_var : file_state SM.t option ref = ref None

  let create () = {
    previous_map = File_map.create ();
    added_files = [];
    modified_files = [];
  }

  let update_files (t : t) (new_pairs : (string * file_state) list) =
    let new_map = File_map.merge (File_map.create ()) new_pairs in
    let prev = t.previous_map in
    let added = ref [] in
    let modified = ref [] in
    List.iter ~f:(fun (path, new_state) ->
      match File_map.get path prev with
      | None -> added := path :: !added
      | Some s ->
        if file_changed s new_state.cksum new_state.mtime then
          modified := path :: !modified
    ) new_pairs;
    { previous_map = new_map;
      added_files = List.rev !added;
      modified_files = List.rev !modified }

  (** Mark a file as needing re-analysis by resetting its analyzed timestamp.
      Not yet called from the incremental engine, but will be needed when
      incremental mode is fully activated. *)
  let invalidate_file (t : t) (path : string) =
    match File_map.get path t.previous_map with
    | None -> t
    | Some s ->
      let fresh = { s with analyzed_at = 0.0 } in
      let new_map = File_map.set t.previous_map path fresh in
      { t with previous_map = new_map; modified_files = path :: t.modified_files }

  let get_changed (t : t) =
    (t.added_files, t.modified_files, [])

  let stabilize () = ()
  let value () = File_map.create ()
end

(* Session management *)
type session = {
  file_map : File_map.t;
  changed_files : string list;
  added_files : string list;
  removed_files : string list;
  last_scan_at : float;
}

let make_session ?(file_map = File_map.create ()) () = {
  file_map;
  changed_files = [];
  added_files = [];
  removed_files = [];
  last_scan_at = Unix.gettimeofday ();
}

let empty_session = make_session

(* Change detection types and functions *)
type file_change =
  | Unchanged
  | Modified of { old_state : file_state; new_hash : string; new_mtime : float }
  | Added
  | Removed

let compute_file_change (path : string) (old_map : File_map.t) (new_map : File_map.t) =
  let old_opt = File_map.get path old_map in
  let new_opt = File_map.get path new_map in
  match old_opt, new_opt with
  | None, None -> Unchanged
  | None, _ -> Added
  | _, None -> Removed
  | Some s, Some n ->
    if file_changed s n.cksum n.mtime then
      Modified { old_state = s; new_hash = n.cksum; new_mtime = n.mtime }
    else Unchanged

let compute_session_changes (old : session) (new_map : File_map.t) =
  let extract_paths (m : File_map.t) : string list =
    let paths = ref [] in
    File_map.iter (fun k _ -> paths := k :: !paths) m;
    !paths
  in
  let old_paths = extract_paths old.file_map in
  let new_paths = extract_paths new_map in
  let added = List.filter ~f:(fun p -> not (File_map.mem p old.file_map)) new_paths in
  let removed = List.filter ~f:(fun p -> not (File_map.mem p new_map)) old_paths in
  let changed = List.filter_map ~f:(fun p ->
    match File_map.get p old.file_map, File_map.get p new_map with
    | Some o, Some n when file_changed o n.cksum n.mtime -> Some p
    | _ -> None
  ) new_paths in
  { file_map = new_map; changed_files = changed; added_files = added;
    removed_files = removed; last_scan_at = Unix.gettimeofday () }

(* Cache integration stubs *)
let load_from_cache (_cache : unit) (_path : string) =
  None

(* API helpers *)
let changed_files_count (s : session) =
  List.length s.added_files + List.length s.changed_files + List.length s.removed_files

let should_full_analyze (s : session) =
  s.added_files <> [] || s.changed_files <> []

let affected_files (s : session) =
  s.added_files @ s.changed_files