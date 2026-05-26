(* lib/catseye_incremental/diff_engine.ml
   Diff-based incremental analysis engine.

   Provides the core logic for computing minimal changes
   and triggering only affected recomputations. *)

open Base
open Incremental

(* ── File Change Detection ─────────────────────────────────────────── *)

(** Represents a file change event *)
type file_event =
  | Created of string
  | Modified of string
  | Deleted of string

(** Compute the minimal set of files that changed between two scans *)
let compute_file_events (old_hashes : (string * string) list) 
                        (new_hashes : (string * string) list) : file_event list =
  let old_map = String.Map.of_list old_hashes in
  let new_map = String.Map.of_list new_hashes in
  
  let events = [] in
  
  (* Find deleted files *)
  let deleted = 
    Map.filter_keys old_map ~f:(fun p -> not (Map.mem new_map p))
    |> Map.keys
    |> List.map ~f:(fun p -> Deleted p)
  in
  
  (* Find created files *)
  let created =
    Map.filter_keys new_map ~f:(fun p -> not (Map.mem old_map p))
    |> Map.keys
    |> List.map ~f:(fun p -> Created p)
  in
  
  (* Find modified files *)
  let modified =
    Map.merge old_map new_map ~f:(fun ~key ->
      function
      | `Left _ -> None
      | `Right _ -> None
      | `Both (old_hash, new_hash) ->
        if String.equal old_hash new_hash then None
        else Some (Modified key)
    )
    |> Map.data
    |> List.filter_opt
  in
  
  deleted @ created @ modified

(* ── Dependency Analysis ────────────────────────────────────────────── *)

(** Represents a dependency relationship between files *)
type dependency = {
  source : string;  (* File that depends on another *)
  target : string;  (* File being depended upon *)
  kind : [ `import | `inherit | `call | `type_use ];
}

(** Build a dependency graph from file relationships *)
module DepGraph = struct
  type t = dependency list
  
  let empty = []
  
  (** Find all files that depend on a given file *)
  let dependents (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.target path then Some d.source else None
    )
    |> String.Set.of_list
    |> Set.to_list
  
  (** Find all files that a given file depends on *)
  let dependencies (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.source path then Some d.target else None
    )
end

(* ── Incremental Analysis State ─────────────────────────────────────── *)

(** State for incremental analysis sessions *)
module State = struct
  type t = {
    file_hashes : (string * string) Map.M(String).t;
    dependencies : DepGraph.t;
    last_scan_time : float;
  }

  let empty = {
    file_hashes = Map.empty (module String);
    dependencies = [];
    last_scan_time = 0.0;
  }

  (** Update with new file hashes *)
  let update_hashes (s : t) (hashes : (string * string) list) : t =
    { s with file_hashes = Map.of_alist_exn hashes }

  (** Add a dependency *)
  let add_dependency (s : t) (dep : dependency) : t =
    { s with dependencies = dep :: s.dependencies }
end

(* ── Minimal Recomputation ──────────────────────────────────────────── *)

(** Result of a minimal recomputation request *)
type recompute_result = {
  files_to_reparse : string list;
  files_to_rerelyze : string list;
  findings_affected : int;
}

(** Compute the minimal set of files that need recomputation after changes *)
let compute_minimal_recompute 
    (state : State.t) 
    (events : file_event list)
    (dependency_file : string) : recompute_result =
  let changed_files =
    List.filter_map events ~f:(function
      | Created p | Modified p | Deleted p -> Some p
    )
  in
  
  (* Collect files that need reparsing (changed files + their dependents) *)
  let rec collect_affected acc = function
    | [] -> acc
    | file :: rest ->
      let dependents = DepGraph.dependents state.dependencies file in
      let new_affected = file :: (dependents @ acc) in
      let unique = String.Set.of_list new_affected |> Set.to_list in
      collect_affected unique rest
  in
  
  let files_to_analyze = collect_affected changed_files changed_files in
  
  {
    files_to_reparse = changed_files;
    files_to_rerelyze = files_to_analyze;
    findings_affected = 0;  (* TODO: compute from actual findings *)
  }

(* ── Watch and Update Loop ─────────────────────────────────────────── *)

(** Represents an incremental scan session *)
module Session = struct
  type t = {
    state : State.t;
    config : incremental_config;
  }
  and incremental_config = {
    debounce_ms : int;
    max_parallelism : int;
    incremental : bool;
  }

  let default_config = {
    debounce_ms = 100;
    max_parallelism = 0;  (* 0 = auto *)
    incremental = true;
  }

  (** Start a new incremental session *)
  let create ?(config = default_config) () =
    { state = State.empty; config }

  (** Update session with new scan results *)
  let update (s : t) (new_hashes : (string * string) list) : t =
    let events = compute_file_events 
      (Map.to_alist s.state.file_hashes) 
      new_hashes 
    in
    let recompute = compute_minimal_recompute s.state events "" in
    let new_state = State.update_hashes s.state new_hashes in
    { s with state = new_state }

  (** Get current state *)
  let get_state (s : t) = s.state
end