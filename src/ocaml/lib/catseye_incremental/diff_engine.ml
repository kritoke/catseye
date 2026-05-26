(* lib/catseye_incremental/diff_engine.ml
   Diff-based incremental analysis engine. *)

open Base

(* ── File Change Detection ─────────────────────────────────────────── *)

type file_event =
  | Created of string
  | Modified of string
  | Deleted of string

let compute_file_events (old_hashes : (string * string) list) 
                        (new_hashes : (string * string) list) : file_event list =
  let old_keys = List.map old_hashes ~f:fst in
  let new_keys = List.map new_hashes ~f:fst in
  
  let deleted = 
    List.filter old_keys ~f:(fun p -> not (List.mem new_keys p ~equal:String.equal))
    |> List.map ~f:(fun p -> Deleted p)
  in
  
  let created =
    List.filter new_keys ~f:(fun p -> not (List.mem old_keys p ~equal:String.equal))
    |> List.map ~f:(fun p -> Created p)
  in
  
  let modified =
    List.filter new_hashes ~f:(fun (path, new_hash) ->
      match List.Assoc.find old_hashes path ~equal:String.equal with
      | None -> false
      | Some old_hash -> not (String.equal old_hash new_hash)
    )
    |> List.map ~f:(fun (path, _) -> Modified path)
  in
  
  deleted @ created @ modified

(* ── Dependency Analysis ────────────────────────────────────────────── *)

type dep_kind = Import | Inherit | Call | Type_use

type dependency = {
  source : string;
  target : string;
  kind : dep_kind;
}

module DepGraph = struct
  type t = dependency list
  
  let empty = []
  
  let add_dep (g : t) ~(source : string) ~(target : string) ~(kind : dep_kind) : t =
    { source; target; kind } :: g
  
  let dependents (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.target path then Some d.source else None
    )
    |> List.dedup_and_sort ~compare:String.compare
  
  let dependencies (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.source path then Some d.target else None
    )
    |> List.dedup_and_sort ~compare:String.compare
end

(* ── Incremental Analysis State ─────────────────────────────────────── *)

module State = struct
  type t = {
    file_hashes : (string * string) list;
    dependencies : DepGraph.t;
  }

  let create () = {
    file_hashes = [];
    dependencies = [];
  }

  let update_hashes (s : t) (hashes : (string * string) list) : t =
    { s with file_hashes = hashes }

  let update_deps (s : t) (deps : DepGraph.t) : t =
    { s with dependencies = deps }

  let compute_affected (s : t) (changed_files : string list) : string list =
    let rec collect_affected acc = function
      | [] -> List.dedup_and_sort acc ~compare:String.compare
      | file :: rest ->
        let deps = DepGraph.dependents s.dependencies file in
        let new_affected = file :: (List.rev_append deps acc) in
        collect_affected new_affected rest
    in
    collect_affected [] changed_files

  let diff (s : t) (new_hashes : (string * string) list) : string list * string list =
    let events = compute_file_events s.file_hashes new_hashes in
    let changed_files = List.map events ~f:(function
      | Created p | Modified p -> p
      | Deleted _ -> ""
    ) |> List.filter ~f:(fun p -> not (String.is_empty p))
    in
    let affected = compute_affected s changed_files in
    (changed_files, affected)
end
