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
  let module StringMap = Map.Make(String) in
  let old_map = StringMap.of_list old_hashes in
  let new_map = StringMap.of_list new_hashes in
  
  let deleted = 
    StringMap.filter_keys old_map ~f:(fun p -> not (StringMap.mem new_map p))
    |> StringMap.keys
    |> List.map ~f:(fun p -> Deleted p)
  in
  
  let created =
    StringMap.filter_keys new_map ~f:(fun p -> not (StringMap.mem old_map p))
    |> StringMap.keys
    |> List.map ~f:(fun p -> Created p)
  in
  
  let modified =
    StringMap.merge old_map new_map ~f:(fun ~key ->
      function
      | `Left _ -> None
      | `Right _ -> None
      | `Both (old_hash, new_hash) ->
        if String.equal old_hash new_hash then None
        else Some (Modified key)
    )
    |> StringMap.data
    |> List.filter_opt
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
  
  let dependents (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.target path then Some d.source else None
    )
    |> String.Set.of_list
    |> Set.to_list
  
  let dependencies (g : t) (path : string) : string list =
    List.filter_map g ~f:(fun d ->
      if String.equal d.source path then Some d.target else None
    )
end

(* ── Incremental Analysis State ─────────────────────────────────────── *)

module State = struct
  type t = {
    file_hashes : (string * string) list;
    dependencies : DepGraph.t;
    last_scan_time : float;
  }

  let empty = {
    file_hashes = [];
    dependencies = [];
    last_scan_time = 0.0;
  }

  let update_hashes (s : t) (hashes : (string * string) list) : t =
    { s with file_hashes = hashes }

  let add_dependency (s : t) (dep : dependency) : t =
    { s with dependencies = dep :: s.dependencies }
end

(* ── Minimal Recomputation ──────────────────────────────────────────── *)

type recompute_result = {
  files_to_reparse : string list;
  files_to_rerelyze : string list;
  findings_affected : int;
}

let compute_minimal_recompute 
    (state : State.t) 
    (events : file_event list)
    (_dependency_file : string) : recompute_result =
  let changed_files =
    List.filter_map events ~f:(function
      | Created p | Modified p | Deleted p -> Some p
    )
  in
  
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
    findings_affected = 0;
  }

(* ── Session ────────────────────────────────────────────────────────── *)

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
    max_parallelism = 0;
    incremental = true;
  }

  let create ?(config = default_config) () =
    { state = State.empty; config }

  let update (s : t) (new_hashes : (string * string) list) : t =
    let events = compute_file_events 
      s.state.file_hashes 
      new_hashes 
    in
    let _recompute = compute_minimal_recompute s.state events "" in
    let new_state = State.update_hashes s.state new_hashes in
    { s with state = new_state }

  let get_state (s : t) = s.state
end