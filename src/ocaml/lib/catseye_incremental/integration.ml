(* lib/catseye_incremental/integration.ml
   Integration layer: wires incremental state into the analysis engine. *)

open Base

(* Re-export from state_manager for convenience *)
module State_manager = State_manager
module Incremental_graph = Incremental_graph

(* Expose StringMap type for other modules *)
module StringMap = Incremental_graph.StringMap

(** Source file info for incremental analysis *)
type source_info = {
  path : string;
  lang : string;
}

(** Session tracking for incremental analysis *)
module Session = struct
  type session = State_manager.session

  (** Create a new incremental session for a scan *)
  let create_session sources =
    let pairs = List.map ~f:(fun (s : source_info) ->
      let hash = Catseye_engine.Cache.file_hash s.path in
      let mtime = try (Unix.stat s.path).Unix.st_mtime with _ -> 0.0 in
      let state = State_manager.make_file_state
        ~path:s.path
        ~lang:s.lang
        ~cksum:hash
        ~mtime
        ~ast_json:""
        ~nodes:[]
      in
      (s.path, state)
    ) sources
    in
    let file_map = State_manager.File_map.merge (State_manager.File_map.create ()) pairs in
    State_manager.make_session ~file_map ()

  (** Get files that need re-analysis based on content changes *)
  let get_changed_files old_session new_paths =
    let changed_paths = ref [] in
    let added_paths = ref [] in
    List.iter ~f:(fun path ->
      let hash = Catseye_engine.Cache.file_hash path in
      let mtime = try (Unix.stat path).Unix.st_mtime with _ -> 0.0 in
      match State_manager.File_map.get path old_session.State_manager.file_map with
      | None ->
        added_paths := path :: !added_paths
      | Some old_state ->
        if State_manager.file_changed old_state hash mtime then
          changed_paths := path :: !changed_paths
    ) new_paths;
    (!changed_paths, !added_paths)
end

(** File-to-AST cache using reactive map *)
module Ast_cache = struct
  let get_cached path = Incremental_graph.File_to_AST.get_ast path
  
  let store path ast_json = Incremental_graph.File_to_AST.update_file_ast path ast_json
  
  let update_file_ast path ast_json = Incremental_graph.File_to_AST.update_file_ast path ast_json
  let get_ast path = Incremental_graph.File_to_AST.get_ast path
  let clear_ast path = Incremental_graph.File_to_AST.clear_ast path
  let get_all () = Incremental_graph.File_to_AST.get_all ()
  let init (_map : string StringMap.t) = ()
  let clear () = Incremental_graph.invalidate_all ()
end

(** Findings cache using reactive map *)
module Findings_cache = struct
  let get_cached path = Incremental_graph.AST_to_Findings.get_findings path

  let store path findings = Incremental_graph.AST_to_Findings.update_file_findings path findings

  let get_all () = Incremental_graph.AST_to_Findings.all_findings ()

  let update_file_findings path findings = 
    Incremental_graph.AST_to_Findings.update_file_findings path findings
  let get_findings path = Incremental_graph.AST_to_Findings.get_findings path
  let clear_path path = Incremental_graph.AST_to_Findings.clear_path path
  let all_findings () = Incremental_graph.AST_to_Findings.all_findings ()
  let init (_map : Catseye_types.Finding.t list StringMap.t) = ()
  let clear () = Incremental_graph.invalidate_all ()
end

(** Change detection for incremental analysis *)
module Change_detector = struct
  type t = Incremental_graph.incremental_tracker

  let create () = Incremental_graph.create_incremental_tracker ()

  let detect t paths =
    Incremental_graph.detect_file_changes t paths (fun path ->
      try Some (Stdio.In_channel.read_all path) with _ -> None
    )

  let has_changes = Incremental_graph.has_changes
  let changed_count = Incremental_graph.changed_count
  let changed t = t.Incremental_graph.changed
  let added t = t.Incremental_graph.added
  let removed t = t.Incremental_graph.removed
end