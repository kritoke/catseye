(* lib/catseye_incremental/integration.ml
   Integration layer: wires incremental state into the analysis engine. *)

open Base

(* Re-export from state_manager for convenience *)
module State_manager = State_manager
module Incremental_graph = Incremental_graph

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

(** File-to-AST cache integration *)
module Ast_cache = struct
  let ast_var : string Incremental_graph.SM.t option ref = ref None
  
  let get_cached path =
    let open Stdlib in
    match !ast_var with
    | None -> None
    | Some map -> Incremental_graph.SM.find_opt path map

  let store path ast_json =
    let open Stdlib in
    match !ast_var with
    | None -> ast_var := Some (Incremental_graph.SM.add path ast_json Incremental_graph.SM.empty)
    | Some map -> ast_var := Some (Incremental_graph.SM.add path ast_json map)

  let init map = ast_var := Some map
  let clear () = ast_var := None
  let update_file_ast (_path : string) (_ast_json : string) = ()
  let get_ast (_path : string) = None
  let clear_ast (_path : string) = ()
end

(** Findings cache integration *)
module Findings_cache = struct
  let findings_var : Catseye_types.Finding.t list Incremental_graph.SM.t option ref = ref None

  let get_cached path =
    let open Stdlib in
    match !findings_var with
    | None -> None
    | Some map -> Incremental_graph.SM.find_opt path map

  let store path findings =
    let open Stdlib in
    match !findings_var with
    | None -> findings_var := Some (Incremental_graph.SM.add path findings Incremental_graph.SM.empty)
    | Some map -> findings_var := Some (Incremental_graph.SM.add path findings map)

  let get_all () =
    let open Stdlib in
    match !findings_var with
    | None -> []
    | Some map -> Incremental_graph.SM.fold (fun _ v acc -> v :: acc) map []

  let init map = findings_var := Some map
  let clear () = findings_var := None
  let update_file_findings (_path : string) (_findings : Catseye_types.Finding.t list) = ()
  let get_findings (_path : string) = None
  let clear_path (_path : string) = ()
  let all_findings () = []
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