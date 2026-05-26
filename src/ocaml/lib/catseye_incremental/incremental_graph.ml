(* lib/catseye_incremental/incremental_graph.ml
   Incremental DAG integration with analysis engine.
   Uses reactive state management for self-updating computation. *)

open Base

(* Avoid Base shadowing for comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

module StringMap = Stdlib.Map.Make(String)

(* Analysis node types *)
type analysis_node =
  | File_node of { path : string; lang : string; mtime : float; hash : string; }
  | AST_node of { path : string; ast_json : string; }
  | Security_node of { path : string; nodes : Catseye_types.Security_node.t list; }
  | Finding_node of { rule : string; severity : string; file : string; line : int;
                      original : Catseye_types.Finding.t; }

(* File_to_AST state - reactive map for incremental updates *)
module File_to_AST = struct
  let ast_map : string StringMap.t ref = ref StringMap.empty

  let update_file_ast (path : string) (ast_json : string) =
    ast_map := StringMap.add path ast_json !ast_map

  let get_ast (path : string) =
    StringMap.find_opt path !ast_map

  let clear_ast (path : string) =
    ast_map := StringMap.remove path !ast_map

  let get_all () = !ast_map
end

(* AST_to_Findings state - reactive map for incremental updates *)
module AST_to_Findings = struct
  let findings_map : Catseye_types.Finding.t list StringMap.t ref = ref StringMap.empty

  let update_file_findings (path : string) (findings : Catseye_types.Finding.t list) =
    findings_map := StringMap.add path findings !findings_map

  let get_findings (path : string) =
    StringMap.find_opt path !findings_map

  let clear_path (path : string) =
    findings_map := StringMap.remove path !findings_map

  let all_findings () =
    StringMap.fold (fun _ v acc -> v @ acc) !findings_map []
end

(* Stabilization - placeholder for incremental DAG cycle *)
let stabilize () = ()

(* File change tracker type *)
type incremental_tracker = {
  mutable file_map : (string, int) Map.Poly.t;
  mutable changed : string list;
  mutable added : string list;
  mutable removed : string list;
}

let create_incremental_tracker () = {
  file_map = Map.Poly.empty;
  changed = [];
  added = [];
  removed = [];
}

(* Simple content hash using first/last chars and length *)
let compute_content_hash (content : string) =
  let len = String.length content in
  if len = 0 then ""
  else
    let first = Char.to_int content.[0] in
    let last = Char.to_int content.[len - 1] in
    Printf.sprintf "%d_%d_%d" len first last

(* Detect which files changed *)
let detect_file_changes (t : incremental_tracker) 
    (new_paths : string list) 
    (get_content : string -> string option) =
  let new_map = ref Map.Poly.empty in
  let changed = ref [] in
  let added = ref [] in
  List.iter ~f:(fun path ->
    let content = match get_content path with Some c -> c | None -> "" in
    let raw_hash = compute_content_hash content in
    let key = Hashtbl.hash raw_hash in
    new_map := Map.Poly.set !new_map ~key:path ~data:key;
    match Map.Poly.find t.file_map path with
    | None -> added := path :: !added
    | Some old_key when Stdlib.(<>) old_key key -> changed := path :: !changed
    | _ -> ()
  ) new_paths;
  let removed = List.filter ~f:(fun p ->
    not (List.mem new_paths ~equal:String.equal p)
  ) (Map.Poly.keys t.file_map) in
  t.file_map <- !new_map;
  t.changed <- List.rev !changed;
  t.added <- List.rev !added;
  t.removed <- removed

let has_changes (t : incremental_tracker) =
  t.added <> [] || t.changed <> [] || t.removed <> []

let changed_count (t : incremental_tracker) =
  List.length t.added + List.length t.changed + List.length t.removed

(* Cache invalidation - triggers re-analysis *)
let invalidate_all () =
  File_to_AST.ast_map := StringMap.empty;
  AST_to_Findings.findings_map := StringMap.empty

let invalidate_file (path : string) =
  File_to_AST.clear_ast path;
  AST_to_Findings.clear_path path

(* Findings management - update reactive map *)
let update_findings (path : string) (findings : Catseye_types.Finding.t list) =
  AST_to_Findings.update_file_findings path findings

(* Propagate changes through the analysis pipeline *)
let propagate_changes (tracker : incremental_tracker)
    (re_analyze_file : string -> Catseye_types.Finding.t list) =
  let all_findings = ref [] in
  List.iter ~f:(fun path ->
    let findings = re_analyze_file path in
    update_findings path findings;
    all_findings := findings @ !all_findings
  ) (tracker.changed @ tracker.added);
  stabilize ();
  List.rev !all_findings