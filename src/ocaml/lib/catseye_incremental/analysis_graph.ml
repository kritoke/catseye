(* lib/catseye_incremental/analysis_graph.ml
   Incremental DAG for Catseye analysis state management. *)

open Base

(* ── Node Types ─────────────────────────────────────────────────────── *)

type file_node = {
  path : string;
  lang : string;
  hash : string;
  mtime : float;
}

type ast_node = {
  file : file_node;
  ast_json : string;
}

type finding_node = {
  rule : string;
  severity : string;
  file : string;
  line : int;
  message : string;
}

type smell_node = {
  detector : string;
  file : string;
  line : int;
  metric : string;
  value : float;
}

type graph_node =
  | File of file_node
  | AST of ast_node
  | Finding of finding_node
  | Smell of smell_node

(* ── Incremental Graph Structure ─────────────────────────────────────── *)

module AnalysisGraph = struct
  type t = {
    mutable files : file_node list;
    mutable asts : ast_node list;
    mutable findings : finding_node list;
    mutable smells : smell_node list;
  }

  let create ~(files : file_node list) =
    { files; asts = []; findings = []; smells = [] }

  let get_files (g : t) = g.files

  let update_ast (g : t) (path : string) (ast_json : string) =
    let file = { path; lang = ""; hash = ""; mtime = 0. } in
    let existing = List.filter g.asts ~f:(fun a -> not (String.equal a.file.path path)) in
    g.asts <- { file; ast_json } :: existing

  let findings_for_file (g : t) (path : string) : finding_node list =
    List.filter g.findings ~f:(fun f -> String.equal f.file path)

  let smells_for_file (g : t) (path : string) : smell_node list =
    List.filter g.smells ~f:(fun s -> String.equal s.file path)
end

(* ── Incremental Computation Helpers ────────────────────────────────── *)

module Computation = struct
  let return (x : 'a) : 'a list = [x]

  let map (inc : 'a list) ~(f : 'a -> 'b) : 'b list =
    List.map inc ~f

  let bind (inc : 'a list) ~(f : 'a -> 'b list) : 'b list =
    List.concat_map inc ~f
end

(* ── Diff Computation ───────────────────────────────────────────────── *)

type change =
  | Added of string
  | Modified of string
  | Removed of string

let compute_diff (old_files : file_node list) (new_files : file_node list) : change list =
  let old_paths = List.map old_files ~f:(fun f -> f.path) in
  let new_paths = List.map new_files ~f:(fun f -> f.path) in
  
  let removed =
    List.filter old_paths ~f:(fun p -> not (List.mem new_paths p ~equal:String.equal))
    |> List.map ~f:(fun p -> Removed p)
  in
  let added =
    List.filter new_paths ~f:(fun p -> not (List.mem old_paths p ~equal:String.equal))
    |> List.map ~f:(fun p -> Added p)
  in
  let modified =
    List.filter new_files ~f:(fun new_file ->
      match List.find old_files ~f:(fun f -> String.equal f.path new_file.path) with
      | None -> false
      | Some old_file -> not (String.equal old_file.hash new_file.hash)
    )
    |> List.map ~f:(fun f -> Modified f.path)
  in
  
  removed @ added @ modified
