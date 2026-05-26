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

  let invalidate_file (g : t) (_path : string) =
    (* Keep all files, hash change will propagate *)
    g.files <- g.files

  let get_files (g : t) = g.files

  let update_ast (g : t) (path : string) (ast_json : string) =
    let file = { path; lang = ""; hash = ""; mtime = 0. } in
    let existing = List.filter g.asts ~f:(fun a -> a.file.path <> path) in
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

module Diff = struct
  type change =
    | Added of string
    | Modified of string
    | Removed of string

  let compute_diff (old_files : file_node list) (new_files : file_node list) =
    let old_map = List.map old_files ~f:(fun f -> f.path, f) |> String.Map.of_alist_exn in
    let new_map = List.map new_files ~f:(fun f -> f.path, f) |> String.Map.of_alist_exn in
    
    let removed =
      Map.filter_keys old_map ~f:(fun p -> not (Map.mem new_map p))
      |> Map.keys
      |> List.map ~f:(fun p -> Removed p)
    in
    let added =
      Map.filter_keys new_map ~f:(fun p -> not (Map.mem old_map p))
      |> Map.keys
      |> List.map ~f:(fun p -> Added p)
    in
    let modified =
      Map.merge old_map new_map ~f:(fun ~key ->
        function
        | `Left _ -> None
        | `Right _ -> None
        | `Both (old, new_) ->
          if not (String.equal old.hash new_.hash) then Some (Modified key) else None
      )
      |> Map.data
      |> List.filter_opt
    in
    removed @ added @ modified

  let affected_findings (findings : finding_node list) (changes : change list) =
    let changed_files =
      List.filter_map changes ~f:(function
        | Added p | Modified p | Removed p -> Some p
      )
      |> String.Set.of_list
    in
    List.filter findings ~f:(fun f ->
      Set.mem changed_files f.file
    )
end

(* ── Version tracking ───────────────────────────────────────────────── *)

let version = "0.1.0"