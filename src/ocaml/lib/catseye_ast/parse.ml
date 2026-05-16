(* src/ocaml/lib/catseye_ast/parse.ml
   Unified parsing interface - JSON Bridge for Gleam and Crystal
*)

open Types
open Error

(** Language from file extension *)
let lang_of_extension path =
  if Filename.check_suffix path ".gleam" then Some Gleam
  else if Filename.check_suffix path ".cr" then Some Crystal
  else None

(** Parse a Gleam file using tree-sitter *)
let parse_gleam = Gleam_mapper.parse_file

(** Parse a Crystal file using hierarchical extractor (preferred) *)
let parse_crystal = Crystal_hierarchical_mapper.parse_file

(** Parse a Crystal file using flat extractor (fallback) *)
let parse_crystal_flat = Crystal_mapper.parse_file

(** Parse a file, inferring language from extension *)
let parse_file ~(path : string) : (t, parse_error) result =
  match lang_of_extension path with
  | None -> Error (make_error ~file:path ~message:"Unknown file type")
  | Some lang ->
      match lang with
      | Gleam -> parse_gleam ~path
      | Crystal ->
        (* Try hierarchical first, fall back to flat on failure *)
        match parse_crystal ~path with
        | Ok _ as result -> result
        | Error _ -> parse_crystal_flat ~path