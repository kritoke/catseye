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

(** Parse a file, inferring language from extension.
    Uses the extractor_cmd from the registry for Crystal files. *)
let parse_file ~(extractor_registry : Catseye_engine.Extractor_registry.t option) ~(path : string)
    : (t, parse_error) result =
  match lang_of_extension path with
  | None -> Error (make_error ~file:path ~message:"Unknown file type")
  | Some lang ->
      match lang with
      | Gleam -> parse_gleam ~path
      | Crystal ->
        let hier_cmd = match extractor_registry with
          | Some r -> Catseye_engine.Extractor_registry.hier_cmd r
          | None -> "crystal run src/extractor/hierarchical_extractor.cr --"
        in
        let flat_cmd = match extractor_registry with
          | Some r -> Catseye_engine.Extractor_registry.flat_cmd r
          | None -> "crystal run src/extractor/extractor.cr --"
        in
        (* Try hierarchical first, fall back to flat on failure *)
        match parse_crystal ~extractor_cmd:hier_cmd ~path with
        | Ok _ as result -> result
        | Error _ -> parse_crystal_flat ~extractor_cmd:flat_cmd ~path
