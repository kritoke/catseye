(* src/ocaml/lib/catseye_ast/parse.ml
   Unified parsing interface - dispatches through plugin registry.
 *)

module PE = Error

open Base
open Types
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(** Language from file extension — legacy API, prefer plugin_registry. *)
let lang_of_extension path =
  if Stdlib.Filename.check_suffix path ".gleam" then Some Gleam
  else if Stdlib.Filename.check_suffix path ".cr" then Some Crystal
  else if Stdlib.Filename.check_suffix path ".ts" || Stdlib.Filename.check_suffix path ".tsx" then Some TypeScript
  else if Stdlib.Filename.check_suffix path ".js" || Stdlib.Filename.check_suffix path ".jsx" || Stdlib.Filename.check_suffix path ".mjs" || Stdlib.Filename.check_suffix path ".cjs" then Some JavaScript
  else if Stdlib.Filename.check_suffix path ".svelte" then Some Svelte
  else if Stdlib.Filename.check_suffix path ".rs" then Some Rust
  else if Stdlib.Filename.check_suffix path ".ml" || Stdlib.Filename.check_suffix path ".mli" then Some (Other "ocaml")
  else None

(** Parse a Gleam file using tree-sitter *)
let parse_gleam = Gleam_mapper.parse_file

(** Parse a Crystal file using hierarchical extractor (preferred) *)
let parse_crystal = Crystal_hierarchical_mapper.parse_file

(** Parse a Crystal file using flat extractor (fallback) *)
let parse_crystal_flat = Crystal_mapper.parse_file

(** Parse a file using the plugin registry.
    Looks up the plugin by file extension and calls its parse_file function. *)
let parse_via_registry ~(registry : Plugin_registry.registry) ~(path : string)
    : (t, PE.parse_error) Result.t =
  (* Find the extension — check all registered extensions *)
  let exts = Plugin_registry.all_extensions registry in
  let matching_plugin = Stdlib.List.find_map (fun ext ->
    if Stdlib.Filename.check_suffix path ext then
      Plugin_registry.for_extension registry ext
    else None
  ) exts in
  match matching_plugin with
  | None -> Result.Error (PE.make_error ~file:path ~message:"No plugin for file type")
  | Some plugin -> plugin.Language_plugin.parse_file ~path

(** Parse a file, inferring language from extension.
    Uses the extractor_cmd from the registry for Crystal files.
    Falls back to legacy dispatch if no plugin registry is provided. *)
let parse_file ~(extractor_registry : Catseye_engine.Extractor_registry.t option)
    ~(path : string)
    : (t, PE.parse_error) Result.t =
  match lang_of_extension path with
  | None -> Result.Error (PE.make_error ~file:path ~message:"Unknown file type")
  | Some lang ->
      match lang with
      | Gleam -> parse_gleam ~path
      | Crystal ->
        (let hier_cmd = match extractor_registry with
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
        | Error _ -> parse_crystal_flat ~extractor_cmd:flat_cmd ~path)
      | JavaScript -> Javascript_mapper.parse_file ~path
      | TypeScript -> Typescript_mapper.parse_file ~path
      | Svelte -> Svelte_mapper.parse_file ~path
      | Rust -> Rust_mapper.parse_file ~path
      | Other "ocaml" -> Ocaml_mapper.parse_file ~path
      | Other _ ->
        Result.Error (PE.make_error ~file:path ~message:"Unsupported language")
