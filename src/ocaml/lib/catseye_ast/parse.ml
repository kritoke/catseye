(* src/ocaml/lib/catseye_ast/parse.ml
   Unified parsing interface - dispatches through plugin registry.
*)

open Types
open Error

(** Language from file extension — legacy API, prefer plugin_registry. *)
let lang_of_extension path =
  if Filename.check_suffix path ".gleam" then Some Gleam
  else if Filename.check_suffix path ".cr" then Some Crystal
  else if Filename.check_suffix path ".ts" || Filename.check_suffix path ".tsx" then Some TypeScript
  else if Filename.check_suffix path ".js" || Filename.check_suffix path ".jsx" then Some JavaScript
  else if Filename.check_suffix path ".svelte" then Some Svelte
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
    : (t, parse_error) result =
  (* Find the extension — check all registered extensions *)
  let exts = Plugin_registry.all_extensions registry in
  let matching_plugin = List.find_map (fun ext ->
    if Filename.check_suffix path ext then
      Plugin_registry.for_extension registry ext
    else None
  ) exts in
  match matching_plugin with
  | None -> Error (make_error ~file:path ~message:"No plugin for file type")
  | Some plugin -> plugin.Language_plugin.parse_file ~path

(** Parse a file, inferring language from extension.
    Uses the extractor_cmd from the registry for Crystal files.
    Falls back to legacy dispatch if no plugin registry is provided. *)
let parse_file ~(extractor_registry : Catseye_engine.Extractor_registry.t option)
    ~(path : string)
    : (t, parse_error) result =
  match lang_of_extension path with
  | None -> Error (make_error ~file:path ~message:"Unknown file type")
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
      | Other _ ->
        Error (make_error ~file:path ~message:"Unsupported language")
