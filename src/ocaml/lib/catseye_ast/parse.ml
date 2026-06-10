(* src/ocaml/lib/catseye_ast/parse.ml
   Unified parsing interface - dispatches based on file extension.
   
   Architecture: catseye.ast is a PURE leaf library with zero dependencies
   on other catseye libraries. It receives extractor commands as simple
   string parameters, not registry objects.
 *)

module PE = Error

open Base
open Types
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* ── Language detection ─────────────────────────────────────────────── *)

(** Language from file extension *)
let lang_of_extension path =
  if Stdlib.Filename.check_suffix path ".gleam" then Some Gleam
  else if Stdlib.Filename.check_suffix path ".cr" then Some Crystal
  else if Stdlib.Filename.check_suffix path ".ts" || Stdlib.Filename.check_suffix path ".tsx" then Some TypeScript
  else if Stdlib.Filename.check_suffix path ".ex" || Stdlib.Filename.check_suffix path ".exs" || Stdlib.Filename.check_suffix path ".heex" then Some Elixir
  else if Stdlib.Filename.check_suffix path ".js" || Stdlib.Filename.check_suffix path ".jsx" || Stdlib.Filename.check_suffix path ".mjs" || Stdlib.Filename.check_suffix path ".cjs" then Some JavaScript
  else if Stdlib.Filename.check_suffix path ".svelte" then Some Svelte
  else if Stdlib.Filename.check_suffix path ".rs" then Some Rust
  else if Stdlib.Filename.check_suffix path ".ml" || Stdlib.Filename.check_suffix path ".mli" then Some OCaml
  else if Stdlib.Filename.check_suffix path ".fs" || Stdlib.Filename.check_suffix path ".fsx" || Stdlib.Filename.check_suffix path ".fsi" then Some FSharp
  else None

(* ── File parsing ────────────────────────────────────────────────────── *)

(** Parse a Gleam file using tree-sitter *)
let parse_gleam = Gleam_mapper.parse_file

(** Parse a Crystal file using hierarchical extractor (preferred) *)
let parse_crystal = Crystal_hierarchical_mapper.parse_file

(** Parse a Crystal file using flat extractor (fallback) *)
let parse_crystal_flat = Crystal_mapper.parse_file

(** Parse an Elixir file using the escript-based extractor *)
let parse_elixir = Elixir_mapper.parse_file

(** Parse a file using the plugin registry.
    Looks up the plugin by file extension and calls its parse_file function. *)
let parse_via_registry ~(registry : Plugin_registry.registry) ~(path : string)
    : (t, PE.parse_error) Stdlib.Result.t =
  (* Find the extension — check all registered extensions *)
  let exts = Plugin_registry.all_extensions registry in
  let matching_plugin = Stdlib.List.find_map (fun ext ->
    if Stdlib.Filename.check_suffix path ext then
      Plugin_registry.for_extension registry ext
    else None
  ) exts in
  match matching_plugin with
  | None -> Stdlib.Result.Error (PE.make_error ~file:path ~message:"No plugin for file type")
  | Some plugin -> plugin.Language_plugin.parse_file ~path

(** Parse a file, inferring language from extension.
    
    @param extractor_cmds Optional record of extractor commands.
                         If None, uses default crystal run commands.
    @param path File to parse.
*)
let parse_file 
    ~(extractor_cmds : Catseye_types.Extractor_cmds.t option)
    ~(path : string)
    : (t, PE.parse_error) Stdlib.Result.t =
  let cmds = Option.value extractor_cmds ~default:Catseye_types.Extractor_cmds.default in
  match lang_of_extension path with
  | None -> Stdlib.Result.Error (PE.make_error ~file:path ~message:"Unknown file type")
  | Some lang ->
      (match lang with
      | Gleam -> parse_gleam ~path
      | Crystal ->
          (match parse_crystal ~extractor_cmd:cmds.hier ~path with
          | Ok ast -> Stdlib.Result.Ok ast
          | Error _ -> parse_crystal_flat ~extractor_cmd:cmds.flat ~path)
      | JavaScript -> Javascript_mapper.parse_file ~path
      | TypeScript -> Typescript_mapper.parse_file ~path
      | Svelte -> Svelte_mapper.parse_file ~path
      | Rust -> Rust_mapper.parse_file ~path
      | OCaml -> Ocaml_mapper.parse_file ~path
      | Elixir -> parse_elixir ~path ~extractor_cmd:cmds.flat
      | FSharp -> Fsharp_mapper.parse_file ~path
      | Other _ -> Stdlib.Result.Error (PE.make_error ~file:path ~message:"Unsupported language"))
