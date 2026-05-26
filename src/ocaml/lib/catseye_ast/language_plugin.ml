(* lib/catseye_ast/language_plugin.ml
   Language plugin interface.

   Each supported language is described by a plugin descriptor — a record
   of functions and metadata that the core system calls into. The core never
   pattern-matches on language names; it looks up a plugin by file extension
   and calls its interface.
 *)

module PE = Error

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(** Extractor specification for languages with external extractors. *)
type extractor_spec = {
  binary_name : string;             (* "catseye-crystal-extractor" *)
  source_relative : string list;    (* ["src/extractor/extractor.cr"] *)
  env_var : string;                 (* "CATSEYE_CRYSTAL_EXTRACTOR" *)
  hierarchical : bool;              (* Has a hierarchical extractor too? *)
}

(** A language plugin descriptor. *)
type t = {
  (* Identity *)
  name : string;                    (* "crystal", "gleam", "svelte", "typescript" *)
  extensions : string list;         (* [".cr"], [".gleam"], [".svelte"], [".ts"; ".tsx"] *)

  (* Parsing — produces CatseyeAST.t from a source file *)
  parse_file : path:string -> (Types.t, PE.parse_error) Result.t;

  (* Extraction — optional, for languages with external extractors.
     Produces Security_node.t list from a source file. *)
  extract_file : (string -> Catseye_types.Security_node.t list option) option;

  (* Security — language-specific taint sources and sinks *)
  taint_sources : string list;
  taint_sinks : string list;
  skip_calls : string list;

  (* Dependency discovery *)
  manifest_files : string list;     (* ["shard.yml"], ["gleam.toml"], ["package.json"] *)
  skip_lib_dir : bool;              (* Skip lib/ directory for this language's projects *)

  (* Capabilities *)
  supports_ast_bridge : bool;       (* Can produce CatseyeAST.t *)
  supports_il_cfg : bool;           (* Can produce IL for CFG-based taint *)
}
