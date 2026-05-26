(* lib/catseye_ast/gleam_plugin.ml
   Gleam language plugin descriptor.
   
   Gleam uses tree-sitter exclusively via Gleam_mapper.
   No extractor registry needed for this language.
 *)

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let plugin : Language_plugin.t = {
  name = "gleam";
  extensions = [".gleam"];

  parse_file = Gleam_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter via parse_file *)

  taint_sources = ["request"; "dynamic.from"];
  taint_sinks = ["ffi"; "todo"];
  skip_calls = [];
  manifest_files = ["gleam.toml"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}