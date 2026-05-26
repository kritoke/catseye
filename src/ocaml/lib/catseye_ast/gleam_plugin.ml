(* lib/catseye_ast/plugins/gleam_plugin.ml
   Gleam language plugin descriptor.
 *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let plugin : Language_plugin.t = {
  name = "gleam";
  extensions = [".gleam"];

  parse_file = Gleam_mapper.parse_file;

  extract_file = Some (fun path ->
    try
      let nodes = Catseye_engine.Gleam.extract path in
      (match nodes with
       | Ok ns -> Some ns
       | Error _ -> None)
    with _ -> None
  );

  taint_sources = ["request"; "dynamic.from"];
  taint_sinks = ["ffi"; "todo"];
  skip_calls = [];
  manifest_files = ["gleam.toml"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
