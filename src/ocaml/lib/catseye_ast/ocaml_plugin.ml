(* lib/catseye_ast/ocaml_plugin.ml
   OCaml language plugin descriptor.
*)

let plugin : Language_plugin.t = {
  name = "ocaml";
  extensions = [".ml"; ".mli"];

  parse_file = Ocaml_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter → AST → Security_node bridge *)

  taint_sources = ["Sys.argv"; "Arg.current"; "read_line"; "Scanf";
                    "input"; "input_line"; "input_value";
                    "Unix.getenv"; "Sys.getenv"; "Sys.argv"];
  taint_sinks = ["print_string"; "print_endline"; "Printf.printf";
                  "output"; "output_string"; "Buffer.add_string";
                  "Unix.exec"; "Unix.execv"; "Unix.execvp";
                  "Sys.command"; "open_out"; "open_out_gen";
                  "Marshal.to_channel"; "write"];
  skip_calls = ["ignore"; "failwith"; "raise"];
  manifest_files = ["dune-project"; "opam"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
