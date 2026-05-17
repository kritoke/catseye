(* lib/catseye_ast/javascript_plugin.ml
   JavaScript language plugin descriptor.
*)

let plugin : Language_plugin.t = {
  name = "javascript";
  extensions = [".js"; ".jsx"; ".mjs"; ".cjs"];

  parse_file = Javascript_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter → AST → Security_node bridge *)

  taint_sources = ["process.argv"; "process.env"; "request.body"; "request.params";
                    "request.query"; "window.location"; "document.location"; "event.target"];
  taint_sinks = ["eval"; "Function"; "setTimeout"; "setInterval";
                  "child_process.exec"; "child_process.execSync";
                  "fs.readFile"; "fs.writeFile"; "fs.unlink";
                  "fetch"; "axios"; "XMLHttpRequest";
                  "innerHTML"; "outerHTML"; "document.write";
                  "response.redirect"; "location.assign"; "location.replace"];
  skip_calls = [];
  manifest_files = ["package.json"];
  skip_lib_dir = false;  (* JS uses node_modules, handled by exclude_dirs *)

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
