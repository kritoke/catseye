(* lib/catseye_ast/typescript_plugin.ml
   TypeScript language plugin descriptor.
*)

let plugin : Language_plugin.t = {
  name = "typescript";
  extensions = [".ts"; ".tsx"];

  parse_file = Typescript_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter → AST → Security_node bridge *)

  taint_sources = ["process.argv"; "process.env"; "request.body"; "request.params";
                    "request.query"; "window.location"; "document.location"; "event.target";
                    "req.body"; "req.params"; "req.query"; "ctx.request.body"];
  taint_sinks = ["eval"; "Function"; "setTimeout"; "setInterval";
                  "child_process.exec"; "child_process.execSync";
                  "fs.readFile"; "fs.writeFile"; "fs.unlink";
                  "fetch"; "axios"; "XMLHttpRequest";
                  "innerHTML"; "outerHTML"; "document.write";
                  "response.redirect"; "location.assign"; "location.replace";
                  "dangerouslySetInnerHTML"];
  skip_calls = [];
  manifest_files = ["package.json"; "tsconfig.json"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
