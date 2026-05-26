(* lib/catseye_ast/svelte_plugin.ml
   Svelte language plugin descriptor.
 *)


let plugin : Language_plugin.t = {
  name = "svelte";
  extensions = [".svelte"];

  parse_file = Svelte_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter → AST → Security_node bridge *)

  taint_sources = ["$page.url.searchParams"; "$page.url.pathname";
                    "$app/stores"; "export let"; "window.location";
                    "document.location"; "event.target"];
  taint_sinks = ["{@html}"; "innerHTML"; "outerHTML"; "document.write";
                  "eval"; "Function"; "setTimeout"; "fetch"; "axios";
                  "response.redirect"; "location.assign"];
  skip_calls = [];
  manifest_files = ["package.json"; "svelte.config.js"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
