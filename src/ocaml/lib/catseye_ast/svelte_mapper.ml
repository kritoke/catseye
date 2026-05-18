(* lib/catseye_ast/svelte_mapper.ml
   Bridge from tree-sitter Svelte XML output to CatseyeAST.t.
   
   Two-pass parsing:
   1. Parse .svelte with tree-sitter-svelte → top-level CST
   2. Extract <script> blocks → parse content with JS or TS grammar
   3. Map template {@html} directives from Svelte CST
   4. Merge into single CatseyeAST.t
*)

open Types
open Error

(* Import shared tree-sitter XML types *)
module Tsx = Tree_sitter_xml

type xml = Tsx.xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

let attr = Tsx.attr
let line_of = Tsx.line_of
let find = Tsx.find
let parse_xml = Tsx.parse_xml

(* ── Position helpers ─────────────────────────────────────────────── *)

let position_of_xml (n : xml) ~field =
  let row = try int_of_string (attr n field) + 1 with _ -> 0 in
  Position.make ~line:row ~column:0 ~byte_offset:0

let range_of_xml (n : xml) =
  { start = position_of_xml n ~field:"srow";
    end_ = position_of_xml n ~field:"erow" }

let children_with_field (n : xml) ~(field : string) : xml list =
  List.filter (fun c -> attr c "field" = field) n.children

let children_with_tag (n : xml) ~(tag : string) : xml list =
  List.filter (fun c -> c.tag = tag) n.children

(* ── Svelte grammar resolution ──────────────────────────────────────── *)

let resolve_svelte_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"svelte" ~env_var:"TREE_SITTER_SVELTE_GRAMMAR"

(* ── Run tree-sitter on a source string via temp file ───────────────── *)

let run_tree_sitter_on_string ~grammar ~lang ~source : xml option =
  let tmp = Filename.temp_file "catseye_svelte" ".src" in
  let cleanup () = try Sys.remove tmp with _ -> () in
  try
    let oc = open_out tmp in
    output_string oc source;
    close_out oc;
    let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name %s -x '%s' 2>/dev/null"
      grammar lang tmp in
    let ic = Unix.open_process_in cmd in
    let buf = Buffer.create 4096 in
    (try while true do Buffer.add_channel buf ic 4096 done with End_of_file -> ());
    let _ = Unix.close_process_in ic in
    let xml_str = Buffer.contents buf in
    cleanup ();
    if xml_str = "" then None
    else Some (parse_xml xml_str)
  with _ -> cleanup (); None

(* ── Extract <script> block content from Svelte CST ──────────────────── *)

(** Find the <script> tag and extract its raw text content + lang attribute. *)
let extract_script_block (doc : xml) : (string * string) option =
  let scripts = find doc ~tag:"script_element" in
  match scripts with
  | s :: _ ->
    let text_children = List.filter (fun c -> c.text <> "") s.children in
    let content = String.concat "" (List.map (fun c -> c.text) text_children) in
    let lang_attr = attr s "lang" in
    Some (content, lang_attr)
  | [] ->
    let alt = find doc ~tag:"script" in
    (match alt with
     | s :: _ ->
       let text_children = List.filter (fun c -> c.text <> "") s.children in
       let content = String.concat "" (List.map (fun c -> c.text) text_children) in
       let lang_attr = attr s "lang" in
       Some (content, lang_attr)
     | [] -> None)

(* ── Template directive extraction ───────────────────────────────────── *)

(** Walk the Svelte template CST and find {@html ...} directives.
    Maps them to IFunction items for sink detection. *)
let rec extract_template_items (n : xml) (file : string) : item list =
  let loc = range_of_xml n in
  match n.tag with
  | "html_expression" | "raw_html_expression" | "html" ->
    let inner_exprs = List.filter (fun c -> c.tag <> "") n.children in
    let expr = match inner_exprs with
      | [e] -> { expr_value = EVar (String.trim e.text); expr_location = range_of_xml e }
      | _ -> { expr_value = EVar "__html_content"; expr_location = loc }
    in
    [{ item_value = IFunction ("__svelte_html", [], None,
        { expr_value = EApp ({ expr_value = EVar "__svelte_html"; expr_location = loc }, [expr]);
          expr_location = loc });
       item_location = loc }]
  | "if_statement" | "each_statement" | "await_statement" | "if_else_statement" ->
    List.concat_map (fun c -> extract_template_items c file) n.children
  | _ ->
    List.concat_map (fun c -> extract_template_items c file) n.children

(* ── Parse Svelte file ──────────────────────────────────────────────── *)

let parse_file ~(path : string) : (t, parse_error) result =
  match resolve_svelte_grammar () with
  | None ->
    Error (make_error ~file:path ~message:"Svelte tree-sitter grammar not found. Set TREE_SITTER_SVELTE_GRAMMAR or install tree-sitter-svelte.")
  | Some grammar ->
    let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name svelte -x '%s' 2>/dev/null" grammar path in
    try
      let ic = Unix.open_process_in cmd in
      let xml_str = Buffer.create 4096 in
      (try while true do Buffer.add_channel xml_str ic 4096 done with End_of_file -> ());
      let status = Unix.close_process_in ic in
      match status with
      | Unix.WEXITED 0 | Unix.WEXITED 1 ->
        let doc = parse_xml (Buffer.contents xml_str) in
        (* Extract <script> block and parse with JS/TS grammar *)
        let script_items = match extract_script_block doc with
          | None -> []
          | Some (script_content, lang_attr) ->
            let use_ts = lang_attr = "ts" || lang_attr = "typescript" in
            let js_grammar = Tree_sitter_xml.resolve_grammar ~lang:"javascript" ~env_var:"TREE_SITTER_JAVASCRIPT_GRAMMAR" in
            let ts_grammar = Tree_sitter_xml.resolve_grammar ~lang:"typescript" ~env_var:"TREE_SITTER_TYPESCRIPT_GRAMMAR" in
            let grammar = if use_ts then ts_grammar else js_grammar in
            match grammar with
            | None -> []
            | Some g ->
              let lang_name = if use_ts then "typescript" else "javascript" in
              (match run_tree_sitter_on_string ~grammar:g ~lang:lang_name ~source:script_content with
               | None -> []
               | Some script_doc ->
                 (* Wrap in <program> tag like JS mapper does *)
                 let program = match find script_doc ~tag:"program" with
                   | [p] -> p
                   | _ -> script_doc
                 in
                 List.concat_map (fun c ->
                   Javascript_mapper.walk_statement c path
                 ) program.children)
        in
        (* Extract template directives *)
        let template_items = extract_template_items doc path in
        let all_items = script_items @ template_items in
        Ok { mod_lang = Svelte; mod_path = path; mod_items = all_items; parse_errors = [] }
      | _ ->
        Error (make_error ~file:path ~message:"Svelte tree-sitter parse failed")
    with Sys_error msg ->
      Error (make_error ~file:path ~message:("tree-sitter error: " ^ msg))
