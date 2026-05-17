(* lib/catseye_ast/javascript_mapper.ml
   Bridge from tree-sitter JavaScript/TypeScript XML output to CatseyeAST.t.
   
   Uses shared Tree_sitter_xml module for XML parsing.
   Handles both .js/.jsx (JavaScript) and .ts/.tsx (TypeScript).
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

(* ── XML → CatseyeAST conversion ────────────────────────────────────── *)

let rec walk_expr (n : xml) (file : string) : expr =
  let loc = range_of_xml n in
  let v = match n.tag with
    | "identifier" | "property_identifier" | "shorthand_property_identifier" | "type_identifier" ->
      EVar n.text
    | "number" | "string" | "template_string" | "regex" | "undefined" ->
      ELiteral (LString n.text)
    | "true" -> ELiteral (LBool true)
    | "false" -> ELiteral (LBool false)
    | "null" -> ELiteral LNull
    | "object" ->
      let pairs = List.concat_map (fun c ->
        match c.tag with
        | "pair" ->
          let key_nodes = children_with_tag c ~tag:"property_identifier" in
          let val_nodes = children_with_field c ~field:"value" in
          (match key_nodes, val_nodes with
           | [k], [v] -> [(k.text, walk_expr v file)]
           | _ -> [])
        | "spread_element" -> []  (* TODO: handle spread *)
        | _ -> []
      ) n.children in
      ERecord pairs
    | "array" ->
      let elems = List.filter_map (fun c ->
        (* Skip punctuation *)
        if c.tag = "," then None
        else Some (walk_expr c file)
      ) n.children in
      EList elems
    | "call_expression" ->
      let fn_node = List.filter_map (fun c ->
        if attr c "field" = "function" then Some c else None
      ) n.children in
      let arg_nodes = List.filter (fun c -> attr c "field" = "arguments") n.children in
      let args = List.concat_map (fun a ->
        List.filter_map (fun c ->
          if c.tag = "," then None
          else Some (walk_expr c file)
        ) a.children
      ) arg_nodes in
      let fn_expr = match fn_node with [f] -> walk_expr f file | _ -> { expr_value = EVar "<call>"; expr_location = loc } in
      EApp (fn_expr, args)
    | "member_expression" ->
      let obj = List.filter_map (fun c ->
        if attr c "field" = "object" then Some (walk_expr c file) else None
      ) n.children in
      let prop = List.filter_map (fun c ->
        if attr c "field" = "property" then Some c.text else None
      ) n.children in
      (match obj, prop with
       | [o], [p] -> EFieldAccess (o, p)
       | _ -> EUnknown "member_expression")
    | "binary_expression" ->
      let left = List.filter_map (fun c ->
        if attr c "field" = "left" then Some (walk_expr c file) else None
      ) n.children in
      let op = List.filter_map (fun c ->
        if c.tag = "&&" || c.tag = "||" || c.tag = "+" || c.tag = "-"
        || c.tag = "==" || c.tag = "!=" || c.tag = "==="
        || c.tag = "!==" || c.tag = "+" || c.tag = "++"
        then Some c.text else None
      ) n.children in
      let right = List.filter_map (fun c ->
        if attr c "field" = "right" then Some (walk_expr c file) else None
      ) n.children in
      (match left, op, right with
       | [l], [o], [r] -> EBinOp (l, o, r)
       | _ -> EUnknown "binary_expression")
    | "assignment_expression" ->
      let left = List.filter_map (fun c ->
        if attr c "field" = "left" then Some (walk_expr c file) else None
      ) n.children in
      let right = List.filter_map (fun c ->
        if attr c "field" = "right" then Some (walk_expr c file) else None
      ) n.children in
      (match left, right with
       | [l], [r] -> EAssignment (l, r)
       | _ -> EUnknown "assignment")
    | "parenthesized_expression" | "expression_statement" ->
      (match List.filter (fun c -> attr c "field" <> "" || true) n.children with
       | [inner] -> (walk_expr inner file).expr_value
       | _ -> EUnknown n.tag)
    | "statement_block" ->
      (* Block of statements — collect each as an expression *)
      let stmts = List.filter_map (fun c ->
        match c.tag with
        | "," | "comment" -> None
        | "return_statement" ->
          let vals = List.filter_map (fun inner ->
            if attr inner "field" = "argument" then Some (walk_expr inner file) else None
          ) c.children in
          (match vals with [v] -> Some { expr_value = EApp ({ expr_value = EVar "return"; expr_location = range_of_xml c }, [v]); expr_location = range_of_xml c } | _ -> None)
        | _ -> Some (walk_expr c file)
      ) n.children in
      EBlock stmts
    | "new_expression" ->
      let constructor = List.filter_map (fun c ->
        if attr c "field" = "constructor" then Some (walk_expr c file) else None
      ) n.children in
      let arg_nodes = List.filter (fun c -> attr c "field" = "arguments") n.children in
      let args = List.concat_map (fun a ->
        List.filter_map (fun c ->
          if c.tag = "," then None
          else Some (walk_expr c file)
        ) a.children
      ) arg_nodes in
      (match constructor with
       | [c] -> EApp (c, args)  (* new X() represented as EApp *)
       | _ -> EUnknown "new_expression")
    | "arrow_function" | "function_expression" ->
      let params = List.concat_map (fun c ->
        if attr c "field" = "parameters" then
          List.filter_map (fun p ->
            if p.tag = "identifier" then Some (PVar p.text) else None
          ) c.children
        else []
      ) n.children in
      let body_nodes = List.filter (fun c -> attr c "field" = "body") n.children in
      let body = match body_nodes with
        | [b] -> walk_expr b file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      EFn (params, body)
    | "ternary_expression" ->
      let cond = List.filter_map (fun c ->
        if attr c "field" = "condition" then Some (walk_expr c file) else None
      ) n.children in
      let cons = List.filter_map (fun c ->
        if attr c "field" = "consequence" then Some (walk_expr c file) else None
      ) n.children in
      let alt = List.filter_map (fun c ->
        if attr c "field" = "alternative" then Some (walk_expr c file) else None
      ) n.children in
      (match cond, cons, alt with
       | [c], [t], [e] -> EIf (c, t, Some e)
       | [c], [t], [] -> EIf (c, t, None)
       | _ -> EUnknown "ternary")
    | "await_expression" ->
      (match List.filter (fun c -> attr c "field" = "argument") n.children with
       | [inner] -> (walk_expr inner file).expr_value
       | _ -> EUnknown "await")
    | "unary_expression" ->
      let arg = List.filter_map (fun c ->
        if attr c "field" = "argument" then Some (walk_expr c file) else None
      ) n.children in
      let op = List.filter_map (fun c ->
        if c.tag = "!" || c.tag = "-" || c.tag = "+" || c.tag = "~" || c.tag = "typeof" || c.tag = "void" || c.tag = "delete"
        then Some c.text else None
      ) n.children in
      (match op, arg with
       | [o], [a] -> EUnOp (o, a)
       | _ -> EUnknown "unary")
    | "subscript_expression" ->
      let obj = List.filter_map (fun c ->
        if attr c "field" = "object" then Some (walk_expr c file) else None
      ) n.children in
      let idx = List.filter_map (fun c ->
        if attr c "field" = "index" then Some (walk_expr c file) else None
      ) n.children in
      (match obj, idx with
       | [o], [i] -> EApp ({ expr_value = EVar "[]"; expr_location = loc }, [o; i])
       | _ -> EUnknown "subscript")
    | _ -> EUnknown n.tag
  in
  { expr_value = v; expr_location = loc }

(* ── Statement → item conversion ──────────────────────────────────── *)

let rec walk_statement (n : xml) (file : string) : item list =
  let loc = range_of_xml n in
  match n.tag with
  | "function_declaration" | "generator_function_declaration" | "function" ->
    let name = List.filter_map (fun c ->
      if attr c "field" = "name" then Some c.text else None
    ) n.children in
    let params = List.concat_map (fun c ->
      if attr c "field" = "parameters" then
        List.filter_map (fun p ->
          match p.tag with
          | "identifier" -> Some (PVar p.text)
          | "required_parameter" ->
            let bindings = children_with_tag p ~tag:"identifier" in
            (match bindings with [b] -> Some (PVar b.text) | _ -> Some PDiscard)
          | _ -> None
        ) c.children
      else []
    ) n.children in
    let body = List.filter (fun c -> attr c "field" = "body") n.children in
    let body_expr = match body with
      | [b] -> walk_expr b file
      | _ -> { expr_value = EUnit; expr_location = loc }
    in
    let fn_name = match name with [n] -> n | _ -> "<anonymous>" in
    [{ item_value = IFunction (fn_name, params, None, body_expr); item_location = loc }]
  | "variable_declaration" | "lexical_declaration" ->
    List.filter_map (fun c ->
      if c.tag = "variable_declarator" then
        let name = List.filter_map (fun inner ->
          if attr inner "field" = "name" then Some inner.text else None
        ) c.children in
        let value = List.filter (fun inner -> attr inner "field" = "value") c.children in
        let pat = match name with [n] -> PVar n | _ -> PDiscard in
        let expr = match value with [v] -> walk_expr v file | _ -> { expr_value = EUnit; expr_location = loc } in
        Some { item_value = IConstant (pat, None, expr); item_location = range_of_xml c }
      else None
    ) n.children
  | "class_declaration" ->
    let name = List.filter_map (fun c ->
      if attr c "field" = "name" then Some c.text else None
    ) n.children in
    let body = List.filter (fun c -> attr c "field" = "body") n.children in
    let class_items = match body with
      | [b] -> List.concat_map (fun c -> walk_statement c file) b.children
      | _ -> []
    in
    let class_name = match name with [n] -> n | _ -> "<class>" in
    [{ item_value = IClass (class_name, class_items); item_location = loc }]
  | "method_definition" ->
    let name = List.filter_map (fun c ->
      if attr c "field" = "name" then Some c.text else None
    ) n.children in
    let params = List.concat_map (fun c ->
      if attr c "field" = "parameters" then
        List.filter_map (fun p ->
          match p.tag with
          | "identifier" -> Some (PVar p.text)
          | "required_parameter" ->
            let bindings = children_with_tag p ~tag:"identifier" in
            (match bindings with [b] -> Some (PVar b.text) | _ -> Some PDiscard)
          | _ -> None
        ) c.children
      else []
    ) n.children in
    let body = List.filter (fun c -> attr c "field" = "body") n.children in
    let body_expr = match body with
      | [b] -> walk_expr b file
      | _ -> { expr_value = EUnit; expr_location = loc }
    in
    let fn_name = match name with [n] -> n | _ -> "<method>" in
    [{ item_value = IFunction (fn_name, params, None, body_expr); item_location = loc }]
  | "import_statement" ->
    let source = List.filter_map (fun c ->
      if attr c "field" = "source" && c.tag = "string" then
        let s = c.text in
        Some (if String.length s >= 2 then String.sub s 1 (String.length s - 2) else s)
      else None
    ) n.children in
    let imp_name = match source with [s] -> s | _ -> "" in
    [{ item_value = IImport (imp_name, None); item_location = loc }]
  | "export_statement" | "export_default_declaration" ->
    (* Unwrap export — just process the inner declaration *)
    List.concat_map (fun c -> walk_statement c file) n.children
  | "expression_statement" ->
    []  (* Expressions at statement level — not top-level items *)
  | "statement_block" | "program" | "module" ->
    List.concat_map (fun c -> walk_statement c file) n.children
  | "if_statement" | "for_statement" | "while_statement" | "try_statement"
  | "switch_statement" | "return_statement" | "throw_statement"
  | "break_statement" | "continue_statement" | "comment"
  | "empty_statement" | "labeled_statement" | "with_statement"
  | "do_statement" | "for_in_statement" | " debugger_statement" ->
    []  (* Control flow — not top-level items *)
  | _ ->
    []

(* ── Parse via tree-sitter CLI ─────────────────────────────────────── *)

let resolve_js_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"javascript" ~env_var:"TREE_SITTER_JAVASCRIPT_GRAMMAR"

let resolve_ts_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"typescript" ~env_var:"TREE_SITTER_TYPESCRIPT_GRAMMAR"

let parse_with_grammar ~grammar ~lang ~path : (t, parse_error) result =
  let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name %s -x '%s' 2>/dev/null" grammar lang path in
  try
    let ic = Unix.open_process_in cmd in
    let xml_str = Buffer.create 4096 in
    (try while true do Buffer.add_channel xml_str ic 4096 done with End_of_file -> ());
    let status = Unix.close_process_in ic in
    match status with
    | Unix.WEXITED 0 | Unix.WEXITED 1 ->
      let doc = parse_xml (Buffer.contents xml_str) in
      (* Drill through <sources><source><program> wrapper *)
      let program = match find doc ~tag:"program" with
        | [p] -> p
        | _ -> doc
      in
      let items = List.concat_map (fun c -> walk_statement c path) program.children in
      let mod_lang = match lang with
        | "javascript" -> JavaScript
        | "typescript" -> TypeScript
        | _ -> Other lang
      in
      Ok { mod_lang; mod_path = path; mod_items = items; parse_errors = [] }
    | _ ->
      Error (make_error ~file:path ~message:"tree-sitter parse failed")
  with Sys_error msg ->
    Error (make_error ~file:path ~message:("tree-sitter error: " ^ msg))

(** Parse a JavaScript file (.js, .jsx). *)
let parse_file ~(path : string) : (t, parse_error) result =
  match resolve_js_grammar () with
  | None ->
    Error (make_error ~file:path ~message:"JavaScript tree-sitter grammar not found. Set TREE_SITTER_JAVASCRIPT_GRAMMAR or install tree-sitter-javascript.")
  | Some grammar ->
    parse_with_grammar ~grammar ~lang:"javascript" ~path
