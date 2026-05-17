(* lib/catseye_ast/ocaml_mapper.ml
   Bridge from tree-sitter OCaml XML output to CatseyeAST.t.
   
   Maps OCaml CST (value_definition, let_binding, function, application, etc.)
   onto the shared CatseyeAST.t type for taint analysis and code smell detection.
*)

open Types
open Error

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

let text_of (n : xml) = String.trim n.text

let rec walk_expr (n : xml) (file : string) : expr =
  let loc = range_of_xml n in
  let v = match n.tag with
    (* Identifiers *)
    | "value_name" | "value_path" | "constructor_name" | "constructor_path"
    | "type_constructor" | "module_name" | "module_path" ->
      EVar (text_of n)
    | "long_identifier" | "identifier" ->
      EVar (text_of n)
    
    (* Literals *)
    | "string" | "character" ->
      ELiteral (LString n.text)
    | "integer" | "float" ->
      ELiteral (LString (text_of n))
    | "true" -> ELiteral (LBool true)
    | "false" | "()" -> ELiteral (LBool false)
    | "unit" -> ELiteral LUnit
    
    (* Function/apply *)
    | "application_expression" ->
      let fn_nodes = children_with_field n ~field:"function" in
      let arg_nodes = children_with_field n ~field:"argument" in
      (* Also collect children without explicit field as args *)
      let fn_expr = match fn_nodes with
        | [f] -> walk_expr f file
        | _ -> { expr_value = EVar "<app>"; expr_location = loc }
      in
      let args = List.filter_map (fun c ->
        match c.tag with
        | "unit" -> None
        | _ -> Some (walk_expr c file)
      ) arg_nodes in
      EApp (fn_expr, args)
    
    | "function_expression" | "fun_expression" ->
      let params = List.concat_map (fun c ->
        if c.tag = "parameter" || c.tag = "pattern" then
          match children_with_tag c ~tag:"value_name" with
          | [v] -> [PVar (text_of v)]
          | _ -> [PDiscard]
        else []
      ) n.children in
      let body = match children_with_field n ~field:"body" with
        | [b] -> walk_expr b file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      EFn (params, body)
    
    (* Let/in *)
    | "let_expression" ->
      let bindings = children_with_tag n ~tag:"let_binding" in
      let body = match children_with_field n ~field:"body" with
        | [b] -> walk_expr b file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      (match bindings with
       | [b] ->
         let pat = match children_with_tag b ~tag:"value_name" with
           | [v] -> PVar (text_of v)
           | _ -> PDiscard
         in
         let rhs = match children_with_field b ~field:"expression" with
           | [e] -> walk_expr e file
           | _ -> { expr_value = EUnit; expr_location = loc }
         in
         ELet (pat, rhs, body)
       | _ -> body.expr_value)
    
    (* If/then/else *)
    | "if_expression" ->
      let cond = match children_with_field n ~field:"condition" with
        | [c] -> walk_expr c file
        | _ -> { expr_value = EVar "<cond>"; expr_location = loc }
      in
      let then_ = match children_with_field n ~field:"body" with
        | [b] -> walk_expr b file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let else_ = match children_with_field n ~field:"else" with
        | [e] -> Some (walk_expr e file)
        | _ -> None
      in
      EIf (cond, then_, else_)
    
    (* Match *)
    | "match_expression" ->
      let scrutinee = match children_with_field n ~field:"expression" with
        | [e] -> walk_expr e file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let cases = List.filter_map (fun c ->
        if c.tag = "match_case" then begin
          let body = match children_with_field c ~field:"body" with
            | [b] -> Some (walk_expr b file)
            | _ -> None
          in
          match body with
          | Some b -> Some (PDiscard, b)
          | None -> None
        end else None
      ) n.children in
      ECase (scrutinee, cases)
    
    (* Sequence / block *)
    | "sequence_expression" | "body" | "compilation_unit" ->
      let children = List.filter (fun c ->
        c.tag <> "" && c.tag <> "comment" && c.tag <> ";"
      ) n.children in
      (match children with
       | [single] -> (walk_expr single file).expr_value
       | multiple ->
         EBlock (List.map (fun c -> walk_expr c file) multiple))
    
    (* Tuple *)
    | "tuple_expression" ->
      let elems = List.filter_map (fun c ->
        if c.tag = "," then None
        else Some (walk_expr c file)
      ) n.children in
      ETuple elems
    
    (* Record *)
    | "record_expression" ->
      let fields = List.filter_map (fun c ->
        if c.tag = "record_field" then begin
          let label = children_with_tag c ~tag:"label" in
          let value = children_with_field c ~field:"value" in
          match label, value with
          | [l], [v] -> Some (text_of l, walk_expr v file)
          | _ -> None
          end
        else None
      ) n.children in
      ERecord fields
    
    (* Field access *)
    | "field_access_expression" ->
      let obj = children_with_field n ~field:"value" in
      let field = children_with_field n ~field:"field" in
      (match obj, field with
       | [o], [f] -> EFieldAccess (walk_expr o file, text_of f)
       | _ -> EUnknown "field_access")
    
    (* Binary ops *)
    | "binary_expression" | "infix_expression" ->
      let left = children_with_field n ~field:"left" in
      let right = children_with_field n ~field:"right" in
      let op = List.filter_map (fun c ->
        if attr c "field" = "operator" || c.tag = "operator"
        then Some (text_of c) else None
      ) n.children in
      (match left, op, right with
       | [l], [o], [r] -> EBinOp (walk_expr l file, o, walk_expr r file)
       | _ -> EUnknown "binary")
    
    (* Unary ops *)
    | "unary_expression" | "prefix_expression" ->
      let arg = children_with_field n ~field:"argument" in
      let op = List.filter_map (fun c ->
        if attr c "field" = "operator" then Some (text_of c) else None
      ) n.children in
      (match op, arg with
       | [o], [a] -> EUnOp (o, walk_expr a file)
       | _ -> EUnknown "unary")
    
    (* Try/with *)
    | "try_expression" ->
      let body = match children_with_field n ~field:"body" with
        | [b] -> walk_expr b file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      ETryCatchFinally {
        try_body = body;
        rescue_clauses = [];
        ensure_body = None;
        else_body = None;
      }
    
    (* Parenthesized — unwrap *)
    | "parenthesized_expression" ->
      (match List.filter (fun c -> c.tag <> "(" && c.tag <> ")") n.children with
       | [inner] -> (walk_expr inner file).expr_value
       | _ -> EUnit)
    
    | _ -> EUnknown n.tag
  in
  { expr_value = v; expr_location = loc }

(* ── Statement → item conversion ──────────────────────────────────── *)

let rec walk_item (n : xml) (file : string) : item list =
  let loc = range_of_xml n in
  match n.tag with
  | "value_definition" ->
    let bindings = children_with_tag n ~tag:"let_binding" in
    List.concat_map (fun b ->
      let names = children_with_tag b ~tag:"value_name" in
      let params = List.filter_map (fun c ->
        if c.tag = "parameter" then
          match children_with_tag c ~tag:"value_name" with
          | [v] -> Some (PVar (text_of v))
          | _ -> Some PDiscard
        else None
      ) b.children in
      let body = match children_with_field b ~field:"body" with
        | [bd] -> walk_expr bd file
        | _ -> { expr_value = EUnit; expr_location = range_of_xml b }
      in
      match names with
      | [name] ->
        if params <> [] then
          [{ item_value = IFunction (text_of name, params, None, body); item_location = loc }]
        else
          [{ item_value = IConstant (PVar (text_of name), None, body); item_location = loc }]
      | _ -> []
    ) bindings
  
  | "type_definition" ->
    let bindings = children_with_tag n ~tag:"type_binding" in
    List.concat_map (fun b ->
      let names = children_with_tag b ~tag:"type_constructor" in
      (match names with
       | [name] ->
         [{ item_value = ITypeAlias (text_of name, [], TUnknown); item_location = loc }]
       | _ -> [])
    ) bindings
  
  | "module_definition" ->
    let names = children_with_tag n ~tag:"module_name" in
    (match names with
     | [name] ->
       let body_items = List.concat_map (fun c -> walk_item c file) n.children in
       [{ item_value = IModule (text_of name, body_items); item_location = loc }]
     | _ -> [])
  
  | "open_module" | "include_module" ->
    let modules = children_with_tag n ~tag:"module_path" in
    (match modules with
     | [m] -> [{ item_value = IImport (text_of m, None); item_location = loc }]
     | _ -> [])
  
  | "compilation_unit" | "module_body" | "structure" ->
    List.concat_map (fun c -> walk_item c file) n.children
  
  | "comment" | "attribute" | "directive" | "extension" ->
    []
  
  | _ ->
    (* Try walking as an expression — if it has children, recurse *)
    List.concat_map (fun c -> walk_item c file) n.children

(* ── Grammar resolution ────────────────────────────────────────────── *)

let resolve_ocaml_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"ocaml" ~env_var:"TREE_SITTER_OCAML_GRAMMAR"

(* ── Parse entry point ─────────────────────────────────────────────── *)

let parse_file ~(path : string) : (t, parse_error) result =
  match resolve_ocaml_grammar () with
  | None ->
    Error (make_error ~file:path ~message:"OCaml tree-sitter grammar not found. Set TREE_SITTER_OCAML_GRAMMAR or install tree-sitter-ocaml.")
  | Some grammar ->
    let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name ocaml -x '%s' 2>/dev/null" grammar path in
    try
      let ic = Unix.open_process_in cmd in
      let xml_str = Buffer.create 8192 in
      (try while true do Buffer.add_channel xml_str ic 8192 done with End_of_file -> ());
      let status = Unix.close_process_in ic in
      match status with
      | Unix.WEXITED 0 | Unix.WEXITED 1 ->
        let doc = parse_xml (Buffer.contents xml_str) in
        let compilation = match find doc ~tag:"compilation_unit" with
          | [c] -> c
          | _ -> doc
        in
        let items = List.concat_map (fun c -> walk_item c path) compilation.children in
        Ok { mod_lang = Other "ocaml"; mod_path = path; mod_items = items; parse_errors = [] }
      | _ ->
        Error (make_error ~file:path ~message:"OCaml tree-sitter parse failed")
    with Sys_error msg ->
      Error (make_error ~file:path ~message:("tree-sitter error: " ^ msg))
