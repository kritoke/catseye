(* src/ocaml/lib/catseye_ast/nim_mapper.ml
   Bridge from tree-sitter Nim XML output to CatseyeAST.t

   Uses shared Tree_sitter_xml module for XML parsing.
   
   tree-sitter-nim grammar key node types:
   - proc_expression, func_expression, method_expression, iterator_expression,
     template_expression, macro_expression → IFunction
   - import_statement, from_import_statement, include_statement → IImport
   - type_section → type_declaration → ITypeDef/ITypeAlias
   - var_section, let_section, const_section → variable_declaration → IConstant
   - call → EApp (with UFCS via first_argument field)
   - dot_expression → EFieldAccess
   - if, elif_branch, else_branch → EIf
   - case, of_branch → ECase
   - for → loop expression
   - try, except_branch, finally_branch → ETryCatchFinally
   - assignment → EAssignment
   - infix_expression → EBinOp
   - identifier → EVar
   - pragma_expression → metadata
*)

module PE = Error

open Base
open Types

(* Import shared tree-sitter XML types and functions *)
module Tsx = Tree_sitter_xml

type xml = Tsx.xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

let attr = Tsx.attr
let text = Tsx.text
let line_of = Tsx.line_of
let find = Tsx.find
let children_where = Tsx.children_where
let parse_xml = Tsx.parse_xml
let position_of_xml = Tsx.position_of_xml
let range_of_xml = Tsx.range_of_xml
let children_with_field = Tsx.children_with_field
let children_with_tag = Tsx.children_with_tag

(* ── XML → CatseyeAST conversion ────────────────────────────────────── *)

(** Extract the name from an identifier or symbol_declaration node *)
let name_of_node (n : xml) : string =
  match n.tag with
  | "identifier" -> String.strip (text n)
  | "symbol_declaration" ->
    (* field: name -> identifier/exported_symbol *)
    (match children_with_field n ~field:"name" with
     | [name_node] -> String.strip (text name_node)
     | _ ->
       (* fallback: look for identifier child *)
       (match children_with_tag n ~tag:"identifier" with
        | [id] -> String.strip (text id)
        | _ -> "_"))
  | "exported_symbol" ->
    (match children_with_tag n ~tag:"identifier" with
     | [id] -> String.strip (text id)
     | _ -> String.strip (text n))
  | _ -> String.strip (text n)

(** Get all identifier names from a symbol_declaration_list *)
let names_from_symbol_list (n : xml) : string list =
  match n.tag with
  | "symbol_declaration_list" ->
    List.filter_map ~f:(fun c ->
      match c.tag with
      | "symbol_declaration" -> Some (name_of_node c)
      | "identifier" -> Some (String.strip (text c))
      | _ -> None
    ) n.children
  | _ -> [name_of_node n]

(** Get the text of a node's direct identifier child *)
let identifier_text (n : xml) ~(field : string) : string =
  match children_with_field n ~field with
  | [child] -> name_of_node child
  | _ -> ""

(** Recursively convert an expression node *)
let rec expr_of_xml ?(depth=0) (n : xml) : expr =
  let loc = range_of_xml n in
  if depth > 100 then
    { expr_value = EUnknown ("depth:" ^ n.tag); expr_location = loc }
  else
  let d = depth + 1 in
  let value : expr_value = match n.tag with

    (* Literals *)
    | "interpreted_string_literal" | "long_string_literal" | "raw_string_literal" ->
      ELiteral (LString (String.strip (text n)))
    | "integer_literal" -> ELiteral (LInt (String.strip (text n)))
    | "float_literal" | "custom_numeric_literal" -> ELiteral (LFloat (String.strip (text n)))
    | "char_literal" ->
      let t = String.strip (text n) in
      if String.length t > 0 then ELiteral (LChar t.[0]) else ELiteral (LChar '\000')
    | "nil_literal" -> ELiteral LNull
    | "blank_identifier" -> EVar "_"

    (* Identifiers *)
    | "identifier" -> EVar (String.strip (text n))
    | "accent_quoted" ->
      (* `foo` — quoted identifier *)
      (match children_with_tag n ~tag:"identifier" with
       | [id] -> EVar (String.strip (text id))
       | _ -> EVar (String.strip (text n)))

    (* Dot expression: receiver.field *)
    | "dot_expression" ->
      let receiver = match children_with_field n ~field:"left" with
        | [l] -> expr_of_xml ~depth:d l
        | _ -> { expr_value = EUnknown "no_receiver"; expr_location = loc }
      in
      let field_name = match children_with_field n ~field:"right" with
        | [r] -> name_of_node r
        | _ -> ""
      in
      EFieldAccess (receiver, field_name)

    (* Call: function(first_argument, argument_list)
       Nim UFCS: `foo.bar(baz)` is a call node with function=dot_expression(bar),
       first_argument=foo. We normalize to EApp(EFieldAccess(foo, bar), [baz]). *)
    | "call" ->
      let fn_expr = match children_with_field n ~field:"function" with
        | [f] -> expr_of_xml ~depth:d f
        | _ -> { expr_value = EUnknown "no_fn"; expr_location = loc }
      in
      let first_arg = match children_with_field n ~field:"first_argument" with
        | [fa] -> Some (expr_of_xml ~depth:d fa)
        | _ -> None
      in
      let rest_args = match children_where n ~f:(fun c -> c.tag = "argument_list") with
        | [al] ->
          List.filter_map ~f:(fun c ->
            match c.tag with
            | "comment" | "" -> None
            | _ -> Some (expr_of_xml ~depth:d c)
          ) al.children
        | _ -> []
      in
      (* UFCS: if we have first_argument and function is a dot_expression,
         rewrite as method call on the first argument *)
      let (final_fn, all_args) = match first_arg with
        | Some fa ->
          (match fn_expr.expr_value with
           | EFieldAccess (recv, field_name) ->
             (* dot_expression.left might be a placeholder; use first_arg as receiver *)
             let recv_name = match recv.expr_value with
               | EUnknown _ | EVar "" -> fa
               | _ -> recv
             in
             ({ expr_value = EFieldAccess (recv_name, field_name); expr_location = fn_expr.expr_location },
              rest_args)
           | _ ->
             (fn_expr, fa :: rest_args))
        | None -> (fn_expr, rest_args)
      in
      EApp (final_fn, all_args)

    (* Dot generic call: func[T](args) *)
    | "dot_generic_call" ->
      (* Treat like a call but ignore generics for now *)
      let fn_expr = match children_with_field n ~field:"function" with
        | [f] -> expr_of_xml ~depth:d f
        | _ -> { expr_value = EUnknown "no_fn"; expr_location = loc }
      in
      let args = match children_where n ~f:(fun c -> c.tag = "argument_list") with
        | [al] ->
          List.filter_map ~f:(fun c ->
            match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth:d c)
          ) al.children
        | _ -> []
      in
      EApp (fn_expr, args)

    (* Infix expression: left operator right *)
    | "infix_expression" ->
      let left = match children_with_field n ~field:"left" with
        | [l] -> expr_of_xml ~depth:d l
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let right = match children_with_field n ~field:"right" with
        | [r] -> expr_of_xml ~depth:d r
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let op = match children_with_field n ~field:"operator" with
        | [o] -> String.strip (text o)
        | _ -> String.strip (text n)
      in
      EBinOp (left, op, right)

    (* Prefix expression: operator expr *)
    | "prefix_expression" ->
      let operand = match List.filter ~f:(fun c ->
        c.tag <> "comment" && c.tag <> ""
      ) n.children with
        | [_op; operand] -> expr_of_xml ~depth:d operand
        | [operand] -> expr_of_xml ~depth:d operand
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let op = match List.filter ~f:(fun c -> c.tag <> "comment" && c.tag <> "") n.children with
        | [o; _] -> String.strip (text o)
        | _ -> ""
      in
      EUnOp (op, operand)

    (* Parenthesized expression *)
    | "parenthesized" | "bracket_expression" ->
      (match List.filter ~f:(fun c -> c.tag <> "comment" && c.tag <> "") n.children with
       | [child] -> (expr_of_xml ~depth:d child).expr_value
       | _ -> EUnknown "parenthesized")

    (* If expression *)
    | "if" | "when" ->
      let cond = match children_with_field n ~field:"condition" with
        | [c] -> expr_of_xml ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let then_ = match children_with_field n ~field:"consequence" with
        | [c] -> expr_of_xml_block ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let else_ = match children_with_field n ~field:"alternative" with
        | alt_nodes ->
          (* Find elif or else branch *)
          let else_branch = List.find ~f:(fun c -> c.tag = "else_branch") alt_nodes in
          let elif_branch = List.find ~f:(fun c -> c.tag = "elif_branch") alt_nodes in
          match else_branch with
          | Some eb ->
            (match children_with_field eb ~field:"consequence" with
             | [c] -> Some (expr_of_xml_block ~depth:d c)
             | _ -> Some { expr_value = EUnit; expr_location = loc })
          | None ->
            (match elif_branch with
             | Some elb ->
               (* Nest as EIf *)
               Some (expr_of_xml ~depth:d elb)
             | None -> None)
      in
      EIf (cond, then_, else_)

    (* elif_branch — when encountered directly, treat as nested if *)
    | "elif_branch" ->
      let cond = match children_with_field n ~field:"condition" with
        | [c] -> expr_of_xml ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let then_ = match children_with_field n ~field:"consequence" with
        | [c] -> expr_of_xml_block ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      EIf (cond, then_, None)

    (* Case expression *)
    | "case" ->
      let subject = match children_with_field n ~field:"value" with
        | [v] -> expr_of_xml ~depth:d v
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let branches =
        List.filter_map ~f:(fun (alt : xml) ->
          match alt.tag with
          | "of_branch" ->
            let body = match children_with_field alt ~field:"consequence" with
              | [c] -> Some (expr_of_xml_block ~depth:d c)
              | _ -> Some { expr_value = EUnit; expr_location = loc }
            in
            (* Use PDiscard for now — full pattern matching is complex *)
            Option.map body ~f:(fun b -> (PDiscard, b))
          | "else_branch" ->
            let body = match children_with_field alt ~field:"consequence" with
              | [c] -> Some (expr_of_xml_block ~depth:d c)
              | _ -> Some { expr_value = EUnit; expr_location = loc }
            in
            Option.map body ~f:(fun b -> (PDiscard, b))
          | _ -> None
        ) (children_with_field n ~field:"alternative")
      in
      ECase (subject, branches)

    (* For loop *)
    | "for" ->
      let body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml_block ~depth:d b
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      (* For loops are modelled as EBlock containing the body *)
      body.expr_value

    (* While — not a named node in tree-sitter-nim, but handle if present *)
    | "while" ->
      let body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml_block ~depth:d b
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      body.expr_value

    (* Try/except/finally *)
    | "try" ->
      let try_body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml_block ~depth:d b
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let rescue_clauses = List.filter_map ~f:(fun (c : xml) ->
        if c.tag = "except_branch" then
          let body = match children_with_field c ~field:"consequence" with
            | [b] -> expr_of_xml_block ~depth:d b
            | _ -> { expr_value = EUnit; expr_location = loc }
          in
          Some { exception_var = None; matched_types = []; rescue_body = body }
        else None
      ) n.children in
      let ensure_body = List.find_map ~f:(fun (c : xml) ->
        if c.tag = "finally_branch" then
          match children_with_field c ~field:"body" with
          | [b] -> Some (expr_of_xml_block ~depth:d b)
          | _ -> Some { expr_value = EUnit; expr_location = loc }
        else None
      ) n.children in
      ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body = None }

    (* Block *)
    | "block" ->
      let body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml_block ~depth:d b
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      body.expr_value

    (* Assignment *)
    | "assignment" ->
      let left = match children_with_field n ~field:"left" with
        | [l] -> expr_of_xml ~depth:d l
        | _ -> { expr_value = EVar "_"; expr_location = loc }
      in
      let right = match children_with_field n ~field:"right" with
        | [r] -> expr_of_xml ~depth:d r
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      EAssignment (left, right)

    (* Return statement *)
    | "return_statement" ->
      (match List.filter ~f:(fun c -> c.tag <> "comment" && c.tag <> "") n.children with
       | [child] -> (expr_of_xml ~depth:d child).expr_value  (* child is the return expr *)
       | [] -> EUnit
       | children ->
         (* Multiple children = block *)
         EBlock (List.map ~f:(expr_of_xml ~depth:d) children))

    (* Discard statement *)
    | "discard_statement" ->
      (match List.filter ~f:(fun c -> c.tag <> "comment" && c.tag <> "") n.children with
       | [child] -> (expr_of_xml ~depth:d child).expr_value
       | _ -> EUnit)

    (* Raise statement *)
    | "raise_statement" ->
      (match List.filter ~f:(fun c -> c.tag <> "comment" && c.tag <> "") n.children with
       | [child] ->
         let exn = expr_of_xml ~depth:d child in
         EApp ({ expr_value = EVar "raise"; expr_location = loc }, [exn])
       | _ -> EApp ({ expr_value = EVar "raise"; expr_location = loc }, []))

    (* Tuple construction *)
    | "tuple_construction" ->
      let elems = List.filter_map ~f:(fun c ->
        match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth:d c)
      ) n.children in
      ETuple elems

    (* Array construction *)
    | "array_construction" ->
      let elems = List.filter_map ~f:(fun c ->
        match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth:d c)
      ) n.children in
      EList elems

    (* Curly construction (sets) *)
    | "curly_construction" ->
      let elems = List.filter_map ~f:(fun c ->
        match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth:d c)
      ) n.children in
      EList elems

    (* Pragma expression — left is the actual expression, right is pragma *)
    | "pragma_expression" ->
      (match children_with_field n ~field:"left" with
       | [l] -> (expr_of_xml ~depth:d l).expr_value
       | _ -> EUnknown "pragma_expression")

    (* Do block *)
    | "do_block" ->
      (match children_with_field n ~field:"body" with
       | [b] -> (expr_of_xml_block ~depth:d b).expr_value
       | _ -> EUnknown "do_block")

    (* Let/var/const sections inside a body — convert to ELet.
       let_section/var_section/const_section contain variable_declaration children;
       each declares one or more bindings. We emit an ELet per binding so the
       taint engine can track the assign. *)
    | "let_section" | "var_section" | "const_section" ->
      let lets = List.filter_map ~f:(fun c ->
        match c.tag with
        | "variable_declaration" ->
          let names = match children_where c ~f:(fun cc -> cc.tag = "symbol_declaration_list") with
            | [sdl] -> names_from_symbol_list sdl
            | _ -> ["_"]
          in
          let value = match children_with_field c ~field:"value" with
            | [v] -> expr_of_xml ~depth:d v
            | _ -> { expr_value = EUnit; expr_location = range_of_xml c }
          in
          (match names with
           | name :: _ ->
             Some { expr_value = ELet (PVar name, value, { expr_value = EUnit; expr_location = loc });
                    expr_location = range_of_xml c }
           | [] -> None)
        | _ -> None
      ) n.children in
      (match lets with
       | [] -> EUnit
       | [e] -> e.expr_value
       | _ -> EBlock lets)

    (* Bare variable_declaration inside a body *)
    | "variable_declaration" ->
      let names = match children_where n ~f:(fun cc -> cc.tag = "symbol_declaration_list") with
        | [sdl] -> names_from_symbol_list sdl
        | _ -> ["_"]
      in
      let value = match children_with_field n ~field:"value" with
        | [v] -> expr_of_xml ~depth:d v
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      (match names with
       | name :: _ -> ELet (PVar name, value, { expr_value = EUnit; expr_location = loc })
       | [] -> EUnit)

    (* Statement list — sequence of statements *)
    | "statement_list" ->
      let stmts = List.filter_map ~f:(fun c ->
        match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth:d c)
      ) n.children in
      (match stmts with
       | [] -> EUnit
       | [e] -> e.expr_value
       | _ -> EBlock stmts)

    (* Generalized string (e.g., echo"hello") *)
    | "generalized_string" ->
      EUnknown "generalized_string"

    (* Cast *)
    | "cast" ->
      EUnknown "cast"

    (* ERROR nodes from tree-sitter *)
    | "ERROR" -> EError (String.strip (text n))

    (* Fallback *)
    | _ ->
      let t = String.strip (text n) in
      if t <> "" then EVar t
      else EUnknown n.tag
  in
  { expr_value = value; expr_location = loc }

(** Convert a statement_list or block body to an expression *)
and expr_of_xml_block ?(depth=0) (n : xml) : expr =
  let loc = range_of_xml n in
  match n.tag with
  | "statement_list" | "field_declaration_list" ->
    let stmts = List.filter_map ~f:(fun c ->
      match c.tag with "comment" | "" -> None | _ -> Some (expr_of_xml ~depth c)
    ) n.children in
    (match stmts with
     | [] -> { expr_value = EUnit; expr_location = loc }
     | [e] -> e
     | _ -> { expr_value = EBlock stmts; expr_location = loc })
  | _ -> expr_of_xml ~depth n

(** Extract pragma names from a pragma_list node *)
let pragmas_of_xml (n : xml) : string list =
  match n.tag with
  | "pragma_list" ->
    List.filter_map ~f:(fun c ->
      match c.tag with
      | "identifier" -> Some (String.strip (text c))
      | "pragma_expression" ->
        (* nested pragma like raises: [Exception] *)
        (match children_with_field c ~field:"left" with
         | [l] -> Some (name_of_node l)
         | _ -> Some (String.strip (text c)))
      | "comment" | "" -> None
      | _ -> Some (String.strip (text c))
    ) n.children
  | _ -> []

(** Convert a top-level proc/func/method/etc declaration to an IFunction item.
    Declaration nodes (proc_declaration, func_declaration, etc.) have a `name`
    field, unlike proc_expression (anonymous proc literals). *)
let function_item_of_xml (n : xml) : item_value =
  let loc = range_of_xml n in
  (* Extract name from the `name` field (identifier) *)
  let name = match children_with_field n ~field:"name" with
    | [name_node] -> name_of_node name_node
    | _ -> "anonymous"
  in
  let params = match children_with_field n ~field:"parameters" with
    | [pl] ->
      List.filter_map ~f:(fun c ->
        match c.tag with
        | "parameter_declaration" ->
          let names = match children_where c ~f:(fun cc -> cc.tag = "symbol_declaration_list") with
            | [sdl] -> names_from_symbol_list sdl
            | _ ->
              let ids = children_where c ~f:(fun cc -> cc.tag = "identifier") in
              match ids with
              | [] -> ["_"]
              | _ -> List.map ~f:name_of_node ids
          in
          (match names with
           | [name] -> Some (PVar name)
           | _ -> Some (PVar (String.concat ~sep:", " names)))
        | "comment" | "" -> None
        | _ -> Some (PVar "_")
      ) pl.children
    | _ -> []
  in
  let body = match children_with_field n ~field:"body" with
    | [b] -> expr_of_xml_block b
    | _ -> { expr_value = EUnit; expr_location = loc }
  in
  IFunction (name, params, None, body)

(** Convert a top-level XML statement to a CatseyeAST item.
    Returns None for expressions that are not top-level declarations. *)
let item_of_xml (n : xml) : item option =
  let loc = range_of_xml n in
  match n.tag with

  (* Import statements *)
  | "import_statement" ->
    let names = List.filter_map ~f:(fun c ->
      match c.tag with
      | "identifier" -> Some (String.strip (text c))
      | "accent_quoted" -> Some (String.strip (text c))
      | "comment" | "" -> None
      | _ -> Some (String.strip (text c))
    ) n.children in
    let name = String.concat ~sep:", " names in
    Some { item_value = IImport (name, None); item_location = loc }

  | "from_import_statement" ->
    let module_name = match List.filter ~f:(fun c -> c.tag = "identifier") n.children with
      | [m] -> String.strip (text m)
      | _ -> ""
    in
    Some { item_value = IImport (module_name, None); item_location = loc }

  | "include_statement" ->
    let names = List.filter_map ~f:(fun c ->
      match c.tag with "identifier" -> Some (String.strip (text c)) | _ -> None
    ) n.children in
    let name = String.concat ~sep:", " names in
    Some { item_value = IImport (name, None); item_location = loc }

  | "export_statement" ->
    let names = List.filter_map ~f:(fun c ->
      match c.tag with "identifier" -> Some (String.strip (text c)) | _ -> None
    ) n.children in
    let name = String.concat ~sep:", " names in
    Some { item_value = IImport (name, None); item_location = loc }

  (* Type section: contains type_declaration children *)
  | "type_section" ->
    let type_items = List.filter_map ~f:(fun c ->
      match c.tag with
      | "type_declaration" ->
        (* type_declaration contains type_symbol_declaration (name) + body *)
        let name = match children_where c ~f:(fun cc -> cc.tag = "type_symbol_declaration") with
          | [tsd] ->
            (match children_with_field tsd ~field:"name" with
             | [name_node] -> name_of_node name_node
             | _ -> "anonymous")
          | _ -> "anonymous"
        in
        (* Check if it's an object, enum, or alias *)
        let has_object = List.exists ~f:(fun cc -> cc.tag = "object_declaration") c.children in
        let has_enum = List.exists ~f:(fun cc -> cc.tag = "enum_declaration") c.children in
        if has_object || has_enum then
          Some { item_value = ITypeDef (name, [], []); item_location = range_of_xml c }
        else
          Some { item_value = ITypeAlias (name, [], TUnknown); item_location = range_of_xml c }
      | "comment" | "" -> None
      | _ -> None
    ) n.children in
    (* Return as a module if multiple, or single item *)
    (match type_items with
     | [item] -> Some item
     | items ->
       Some { item_value = IModule ("type_section", items); item_location = loc })

  (* Standalone type declarations (outside a type_section) *)
  | "type_declaration" ->
    let name =
      (match children_where n ~f:(fun cc -> cc.tag = "type_symbol_declaration") with
       | [tsd] ->
         (match children_with_field tsd ~field:"name" with
          | [name_node] -> name_of_node name_node
          | _ -> "anonymous")
       | _ -> "anonymous")
    in
    let has_object = List.exists ~f:(fun cc -> cc.tag = "object_declaration") n.children in
    let has_enum = List.exists ~f:(fun cc -> cc.tag = "enum_declaration") n.children in
    if has_object || has_enum then
      Some { item_value = ITypeDef (name, [], []); item_location = loc }
    else
      Some { item_value = ITypeAlias (name, [], TUnknown); item_location = loc }

  (* Variable declarations: var_section, let_section, const_section *)
  | "var_section" | "let_section" | "const_section" ->
    let var_items = List.filter_map ~f:(fun c ->
      match c.tag with
      | "variable_declaration" ->
        let names = match children_where c ~f:(fun cc -> cc.tag = "symbol_declaration_list") with
          | [sdl] -> names_from_symbol_list sdl
          | _ -> ["_"]
        in
        let value = match children_with_field c ~field:"value" with
          | [v] -> expr_of_xml v
          | _ -> { expr_value = EUnit; expr_location = range_of_xml c }
        in
        let name = match names with [n] -> n | _ -> String.concat ~sep:", " names in
        Some { item_value = IConstant (PVar name, None, value); item_location = range_of_xml c }
      | "comment" | "" -> None
      | _ -> None
    ) n.children in
    (match var_items with
     | [item] -> Some item
     | items ->
       Some { item_value = IModule (n.tag, items); item_location = loc })

  (* Pragma on a function — extract the function definition *)
  | "pragma_expression" ->
    (* Check if the left side is a proc/func/etc expression *)
    (match children_with_field n ~field:"left" with
     | [l] ->
       (match l.tag with
        | "proc_expression" | "func_expression" | "method_expression"
        | "iterator_expression" | "template_expression" | "macro_expression" ->
          Some { item_value = function_item_of_xml l; item_location = loc }
        | "identifier" ->
          Some { item_value = IUnknown ("pragma:" ^ name_of_node l); item_location = loc }
        | _ -> None)
     | _ -> None)

  (* Standalone proc/func/etc declarations (top-level named procedures) *)
  | "proc_declaration" | "func_declaration" | "method_declaration"
  | "iterator_declaration" | "template_declaration" | "macro_declaration"
  | "converter_declaration" ->
    Some { item_value = function_item_of_xml n; item_location = loc }

  (* Anonymous proc/func/etc expressions (proc literals) *)
  | "proc_expression" | "func_expression" | "method_expression"
  | "iterator_expression" | "template_expression" | "macro_expression" ->
    Some { item_value = function_item_of_xml n; item_location = loc }

  (* Comment blocks — skip *)
  | "comment" | "block_comment" | "block_documentation_comment" | "line_comment" -> None

  (* Everything else is an expression, not a top-level item *)
  | _ -> None

(* ── Parse via tree-sitter CLI ─────────────────────────────────────── *)

(** Resolve the Nim tree-sitter grammar path. *)
let resolve_nim_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"nim" ~env_var:"TREE_SITTER_NIM_GRAMMAR"

let parse_file ~(path : string) : (t, PE.parse_error) Result.t =
  let grammar_path = resolve_nim_grammar () in
  match grammar_path with
  | None ->
    Error (PE.make_error ~file:path ~message:"Nim tree-sitter grammar not found. Set TREE_SITTER_NIM_GRAMMAR or install tree-sitter-nim.")
  | Some grammar ->
    let lib_path = if Stdlib.Filename.check_suffix grammar ".so" then grammar
      else Stdlib.Filename.dirname grammar in
    let cmd = Stdlib.Printf.sprintf "tree-sitter parse --lib-path %s --lang-name nim -x %s 2>/dev/null"
      (Stdlib.Filename.quote lib_path) (Stdlib.Filename.quote path) in
    (try
      let ic = Unix.open_process_in cmd in
      let xml_str = Stdlib.Buffer.create 4096 in
      (try while true do Stdlib.Buffer.add_channel xml_str ic 4096 done with Stdlib.End_of_file -> ());
      let status = Unix.close_process_in ic in
      match status with
      | Unix.WEXITED 0 | Unix.WEXITED 1 ->
        let xml_content = Stdlib.Buffer.contents xml_str in
        if String.length xml_content > 100 && Stdlib.String.sub xml_content 0 5 = "<?xml" then begin
          let xml = parse_xml xml_content in
          (* tree-sitter XML wraps in <sources><source>... *)
          let root = if xml.tag = "sources" && List.length xml.children > 0 then
            (match xml.children with c :: _ -> c | [] -> xml)
          else xml in
          let source_file = if root.tag = "source" && List.length root.children > 0 then
            (match root.children with c :: _ -> c | [] -> root)
          else root in
          (* Walk top-level nodes and convert to items *)
          let items = List.filter_map ~f:item_of_xml source_file.children in
          Ok { mod_lang = Nim; mod_path = path; mod_items = items; parse_errors = [] }
        end else
          Error (PE.make_error ~file:path ~message:("Invalid XML output from tree-sitter-nim: " ^
            Stdlib.String.sub xml_content 0 (min 100 (String.length xml_content))))
      | Unix.WEXITED code ->
        let err = Stdlib.Buffer.contents xml_str in
        Error (PE.make_error ~file:path ~message:(Stdlib.Printf.sprintf "tree-sitter-nim exited with code %d: %s" code err))
      | Unix.WSIGNALED _ | Unix.WSTOPPED _ ->
        Error (PE.make_error ~file:path ~message:"tree-sitter-nim terminated by signal")
    with e ->
      Error (PE.make_error ~file:path ~message:(Exn.to_string e)))
