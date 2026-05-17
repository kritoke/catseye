(* src/ocaml/lib/catseye_ast/gleam_mapper.ml
   Bridge from tree-sitter Gleam XML output to CatseyeAST.t
   
   Uses shared Tree_sitter_xml module for XML parsing.
*)

open Types
open Error

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

(* ── Position helpers ─────────────────────────────────────────────── *)

let position_of_xml (n : xml) ~field =
  let row = try int_of_string (attr n field) + 1 with _ -> 0 in
  Position.make ~line:row ~column:0 ~byte_offset:0

let range_of_xml (n : xml) =
  { start = position_of_xml n ~field:"srow";
    end_ = position_of_xml n ~field:"erow" }

(* ── XML child helpers (non-recursive, direct children only) ─────── *)

let children_with_field (n : xml) ~(field : string) : xml list =
  List.filter (fun c -> attr c "field" = field) n.children

let children_with_tag (n : xml) ~(tag : string) : xml list =
  List.filter (fun c -> c.tag = tag) n.children

(* ── XML → CatseyeAST conversion ────────────────────────────────────── *)

let rec literal_of_xml (n : xml) =
  match attr n "type" with
  | "string" -> LString (text n)
  | "integer" -> LInt (text n)
  | "float" -> LFloat (text n)
  | "char" when text n <> "" -> LChar (text n).[0]
  | _ -> LUnit

and pattern_of_xml (n : xml) =
  match attr n "type" with
  | "identifier" | "_" -> PVar (text n)
  | _ when text n <> "" -> PLiteral (literal_of_xml n)
  | _ -> PVar (attr n "type")

(** [expr_of_xml ~depth n] converts an XML node to a typed expression.
    Depth limits recursion to prevent stack overflow on malformed input. *)
and expr_of_xml ?(depth=0) (n : xml) : expr =
  let loc = range_of_xml n in
  if depth > 100 then
    { expr_value = EUnknown ("depth:" ^ n.tag); expr_location = loc }
  else
  let d = depth + 1 in
  let value : expr_value = match n.tag with

    (* Literals *)
    | "string" -> ELiteral (literal_of_xml n)
    | "integer" -> ELiteral (literal_of_xml n)
    | "float" -> ELiteral (literal_of_xml n)
    | "unit" -> EUnit

    (* Identifiers and constructors *)
    | "identifier" -> EVar (text n)
    | "constructor_name" -> EVar (text n)
    | "label" -> EVar (text n)

    (* Field access: receiver.field *)
    | "field_access" ->
        let receiver = match children_with_field n ~field:"record" with
          | [r] -> expr_of_xml ~depth:d r
          | _ -> (match children_where n ~f:(fun c ->
              c.tag = "identifier" || c.tag = "field_access") with
            | [r] -> expr_of_xml ~depth:d r
            | _ -> { expr_value = EUnknown "no_receiver"; expr_location = loc })
        in
        let field = match children_with_tag n ~tag:"label" with
          | [l] -> text l
          | _ -> ""
        in
        EFieldAccess (receiver, field)

    (* Record construction (e.g., Ok(value), List, User{name: x}) *)
    | "record" ->
        let name = match children_with_tag n ~tag:"constructor_name" with
        | [cn] -> text cn | _ -> "" in
        (match children_with_tag n ~tag:"arguments" with
         | [args_node] ->
             let arg_exprs = List.filter_map (fun a ->
               match children_where a ~f:(fun c -> c.tag <> "type") with
               | [v] -> Some (expr_of_xml ~depth:d v)
               | _ -> None
             ) (children_with_tag args_node ~tag:"argument") in
             EApp ({ expr_value = EVar name; expr_location = loc }, arg_exprs)
         | _ -> EVar name)

    (* Collections *)
    | "tuple" ->
        ETuple (List.map (expr_of_xml ~depth:d)
          (children_where n ~f:(fun c -> c.tag <> "type" && c.tag <> "")))
    | "list" ->
        EList (List.map (expr_of_xml ~depth:d)
          (children_where n ~f:(fun c -> c.tag <> "type" && c.tag <> "")))

    (* Function call: <function_call> with function and arguments *)
    | "function_call" ->
        let fn_expr = match children_with_field n ~field:"function" with
        | [f] -> expr_of_xml ~depth:d f
        | _ -> { expr_value = EUnknown "no_fn"; expr_location = loc }
        in
        let args = match children_with_field n ~field:"arguments" with
        | [args_node] ->
            List.filter_map (fun a ->
              match children_where a ~f:(fun c -> c.tag <> "type") with
              | [v] -> Some (expr_of_xml ~depth:d v)
              | _ -> None
            ) (children_with_tag args_node ~tag:"argument")
        | _ -> []
        in
        EApp (fn_expr, args)

    (* Anonymous function *)
    | "fn" ->
        let params = children_where n ~f:(fun c -> c.tag = "parameter") in
        let body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml ~depth:d b
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        EFn (List.map pattern_of_xml params, body)

    (* If expression *)
    | "if" ->
        let cond = match children_with_field n ~field:"condition" with
        | [c] -> expr_of_xml ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        let then_ = match children_with_field n ~field:"then" with
        | [c] -> expr_of_xml ~depth:d c
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        let else_ = match children_with_field n ~field:"else" with
        | [c] -> Some (expr_of_xml ~depth:d c)
        | _ -> None
        in
        EIf (cond, then_, else_)

    (* Let binding *)
    | "let" | "assignment" ->
        let pat = match children_with_field n ~field:"pattern" with
        | [p] -> PVar (text p)
        | _ -> PVar "_"
        in
        let val_expr = match children_with_field n ~field:"value" with
        | [v] -> expr_of_xml ~depth:d v
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        (* Let bindings in blocks: the body is the next sibling in the parent block,
           not a child of this node. Return just the binding. *)
        ELet (pat, val_expr, { expr_value = EUnit; expr_location = loc })

    (* Panic — treat as a function call *)
    | "panic" ->
        EApp ({ expr_value = EVar "panic"; expr_location = loc }, [])

    (* Todo *)
    | "todo" ->
        EApp ({ expr_value = EVar "todo"; expr_location = loc }, [])

    (* Block — sequence of expressions *)
    | "block" ->
        let body_exprs = List.filter_map (fun c ->
          match c.tag with
          | "comment" | "" -> None
          | _ -> Some (expr_of_xml ~depth:d c)
        ) n.children in
        (match body_exprs with
         | [] -> EUnit
         | [e] -> e.expr_value  (* unwrap single-child blocks *)
         | _ -> EBlock body_exprs)

    (* Case expression *)
    | "case" ->
        let subject = match children_with_field n ~field:"subjects" with
        | [s] ->
          (* subjects wrapper -> get first child as the actual subject expr *)
          (match s.children with
           | [subj] -> expr_of_xml ~depth:d subj
           | _ -> { expr_value = EUnit; expr_location = loc })
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        let branches =
          match children_with_field n ~field:"clauses" with
          | [clauses_node] ->
            List.filter_map (fun (clause : xml) ->
              if clause.tag = "case_clause" then begin
                let body = match children_with_field clause ~field:"value" with
                  | [v] -> Some (expr_of_xml ~depth:d v)
                  | _ ->
                    (* No value field — try children after the pattern as block *)
                    let body_children = List.filter (fun (c : xml) ->
                      c.tag <> "case_clause_patterns"
                      && c.tag <> "case_clause_guard"
                    ) clause.children in
                    if body_children <> [] then
                      Some { expr_value = EBlock (List.map (expr_of_xml ~depth:d) body_children); expr_location = loc }
                    else
                      Some { expr_value = EUnit; expr_location = loc }
                in
                let pat = match children_with_field clause ~field:"patterns" with
                  | [p] -> (
                    match p.children with
                    | [cp] -> (
                      match cp.children with
                      | [pat_node] -> pattern_of_xml pat_node
                      | _ -> PDiscard
                    )
                    | _ -> PDiscard
                  )
                  | _ -> PDiscard
                in
                Some (pat, Option.value body ~default:{ expr_value = EUnit; expr_location = loc })
              end else None
            ) clauses_node.children
          | _ -> []
        in
        ECase (subject, branches)

    (* Binary expression *)
    | "binary_expression" ->
        let left = match children_with_field n ~field:"left" with
        | [l] -> expr_of_xml ~depth:d l
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        let right = match children_with_field n ~field:"right" with
        | [r] -> expr_of_xml ~depth:d r
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        let op = String.trim (text n) in
        EBinOp (left, op, right)

    (* ERROR nodes from tree-sitter *)
    | "ERROR" -> EError (String.trim (text n))

    (* Fallback: bare text becomes a variable reference *)
    | _ ->
        let t = String.trim (text n) in
        if t <> "" then EVar t
        else EUnknown n.tag
  in
  { expr_value = value; expr_location = loc }

(** Convert a top-level XML item to a CatseyeAST item. *)
and item_of_xml (n : xml) : item =
  let loc = range_of_xml n in
  let value = match n.tag with
    | "function" ->
        let name = (try List.find (fun c ->
          c.tag = "identifier" && attr c "field" = "name"
        ) n.children |> text with Not_found -> "unknown") in
        let params = List.map (fun p -> PVar (text p))
          (children_with_tag n ~tag:"function_parameter") in
        let body = match children_with_field n ~field:"body" with
        | [b] -> expr_of_xml b
        | _ -> { expr_value = EUnit; expr_location = loc }
        in
        IFunction (name, params, None, body)
    | "import" ->
        let name = match children_with_tag n ~tag:"module" with
        | [m] -> text m | _ -> "" in
        IImport (name, None)
    | "type" -> ITypeDef (text n, [], [])
    | "module" -> IModule (text n, [])
    | _ -> IUnknown ("tag:" ^ n.tag)
  in
  { item_value = value; item_location = loc }

(* ── Parse via tree-sitter CLI ─────────────────────────────────────── *)

(** Resolve the Gleam tree-sitter grammar path.
    Delegates to shared Tree_sitter_xml.resolve_grammar. *)
let resolve_gleam_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"gleam" ~env_var:"TREE_SITTER_GLEAM_GRAMMAR"

let parse_file ~(path : string) : (t, parse_error) result =
  let grammar_path = resolve_gleam_grammar () in
  match grammar_path with
  | None ->
      Error (make_error ~file:path ~message:"Gleam tree-sitter grammar not found. Set TREE_SITTER_GLEAM_GRAMMAR or install tree-sitter-gleam.")
  | Some grammar ->
      let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>/dev/null" grammar path in
      (try
        let ic = Unix.open_process_in cmd in
        let xml_str = Buffer.create 4096 in
        (try while true do Buffer.add_channel xml_str ic 4096 done with End_of_file -> ());
        let status = Unix.close_process_in ic in
        match status with
        | Unix.WEXITED 0 | Unix.WEXITED 1 ->
            let xml_content = Buffer.contents xml_str in
            if String.length xml_content > 100 && String.sub xml_content 0 5 = "<?xml" then
              let xml = parse_xml xml_content in
              let root = if xml.tag = "sources" && List.length xml.children > 0 then List.hd xml.children else xml in
              let source_file = if root.tag = "source" && List.length root.children > 0 then List.hd root.children else root in
              let items = List.filter (fun c -> List.mem c.tag ["function"; "import"; "type"; "module"]) source_file.children in
              let items_list = List.map item_of_xml items in
              Ok { mod_lang = Gleam; mod_path = path; mod_items = items_list; parse_errors = [] }
            else
              Error (make_error ~file:path ~message:("Invalid XML output: " ^ String.sub xml_content 0 (min 100 (String.length xml_content))))
        | _ ->
            let xml_str = Buffer.contents xml_str in
            Error (make_error ~file:path ~message:("tree-sitter parse failed: " ^ xml_str))
      with e ->
        Error (make_error ~file:path ~message:(Printexc.to_string e)))
