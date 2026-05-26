(* lib/catseye_ast/rust_mapper.ml
   Bridge from tree-sitter Rust XML output to CatseyeAST.t.
   
   Rust-specific constructs mapped to unified CatseyeAST schema:
   - Functions (fn) → IFunction items
   - Structs → ERecord
   - Match expressions → ECase
   - Let bindings → ELet
   - Macros → EApp
*)

module PE = Error

open Base
open Types

module Tsx = Tree_sitter_xml

(* Tree-sitter XML node type *)
type xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

let attr (n : xml) (k : string) : string =
  try Stdlib.List.assoc k n.attrs with Stdlib.Not_found -> ""

let line_of (n : xml) : int =
  match attr n "srow" with "" -> 0 | s -> (try Stdlib.int_of_string s + 1 with _ -> 0)

let parse_xml = Tsx.parse_xml
let find = Tsx.find

(* Convert Tsx.xml to our local xml type *)
let rec convert_xml (n : Tsx.xml) : xml = {
  tag = n.tag;
  attrs = n.attrs;
  children = List.map ~f:convert_xml n.children;
  text = n.text;
}

(* ── Position helpers ─────────────────────────────────────────────── *)

let position_of_xml (n : xml) ~(field : string) =
  let row = try Stdlib.int_of_string (attr n field) + 1 with _ -> 0 in
  Position.make ~line:row ~column:0 ~byte_offset:0

let range_of_xml (n : xml) =
  { start = position_of_xml n ~field:"srow";
    end_ = position_of_xml n ~field:"erow" }

let children_with_field (n : xml) ~(field : string) : xml list =
  List.filter ~f:(fun c -> attr c "field" = field) n.children

let children_with_tag (n : xml) ~(tag : string) : xml list =
  List.filter ~f:(fun c -> c.tag = tag) n.children

let child_with_tag (n : xml) ~(tag : string) : xml option =
  let rec find = function
    | [] -> None
    | c :: _ when c.tag = tag -> Some c
    | _ :: rest -> find rest
  in find n.children

let child_with_field (n : xml) ~(field : string) : xml option =
  let rec find = function
    | [] -> None
    | c :: _ when attr c "field" = field -> Some c
    | _ :: rest -> find rest
  in find n.children

(* ── String utilities ─────────────────────────────────────────────── *)

let trim_quotes (s : string) : string =
  if String.length s >= 2 then
    let first = s.[0] and last = s.[String.length s - 1] in
    if (first = '"' && last = '"') || (first = '\'' && last = '\'') then
      Stdlib.String.sub s 1 (String.length s - 2)
    else s
  else s

(* ── Pattern mapping ──────────────────────────────────────────────── *)

let rec walk_pattern (n : xml) : pattern =
  match n.tag with
  | "identifier" -> PVar n.text
  | "_" -> PDiscard
  | "literal_pattern" ->
    (match children_with_tag n ~tag:"string_literal" with
     | [s] -> PLiteral (LString (trim_quotes s.text))
     | _ -> (match children_with_tag n ~tag:"integer_literal" with
              | [i] -> PLiteral (LInt i.text)
              | _ -> PLiteral LUnit))
  | "tuple_pattern" ->
    let elems = List.filter ~f:(fun c -> c.tag <> ",") n.children in
    PTuple (List.map ~f:walk_pattern elems)
  | _ -> PVar n.text

(* ── Expression mapping ─────────────────────────────────────────────── *)

let rec walk_expr (n : xml) : expr =
  let loc = range_of_xml n in
  let v = match n.tag with
    | "identifier" | "primitive_type" | "type_identifier" | "lifetime" ->
      EVar n.text
    | "string_literal" | "char_literal" ->
      ELiteral (LString (trim_quotes n.text))
    | "boolean_literal" ->
      ELiteral (LBool (n.text = "true"))
    | "integer_literal" ->
      ELiteral (LInt n.text)
    | "float_literal" ->
      ELiteral (LFloat n.text)
    | "unit" ->
      ELiteral LUnit

    (* Block expressions *)
    | "block" ->
      EBlock (walk_block n)

    (* Struct *)
    | "struct_item" ->
      let fields = List.filter_map ~f:(fun c ->
        if c.tag = "field_declaration" then
          let name = match child_with_tag c ~tag:"field_identifier" with
            | Some f -> f.text
            | None -> "_" in
          Some (name, { expr_value = EVar "_"; expr_location = range_of_xml c })
        else None
      ) n.children in
      ERecord fields

    (* Use declarations → skip for now *)
    | "use_declaration" ->
      EUnit

    (* Match expressions *)
    | "match_expression" ->
      let scrutinee = match child_with_field n ~field:"value" with
        | Some v -> walk_expr v
        | None -> { expr_value = EVar "?"; expr_location = loc } in
      let arms = List.filter_map ~f:(fun c ->
        if c.tag = "match_arm" then Some (walk_match_arm c) else None
      ) n.children in
      ECase (scrutinee, arms)

    (* If/else *)
    | "if_expression" ->
      let cond = match child_with_field n ~field:"condition" with
        | Some c -> walk_expr c
        | None -> { expr_value = EVar "?"; expr_location = loc } in
      let then_ = match child_with_field n ~field:"consequence" with
        | Some b -> walk_expr b
        | None -> { expr_value = EBlock []; expr_location = loc } in
      let else_ = match child_with_field n ~field:"alternative" with
        | Some b -> Some (walk_expr b)
        | None -> None in
      EIf (cond, then_, else_)

    (* While/loop/for *)
    | "while_expression" | "loop_expression" ->
      let body = match child_with_field n ~field:"body" with
        | Some b -> walk_expr b
        | None -> { expr_value = EBlock []; expr_location = loc } in
      EFn ([PDiscard], body)

    (* For loops *)
    | "for_expression" ->
      let iter = match child_with_field n ~field:"value" with
        | Some i -> walk_expr i
        | None -> { expr_value = EUnit; expr_location = loc } in
      let body = match child_with_field n ~field:"body" with
        | Some b -> walk_expr b
        | None -> { expr_value = EBlock []; expr_location = loc } in
      (* Return both iterator and body so collect_apps can traverse them *)
      EBlock [iter; body]

    (* Let bindings *)
    | "let_declaration" ->
      let pat = match child_with_field n ~field:"pattern" with
        | Some p -> walk_pattern p
        | None -> PVar "_" in
      let init = match child_with_field n ~field:"value" with
        | Some v -> walk_expr v
        | None -> { expr_value = EUnit; expr_location = loc } in
      ELet (pat, init, { expr_value = EUnit; expr_location = loc })

    (* Assignment *)
    | "assignment_expression" ->
      let lhs = match child_with_field n ~field:"left" with
        | Some l -> walk_expr l
        | _ -> { expr_value = EVar "_"; expr_location = loc } in
      let rhs = match child_with_field n ~field:"value" with
        | Some r -> walk_expr r
        | _ -> { expr_value = EUnit; expr_location = loc } in
      EAssignment (lhs, rhs)

    (* Binary operators *)
    | "binary_expression" ->
      let lhs = match child_with_field n ~field:"left" with
        | Some l -> walk_expr l
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      let rhs = match child_with_field n ~field:"right" with
        | Some r -> walk_expr r
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      EBinOp (lhs, "+", rhs)  (* Simplified *)

    (* Unary operators *)
    | "reference_expression" ->
      let rhs = match child_with_field n ~field:"value" with
        | Some r -> walk_expr r
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      EUnOp ("&", rhs)

    | "dereference_expression" ->
      let rhs = match child_with_field n ~field:"value" with
        | Some r -> walk_expr r
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      EUnOp ("*", rhs)

    (* Call expressions *)
    | "call_expression" ->
      let fn_node = match child_with_field n ~field:"function" with
        | Some f -> walk_expr f
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      let args = List.filter_map ~f:(fun c ->
        if c.tag = "," then None else Some (walk_expr c)
      ) (children_with_field n ~field:"arguments") in
      EApp (fn_node, args)

    (* Field access *)
    | "field_access_expression" ->
      let obj = match child_with_field n ~field:"value" with
        | Some o -> walk_expr o
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      let field = match child_with_tag n ~tag:"field_identifier" with
        | Some f -> f.text
        | None -> "_" in
      EFieldAccess (obj, field)

    (* Field expression (method call receiver): obj.field *)
    | "field_expression" ->
      let obj = match child_with_tag n ~tag:"identifier" with
        | Some o -> o.text
        | None -> "" in
      let field = match child_with_tag n ~tag:"field_identifier" with
        | Some f -> f.text
        | None -> "" in
      EVar (obj ^ "." ^ field)

    (* Index expressions *)
    | "index_expression" ->
      let obj = match child_with_field n ~field:"value" with
        | Some o -> walk_expr o
        | _ -> { expr_value = EVar "?"; expr_location = loc } in
      let idx = match child_with_field n ~field:"index" with
        | Some i -> walk_expr i
        | _ -> { expr_value = EVar "0"; expr_location = loc } in
      EApp ({ expr_value = EVar "[]"; expr_location = loc }, [obj; idx])

    (* Macro invocation *)
    | "macro_invocation" ->
      let name_node = child_with_tag n ~tag:"identifier" in
      let args = List.filter_map ~f:(fun c ->
        if c.tag = "," then None else Some (walk_expr c)
      ) n.children in
      let name = match name_node with
        | Some id -> id.text ^ "!"
        | None -> "macro!" in
      EApp ({ expr_value = EVar name; expr_location = loc }, args)

    (* Return expressions *)
    | "return_expression" ->
      let val_ = match child_with_field n ~field:"value" with
        | Some v -> Some (walk_expr v)
        | None -> None in
      EApp ({ expr_value = EVar "return"; expr_location = loc }, Option.to_list val_)

    (* Break/continue *)
    | "break_expression" | "continue_expression" ->
      EVar "break"

    (* Expression statement (wraps expressions with trailing semicolon) *)
    | "expression_statement" ->
      let children = List.filter ~f:(fun c -> c.text <> "") n.children in
      (match children with
       | [c] -> (walk_expr c).expr_value
       | _ -> EUnit)

    (* Self *)
    | "self" ->
      EVar "self"

    | _ ->
      EVar n.text
  in
  { expr_value = v; expr_location = loc }

and walk_block (n : xml) : expr list =
  List.filter_map ~f:(fun c ->
    match c.tag with
    | ";" -> None
    | "attribute_item" -> None
    | "comment" | "line_comment" | "block_comment" -> None
    | _ -> Some (walk_expr c)
  ) n.children

and walk_match_arm (n : xml) : (pattern * expr) =
  let loc = range_of_xml n in
  let pat = match child_with_field n ~field:"pattern" with
    | Some p -> walk_pattern p
    | None -> PVar "_" in
  let body = match child_with_field n ~field:"body" with
    | Some b -> walk_expr b
    | None -> { expr_value = EUnit; expr_location = loc } in
  (pat, body)

(* ── Top-level item extraction ───────────────────────────────────── *)

let rec walk_item (n : xml) (file : string) : item list =
  match n.tag with
  | "function_item" ->
    let name = match child_with_tag n ~tag:"identifier" with
      | Some id -> id.text
      | None -> "_" in
    let params = List.filter_map ~f:(fun p ->
      if p.tag = "parameter" then
        let pname = match child_with_tag p ~tag:"identifier" with
          | Some id -> id.text
          | None -> "_" in
        Some (PVar pname)
      else None
    ) n.children in
    let body = match child_with_tag n ~tag:"block" with
      | Some b -> walk_expr b
      | None -> { expr_value = EBlock []; expr_location = range_of_xml n } in
    [{ item_location = range_of_xml n; item_value = IFunction (name, params, None, body) }]
  | "struct_item" ->
    let name = match child_with_tag n ~tag:"type_identifier" with
      | Some id -> id.text
      | None -> "_" in
    let fields = List.filter_map ~f:(fun f ->
      if f.tag = "field_declaration" then
        let fname = match child_with_tag f ~tag:"field_identifier" with
          | Some id -> id.text
          | None -> "_" in
        Some (PVar fname)
      else None
    ) n.children in
    let body = { expr_value = ERecord []; expr_location = range_of_xml n } in
    [{ item_location = range_of_xml n; item_value = IClass (name, [{ item_location = range_of_xml n; item_value = IFunction (name, fields, None, body) }]) }]
  | "source_file" ->
    List.concat_map ~f:(fun c -> walk_item c file) n.children
  | _ -> []

(* ── Parse via tree-sitter CLI ─────────────────────────────────────── *)

let resolve_rust_grammar () : string option =
  Tree_sitter_xml.resolve_grammar ~lang:"rust" ~env_var:"TREE_SITTER_RUST_GRAMMAR"

let parse_with_grammar ~grammar ~path : (t, PE.parse_error) Result.t =
  (* Use --lib-path for native .so parsers, --grammar-path for WASM/compiled grammars *)
  let cmd =
    (* Check if grammar looks like a native .so (exports tree_sitter_rust) *)
    if Stdlib.Sys.file_exists grammar && not (Stdlib.Sys.is_directory grammar) then
      (* Native parser - use --lib-path with --lang-name *)
      Stdlib.Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name rust -x '%s' 2>/dev/null" grammar path
    else
      (* WASM or compiled grammar - use --grammar-path *)
      Stdlib.Printf.sprintf "tree-sitter parse --grammar-path '%s' -x '%s' 2>/dev/null" grammar path
  in
  try
    let ic = Unix.open_process_in cmd in
    let xml_str = Stdlib.Buffer.create 4096 in
    (try while true do Stdlib.Buffer.add_channel xml_str ic 4096 done with Stdlib.End_of_file -> ());
    let status = Unix.close_process_in ic in
    match status with
    | Unix.WEXITED 0 | Unix.WEXITED 1 ->
      let doc = parse_xml (Stdlib.Buffer.contents xml_str) in
      (* Drill through wrapper tags *)
      let program = match find doc ~tag:"source_file" with
        | [p] -> convert_xml p
        | _ -> convert_xml doc
      in
      let items = List.concat_map ~f:(fun c -> walk_item c path) program.children in
      let mod_ = {
        mod_lang = Rust;
        mod_path = path;
        mod_items = items;
        parse_errors = [];
      } in
      Ok mod_
    | _ ->
      Error (PE.make_error ~file:path ~message:"tree-sitter parse failed")
  with e ->
    Error (PE.make_error ~file:path ~message:(Exn.to_string e))

(* ── Main entry point ─────────────────────────────────────────────── *)

let parse_file ~(path : string) : (t, PE.parse_error) Result.t =
  match resolve_rust_grammar () with
  | None ->
    Error (PE.make_error ~file:path ~message:"Rust tree-sitter grammar not found. Set TREE_SITTER_RUST_GRAMMAR or install tree-sitter-rust.")
  | Some grammar ->
    parse_with_grammar ~grammar ~path