(* src/ocaml/lib/catseye_ast/crystal_hierarchical_mapper.ml
   Hierarchical Crystal JSON → CatseyeAST.t 

   Parses the nested JSON produced by hierarchical_extractor.cr directly
   into CatseyeAST.t expressions. No heuristic reconstruction needed —
   if/else, case/when, class/module all have proper nesting in the JSON.

   This is the target path for Crystal AST construction. The old flat-node
   path (crystal_mapper.ml) is kept for backward compatibility.
 *)

module PE = Error

open Base
open Types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* ── JSON helpers ──────────────────────────────────────────────────── *)

let string_of_json = function `String s -> s | _ -> ""
let int_of_json = function `Int i -> i | _ -> 0
let list_of_json = function `List l -> l | _ -> []
let assoc_of_json = function `Assoc l -> l | _ -> []

let rec find_field fields key =
  match fields with [] -> `Null | (k, v) :: _ when k = key -> v | _ :: r -> find_field r key

let get_str json key = match assoc_of_json json with
  | fields -> string_of_json (find_field fields key)

let get_int json key = match assoc_of_json json with
  | fields -> int_of_json (find_field fields key)

let get_obj json key = match assoc_of_json json with
  | fields ->
    match find_field fields key with
    | `Assoc _ as v -> Some v
    | `Null -> None
    | _ -> None

let get_list json key = match assoc_of_json json with
  | fields -> list_of_json (find_field fields key)

let get_opt_obj json key = match assoc_of_json json with
  | fields ->
    match find_field fields key with
    | `Assoc _ as v -> Some v
    | `Null | _ -> None

let get_type json = get_str json "type"

(* ── Location ──────────────────────────────────────────────────────── *)

let zero_loc =
  { start = { line = 0; column = 0; byte_offset = 0 };
    end_ = { line = 0; column = 0; byte_offset = 0 } }

let loc_of_json json =
  let line = get_int json "line" in
  { start = { line; column = 0; byte_offset = 0 };
    end_ = { line; column = 0; byte_offset = 0 } }

(* ── Expression parsing ────────────────────────────────────────────── *)

let rec expr_of_json json : expr =
  let loc = loc_of_json json in
  let value = match get_type json with
    | "call" -> parse_call json loc
    | "var" -> EVar (get_str json "name")
    | "instance_var" -> EVar (get_str json "name")
    | "path" -> EVar (get_str json "name")
    | "literal" -> parse_literal json
    | "if" -> parse_if json loc
    | "unless" -> parse_unless json loc
    | "case" -> parse_case json loc
    | "when" -> parse_when_body json loc  (* when body is just the body expr *)
    | "assign" -> parse_assign json loc
    | "Expressions" -> parse_expressions json loc
    | "block" -> parse_expressions json loc  (* block body is like expressions *)
    | "interpolation" -> EUnknown "interpolation"
    | "array" -> parse_array json loc
    | "hash" -> EUnknown "hash"
    | "exception_handler" -> parse_try json loc
    | "while" | "until" -> parse_loop json loc
    | "return" -> parse_return json loc
    | "raise" -> parse_raise json loc
    | "nop" -> EUnit
    | "Unit" -> EUnit
    | _ -> EUnknown (get_type json)
  in
  { expr_value = value; expr_location = loc }

and parse_call json loc =
  let name = get_str json "name" in
  (* Parse receiver (obj) *)
  let fn_expr = match get_opt_obj json "obj" with
    | Some obj ->
      let recv = expr_of_json obj in
      (* Extract method name after the last dot *)
      let method_name = match Stdlib.String.rindex_opt name '.' with
        | Some idx -> Stdlib.String.sub name (idx + 1) (String.length name - idx - 1)
        | None -> name
      in
      { expr_value = EFieldAccess (recv, method_name); expr_location = loc }
    | None ->
      { expr_value = EVar name; expr_location = loc }
  in
  let args = List.map ~f:arg_of_json (get_list json "args") in
  EApp (fn_expr, args)

and arg_of_json json : expr =
  let arg_type = get_str json "arg_type" in
  let value = get_str json "value" in
  match arg_type with
  | "literal" -> { expr_value = ELiteral (LString value); expr_location = { start = { line = 0; column = 0; byte_offset = 0 }; end_ = { line = 0; column = 0; byte_offset = 0 } } }
  | "var" -> { expr_value = EVar value; expr_location = zero_loc }
  | "call" -> { expr_value = EApp ({ expr_value = EVar value; expr_location = zero_loc }, []); expr_location = zero_loc }
  | _ -> { expr_value = EUnknown value; expr_location = zero_loc }

and parse_literal json =
  match get_str json "literal_type" with
  | "string" -> ELiteral (LString (get_str json "value"))
  | "number" -> ELiteral (LInt (get_str json "value"))
  | "bool" -> (match get_str json "value" with "true" -> ELiteral (LBool true) | _ -> ELiteral (LBool false))
  | "nil" -> ELiteral LNull
  | "symbol" -> ELiteral (LString (get_str json "value"))
  | _ -> ELiteral (LString (get_str json "value"))

and parse_if json loc =
  let cond_expr = match get_opt_obj json "condition" with
    | Some c -> expr_of_json c
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  let then_expr = match get_opt_obj json "then" with
    | Some t -> expr_of_json t
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  let else_expr = match get_opt_obj json "else" with
    | Some e -> Some (expr_of_json e)
    | None -> None
  in
  EIf (cond_expr, then_expr, else_expr)

and parse_unless json loc =
  let cond_expr = match get_opt_obj json "condition" with
    | Some c -> expr_of_json c
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  let then_expr = match get_opt_obj json "then" with
    | Some t -> expr_of_json t
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  let else_expr = match get_opt_obj json "else" with
    | Some e -> Some (expr_of_json e)
    | None -> None
  in
  (* unless = if NOT cond then ... *)
  let negated = { expr_value = EUnOp ("!", cond_expr); expr_location = loc } in
  EIf (negated, then_expr, else_expr)

and parse_case json loc =
  let subject = match get_opt_obj json "subject" with
    | Some s -> expr_of_json s
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  let branches = List.filter_map ~f:(fun when_json ->
    let patterns = get_list when_json "patterns" in
    let pat = match patterns with
      | [p] -> pattern_of_json p
      | _ -> PDiscard
    in
    let body = match get_opt_obj when_json "body" with
      | Some b -> expr_of_json b
      | None -> { expr_value = EUnit; expr_location = loc }
    in
    Some (pat, body)
  ) (get_list json "whens") in
  (* Add else branch if present *)
  let all_branches = match get_opt_obj json "else" with
    | Some e -> branches @ [(PDiscard, expr_of_json e)]
    | None -> branches
  in
  ECase (subject, all_branches)

and parse_when_body json _loc =
  (* A standalone "when" (outside a case) is just its body *)
  match get_opt_obj json "body" with
  | Some b -> (expr_of_json b).expr_value
  | None -> EUnit

and pattern_of_json json =
  let t = get_type json in
  match t with
  | "literal" -> PLiteral (LString (get_str json "value"))
  | "var" -> PVar (get_str json "name")
  | "path" -> PVar (get_str json "name")
  | "number" -> PLiteral (LInt (get_str json "value"))
  | _ -> PDiscard

and parse_assign json loc =
  let target = PVar (get_str json "name") in
  let value = match get_opt_obj json "value" with
    | Some v -> expr_of_json v
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  ELet (target, value, { expr_value = EUnit; expr_location = loc })

and parse_expressions json _loc =
  let children = match get_list json "children" with
    | [] -> get_list json "elements"
    | l -> l
  in
  match children with
  | [] -> EUnit
  | [e] -> (expr_of_json e).expr_value
  | es -> EBlock (List.map ~f:expr_of_json es)

and parse_array json _loc =
  let elems = List.map ~f:expr_of_json (get_list json "elements") in
  EList elems

and parse_try json _loc =
  let try_body = match get_opt_obj json "body" with
    | Some b -> expr_of_json b
    | None -> { expr_value = EUnit; expr_location = zero_loc }
  in
  let rescue_clauses = List.map ~f:parse_rescue_clause (get_list json "rescues") in
  let ensure_body = match get_opt_obj json "ensure" with
    | Some e -> Some (expr_of_json e)
    | None -> None
  in
  let else_body = match get_opt_obj json "else" with
    | Some e -> Some (expr_of_json e)
    | None -> None
  in
  ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body }

and parse_rescue_clause json : rescue_clause =
  let exception_var = match get_opt_obj json "name" with
    | Some n -> Some (get_str n "value")
    | None -> None
  in
  let matched_types = List.map ~f:(fun t -> get_str t "name") (get_list json "types") in
  let rescue_body = match get_opt_obj json "body" with
    | Some b -> expr_of_json b
    | None -> { expr_value = EUnit; expr_location = zero_loc }
  in
  { exception_var; matched_types; rescue_body }

and parse_loop json _loc =
  let body = match get_opt_obj json "body" with
    | Some b -> expr_of_json b
    | None -> { expr_value = EUnit; expr_location = zero_loc }
  in
  body.expr_value

and parse_return json _loc =
  (match get_opt_obj json "value" with
   | Some v -> (expr_of_json v).expr_value
   | None -> EUnit)

and parse_raise json _loc =
  let msg = match get_opt_obj json "value" with
    | Some v -> (match (expr_of_json v).expr_value with ELiteral (LString s) -> s | _ -> "error")
    | None -> "error"
  in
  EError msg

(* ── Item parsing ──────────────────────────────────────────────────── *)

let rec item_of_json json : item =
  let loc = loc_of_json json in
  let value = match get_type json with
    | "def" -> parse_def json loc
    | "class" -> parse_class json loc
    | "module" -> parse_module json loc
    | "import" -> parse_import json loc
    | "struct" -> ITypeDef (get_str json "name", [], [])
    | "Expressions" ->
      (* Top-level expressions: parse children, marking top-level as functions *)
      let children = get_list json "children" in
      parse_top_level_exprs children
    | _ -> IUnknown (get_type json)
  in
  { item_value = value; item_location = loc }

and parse_top_level_exprs (exprs : Yojson.Safe.t list) : item_value =
  (* Group expressions into a synthetic module with synthetic functions *)
  (* Each non-def/class/module item becomes part of a synthetic "<toplevel>" function *)
  let rec group_exprs (exprs : Yojson.Safe.t list) (current_body : Yojson.Safe.t list) (acc : item list) : item list =
    match exprs with
    | [] ->
      (* Don't create empty functions, just return accumulated items *)
      if current_body = [] then List.rev acc
      else List.rev acc  (* Drop empty top-level body *)
    | expr :: rest ->
      let typ = get_type expr in
      if typ = "def" || typ = "class" || typ = "module" then
        (* Start new item group *)
        let new_acc = if current_body = [] then acc else item_of_json expr :: acc in
        group_exprs rest [] (item_of_json expr :: new_acc)
      else
        (* Continue current group *)
        group_exprs rest (expr :: current_body) acc
  in
  let items = group_exprs exprs [] [] in
  IModule ("TopLevel", items)

and parse_def json loc =
  let name = get_str json "name" in
  let params = List.map ~f:(fun arg ->
    PVar (get_str arg "value")
  ) (get_list json "args") in
  let body = match get_opt_obj json "body" with
    | Some b -> expr_of_json b
    | None -> { expr_value = EUnit; expr_location = loc }
  in
  IFunction (name, params, None, body)

and parse_class json _loc =
  let name = get_str json "name" in
  let items = match get_opt_obj json "body" with
    | Some body ->
      let children = get_list body "children" in
      parse_class_body children
    | None -> []
  in
  IClass (name, items)

and parse_class_body (exprs : Yojson.Safe.t list) : item list =
  (* Simple approach: recursively process each expression *)
  (* If it's a def/class/module, parse it. Otherwise, create a synthetic method to hold it *)
  let zero_loc = { start = { line = 0; column = 0; byte_offset = 0 }; end_ = { line = 0; column = 0; byte_offset = 0 } } in
  let rec process_exprs (exprs : Yojson.Safe.t list) (current_body : Yojson.Safe.t list) (acc : item list) : item list =
    match exprs with
    | [] ->
      (* Finalize any pending body *)
      if current_body = [] then List.rev acc
      else 
        let body_expr = { expr_value = EBlock (List.map ~f:expr_of_json (List.rev current_body)); expr_location = zero_loc } in
        let synth_fn = IFunction ("<toplevel>", [], None, body_expr) in
        List.rev ({ item_value = synth_fn; item_location = zero_loc } :: acc)
    | expr :: rest ->
      let typ = get_type expr in
      if typ = "def" || typ = "class" || typ = "module" then
(* First finalize any pending body *)
        let new_acc = if current_body = [] then acc else
          let body_expr = { expr_value = EBlock (List.map ~f:expr_of_json (List.rev current_body)); expr_location = zero_loc } in
          let synth_fn = IFunction ("<toplevel>", [], None, body_expr) in
          { item_value = synth_fn; item_location = zero_loc } :: acc
        in
        (* Then add this item *)
        process_exprs rest [] (item_of_json expr :: new_acc)
      else
        (* Continue accumulating body *)
        process_exprs rest (expr :: current_body) acc
  in
  process_exprs exprs [] []

and parse_module json _loc =
  let name = get_str json "name" in
  let items = match get_opt_obj json "body" with
    | Some body ->
      (* The body can be a single def/class/module or an Expressions node *)
      let body_type = get_type body in
      if body_type = "Expressions" then
        (* Flat list of expressions *)
        let children = get_list body "children" in
        parse_class_body children
      else if body_type = "def" || body_type = "class" || body_type = "module" then
        (* Single item - parse it directly *)
        [item_of_json body]
      else
        (* Expression that isn't a def - group it in a synthetic method *)
        parse_class_body [body]
    | None -> []
  in
  IModule (name, items)

and parse_import json _loc =
  let module_path = match get_list json "args" with
    | [arg] -> get_str arg "value"
    | _ -> get_str json "name"
  in
  IImport (module_path, None)

(* ── Top-level parse ──────────────────────────────────────────────── *)

(** Parse hierarchical JSON from the Crystal extractor into CatseyeAST items.
    The root is either an "Expressions" node with children, or a single item. *)
let parse_items (json : Yojson.Safe.t) : item list =
  match json with
  | `Assoc _ ->
    (match get_type json with
| "Expressions" ->
        get_list json "children" |> List.map ~f:item_of_json
      | _ -> [item_of_json json])
  | `List items ->
    List.filter_map ~f:(fun item ->
      match get_type item with
      | "ParseError" -> None
      | _ -> Some (item_of_json item)
    ) items
  | _ -> []

let parse_file ~(extractor_cmd : string) ~(path : string) : (Types.t, PE.parse_error) Result.t =
  let cmd = Stdlib.Printf.sprintf "%s '%s'" extractor_cmd path in
  Stdio.eprintf "DEBUG: Running: %s\n" cmd;
  let ic = Unix.open_process_in cmd in
  let json_str = Buffer.create 8192 in
  (try while true do Stdlib.Buffer.add_channel json_str ic 4096 done
   with End_of_file -> ());
  let status = Unix.close_process_in ic in
  let output = Buffer.contents json_str in
  Stdio.eprintf "DEBUG: Output length=%d, starts with: %s\n" (String.length output) (Stdlib.String.sub output 0 (min 200 (String.length output)));
  match status with
  | Unix.WEXITED 0 ->
    let json = Yojson.Safe.from_string output in
    let items = parse_items json in
    Ok { mod_lang = Crystal; mod_path = path; mod_items = items; parse_errors = [] }
  | _ ->
    Error (PE.make_error ~file:path ~message:"Crystal extractor failed")
