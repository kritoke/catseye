(* lib/catseye_il/of_catseye_ast.ml
   Convert CatseyeAST.t → il_unit.

   Walks the AST items/expressions and produces IL nodes that preserve
   branch structure, field-sensitive lvalues, and arg positions.
*)

open Catseye_ast.Types
open Il_types

(* ── Position conversion ────────────────────────────────────────────── *)

let pos_of_range (r : range) : pos =
  { line = r.start.line; col = r.start.column }

let pos_of_expr (e : expr) : pos = pos_of_range e.expr_location
let pos_of_item (i : item) : pos = pos_of_range i.item_location

(* ── Pattern → param names ──────────────────────────────────────────── *)

let rec pattern_names (pat : pattern) : string list =
  match pat with
  | PVar v -> [v]
  | PDiscard -> []
  | PLiteral _ -> []
  | PTuple pats -> List.concat_map pattern_names pats
  | PList pats -> List.concat_map pattern_names pats
  | PRecord fields -> List.concat_map (fun (_, p) -> pattern_names p) fields
  | PAlias (p, _) -> pattern_names p
  | PType (_, p) -> pattern_names p

(* ── Expression → lval (when expression is an lvalue) ───────────────── *)

let rec expr_to_lval (e : expr) : lval option =
  match e.expr_value with
  | EVar v -> Some (LVVar v)
  | EFieldAccess (recv, field) ->
    (match expr_to_lval recv with
     | Some lv -> Some (LVField (lv, field, pos_of_expr e))
     | None -> None)
  | _ -> None

(* ── Expression → il_expr ──────────────────────────────────────────── *)

let rec translate_expr (e : expr) : il_expr =
  match e.expr_value with
  | EUnit -> IELiteral "()"
  | ELiteral lit ->
    (match lit with
     | LString s -> IELiteral ("\"" ^ s ^ "\"")
     | LInt i -> IELiteral i
     | LFloat f -> IELiteral f
     | LBool b -> IELiteral (string_of_bool b)
     | LUnit -> IELiteral "()"
     | LNull -> IELiteral "nil"
     | LChar c -> IELiteral (String.make 1 c))
  | EVar v -> IEVar v
  | EFieldAccess (recv, field) ->
    IEField (translate_expr recv, field, pos_of_expr e)
  | EApp (fn, args) ->
    let fn_name = expr_full_name fn in
    IECall (fn_name, List.map translate_expr args, pos_of_expr e)
  | EBinOp (e1, op, e2) ->
    (* Treat binary ops as calls to the operator *)
    IECall (op, [translate_expr e1; translate_expr e2], pos_of_expr e)
  | EUnOp (op, e1) ->
    IECall (op, [translate_expr e1], pos_of_expr e)
  | ETuple es ->
    IECall ("<tuple>", List.map translate_expr es, pos_of_expr e)
  | EList es ->
    IECall ("<list>", List.map translate_expr es, pos_of_expr e)
  | ERecord fields ->
    let all = List.concat_map (fun (k, e) ->
      [IELiteral k; translate_expr e]
    ) fields in
    IECall ("<record>", all, pos_of_expr e)
  | EFn (_, _body) ->
    (* Anonymous function — can't represent as il_expr, track as unknown *)
    IEUnknown "<lambda>"
  | EIf _ | ECase _ ->
    (* These become IL nodes, not expressions. Use as unknown if in expr position. *)
    IEUnknown "<branch_expr>"
  | EBlock es ->
    (* Inline block: just translate the last expression *)
    (match List.rev es with
     | [] -> IELiteral "()"
     | last :: _ -> translate_expr last)
  | EAssignment _ | ELet _ | ELetAssert _ ->
    IEUnknown "<assign_expr>"
  | EError msg -> IEUnknown ("error:" ^ msg)
  | ETryCatchFinally _ -> IEUnknown "<try>"
  | EUnknown s -> IEUnknown s
  | ERecordUpdate (_, _) -> IEUnknown "<record_update>"

and expr_full_name (e : expr) : string =
  match e.expr_value with
  | EVar v -> v
  | EFieldAccess (recv, field) ->
    let prefix = expr_full_name recv in
    if prefix = "" then field
    else prefix ^ "." ^ field
  | _ -> ""

(* ── Expression → il_block (when expression contains statements) ────── *)

and translate_block_expr (e : expr) : il_block =
  match e.expr_value with
  | EBlock es -> List.concat_map translate_stmt_expr es
  | _ -> translate_stmt_expr e

and translate_stmt_expr (e : expr) : il_block =
  match e.expr_value with
  | ELet (pat, e1, e2) ->
    let var_name = match pat with
      | PVar v -> v
      | _ -> "_"
    in
    let lv = LVVar var_name in
    let pos = pos_of_expr e in
    (* First translate the assigned expression *)
    let assign_nodes = match e1.expr_value with
      | EApp (fn, args) ->
        let fn_name = expr_full_name fn in
        let translated_args = List.map translate_expr args in
        (* Walk nested args for sub-calls *)
        let nested = List.concat_map (fun a ->
          match a.expr_value with EApp _ -> extract_calls a | _ -> []
        ) args in
        nested @ [ILCall (Some lv, fn_name, translated_args, pos_of_expr e1)]
      | _ ->
        [ILAssign (lv, translate_expr e1, pos)]
    in
    assign_nodes @ translate_block_expr e2

  | ELetAssert (pat, e1, e2) ->
    (* Assert let — treat same as regular let for taint purposes *)
    translate_stmt_expr { e with expr_value = ELet (pat, e1, e2) }

  | EAssignment (target, value) ->
    let pos = pos_of_expr e in
    (match expr_to_lval target with
     | Some lv ->
       [ILAssign (lv, translate_expr value, pos)]
     | None ->
       (* Complex assignment target, just track calls in value *)
       extract_calls value)

  | EIf (cond, then_, else_) ->
    let pos = pos_of_expr e in
    let cond_expr = translate_expr cond in
    let then_block = translate_block_expr then_ in
    let else_block = Option.map translate_block_expr else_ in
    [ILBranch (cond_expr, then_block, else_block, pos)]

  | ECase (target, branches) ->
    (* Convert case to nested branches *)
    let pos = pos_of_expr e in
    let target_expr = translate_expr target in
    translate_case branches target_expr pos

  | EApp (fn, args) ->
    let pos = pos_of_expr e in
    let fn_name = expr_full_name fn in
    (* Walk args for nested calls first *)
    let arg_calls = List.concat_map (fun a ->
      match a.expr_value with
      | EApp _ -> extract_calls a
      | _ -> []
    ) args in
    arg_calls @ [ILCall (None, fn_name, List.map translate_expr args, pos)]

  | EBlock es ->
    List.concat_map translate_stmt_expr es

  | EBinOp (e1, _op, e2) ->
    (* Walk for nested calls *)
    extract_calls e1 @ extract_calls e2

  | EUnOp (_op, e1) ->
    extract_calls e1

  | EError msg ->
    let pos = pos_of_expr e in
    [ILThrow (IELiteral msg, pos)]

  | _ ->
    (* ELiteral, EVar, EFieldAccess, ETuple, EList, ERecord, etc. —
       these don't produce IL nodes on their own *)
    []

(* Extract calls from an expression tree — catches nested calls
   that the main translation might miss *)
and extract_calls (e : expr) : il_block =
  match e.expr_value with
  | EApp (fn, args) ->
    let pos = pos_of_expr e in
    let fn_name = expr_full_name fn in
    let nested = List.concat_map extract_calls args in
    nested @ [ILCall (None, fn_name, List.map translate_expr args, pos)]
  | EBlock es ->
    List.concat_map (fun e' -> translate_stmt_expr e' @ extract_calls e') es
  | EFieldAccess (recv, _) -> extract_calls recv
  | ETuple es | EList es -> List.concat_map extract_calls es
  | ERecord fields -> List.concat_map (fun (_, e') -> extract_calls e') fields
  | EBinOp (e1, _, e2) -> extract_calls e1 @ extract_calls e2
  | EUnOp (_, e1) -> extract_calls e1
  | EIf (cond, then_, else_) ->
    let cond_calls = extract_calls cond in
    let then_calls = extract_calls then_ in
    let else_calls = match else_ with Some e' -> extract_calls e' | None -> [] in
    cond_calls @ then_calls @ else_calls
  | _ -> []

(* Convert case branches to a chain of ILBranch nodes *)
and translate_case (branches : (pattern * expr) list) (target : il_expr) (pos : pos) : il_block =
  match branches with
  | [] -> []
  | [(_, body)] ->
    (* Single branch — just translate body *)
    translate_block_expr body
  | (_, body) :: rest ->
    let then_block = translate_block_expr body in
    let else_block =
      let rest_block = translate_case rest target pos in
      if rest_block = [] then None else Some rest_block
    in
    [ILBranch (target, then_block, else_block, pos)]

(* ── Item → il_function list ────────────────────────────────────────── *)

let rec walk_item (item : item) : il_function list =
  match item.item_value with
  | IFunction (name, params, _ret, body) ->
    let param_names = List.concat_map pattern_names params in
    let fn_body = translate_block_expr body in
    [{ fn_name = name; fn_params = param_names; fn_body; fn_pos = pos_of_item item }]
  | IClass (_, items) ->
    List.concat_map walk_item items
  | IModule (_, items) ->
    List.concat_map walk_item items
  | IImport _ | ITypeAlias _ | ITypeDef _ | IConstant _
  | IExternal _ | IUnknown _ -> []

(* ── Main entry point ───────────────────────────────────────────────── *)

let translate (mod_ : Catseye_ast.Types.t) : il_unit =
  let lang = match mod_.mod_lang with
    | Gleam -> "gleam"
    | Crystal -> "crystal"
  in
  let fns = List.concat_map walk_item mod_.mod_items in
  { il_file = mod_.mod_path; il_lang = lang; il_functions = fns }
