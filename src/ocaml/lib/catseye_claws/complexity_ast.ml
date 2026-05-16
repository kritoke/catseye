(* lib/catseye_claws/complexity_ast.ml
   AST-native cyclomatic complexity detection.

   Counts decision points by walking the expression tree directly:
   - EIf: +1 (no else) or +2 (with else)
   - ECase: +number of branches
   - EBinOp with &&/||: +1
   - EBlock, ELet: recurse into children

   This replaces the heuristic substring-matching approach in complexity.ml
   which pattern-matches node names like "if", "unless", "case", etc.
*)

open Catseye_ast.Types
open Catseye_types

(** Count decision points in an expression tree.
    McCabe cyclomatic complexity = 1 + decision_count. *)
let rec count_decisions (expr : expr) : int =
  match expr.expr_value with
  | EUnit | ELiteral _ | EVar _ ->
    0
  | EFieldAccess (recv, _) ->
    count_decisions recv
  | ETuple es | EList es ->
    List.fold_left (fun acc e -> acc + count_decisions e) 0 es
  | ERecord fields ->
    List.fold_left (fun acc (_, e) -> acc + count_decisions e) 0 fields
  | ERecordUpdate (e, fields) ->
    count_decisions e +
    List.fold_left (fun acc (_, e) -> acc + count_decisions e) 0 fields
  | EApp (fn, args) ->
    count_decisions fn +
    List.fold_left (fun acc a -> acc + count_decisions a) 0 args
  | EFn (_, body) ->
    count_decisions body
  | EIf (_cond, then_, else_) ->
    (* if with else = 2 decision points; without else = 1 *)
    let base = match else_ with Some _ -> 2 | None -> 1 in
    base
    + count_decisions then_
    + (match else_ with Some e -> count_decisions e | None -> 0)
  | ECase (_target, branches) ->
    (* Each branch is a decision point *)
    List.length branches
    + List.fold_left (fun acc (_, body) -> acc + count_decisions body) 0 branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
    count_decisions e1 + count_decisions e2
  | EAssignment (e1, e2) ->
    count_decisions e1 + count_decisions e2
  | EBinOp (e1, op, e2) ->
    let decision = if op = "&&" || op = "||" || op = "and" || op = "or" then 1 else 0 in
    decision + count_decisions e1 + count_decisions e2
  | EUnOp (_, e1) ->
    count_decisions e1
  | EBlock es ->
    List.fold_left (fun acc e -> acc + count_decisions e) 0 es
  | EError _ | EUnknown _ | ETryCatchFinally _ ->
    0

(** Run complexity analysis on AST scopes. *)
let analyze (modules : Catseye_ast.Types.t list) (config : Types.claws_config)
    : Finding.t list =
  let scopes = Ast_scope.build modules in
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let complexity = 1 + count_decisions scope.body in
    let severity, threshold =
      if complexity >= config.complexity_critical then
        ("High", config.complexity_critical)
      else if complexity >= config.complexity_warning then
        ("Medium", config.complexity_warning)
      else ("", 0)
    in
    if severity = "" then None
    else Some {
      Finding.rule = "HighComplexity";
      severity;
      file = scope.file;
      line = scope.line;
      message = Printf.sprintf
        "Function '%s' has cyclomatic complexity of %d (threshold: %d)"
        scope.fn_name complexity threshold;
      flow = [ {
        Finding.file = scope.file;
        line = scope.line;
        message = Printf.sprintf "Definition of '%s' (complexity: %d)"
          scope.fn_name complexity;
      } ];
      language = scope.lang;
      dependency = None;
      reachability = None; suggestion = None;
    }
  ) scopes
