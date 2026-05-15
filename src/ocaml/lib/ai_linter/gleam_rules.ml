(* src/ocaml/lib/ai_linter/gleam_rules.ml
   Gleam-specific AST rules

   All rules operate on CatseyeAST.t using typed pattern matching.
   No IUnknown or string-prefix matching.
*)

open Catseye_ast.Types

module T = Types

(* ── Expression tree helpers ────────────────────────────────────────── *)

(** Recursively walk an expression, collecting all function applications *)
let rec collect_apps (expr : expr) : (string * int) list =
  match expr.expr_value with
  | EApp (fn, args) ->
      let fn_name = expr_name fn in
      let loc = (fn_name, expr.expr_location.start.line) in
      loc :: List.concat_map collect_apps args
  | EIf (_, then_, else_) ->
      collect_apps then_ @ (match else_ with Some e -> collect_apps e | None -> [])
  | ECase (_, branches) -> List.concat_map (fun (_, e) -> collect_apps e) branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> collect_apps e1 @ collect_apps e2
  | EBlock es -> List.concat_map collect_apps es
  | ETuple es -> List.concat_map collect_apps es
  | EList es -> List.concat_map collect_apps es
  | EFn (_, body) -> collect_apps body
  | _ -> []

(** Get the full name of an expression (e.g., "List.wrap", "Result.is_ok") *)
and expr_name (e : expr) : string =
  match e.expr_value with
  | EVar name -> name
  | EFieldAccess (receiver, field) ->
      let prefix = expr_name receiver in
      if prefix = "" then field else prefix ^ "." ^ field
  | _ -> ""

(** Check if expression contains an app matching a predicate *)
let rec has_app_named (expr : expr) (module_name : string option) (fn_name : string) : bool =
  match expr.expr_value with
  | EApp (fn, args) ->
      (match fn.expr_value with
       | EVar name when name = fn_name -> true
       | EFieldAccess (r, f) when f = fn_name ->
           (match module_name with
            | Some mn -> expr_name r = mn
            | None -> true)
       | _ -> false)
      || List.exists (fun a -> has_app_named a module_name fn_name) args
  | EIf (_, then_, else_) ->
      has_app_named then_ module_name fn_name
      || (match else_ with Some e -> has_app_named e module_name fn_name | None -> false)
  | ECase (_, branches) -> List.exists (fun (_, e) -> has_app_named e module_name fn_name) branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      has_app_named e1 module_name fn_name || has_app_named e2 module_name fn_name
  | EBlock es -> List.exists (fun e -> has_app_named e module_name fn_name) es
  | ETuple es -> List.exists (fun e -> has_app_named e module_name fn_name) es
  | EList es -> List.exists (fun e -> has_app_named e module_name fn_name) es
  | EFn (_, body) -> has_app_named body module_name fn_name
  | _ -> false

(** Collect all field accesses with a specific suffix (e.g., "_or_default") *)
let rec collect_field_access_suffix (suffix : string) (expr : expr) : (string * int) list =
  let check fn_expr line =
    match fn_expr.expr_value with
    | EFieldAccess (_, field) when String.ends_with ~suffix field
      -> Some (field, line)
    | _ -> None
  in
  match expr.expr_value with
  | EApp (fn, args) ->
      (match check fn expr.expr_location.start.line with
       | Some hit -> hit :: List.concat_map (collect_field_access_suffix suffix) args
       | None -> List.concat_map (collect_field_access_suffix suffix) args)
  | EIf (_, then_, else_) ->
      collect_field_access_suffix suffix then_
      @ (match else_ with Some e -> collect_field_access_suffix suffix e | None -> [])
  | ECase (_, branches) -> List.concat_map (fun (_, e) -> collect_field_access_suffix suffix e) branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_field_access_suffix suffix e1 @ collect_field_access_suffix suffix e2
  | EBlock es -> List.concat_map (collect_field_access_suffix suffix) es
  | _ -> []

(** Collect all ERROR nodes (parse errors from tree-sitter) *)
let rec collect_errors (expr : expr) : (string * int) list =
  match expr.expr_value with
  | EError msg -> [(msg, expr.expr_location.start.line)]
  | EApp (fn, args) -> collect_errors fn @ List.concat_map collect_errors args
  | EIf (_, then_, else_) ->
      collect_errors then_ @ (match else_ with Some e -> collect_errors e | None -> [])
  | ECase (_, branches) -> List.concat_map (fun (_, e) -> collect_errors e) branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> collect_errors e1 @ collect_errors e2
  | EBlock es -> List.concat_map collect_errors es
  | _ -> []

(** Collect identifier references with a specific name *)
let rec collect_var_refs (name : string) (expr : expr) : int list =
  match expr.expr_value with
  | EVar v when String.lowercase_ascii v = name -> [expr.expr_location.start.line]
  | EApp (fn, args) -> collect_var_refs name fn @ List.concat_map (collect_var_refs name) args
  | EIf (_, then_, else_) ->
      collect_var_refs name then_
      @ (match else_ with Some e -> collect_var_refs name e | None -> [])
  | EBlock es -> List.concat_map (collect_var_refs name) es
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> collect_var_refs name e1 @ collect_var_refs name e2
  | _ -> []

(* ── Rules ──────────────────────────────────────────────────────────── *)

(** Rule: List.wrap on collection is unnecessary *)
let detect_list_wrap (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) when has_app_named body (Some "List") "wrap" ->
        Some ("List.wrap on collection is unnecessary", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Result.is_ok/is_err deprecated *)
let detect_result_check (m : t) =
  let check body =
    has_app_named body (Some "Result") "is_ok"
    || has_app_named body (Some "Result") "is_err"
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) when check body ->
        Some ("Result.is_ok/is_err is deprecated - use pattern matching", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: panic! call detected *)
let detect_panic (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_var_refs "panic" body with
         | [] -> None
         | line :: _ -> Some ("panic call found - use Result or Option", line))
    | _ -> None
  ) m.mod_items

(** Rule: Hallucinated _or_default functions *)
let detect_hallucinated_or_default (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let hits = collect_field_access_suffix "_or_default" body in
        (match hits with
         | [] -> None
         | (field, line) :: _ ->
             Some (Printf.sprintf "Function %s may not exist in Gleam stdlib" field, line))
    | _ -> None
  ) m.mod_items

(** Rule: Hallucinated to_list *)
let detect_hallucinated_to_list (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let hits = collect_field_access_suffix "_to_list" body in
        (match hits with
         | [] -> None
         | (field, line) :: _ ->
             Some (Printf.sprintf "Method %s may not exist on this type" field, line))
    | _ -> None
  ) m.mod_items

(** Rule: TypeScript 'interface' keyword (appears as EVar "interface" in parse tree) *)
let detect_typescript_interface (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_var_refs "interface" body with
         | [] -> None
         | line :: _ -> Some ("'interface' is TypeScript, not Gleam - use 'type'", line))
    | _ -> None
  ) m.mod_items

(** Rule: Rust fn keyword for function defs *)
let detect_rust_fn (m : t) =
  (* In Gleam, 'fn' is a keyword handled by the parser, not an identifier.
     This would only fire if tree-sitter produces an identifier named "fn",
     which shouldn't happen for valid Gleam. Keep as safety net. *)
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_var_refs "fn" body with
         | [] -> None
         | line :: _ -> Some ("'fn' as function call looks like Rust - Gleam uses 'fn' only for definitions", line))
    | _ -> None
  ) m.mod_items

(** Rule: var keyword (Gleam uses let) *)
let detect_var_keyword (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_var_refs "var" body with
         | [] -> None
         | line :: _ -> Some ("'var' is not valid in Gleam - use 'let'", line))
    | _ -> None
  ) m.mod_items

(** Rule: todo in code *)
let detect_todo (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
        (match collect_var_refs "todo" body with
         | [] -> None
         | line :: _ -> Some (Printf.sprintf "Function '%s' contains todo" name, line))
    | _ -> None
  ) m.mod_items

(** Rule: let assert in non-test code
    Detects ELetAssert nodes which map to Gleam's `let assert` pattern.
    In non-test code, this crashes on mismatch — should use case expressions. *)
let detect_let_assert (m : t) =
  let is_test_file (path : string) =
    String.length path >= 5 &&
    let suffix = String.sub path (String.length path - 5) 5 in
    suffix = "_test" ||
    (String.length path >= 9 && String.sub path (String.length path - 9) 9 = "_test.gleam")
  in
  let rec has_let_assert (expr : expr) : int option =
    match expr.expr_value with
    | ELetAssert _ -> Some expr.expr_location.start.line
    | ELet (_, e1, e2) ->
        (match has_let_assert e1 with Some l -> Some l | None -> has_let_assert e2)
    | EIf (_, then_, else_) ->
        (match has_let_assert then_ with
         | Some l -> Some l
         | None -> match else_ with Some e -> has_let_assert e | None -> None)
    | ECase (_, branches) ->
        List.find_map (fun (_, e) -> has_let_assert e) branches
    | EBlock es -> List.find_map has_let_assert es
    | EApp (fn, args) ->
        (match has_let_assert fn with Some l -> Some l | None -> List.find_map has_let_assert args)
    | _ -> None
  in
  if is_test_file m.mod_path then [] (* let assert is fine in tests *)
  else List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_name, _, _, body) ->
        (match has_let_assert body with
         | Some line -> Some ("let assert crashes on Error — use case expression for graceful error handling", line)
         | None -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Non-exhaustive case (missing Error branch)
    Detects case expressions on Result values that only handle Ok.
    AI often forgets the Error branch. *)
let detect_non_exhaustive_case (m : t) =
  let rec count_case_branches (expr : expr) : (int * int) list =
    (* Returns (num_branches, line) pairs for case expressions with only 1 branch *)
    match expr.expr_value with
    | ECase (_, branches) ->
        let n = List.length branches in
        (n, expr.expr_location.start.line)
        :: List.concat_map (fun (_, e) -> count_case_branches e) branches
    | ELet (_, e1, e2) -> count_case_branches e1 @ count_case_branches e2
    | ELetAssert (_, e1, e2) -> count_case_branches e1 @ count_case_branches e2
    | EIf (_, then_, else_) ->
        count_case_branches then_
        @ (match else_ with Some e -> count_case_branches e | None -> [])
    | EBlock es -> List.concat_map count_case_branches es
    | EApp (fn, args) -> count_case_branches fn @ List.concat_map count_case_branches args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let cases = count_case_branches body in
        List.find_map (fun (n, line) ->
          if n = 1 then
            Some ("Case expression has only 1 branch — likely missing Error variant", line)
          else None
        ) cases
    | _ -> None
  ) m.mod_items

(** Rule: Ignored Result
    Uses type inference DB to detect calls to Result-returning functions
    where the return value is not captured in a case expression. *)
let detect_ignored_result (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let apps = collect_apps body in
        List.find_map (fun (name, line) ->
          match Type_inference.lookup_gleam name with
          | Some { Type_inference.kind = Result; type_name; doc } ->
              Some (Printf.sprintf
                "%s returns %s — %s. Use case expression to handle both Ok and Error"
                name type_name doc, line)
          | _ -> None
        ) apps
    | _ -> None
  ) m.mod_items

(** Rule: Unused Import
    Detects imports whose module name is never referenced in the rest
    of the file. AI often adds unnecessary imports. *)
let detect_unused_import (m : t) =
  let imports = List.filter_map (fun item ->
    match item.item_value with
    | IImport (mod_name, _) -> Some (mod_name, item.item_location.start.line)
    | _ -> None
  ) m.mod_items in
  let used_names = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.filter_map (fun (name, _) ->
          match String.index_opt name '.' with
          | Some idx -> Some (String.sub name 0 idx)
          | None -> Some name
        ) (collect_apps body)
    | _ -> []
  ) m.mod_items in
  let is_used mod_name =
    List.exists (fun n ->
      n = mod_name || String.length n > String.length mod_name + 1 &&
      String.sub n 0 (String.length mod_name + 1) = mod_name ^ "."
    ) used_names
  in
  List.filter_map (fun (mod_name, line) ->
    if is_used mod_name then None
    else Some (Printf.sprintf "Module '%s' is imported but never used" mod_name, line)
  ) imports

(** Rule: Discard Result
    Detects patterns where a Result-returning function's value is
    explicitly discarded with `let _ = ...`. *)
let detect_discard_result (m : t) =
  let rec collect_discarded_result_apps (e : expr) : (string * int) list =
    match e.expr_value with
    | ELet (PDiscard, e1, _) ->
        (* The binding is discarded — check if the value is a Result-returning call *)
        (match e1.expr_value with
         | EApp (fn, _) ->
             let name = expr_name fn in
             (match Type_inference.lookup_gleam name with
              | Some { Type_inference.kind = Result; _ } ->
                  [(name, e1.expr_location.start.line)]
              | _ -> [])
         | _ -> [])
    | EBlock es -> List.concat_map collect_discarded_result_apps es
    | EIf (_, then_, else_) ->
        collect_discarded_result_apps then_ @
        (match else_ with Some e -> collect_discarded_result_apps e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> collect_discarded_result_apps e) branches
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_discarded_result_apps body with
         | (name, line) :: _ ->
             Some (Printf.sprintf
               "Result from %s is discarded with let _ = — use case to handle errors" name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Redundant Pipeline
    Detects pipeline expressions where the final step is an identity-like
    function or where a single-step pipeline could be a direct call.
    AI often overuses the |> operator. *)
let detect_redundant_pipeline (m : t) =
  let rec collect_piped_identity (e : expr) : (string * int) list =
    match e.expr_value with
    (* x |> fn(args) where fn has no args = just fn(x), pipeline is redundant *)
    | EApp (fn, [single_arg]) ->
        let name = expr_name fn in
        let arg_name = expr_name single_arg in
        (* Single-arg call with a named arg — could be piped *)
        if String.length name > 0 && String.length arg_name > 0 &&
           name <> "=" && name <> "==" && name <> "!=" then
          [(name, e.expr_location.start.line)]
        else []
    | EBlock es -> List.concat_map collect_piped_identity es
    | ELet (_, e1, e2) -> collect_piped_identity e1 @ collect_piped_identity e2
    | EIf (_, then_, else_) ->
        collect_piped_identity then_ @
        (match else_ with Some e -> collect_piped_identity e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> collect_piped_identity e) branches
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match collect_piped_identity body with
         | (name, line) :: _ ->
             Some (Printf.sprintf
               "Pipeline to %s could be a direct call — overuse of |> is common in AI-generated code"
               name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Implicit Return Discard
    Detects when the last expression in a function body is a call whose
    return value would be implicitly returned, but the function signature
    suggests it shouldn't be. Heuristic: last call in body is a
    side-effecty function like IO.println, process.sleep, etc. *)
let detect_implicit_return_discard (m : t) =
  let side_effect_calls = [
    "io.println"; "io.print"; "io.debug";
    "process.sleep"; "process.spawn";
    "list.each"; "dict.each";
  ] in
  let is_side_effect (name : string) =
    List.exists (fun s ->
      String.length name >= String.length s &&
      String.sub name (String.length name - String.length s) (String.length s) = s
    ) side_effect_calls
  in
  let rec last_expr (e : expr) : expr option =
    match e.expr_value with
    | EBlock es -> (match List.rev es with [] -> None | last :: _ -> Some last)
    | ELet (_, _, e2) -> last_expr e2
    | _ -> Some e
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match last_expr body with
         | Some e ->
             (match e.expr_value with
              | EApp (fn, _) when is_side_effect (expr_name fn) ->
                  Some (Printf.sprintf
                    "Last expression in function is %s — return value is implicitly discarded"
                    (expr_name fn), e.expr_location.start.line)
              | _ -> None)
         | None -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Deeply Nested Case
    Detects case expressions nested 3+ levels deep.
    AI often generates nested pattern matching instead of combining patterns. *)
let detect_nested_case (m : t) =
  let max_depth = 2 in
  let rec case_depth (e : expr) : int =
    match e.expr_value with
    | ECase (_, branches) ->
        let child_max = List.fold_left (fun acc (_, e) -> max acc (case_depth e)) 0 branches in
        1 + child_max
    | EBlock es -> List.fold_left (fun acc e -> max acc (case_depth e)) 0 es
    | ELet (_, e1, e2) -> max (case_depth e1) (case_depth e2)
    | _ -> 0
  in
  let rec find_deep_cases (e : expr) : (int * int) list =
    match e.expr_value with
    | ECase (_, branches) when case_depth e > max_depth ->
        (case_depth e, e.expr_location.start.line)
        :: List.concat_map (fun (_, e) -> find_deep_cases e) branches
    | EBlock es -> List.concat_map find_deep_cases es
    | ELet (_, e1, e2) -> find_deep_cases e1 @ find_deep_cases e2
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_deep_cases body with
         | (depth, line) :: _ ->
             Some (Printf.sprintf
               "Case expression nested %d levels deep (max %d) — combine patterns or extract functions"
               depth max_depth, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Guard After Wildcard
    Detects case branches that appear after a wildcard pattern.
    In Gleam, a wildcard _ matches everything, so later branches are unreachable.
    AI often puts the wildcard first instead of last. *)
let detect_guard_after_wildcard (m : t) =
  let rec has_wildcard_then_more (branches : (pattern * expr) list) : int option =
    match branches with
    | [] | [_] -> None
    | (pat, _) :: rest ->
        (match pat with
         | PDiscard ->
             (* Wildcard found — any branch after this is unreachable *)
             (match rest with
              | [] -> None
              | (_, e) :: _ -> Some e.expr_location.start.line)
         | _ -> has_wildcard_then_more rest)
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let rec find_in_expr (e : expr) : int option =
          match e.expr_value with
          | ECase (_, branches) ->
              (match has_wildcard_then_more branches with
               | Some line -> Some line
               | None -> List.find_map (fun (_, e) -> find_in_expr e) branches)
          | EBlock es -> List.find_map find_in_expr es
          | ELet (_, e1, e2) ->
              (match find_in_expr e1 with Some l -> Some l | None -> find_in_expr e2)
          | _ -> None
        in
        (match find_in_expr body with
         | Some line ->
             Some ("Case branch after wildcard is unreachable — move wildcard to last position", line)
         | None -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Tuple Abuse
    Detects tuples with 4+ elements. In Gleam, tuples should be small
    (2-3 elements). Larger groupings should use records for clarity.
    AI often generates large tuples instead of named records. *)
let detect_tuple_abuse (m : t) =
  let rec find_large_tuples (e : expr) : (int * int) list =
    match e.expr_value with
    | ETuple elems when List.length elems >= 4 ->
        (List.length elems, e.expr_location.start.line)
        :: List.concat_map find_large_tuples elems
    | ETuple elems -> List.concat_map find_large_tuples elems
    | EBlock es -> List.concat_map find_large_tuples es
    | ELet (_, e1, e2) -> find_large_tuples e1 @ find_large_tuples e2
    | EIf (_, then_, else_) ->
        find_large_tuples then_ @
        (match else_ with Some e -> find_large_tuples e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_large_tuples e) branches
    | EApp (fn, args) -> find_large_tuples fn @ List.concat_map find_large_tuples args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_large_tuples body with
         | (size, line) :: _ ->
             Some (Printf.sprintf
               "Tuple has %d elements (max 3) — use a named record for clarity" size, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Complex Pipeline
    Detects pipeline chains (function application chains) with 6+ steps.
    AI often generates very long pipelines that are hard to debug.
    Heuristic: count EApp nesting depth where the function is also an EApp. *)
let detect_complex_pipeline (m : t) =
  let max_depth = 5 in
  let rec pipeline_depth (e : expr) : int =
    match e.expr_value with
    | EApp (fn, [arg]) ->
        1 + pipeline_depth fn + pipeline_depth arg
    | EApp (fn, args) ->
        1 + pipeline_depth fn + List.fold_left (fun acc a -> max acc (pipeline_depth a)) 0 args
    | EBlock es -> List.fold_left (fun acc e -> max acc (pipeline_depth e)) 0 es
    | ELet (_, e1, e2) -> max (pipeline_depth e1) (pipeline_depth e2)
    | _ -> 0
  in
  let rec find_deep_pipelines (e : expr) : (int * int) list =
    match e.expr_value with
    | EApp (fn, args) when pipeline_depth e > max_depth ->
        (pipeline_depth e, e.expr_location.start.line)
        :: List.concat_map find_deep_pipelines (fn :: args)
    | EApp (fn, args) ->
        find_deep_pipelines fn @ List.concat_map find_deep_pipelines args
    | EBlock es -> List.concat_map find_deep_pipelines es
    | ELet (_, e1, e2) -> find_deep_pipelines e1 @ find_deep_pipelines e2
    | EIf (_, then_, else_) ->
        find_deep_pipelines then_ @
        (match else_ with Some e -> find_deep_pipelines e | None -> [])
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_deep_pipelines body with
         | (depth, line) :: _ ->
             Some (Printf.sprintf
               "Pipeline chain has %d steps (max %d) — break into named intermediates for readability"
               depth max_depth, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Assert Density
    Detects functions with 3+ let assert statements.
    Using too many asserts indicates the function assumes too much about
    its data — use proper case/Result handling instead.
    AI often generates assert-heavy code instead of proper error handling. *)
let detect_assert_density (m : t) =
  let max_asserts = 2 in
  let rec count_asserts (e : expr) : int =
    match e.expr_value with
    | ELetAssert _ -> 1
    | EBlock es -> List.fold_left (fun acc e -> acc + count_asserts e) 0 es
    | ELet (_, e1, e2) -> count_asserts e1 + count_asserts e2
    | EIf (_, then_, else_) ->
        count_asserts then_ + (match else_ with Some e -> count_asserts e | None -> 0)
    | ECase (_, branches) ->
        List.fold_left (fun acc (_, e) -> acc + count_asserts e) 0 branches
    | EApp (fn, args) -> count_asserts fn + List.fold_left (fun acc a -> acc + count_asserts a) 0 args
    | _ -> 0
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
        let count = count_asserts body in
        if count > max_asserts then
          Some (Printf.sprintf
            "Function '%s' has %d let assert statements (max %d) — use case expressions for proper error handling"
            name count max_asserts, item.item_location.start.line)
        else None
    | _ -> None
  ) m.mod_items

(** Rule: Shadow Variable
    Detects let-bindings that reuse a variable name from an outer scope.
    AI often accidentally shadows variables, causing subtle bugs.
    Heuristic: PVar in ELet whose name already appears in an enclosing let. *)
let detect_shadow_variable (m : t) =
  let rec find_shadows (e : expr) (bound : string list) : (string * int) list =
    match e.expr_value with
    | ELet (PVar name, e1, body) ->
        let shadow_findings =
          if List.mem name bound then [(name, e.expr_location.start.line)] else [] in
        shadow_findings @ find_shadows e1 bound @ find_shadows body (name :: bound)
    | EBlock es -> List.concat_map (fun e -> find_shadows e bound) es
    | ELet (_, e1, e2) -> find_shadows e1 bound @ find_shadows e2 bound
    | EIf (_, then_, else_) ->
        find_shadows then_ bound @ (match else_ with Some e -> find_shadows e bound | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_shadows e bound) branches
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, params, _, body) ->
        let param_names = List.filter_map (function PVar v -> Some v | _ -> None) params in
        (match find_shadows body param_names with
         | (name, line) :: _ ->
             Some (Printf.sprintf
               "Variable '%s' shadows an outer binding — rename to avoid confusion" name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Let Assert on Result
    Detects let assert on functions known to return Result type.
    Using assert on Result types will crash at runtime on Error —
    use a proper case expression instead. *)
let detect_let_assert_on_result (m : t) =
  let rec find_asserts_on_results (e : expr) : (string * int) list =
    match e.expr_value with
    | ELetAssert (_, e1, _) ->
        (match e1.expr_value with
         | EApp (fn, _) ->
             let name = expr_name fn in
             (match Type_inference.lookup_gleam name with
              | Some { Type_inference.kind = Result; _ } ->
                  [(name, e1.expr_location.start.line)]
              | _ -> [])
         | _ -> [])
    | EBlock es -> List.concat_map find_asserts_on_results es
    | ELet (_, e1, e2) -> find_asserts_on_results e1 @ find_asserts_on_results e2
    | EIf (_, then_, else_) ->
        find_asserts_on_results then_ @
        (match else_ with Some e -> find_asserts_on_results e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_asserts_on_results e) branches
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_asserts_on_results body with
         | (name, line) :: _ ->
             Some (Printf.sprintf
               "let assert on %s which returns Result — will crash on Error. Use case expression"
               name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Todo as Body
    Detects functions whose body is just a call to todo().
    AI often generates stub functions with todo that never get implemented.
    These will crash at runtime. *)
let detect_todo_as_body (m : t) =
  let rec is_todo_call (e : expr) : bool =
    match e.expr_value with
    | EApp (fn, _) -> expr_name fn = "todo"
    | EBlock [e] -> is_todo_call e
    | _ -> false
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) when is_todo_call body ->
        Some (Printf.sprintf
          "Function '%s' body is just todo() — will crash at runtime if called" name,
          item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: String Concat Chain
    Detects 3+ string concatenations using <> operator.
    Should use string.concat or string.join instead for readability.
    AI often generates long concat chains instead of joining a list. *)
let detect_string_concat_chain (m : t) =
  let rec count_concats (e : expr) : int =
    match e.expr_value with
    | EBinOp (_, "<>", e2) -> 1 + count_concats e2
    | EBlock es -> List.fold_left (fun acc e -> max acc (count_concats e)) 0 es
    | ELet (_, e1, e2) -> max (count_concats e1) (count_concats e2)
    | EApp (fn, args) ->
        max (count_concats fn) (List.fold_left (fun acc a -> max acc (count_concats a)) 0 args)
    | _ -> 0
  in
  let rec find_chains (e : expr) : (int * int) list =
    match e.expr_value with
    | EBinOp (_, "<>", e2) ->
        let depth = count_concats e in
        if depth >= 3 then [(depth, e.expr_location.start.line)]
        else find_chains e2
    | EBlock es -> List.concat_map find_chains es
    | ELet (_, e1, e2) -> find_chains e1 @ find_chains e2
    | EApp (fn, args) -> find_chains fn @ List.concat_map find_chains args
    | EIf (_, then_, else_) ->
        find_chains then_ @ (match else_ with Some e -> find_chains e | None -> [])
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_chains body with
         | (count, line) :: _ ->
             Some (Printf.sprintf
               "String concat chain of %d segments — use string.concat or string.join" count, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(* ── Category 5: The Mute Trap (Security) ──────────────────────────── *)

(** Rule: Hardcoded Secrets *)
let detect_hardcoded_secrets (m : t) =
  let secret_prefixes = [
    "sk_"; "sk_live_"; "sk_test_";
    "ghp_"; "gho_"; "ghu_"; "ghs_";
    "AKIA"; "ASIA";
    "AIza";
    "xoxb-"; "xoxp-"; "xoxa-";
    "eyJ";
  ] in
  let is_likely_secret (s : string) =
    String.length s >= 20 &&
    List.exists (fun prefix ->
      String.length prefix <= String.length s &&
      String.sub s 0 (String.length prefix) = prefix
    ) secret_prefixes
  in
  let rec collect_string_literals (e : expr) : (string * int) list =
    match e.expr_value with
    | ELiteral (LString s) when is_likely_secret s ->
        [(s, e.expr_location.start.line)]
    | ELiteral _ -> []
    | EApp (fn, args) ->
        collect_string_literals fn @ List.concat_map collect_string_literals args
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
        collect_string_literals e1 @ collect_string_literals e2
    | EIf (_, then_, else_) ->
        collect_string_literals then_ @
        (match else_ with Some e -> collect_string_literals e | None -> [])
    | EBlock es -> List.concat_map collect_string_literals es
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
        (match collect_string_literals body with
         | (s, line) :: _ ->
             let masked = String.sub s 0 (min 8 (String.length s)) ^ "..." in
             Some (Printf.sprintf
               "Potential hardcoded secret in '%s': %s — use environment variables or config"
               name masked, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** All rules *)
let all () = [
  ("list-wrap-unnecessary", T.Warning, detect_list_wrap);
  ("deprecated-result-check", T.Hint, detect_result_check);
  ("panic-call", T.Error, detect_panic);
  ("hallucinated-or-default", T.Error, detect_hallucinated_or_default);
  ("hallucinated-to-list", T.Error, detect_hallucinated_to_list);
  ("typescript-interface", T.Error, detect_typescript_interface);
  (* Removed: rust-fn — 'fn' appears as identifier in Gleam's tree-sitter
     output for anonymous functions, causing 100% FP rate *)
  ("var-keyword", T.Error, detect_var_keyword);
  ("todo-in-code", T.Warning, detect_todo);
  ("let-assert", T.Error, detect_let_assert);
  ("non-exhaustive-case", T.Warning, detect_non_exhaustive_case);
  ("ignored-result", T.Warning, detect_ignored_result);
  (* unused-import disabled: Gleam tree-sitter module parsing is broken — extracts '/' not module names *)
  (* redundant-pipeline disabled: |> is idiomatic Gleam, this rule is 100% FP *)
  ("discard-result", T.Warning, detect_discard_result);

  ("implicit-return-discard", T.Hint, detect_implicit_return_discard);
  ("nested-case", T.Warning, detect_nested_case);
  ("guard-after-wildcard", T.Warning, detect_guard_after_wildcard);
  ("tuple-abuse", T.Hint, detect_tuple_abuse);
  ("complex-pipeline", T.Hint, detect_complex_pipeline);
  ("assert-density", T.Warning, detect_assert_density);
  ("shadow-variable", T.Hint, detect_shadow_variable);
  ("let-assert-on-result", T.Warning, detect_let_assert_on_result);
  ("todo-as-body", T.Warning, detect_todo_as_body);
  ("string-concat-chain", T.Hint, detect_string_concat_chain);

  (* The Mute Trap *)
  ("hardcoded-secrets", T.Error, detect_hardcoded_secrets);
]

(** Analyze module and return findings *)
let analyze_module (m : t) : Types.finding list =
  List.concat_map (fun (rule_id, sev, detector) ->
    List.map (fun (msg, line) ->
      { Types.file = m.mod_path;
        Types.line = line;
        Types.rule_id = rule_id;
        Types.severity = sev;
        Types.message = msg;
        Types.suggestion = None; }
    ) (detector m)
  ) (all ())
