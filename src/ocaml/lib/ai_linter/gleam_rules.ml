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

(** Rule: Debug in Library
    Detects io.debug calls outside examples/ or tests/ directories.
    Debug output should be removed or use a proper logging library in production code. *)
let detect_debug_in_library (m : t) =
  let is_debug_call (name : string) =
    name = "io.debug" || String.ends_with ~suffix:".debug" name
  in
  let rec find_debug_calls (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, _) when is_debug_call (expr_name fn) ->
        [(expr_name fn, e.expr_location.start.line)]
    | EBlock es -> List.concat_map find_debug_calls es
    | ELet (_, e1, e2) -> find_debug_calls e1 @ find_debug_calls e2
    | EIf (_, then_, else_) ->
        find_debug_calls then_ @ (match else_ with Some e -> find_debug_calls e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> find_debug_calls e) branches
    | EApp (fn, args) -> find_debug_calls fn @ List.concat_map find_debug_calls args
    | _ -> []
  in
  let is_library_code =
    let path = String.lowercase_ascii m.mod_path in
    let _ = path in (* path available for future filtering *)
    true (* Simplified: debug in library is always a potential issue *)
  in
  if is_library_code then
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
          List.map (fun (name, line) ->
            (Printf.sprintf "%s in library code — remove or use proper logging" name, line)
          ) (find_debug_calls body)
      | _ -> []
    ) m.mod_items
  else []

(** Rule: Result in Map
    Detects list.map being called on functions that return Result types.
    This produces a List(Result) which needs further handling.
    Use list.try_map or handle the results explicitly. *)
let detect_result_in_map (m : t) =
  let rec find_result_maps (e : expr) : (string * string * int) list =
    match e.expr_value with
    | EApp (fn, args) ->
        let name = expr_name fn in
        let hits = (match args with
          | [fn_arg] ->
              (* Check if fn_arg is an anonymous function that returns Result *)
              (match fn_arg.expr_value with
               | EFn (_, body) when returns_result body ->
                   [(name, "lambda", e.expr_location.start.line)]
               | _ -> [])
          | _ -> [])
        in
        hits @ List.concat_map find_result_maps args
    | EBlock es -> List.concat_map find_result_maps es
    | ELet (_, e1, e2) -> find_result_maps e1 @ find_result_maps e2
    | EIf (_, then_, else_) ->
        find_result_maps then_ @ (match else_ with Some e -> find_result_maps e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> find_result_maps e) branches
    | _ -> []
  and returns_result (e : expr) : bool =
    match e.expr_value with
    | ECase (_, branches) ->
        List.exists (fun (pat, _body) ->
          match pat with
          | PType ("Result", _) -> true
          | _ -> false
        ) branches || returns_result (snd (List.hd branches))
    | EApp (fn, _) ->
        let name = expr_name fn in
        (match Type_inference.lookup_gleam name with
         | Some { Type_inference.kind = Result; _ } -> true
         | _ -> String.starts_with ~prefix:"Ok " (expr_name fn) ||
                String.starts_with ~prefix:"Error " (expr_name fn))
    | EIf (_, then_, else_) -> returns_result then_ ||
        (match else_ with Some e -> returns_result e | None -> false)
    | EBlock es -> (match List.rev es with [] -> false | last :: _ -> returns_result last)
    | _ -> false
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_result_maps body with
         | (_, _, line) :: _ ->
             Some ("list.map with Result-returning lambda — consider list.try_map for proper error handling", line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Pipeline Steps Overload
    Detects 5+ step pipelines that are hard to read.
    AI often chains too many operations in a single pipeline.
    Suggest breaking into named intermediate variables. *)
let detect_pipeline_steps_overload (m : t) =
  let max_steps = 5 in
  let rec count_pipeline_steps (e : expr) : int =
    match e.expr_value with
    | EApp (fn, [arg]) when expr_name fn = "|>" ->
        1 + count_pipeline_steps arg
    | EApp (fn, [arg]) when String.length (expr_name fn) > 0 && expr_name fn <> "<>" ->
        max (count_pipeline_steps fn) (count_pipeline_steps arg)
    | EBlock es -> List.fold_left (fun acc e -> max acc (count_pipeline_steps e)) 0 es
    | ELet (_, e1, e2) -> max (count_pipeline_steps e1) (count_pipeline_steps e2)
    | EIf (_, then_, else_) ->
        max (count_pipeline_steps then_)
          (match else_ with Some e -> count_pipeline_steps e | None -> 0)
    | ECase (_, branches) ->
        List.fold_left (fun acc (_, e) -> max acc (count_pipeline_steps e)) 0 branches
    | _ -> 0
  in
  let rec find_long_pipelines (e : expr) : (int * int) list =
    match e.expr_value with
    | EApp (fn, [arg]) when expr_name fn = "|>" ->
        let steps = count_pipeline_steps e in
        if steps > max_steps then [(steps, e.expr_location.start.line)]
        else find_long_pipelines arg
    | EApp (fn, args) ->
        List.concat_map find_long_pipelines (fn :: args)
    | EBlock es -> List.concat_map find_long_pipelines es
    | ELet (_, e1, e2) -> find_long_pipelines e1 @ find_long_pipelines e2
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_long_pipelines body with
         | (steps, line) :: _ ->
             Some (Printf.sprintf
               "Pipeline chain has %d steps (max %d) — break into named intermediates for readability"
               steps max_steps, line)
         | [] -> None)
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

(** Rule: Equals True/False
    Detects comparisons like x == True or x == False.
    In Gleam, just use the boolean directly or use not.
    AI coming from other languages often writes this redundant comparison. *)
let detect_equals_true (m : t) =
  let rec find_bool_comparisons (e : expr) : (string * int) list =
    match e.expr_value with
    | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
        let is_bool_literal (x : expr) =
          match x.expr_value with
          | ELiteral (LString "True") | ELiteral (LString "False") -> true
          | EVar v -> v = "True" || v = "False"
          | _ -> false
        in
        let hits =
          if is_bool_literal e1 || is_bool_literal e2 then
            let lit = if is_bool_literal e1 then expr_name e1 else expr_name e2 in
            [(lit, e.expr_location.start.line)]
          else [] in
        hits @ find_bool_comparisons e1 @ find_bool_comparisons e2
    | EBlock es -> List.concat_map find_bool_comparisons es
    | ELet (_, e1, e2) -> find_bool_comparisons e1 @ find_bool_comparisons e2
    | EIf (_, then_, else_) ->
        find_bool_comparisons then_ @
        (match else_ with Some e -> find_bool_comparisons e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_bool_comparisons e) branches
    | EApp (fn, args) ->
        find_bool_comparisons fn @ List.concat_map find_bool_comparisons args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_bool_comparisons body with
         | (lit, line) :: _ ->
             Some (Printf.sprintf
               "Comparison with %s is redundant — use the boolean directly or 'not'" lit, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Redundant Single Case
    Detects case expressions with only one branch.
    A case with one branch is equivalent to a let binding — less noise.
    AI often generates unnecessary case wrapping. *)
let detect_redundant_single_case (m : t) =
  let rec find_single_cases (e : expr) : int list =
    match e.expr_value with
    | ECase (_, [(_branch)]) ->
        e.expr_location.start.line :: []
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_single_cases e) branches
    | EBlock es -> List.concat_map find_single_cases es
    | ELet (_, e1, e2) -> find_single_cases e1 @ find_single_cases e2
    | EIf (_, then_, else_) ->
        find_single_cases then_ @
        (match else_ with Some e -> find_single_cases e | None -> [])
    | EApp (fn, args) -> find_single_cases fn @ List.concat_map find_single_cases args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_single_cases body with
         | line :: _ -> Some ("Case with only one branch — use a let binding instead", line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Unused Let Binding
    Detects let bindings where the variable is never used in subsequent code.
    AI often generates intermediate bindings that are never referenced.
    Heuristic: checks that the bound name appears as an EVar in the body. *)
let detect_unused_let (m : t) =
  let rec collect_vars (e : expr) : string list =
    match e.expr_value with
    | EVar v -> [v]
    | EBlock es -> List.concat_map collect_vars es
    | ELet (_, e1, e2) -> collect_vars e1 @ collect_vars e2
    | ELetAssert (_, e1, e2) -> collect_vars e1 @ collect_vars e2
    | EUse (_, e1, e2) -> collect_vars e1 @ collect_vars e2
    | EIf (_, then_, else_) ->
        collect_vars then_ @ (match else_ with Some e -> collect_vars e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> collect_vars e) branches
    | EApp (fn, args) -> collect_vars fn @ List.concat_map collect_vars args
    | _ -> []
  in
  let rec find_unused (e : expr) : (string * int) list =
    match e.expr_value with
    | ELet (PVar name, _, body) ->
        let used_in_body = collect_vars body in
        let is_used = List.mem name used_in_body in
        let self = if not is_used && String.length name > 1 && name <> "_" then
          [(name, e.expr_location.start.line)] else [] in
        self @ find_unused body
    | EUse (PVar name, _, body) ->
        (* Check if the use binding is used in the continuation body *)
        let used_in_body = collect_vars body in
        let is_used = List.mem name used_in_body in
        let self = if not is_used && String.length name > 1 && name <> "_" then
          [(name, e.expr_location.start.line)] else [] in
        self @ find_unused body
    | EBlock es -> List.concat_map find_unused es
    | ELet (_, e1, e2) -> find_unused e1 @ find_unused e2
    | ELetAssert (_, e1, e2) -> find_unused e1 @ find_unused e2
    | EUse (_, e1, e2) -> find_unused e1 @ find_unused e2
    | EIf (_, then_, else_) ->
        find_unused then_ @ (match else_ with Some e -> find_unused e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_unused e) branches
    | EApp (fn, args) -> find_unused fn @ List.concat_map find_unused args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_unused body with
         | (name, line) :: _ ->
             Some (Printf.sprintf "Let binding '%s' is never used after assignment" name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Nested Function
    Detects anonymous functions (EFn) defined inside named functions that
    are large enough to be their own named function.
    AI often inlines helper functions as anonymous fns instead of
    extracting them as testable, reusable named functions.
    Heuristic: EFn with body containing 3+ expressions. *)
let detect_nested_function (m : t) =
  let rec count_stmts (e : expr) : int =
    match e.expr_value with
    | EBlock es -> List.length es
    | ELet (_, _, e2) -> 1 + count_stmts e2
    | _ -> 1
  in
  let rec find_nested_fns (e : expr) : (int * int) list =
    match e.expr_value with
    | EFn (_, body) when count_stmts body >= 3 ->
        (count_stmts body, e.expr_location.start.line)
        :: find_nested_fns body
    | EFn (_, body) -> find_nested_fns body
    | EBlock es -> List.concat_map find_nested_fns es
    | ELet (_, e1, e2) -> find_nested_fns e1 @ find_nested_fns e2
    | EIf (_, then_, else_) ->
        find_nested_fns then_ @
        (match else_ with Some e -> find_nested_fns e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_nested_fns e) branches
    | EApp (fn, args) -> find_nested_fns fn @ List.concat_map find_nested_fns args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_nested_fns body with
         | (size, line) :: _ ->
             Some (Printf.sprintf
               "Anonymous function with %d statements — extract as a named function for testability"
               size, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Bool Return Check
    Detects if expressions that explicitly return True in one branch and
    False in another — the condition itself should be returned.
    AI often writes verbose boolean returns instead of returning the condition.
    Example: if x > 0 { True } else { False } should just be x > 0 *)
let detect_bool_return_check (m : t) =
  let is_bool_literal (e : expr) =
    match e.expr_value with
    | ELiteral (LBool _) -> true
    | EVar v -> v = "True" || v = "False"
    | _ -> false
  and bool_val (e : expr) =
    match e.expr_value with
    | ELiteral (LBool b) -> Some b
    | EVar v when v = "True" -> Some true
    | EVar v when v = "False" -> Some false
    | _ -> None
  in
  let rec find_bool_returns (e : expr) : int list =
    match e.expr_value with
    | EIf (_, then_, Some else_) when is_bool_literal then_ && is_bool_literal else_ ->
        (match bool_val then_, bool_val else_ with
         | Some true, Some false | Some false, Some true ->
             [e.expr_location.start.line]
         | _ -> [])
    | EBlock es -> List.concat_map find_bool_returns es
    | ELet (_, e1, e2) -> find_bool_returns e1 @ find_bool_returns e2
    | EIf (_, then_, else_) ->
        find_bool_returns then_ @
        (match else_ with Some e -> find_bool_returns e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_bool_returns e) branches
    | EApp (fn, args) -> find_bool_returns fn @ List.concat_map find_bool_returns args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_bool_returns body with
         | line :: _ ->
             Some ("if True else False is redundant — return the condition directly", line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Useless Let Binding
    Detects let x = x where a variable is rebound to itself.
    This is a no-op — AI sometimes generates these by mistake. *)
let detect_useless_let_binding (m : t) =
  let rec find_useless (e : expr) : (string * int) list =
    match e.expr_value with
    | ELet (PVar name, e1, e2) ->
        (match e1.expr_value with
         | EVar v when v = name ->
             (name, e.expr_location.start.line) :: find_useless e2
         | _ -> find_useless e1 @ find_useless e2)
    | EBlock es -> List.concat_map find_useless es
    | ELet (_, e1, e2) -> find_useless e1 @ find_useless e2
    | EIf (_, then_, else_) ->
        find_useless then_ @
        (match else_ with Some e -> find_useless e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> find_useless e) branches
    | EApp (fn, args) -> find_useless fn @ List.concat_map find_useless args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_useless body with
         | (name, line) :: _ ->
             Some (Printf.sprintf "let %s = %s is a no-op — remove the rebinding" name name, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Int/Float Division Confusion
    Detects integer division when the context suggests float division was intended,
    or mixing int and float literals in arithmetic.
    AI coming from dynamically-typed languages often mixes int/float incorrectly.
    Heuristic: division of int literals that should produce a float result. *)
let detect_int_float_division (m : t) =
  let is_int_literal (e : expr) =
    match e.expr_value with
    | ELiteral (LInt _) -> true | _ -> false
  in
  let rec find_suspicious_div (e : expr) : int list =
    match e.expr_value with
    | EBinOp (e1, "/", e2) when is_int_literal e1 && is_int_literal e2 ->
        e.expr_location.start.line :: []
    | EBlock es -> List.concat_map find_suspicious_div es
    | ELet (_, e1, e2) -> find_suspicious_div e1 @ find_suspicious_div e2
    | EIf (_, then_, else_) ->
        find_suspicious_div then_ @
        (match else_ with Some e -> find_suspicious_div e | None -> [])
    | EApp (fn, args) -> find_suspicious_div fn @ List.concat_map find_suspicious_div args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_suspicious_div body with
         | line :: _ ->
             Some ("Integer division of two int literals — use float literals (e.g. 1.0 / 2.0) if float result expected", line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Repeated String Literal
    Detects the same string literal appearing in 2+ functions.
    Should be extracted to a module-level constant.
    AI often duplicates string constants across functions. *)
let detect_repeated_string_literal (m : t) =
  let min_length = 4 in
  let module StringMap = Map.Make(String) in
  let rec collect_strings (e : expr) : string list =
    match e.expr_value with
    | ELiteral (LString s) when String.length s >= min_length -> [s]
    | EBlock es -> List.concat_map collect_strings es
    | ELet (_, e1, e2) -> collect_strings e1 @ collect_strings e2
    | EIf (_, then_, else_) ->
        collect_strings then_ @ (match else_ with Some e -> collect_strings e | None -> [])
    | ECase (_, branches) ->
        List.concat_map (fun (_, e) -> collect_strings e) branches
    | EApp (fn, args) -> collect_strings fn @ List.concat_map collect_strings args
    | _ -> []
  in
  let lit_locations =
    List.fold_left (fun locs item ->
      match item.item_value with
      | IFunction (name, _, _, body) ->
        let strings = collect_strings body in
        let new_locs = List.fold_left (fun acc s ->
          let existing = try StringMap.find s acc with Not_found -> [] in
          StringMap.add s ((name, item.item_location.start.line) :: existing) acc
        ) locs strings in
        new_locs
      | _ -> locs
    ) StringMap.empty m.mod_items in
  let all_strings =
    List.concat_map (fun (s, locations) ->
      if List.length locations >= 2 then
        let sorted_locs = Stdlib.List.sort (fun (a, _) (b, _) -> String.compare a b) locations in
        let funcs = String.concat ", " (Stdlib.List.map fst sorted_locs) in
        let _, line = List.hd locations in
        [Printf.sprintf
          "String \"%s\" appears in %d functions (%s) — extract to a module constant"
          s (List.length locations) funcs, line]
      else []
    ) (StringMap.bindings lit_locations) in
  List.sort_uniq (fun (_, l1) (_, l2) -> Int.compare l1 l2) all_strings

(** Rule: Use Expression Candidate
    Detects patterns where the `use` keyword could improve readability.
    This is a TIPS-style rule — suggests refactoring opportunities, not errors.
    
    Patterns detected:
    1. Nested anonymous functions (3+ levels) that could use `use` for continuation-passing
    2. Callback chains where each callback returns a Result and passes to the next
       
    Example transformation:
    
      Before (callback pyramid):
        fetch_user(id, fn(user):
          fetch_orders(user.id, fn(orders):
            render(orders)
          end)
        end)
      
      After (use expression):
        use user <- fetch_user(id)
        use orders <- fetch_orders(user.id)
        render(orders) *)

(** Rule: List Flatten Singleton
    Detects List.flatten being called on a list that could be a list of lists.
    If you're wrapping a single item in a list, just return the item.
    AI often adds unnecessary List.flatten. *)
let detect_list_flatten_singleton (m : t) =
  let rec find_flatten (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, [arg]) when expr_name fn = "List.flatten" ->
        (match arg.expr_value with
         | EList [_single] ->
             (* Single element list being flattened — likely unnecessary *)
             [(Printf.sprintf "List.flatten on a single-element list is unnecessary",
               e.expr_location.start.line)]
         | _ -> [])
    | EBlock es -> List.concat_map find_flatten es
    | ELet (_, e1, e2) -> find_flatten e1 @ find_flatten e2
    | EIf (_, then_, else_) ->
        find_flatten then_ @ (match else_ with Some e -> find_flatten e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> find_flatten e) branches
    | EApp (fn, args) -> find_flatten fn @ List.concat_map find_flatten args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_flatten body with
         | (msg, line) :: _ -> Some (msg, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Rule: Todo with Message
    Detects todo calls without descriptive messages.
    AI often uses bare `todo` which provides no context.
    Using `todo as "description"` is much more helpful. *)
let detect_todo_with_message (m : t) =
  let rec find_bare_todo (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, []) when expr_name fn = "todo" ->
        [("Bare 'todo' without message — use 'todo as \"description\"' for better error messages",
          e.expr_location.start.line)]
    | EBlock es -> List.concat_map find_bare_todo es
    | ELet (_, e1, e2) -> find_bare_todo e1 @ find_bare_todo e2
    | EIf (_, then_, else_) ->
        find_bare_todo then_ @ (match else_ with Some e -> find_bare_todo e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> find_bare_todo e) branches
    | EApp (fn, args) -> find_bare_todo fn @ List.concat_map find_bare_todo args
    | _ -> []
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (match find_bare_todo body with
         | (msg, line) :: _ -> Some (msg, line)
         | [] -> None)
    | _ -> None
  ) m.mod_items

(** Note: detect_redundant_type_annotation intentionally omitted
    Type annotations in Gleam are generally good practice and Gleam requires
    them on public functions. Private functions can omit them, but it's
    not necessarily an antipattern to include them for documentation. *)

let detect_use_candidates (m : t) =
  (* Count chain depth of function calls with anonymous function arguments *)
  let rec callback_chain_depth (e : expr) : int =
    match e.expr_value with
    | EApp (_, args) ->
        let last_arg = try List.hd (List.rev args) with Failure _ -> { expr_value = EUnit; expr_location = { start = { line = 0; column = 0; byte_offset = 0 }; end_ = { line = 0; column = 0; byte_offset = 0 } } } in
        (match last_arg.expr_value with
         | EFn (_, body) ->
             (* This arg is a callback — depth is 1 + depth of body *)
             1 + callback_chain_depth body
         | _ ->
             (* Check if any arg contains callbacks *)
             List.fold_left (fun acc a -> max acc (callback_chain_depth a)) 0 args)
    | EBlock es ->
        (match List.rev es with
         | [] -> 0
         | last :: _ -> callback_chain_depth last)
    | ELet (_, e1, e2) -> max (callback_chain_depth e1) (callback_chain_depth e2)
    | ELetAssert (_, e1, e2) -> max (callback_chain_depth e1) (callback_chain_depth e2)
    | EUse (_, e1, e2) -> max (callback_chain_depth e1) (callback_chain_depth e2)
    | EIf (_, then_, else_) ->
        max (callback_chain_depth then_) (match else_ with Some e -> callback_chain_depth e | None -> 0)
    | ECase (_, branches) ->
        List.fold_left (fun acc (_, e) -> max acc (callback_chain_depth e)) 0 branches
    | _ -> 0
  in
  
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let depth = callback_chain_depth body in
        if depth >= 3 then
          Some (Printf.sprintf
            "Callback chain with %d nested functions — consider `use` for cleaner continuation-passing style"
            depth, item.item_location.start.line)
        else None
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
  ("pipeline-steps-overload", T.Hint, detect_pipeline_steps_overload);
  ("assert-density", T.Warning, detect_assert_density);
  ("shadow-variable", T.Hint, detect_shadow_variable);
  ("let-assert-on-result", T.Warning, detect_let_assert_on_result);
  ("todo-as-body", T.Warning, detect_todo_as_body);
  ("string-concat-chain", T.Hint, detect_string_concat_chain);
  ("equals-true", T.Hint, detect_equals_true);
  ("redundant-single-case", T.Hint, detect_redundant_single_case);
  ("unused-let", T.Hint, detect_unused_let);
  ("nested-function", T.Hint, detect_nested_function);
  ("bool-return-check", T.Hint, detect_bool_return_check);
  ("useless-let-binding", T.Hint, detect_useless_let_binding);
  ("int-float-division", T.Hint, detect_int_float_division);
  ("repeated-string-literal", T.Hint, detect_repeated_string_literal);
  ("use-candidate", T.Hint, detect_use_candidates);
  ("debug-in-library", T.Warning, detect_debug_in_library);
  ("result-in-map", T.Warning, detect_result_in_map);
  ("list-flatten-singleton", T.Hint, detect_list_flatten_singleton);
  ("todo-with-message", T.Hint, detect_todo_with_message);

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
