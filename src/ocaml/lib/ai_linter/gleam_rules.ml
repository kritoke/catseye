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
  ("unused-import", T.Hint, detect_unused_import);
  ("discard-result", T.Warning, detect_discard_result);
  ("redundant-pipeline", T.Hint, detect_redundant_pipeline);
  ("implicit-return-discard", T.Hint, detect_implicit_return_discard);

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
