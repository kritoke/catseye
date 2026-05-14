(* src/ocaml/lib/ai_linter/gleam_rules.ml
   Gleam-specific AST rules
   
   Per the "Ban the Regex" principle, these rules operate on
   CatseyeAST.t using pattern matching instead of regex.
*)

open Catseye_ast.Types

type severity = Hint | Warning | Error

type finding = {
  file : string;
  line : int;
  rule_id : string;
  severity : string;
  message : string;
  suggestion : string option;
}

(** Severity to string *)
let sev_to_string = function
  | Hint -> "hint"
  | Warning -> "warning"
  | Error -> "error"

(** Collect function calls from expressions *)
let rec collect_calls (expr : expr) =
  match expr.expr_value with
  | EApp (fn, args) ->
      let fn_name = match fn.expr_value with EVar n -> Some n | _ -> None in
      (fn_name, args) :: List.concat_map collect_calls args
  | EIf (cond, then_, else_) ->
      collect_calls cond @ collect_calls then_ @
      (match else_ with Some e -> collect_calls e | None -> [])
  | ECase (scrut, branches) ->
      collect_calls scrut @ List.concat (List.map (fun (_, e) -> collect_calls e) branches)
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_calls e1 @ collect_calls e2
  | EBlock es -> List.concat_map collect_calls es
  | _ -> []

(** Get function name from expression *)
let get_fn_name (fn : expr) =
  match fn.expr_value with
  | EVar name -> Some name
  | _ -> None

(** Rule: List.wrap on collection is unnecessary *)
let detect_list_wrap (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, args) ->
    match name, args with
    | Some "List.wrap", [arg] ->
        (match arg.expr_value with
         | EList _ | ETuple _ ->
             Some ("List.wrap on collection is unnecessary", arg.expr_location.start.line)
         | _ -> None)
    | _ -> None
  ) calls

(** Rule: Result.is_ok/is_err deprecated *)
let detect_result_check (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    | Some ("Result.is_ok" | "Result.is_err" as n) ->
        Some (n ^ " is deprecated - use pattern matching", 0)
    | _ -> None
  ) calls

(** Rule: panic! call detected *)
let detect_panic (m : t) =
  let findings = ref [] in
  let rec check_expr e =
    match e.expr_value with
    | EVar "panic" -> findings := ("panic! call found - use Result or Option", e.expr_location.start.line) :: !findings
    | EApp (fn, _) ->
        (match fn.expr_value with
         | EVar "panic" -> findings := ("panic! call found", e.expr_location.start.line) :: !findings
         | _ -> ())
    | EIf (_, then_, else_) -> check_expr then_; Option.iter check_expr else_
    | ECase (_, branches) -> List.iter (fun (_, e) -> check_expr e) branches
    | ELet (_, _, body) | ELetAssert (_, _, body) -> check_expr body
    | EBlock es -> List.iter check_expr es
    | _ -> ()
  in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> check_expr body
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule: Hallucinated _or_default functions *)
let detect_hallucinated_or_default (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    | Some name when String.length name >= 11 && String.sub name (String.length name - 11) 11 = "_or_default" ->
        Some ("Function " ^ name ^ " may not exist in Gleam stdlib", 0)
    | _ -> None
  ) calls

(** Rule: Hallucinated to_list *)
let detect_hallucinated_to_list (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    | Some name when String.length name >= 8 && String.sub name (String.length name - 8) 8 = "_to_list" ->
        Some (name ^ " may not exist on this type", 0)
    | _ -> None
  ) calls

(** Rule: TypeScript interface keyword *)
let detect_typescript_interface (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s >= 9 && String.sub s 0 9 = "interface" ->
        Some ("'interface' is TypeScript, not Gleam - use 'type'", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Rust fn keyword for function defs *)
let detect_rust_fn (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, args) ->
    match name, args with
    | Some "fn", _ when List.length args > 0 ->
        Some ("'fn' as function call looks like Rust - Gleam uses 'fn' only for lambdas", 0)
    | _ -> None
  ) calls

(** Rule: var keyword (Gleam uses let) *)
let detect_var_keyword (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s >= 3 && String.sub s 0 3 = "var" ->
        Some ("'var' is not valid in Gleam - use 'let'", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** All rules *)
let all () = [
  ("list-wrap-unnecessary", Warning, detect_list_wrap);
  ("deprecated-result-check", Hint, detect_result_check);
  ("panic-call", Error, detect_panic);
  ("hallucinated-or-default", Error, detect_hallucinated_or_default);
  ("hallucinated-to-list", Error, detect_hallucinated_to_list);
  ("typescript-interface", Error, detect_typescript_interface);
  ("rust-fn", Error, detect_rust_fn);
  ("var-keyword", Error, detect_var_keyword);
]

(** Analyze module and return findings *)
let analyze_module (m : t) : finding list =
  List.concat_map (fun (rule_id, sev, detector) ->
    List.map (fun (msg, line) ->
      { file = m.mod_path;
        line;
        rule_id;
        severity = sev_to_string sev;
        message = msg;
        suggestion = None; }
    ) (detector m)
  ) (all ())