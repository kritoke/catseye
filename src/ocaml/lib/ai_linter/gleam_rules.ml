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

(** Rule: List.wrap on collection is unnecessary *)
let detect_list_wrap (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s > 5 && String.sub s 0 5 = "call:" && s = "call:wrap" ->
        Some ("List.wrap on collection is unnecessary", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Result.is_ok/is_err deprecated *)
let detect_result_check (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s > 5 && String.sub s 0 5 = "call:" &&
              (s = "call:is_ok" || s = "call:is_err") ->
        Some ("Result.is_ok/is_err is deprecated - use pattern matching", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: panic! call detected *)
let detect_panic (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when s = "tag:panic" || s = "call:panic" ->
        Some ("panic call found - use Result or Option", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Hallucinated _or_default functions *)
let detect_hallucinated_or_default (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s > 5 && String.sub s 0 5 = "call:" &&
              String.length s >= 16 && String.sub s (String.length s - 11) 11 = "_or_default" ->
        let call_name = String.sub s 5 (String.length s - 5) in
        Some ("Function " ^ call_name ^ " may not exist in Gleam stdlib", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Hallucinated to_list *)
let detect_hallucinated_to_list (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when String.length s > 5 && String.sub s 0 5 = "call:" &&
              let call_name = String.sub s 5 (String.length s - 5) in
              call_name = "to_list" ->
        Some ("Method " ^ String.sub s 5 (String.length s - 5) ^ " may not exist on this type", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: TypeScript interface keyword *)
let detect_typescript_interface (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when s = "tag:interface" || s = "interface" ->
        Some ("'interface' is TypeScript, not Gleam - use 'type'", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: Rust fn keyword for function defs *)
let detect_rust_fn (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when s = "call:fn" ->
        Some ("'fn' as function call looks like Rust - Gleam uses 'fn' only for lambdas", item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(** Rule: var keyword (Gleam uses let) *)
let detect_var_keyword (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IUnknown s when s = "tag:var" || s = "call:var" ->
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