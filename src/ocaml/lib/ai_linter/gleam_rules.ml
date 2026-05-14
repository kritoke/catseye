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
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    | Some "panic" -> Some ("panic! call found - use Result or Option", 0)
    | _ -> None
  ) calls

(** All rules *)
let all () = [
  ("list-wrap-unnecessary", Warning, detect_list_wrap);
  ("deprecated-result-check", Hint, detect_result_check);
  ("panic-call", Error, detect_panic);
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