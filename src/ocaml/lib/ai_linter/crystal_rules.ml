(* src/ocaml/lib/ai_linter/crystal_rules.ml
   Crystal-specific AST rules
   
   Per the "Ban the Regex" principle, these rules operate on
   CatseyeAST.t using pattern matching instead of regex.
   
   See planning/40-ai-patterns-hunting-plan.md for the complete
   list of AI anti-patterns to detect.
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

let sev_to_string = function
  | Hint -> "hint"
  | Warning -> "warning"
  | Error -> "error"

(** Collect all calls from expressions *)
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

(* ── Category 1: Ghost Scent ────────────────────────────────────────── *)

(** Rule 1.1: Non-existent Standard Library Methods *)
let detect_hallucinated_stdlib (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    (* Crystal has no .to_map - it's .to_h for Hash *)
    | Some "to_map" -> Some ("to_map does not exist in Crystal - use .to_h for Hash or .map on Array", 0)
    (* String.join doesn't exist - Array.join does *)
    | Some "String.join" -> Some ("String.join doesn't exist - use Array.join(array, separator)", 0)
    (* object_id is deprecated *)
    | Some name when String.length name >= 10 && String.sub name 0 10 = "object_id" ->
        Some ("object_id is deprecated in Crystal", 0)
    | _ -> None
  ) calls

(** Rule 1.2: Legacy/Deprecated Syntax *)
let detect_deprecated_syntax (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        (* Check for puts/p used in production code *)
        let rec check_expr e =
          match e.expr_value with
          | EApp (fn, _) ->
              (match fn.expr_value with
               | EVar "puts" -> findings := ("puts used for debugging", e.expr_location.start.line) :: !findings
               | EVar "p" | EVar "pp" -> findings := ("debug output statement", e.expr_location.start.line) :: !findings
               | _ -> ())
          | EIf (_, then_, else_) -> check_expr then_; Option.iter check_expr else_
          | ECase (_, branches) -> List.iter (fun (_, e) -> check_expr e) branches
          | ELet (_, _, body) | ELetAssert (_, _, body) -> check_expr body
          | EBlock es -> List.iter check_expr es
          | _ -> ()
        in
        check_expr body
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 2: The Foreigner ──────────────────────────────────────── *)

(** Rule 2.1: Manual Loops vs Iterators *)
let detect_manual_loop (_m : t) =
  (* TODO: Detect while loops that could be iterators *)
  []

(** Rule 2.3: Primitive Obsession (3+ String params) *)
let detect_primitive_obsession (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
        let params = List.filter (function PVar _ -> true | _ -> false) patterns in
        if List.length params >= 3
        then findings := (Printf.sprintf "Function '%s' has %d parameters - consider domain types" name (List.length params), item.item_location.start.line) :: !findings
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 3: The Happy Path ──────────────────────────────────────── *)

(** Rule 3.1: Nil-chaser (unchecked nil access) *)
let detect_nil_chaser (_m : t) =
  (* TODO: Requires type info from Crystal worker *)
  []

(** Rule 3.3: Unsafe Pointers *)
let detect_unsafe_pointers (_m : t) =
  (* TODO: Detect Pointer usage not in @[Safe] context *)
  []

(* ── Category 4: The Tangle ─────────────────────────────────────────── *)

(** Rule 4.1: Redundant Conversions *)
let detect_redundant_conversion (m : t) =
  let calls = List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_calls body
    | _ -> []
  ) m.mod_items in
  List.filter_map (fun (name, _) ->
    match name with
    | Some "String.new" -> Some ("String.new is often redundant - string literal or to_s may suffice", 0)
    | _ -> None
  ) calls

(* ── All Rules ──────────────────────────────────────────────────────── *)

let all () = [
  (* Ghost Scent *)
  ("hallucinated-stdlib", Error, detect_hallucinated_stdlib);
  ("deprecated-syntax", Warning, detect_deprecated_syntax);
  
  (* The Foreigner *)
  ("manual-loop", Hint, detect_manual_loop);
  ("primitive-obsession", Hint, detect_primitive_obsession);
  
  (* The Happy Path *)
  ("nil-chaser", Warning, detect_nil_chaser);
  ("unsafe-pointer", Error, detect_unsafe_pointers);
  
  (* The Tangle *)
  ("redundant-conversion", Hint, detect_redundant_conversion);
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