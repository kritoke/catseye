(* src/ocaml/lib/ai_linter/crystal_rules.ml
   Crystal-specific AST rules

   All rules operate on CatseyeAST.t using typed pattern matching.
   Function bodies now contain proper EApp/EFieldAccess expression trees
   instead of flat IUnknown items.
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

(** Get the final method name from a dotted expression.
    EFieldAccess(EVar "String", "new") -> Some "new"
    EVar "puts" -> None *)
let get_method_name (e : expr) : string option =
  match e.expr_value with
  | EFieldAccess (_, meth) -> Some meth
  | EVar _ -> None
  | _ -> None

(** Get the receiver name chain from a dotted expression.
    EFieldAccess(EFieldAccess(EVar "URI", "parse"), "host") -> ["URI"; "parse"; "host"] *)
let rec get_name_chain (e : expr) : string list =
  match e.expr_value with
  | EFieldAccess (recv, field) -> get_name_chain recv @ [field]
  | EVar name -> [name]
  | _ -> []

(** Get the full dotted name string from an expression *)
let get_full_name (e : expr) : string =
  String.concat "." (get_name_chain e)

(** Collect all function calls (EApp) from an expression tree *)
let rec collect_app_names (e : expr) : (string * int) list =
  match e.expr_value with
  | EApp (fn, args) ->
      let name = get_full_name fn in
      (name, e.expr_location.start.line) :: List.concat_map collect_app_names args
  | EBlock es -> List.concat_map collect_app_names es
  | ELet (_, e1, e2) -> collect_app_names e1 @ collect_app_names e2
  | EIf (cond, then_, else_) ->
      collect_app_names cond @ collect_app_names then_ @
      (match else_ with Some e -> collect_app_names e | None -> [])
  | ECase (scrut, branches) ->
      collect_app_names scrut @ List.concat (List.map (fun (_, e) -> collect_app_names e) branches)
  | EFieldAccess (recv, _) -> collect_app_names recv
  | _ -> []

(* ── Category 1: Ghost Scent ────────────────────────────────────────── *)

(** Rule 1.1: Non-existent Standard Library Methods *)
let detect_hallucinated_stdlib (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          (* Check for .to_map suffix *)
          if String.length name >= 6 &&
             String.sub name (String.length name - 6) 6 = "to_map" then
            findings := ("to_map does not exist - use .to_h or .map", line) :: !findings;
          (* Check for String.join *)
          if name = "String.join" then
            findings := ("String.join doesn't exist - use Array.join", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule 1.2: Legacy/Deprecated Syntax *)
let detect_deprecated_syntax (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "puts" then
            findings := ("puts used for debugging", line) :: !findings;
          if name = "p" then
            findings := ("p used for debugging", line) :: !findings;
          if name = "pp" then
            findings := ("pp used for debugging", line) :: !findings;
          if name = "String.new" then
            findings := ("String.new often redundant", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 2: The Foreigner ──────────────────────────────────────── *)

(** Rule 2.1: Manual Loops vs Iterators *)
let detect_manual_loop (_m : t) =
  (* TODO: Detect while loops that could be iterators *)
  []

(** Rule 2.3: Primitive Obsession (3+ params) *)
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
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "String.new" then
            findings := ("String.new redundant - use literal", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

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
