(* src/ocaml/lib/ai_linter/svelte_rules.ml
   Svelte-specific AST rules for antipattern and AI hallucination detection.

   Key areas:
   1. Svelte 4→5 migration: outdated $:, on:click, slot, etc.
   2. XSS via {@html}, bind:this misuse
   3. Reactive antipatterns: reassigning $derived, missing $state
   4. Svelte-specific AI hallucinations
 *)

open Base
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl
module Printf = Stdlib.Printf

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

open Catseye_ast.Types

module T = Types

(* ── Expression helpers (shared pattern) ────────────────────────────── *)

let rec expr_name (e : expr) : string =
match e.expr_value with
| EVar name -> name
| EFieldAccess (recv, field) ->
let prefix = expr_name recv in
if prefix = "" then field else prefix ^ "." ^ field
| _ -> ""

let rec collect_app_names (e : expr) : (string * int) list =
match e.expr_value with
| EApp (fn, args) ->
let name = expr_name fn in
(name, e.expr_location.start.line) :: List.concat_map collect_app_names (fn :: args)
| EBlock es -> List.concat_map collect_app_names es
| ELet (_, e1, e2) -> collect_app_names e1 @ collect_app_names e2
| EIf (cond, then_, else_) ->
collect_app_names cond @ collect_app_names then_ @
(match else_ with Some e2 -> collect_app_names e2 | None -> [])
| ECase (scrut, branches) ->
collect_app_names scrut @ List.concat (List.map (fun (_, e) -> collect_app_names e) branches)
| EFn (_, body) -> collect_app_names body
| _ -> []

let rec collect_var_names (e : expr) : (string * int) list =
match e.expr_value with
| EVar name -> [(name, e.expr_location.start.line)]
| EApp (fn, args) -> collect_var_names fn @ List.concat_map collect_var_names args
| EBlock es -> List.concat_map collect_var_names es
| ELet (_, e1, e2) -> collect_var_names e1 @ collect_var_names e2
| EFn (_, body) -> collect_var_names body
| _ -> []

let rec walk_items_for_apps (items : item list) : (string * int) list =
List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) -> collect_app_names body
| IConstant (_, _, body) -> collect_app_names body
| IModule (_, subs) -> walk_items_for_apps subs
| _ -> []
) items

let rec walk_items_for_vars (items : item list) : (string * int) list =
List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) -> collect_var_names body
| IConstant (_, _, body) -> collect_var_names body
| IModule (_, subs) -> walk_items_for_vars subs
| _ -> []
) items

(* ── 1. Svelte 4→5 Migration: Outdated Syntax ──────────────────────── *)

(** Variables named with $: prefix pattern — reactive declarations from Svelte 4.
These get parsed as variable names containing $. *)

let check_svelte4_patterns (all_vars : (string * int) list) (all_apps : (string * int) list) (path : string) : T.finding list =
(* $: reactive declarations become variables/expressions in AST *)
let dollar_vars = List.filter_map (fun (name, line) ->
(* Svelte 4 reactive prefix $: becomes tricky in tree-sitter,
but we can catch common Svelte 4 store patterns *)
match name with
| "$set" | "$update" | "$subscribe" ->
(* Svelte store methods that don't exist as standalone in Svelte 5 *)
Some { T.file = path; line; rule_id = "svelte4-store-pattern";
severity = T.Warning;
message = Printf.sprintf "'%s' is Svelte 4 store syntax — Svelte 5 uses runes ($state, $derived)" name;
suggestion = Some "Use $state() for reactive state, $derived() for computed values" }
| "$page" ->
None (* $page is valid in SvelteKit *)
| s when String.length s > 1 && s.[0] = '$' && s.[1] <> 's' && s.[1] <> 'd' && s.[1] <> 'e' && s.[1] <> 'p' ->
(* Dollar-prefixed variables that aren't $state/$derived/$effect/$props *)
None (* Could be valid Svelte store binding *)
| _ -> None
) all_vars in

let outdated_apps = List.filter_map (fun (name, line) ->
match name with
| "onMount" ->
None (* onMount is still valid in Svelte 5 *)
(* Svelte 4 event dispatch patterns *)
| "createEventDispatcher" ->
Some { T.file = path; line; rule_id = "svelte4-event-dispatcher";
severity = T.Warning;
message = "createEventDispatcher is Svelte 4 syntax — Svelte 5 uses callback props";
suggestion = Some "Replace with callback props: let { onclick } = $props()" }
| "beforeUpdate" | "afterUpdate" ->
Some { T.file = path; line; rule_id = "svelte4-lifecycle";
severity = T.Warning;
message = Printf.sprintf "%s is Svelte 4 syntax — Svelte 5 uses $effect()" name;
suggestion = Some "Use $effect(() => { ... }) with appropriate tracking" }
| "onDestroy" ->
Some { T.file = path; line; rule_id = "svelte4-lifecycle";
severity = T.Hint;
message = "onDestroy can be replaced with $effect cleanup in Svelte 5";
suggestion = Some "Use $effect(() => { return () => cleanup() })" }
| _ -> None
) all_apps in

dollar_vars @ outdated_apps

(* ── 2. XSS: {@html} and innerHTML ─────────────────────────────────── *)

let check_xss (all_apps : (string * int) list) (_all_vars : (string * int) list) (path : string) : T.finding list =
let html_sinks = List.filter_map (fun (name, line) ->
match name with
| "__svelte_html" ->
(* Our Svelte mapper maps {@html} to this sink *)
Some { T.file = path; line; rule_id = "svelte-xss";
severity = T.Error;
message = "{@html} with dynamic content is an XSS risk — ensure input is sanitized";
suggestion = Some "Sanitize HTML with DOMPurify before passing to {@html}" }
| "innerHTML" | "outerHTML" ->
Some { T.file = path; line; rule_id = "dom-xss";
severity = T.Error;
message = Printf.sprintf "%s with dynamic content is an XSS risk" name;
suggestion = Some "Use textContent or sanitize with DOMPurify" }
| "document.write" ->
Some { T.file = path; line; rule_id = "dom-xss";
severity = T.Error;
message = "document.write() can lead to XSS and causes performance issues";
suggestion = Some "Use DOM manipulation methods instead" }
| "v-html" ->
Some { T.file = path; line; rule_id = "framework-xss";
severity = T.Warning;
message = "v-html is a Vue.js directive — not valid in Svelte. Use {@html} if needed";
suggestion = Some "Use Svelte's {@html} directive, with DOMPurify sanitization" }
| _ -> None
) all_apps in

html_sinks

(* ── 3. Reactive Antipatterns ──────────────────────────────────────── *)

let check_reactive_antipatterns (all_apps : (string * int) list) (path : string) : T.finding list =
List.filter_map (fun (name, line) ->
match name with
| "$state" ->
None (* Correct usage *)
| "$derived" ->
None (* Correct usage *)
| "$effect" ->
None (* Correct usage *)
| "$props" ->
None (* Correct usage *)
| "writable" | "readable" | "derived" ->
(* Svelte 4 stores — check if it's svelte/store import *)
Some { T.file = path; line; rule_id = "svelte4-store";
severity = T.Hint;
message = Printf.sprintf "%s() is Svelte 4 store syntax — consider runes in Svelte 5" name;
suggestion = Some "Use $state() for writable, $derived() for derived stores" }
| "tick" ->
Some { T.file = path; line; rule_id = "tick-usage";
severity = T.Hint;
message = "tick() forces synchronous DOM updates — often a code smell";
suggestion = Some "Restructure to avoid needing manual DOM sync" }
| _ -> None
) all_apps

(* ── 4. Svelte-specific AI Hallucinations ──────────────────────────── *)

type svelte_hallucination = {
name : string;
correct : string;
}

let svelte_hallucinations : (string * svelte_hallucination) list = [
(* React patterns used in Svelte *)
("useState", { name = "useState"; correct = "Svelte uses $state() rune, not React hooks" });
("useEffect", { name = "useEffect"; correct = "Svelte uses $effect() rune, not React hooks" });
("useRef", { name = "useRef"; correct = "Svelte uses bind:this={ref} for DOM refs" });
("useCallback", { name = "useCallback"; correct = "Svelte doesn't need useCallback — reactivity is compiler-based" });
("useMemo", { name = "useMemo"; correct = "Svelte uses $derived() rune for computed values" });
("useContext", { name = "useContext"; correct = "Svelte uses setContext()/getContext() for context" });
("jsx", { name = "jsx"; correct = "Svelte uses .svelte templates, not JSX" });
("createElement", { name = "createElement"; correct = "Svelte doesn't use React.createElement" });
("className", { name = "className"; correct = "Svelte uses class= attribute, not className" });
("onClick", { name = "onClick"; correct = "Svelte uses onclick={handler} (lowercase), not onClick" });
("onChange", { name = "onChange"; correct = "Svelte uses on:change or onchange, not onChange" });
(* Vue patterns *)
("v-if", { name = "v-if"; correct = "Svelte uses {#if condition}, not v-if" });
("v-for", { name = "v-for"; correct = "Svelte uses {#each items as item}, not v-for" });
("v-model", { name = "v-model"; correct = "Svelte uses bind:value, not v-model" });
("computed", { name = "computed"; correct = "Svelte uses $derived() rune, not Vue computed" });
("watch", { name = "watch"; correct = "Svelte uses $effect() rune, not Vue watch" });
(* Angular patterns *)
("ngModel", { name = "ngModel"; correct = "Svelte uses bind:value, not ngModel" });
("ngIf", { name = "ngIf"; correct = "Svelte uses {#if condition}, not *ngIf" });
("ngFor", { name = "ngFor"; correct = "Svelte uses {#each items as item}, not *ngFor" });
(* Other Svelte hallucinations *)
("on_click", { name = "on_click"; correct = "Svelte uses onclick={handler} (no underscore)" });
("setInterval", { name = "setInterval"; correct = "setInterval needs cleanup in Svelte — use $effect with cleanup" });
]

let svelte_hallucination_map : (string, svelte_hallucination) Hashtbl.t =
let tbl = Hashtbl.create 32 in
List.iter (fun (_, e) -> Hashtbl.add tbl e.name e) svelte_hallucinations;
tbl

let check_svelte_hallucinations (all_apps : (string * int) list) (path : string) : T.finding list =
List.filter_map (fun (name, line) ->
let last = try let i = String.rindex name '.' in String.sub name (i+1) (String.length name - i - 1) with Stdlib.Not_found -> name in
match (Hashtbl.find_opt svelte_hallucination_map name, Hashtbl.find_opt svelte_hallucination_map last) with
| Some entry, _ | _, Some entry ->
Some { T.file = path; line; rule_id = "hallucinated-method";
severity = T.Warning;
message = Printf.sprintf "'%s' is not a Svelte API — %s" name entry.correct;
suggestion = Some entry.correct }
| None, None -> None
) all_apps

(* ── 5. Svelte 5 Rune Validation ─────────────────────────────────────── *)

(** Check for setInterval/setTimeout in an expression *)
let rec check_expr e =
match e.expr_value with
| EApp (fn, _) ->
let name = expr_name fn in
name = "setInterval" || name = "setTimeout"
| EBlock es -> List.exists check_expr es
| EFn (_, body) -> check_expr body
| EIf (_, then_, else_) ->
check_expr then_ || (match else_ with Some e -> check_expr e | None -> false)
| ELet (_, e1, e2) -> check_expr e1 || check_expr e2
| ELetAssert (_, e1, e2) -> check_expr e1 || check_expr e2
| ECase (_, branches) -> List.exists (fun (_, e) -> check_expr e) branches
| _ -> false

(** Check for $effect without cleanup for cleanup-requiring patterns (setInterval/setTimeout) *)
let check_effect_cleanup (items : item list) (path : string) : T.finding list =

let rec check_expr e =
match e.expr_value with
| EApp (fn, _) ->
let name = expr_name fn in
name = "setInterval" || name = "setTimeout"
| EBlock es -> List.exists check_expr es
| EFn (_, body) -> check_expr body
| EIf (_, then_, else_) ->
check_expr then_ || (match else_ with Some e -> check_expr e | None -> false)
| ELet (_, e1, e2) -> check_expr e1 || check_expr e2
| ELetAssert (_, e1, e2) -> check_expr e1 || check_expr e2
| ECase (_, branches) -> List.exists (fun (_, e) -> check_expr e) branches
| _ -> false
in
let rec walk e : int list =
match e.expr_value with
| EApp (fn, args) when expr_name fn = "$effect" && List.length args > 0 ->
(match (List.hd args).expr_value with
| EFn (_, block_body) ->
(match block_body.expr_value with
| EBlock es when List.exists check_expr es ->
[e.expr_location.start.line]
| _ -> [])
| _ -> [])
| EApp (fn, args) -> walk fn @ List.concat_map walk args
| ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> walk e1 @ walk e2
| EIf (_, then_, else_) -> walk then_ @ (match else_ with Some e -> walk e | None -> [])
| ECase (_, branches) -> List.concat_map (fun (_, e) -> walk e) branches
| EBlock es -> List.concat_map walk es
| EFn (_, body) -> walk body
| _ -> []
in
let all_lines = List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) -> walk body
| IConstant (PVar _, _, body) -> walk body
| _ -> []
) items in
List.map (fun line ->
{ T.file = path; line; rule_id = "svelte5-effect-missing-cleanup";
severity = T.Warning;
message = "$effect with setInterval/setTimeout without cleanup return";
suggestion = Some "Return cleanup function: $effect(() => { const id = setInterval(...); return () => clearInterval(id); })" }
) all_lines

(* ── $derived reassignment check ─────────────────────────────────────── *)

(** Find all $derived declarations and their variable names *)
let find_derived_vars (items : item list) : string list =

let rec extract_pattern_var (p : pattern) : string option =
match p with
| PVar name -> Some name
| PAlias (_, alias) -> Some alias
| PTuple ps | PList ps ->
(match ps with [p] -> extract_pattern_var p | _ -> None)
| PRecord fields ->
(match fields with [(_, p)] -> extract_pattern_var p | _ -> None)
| _ -> None
in
let rec walk e : string list =
match e.expr_value with
| EApp (fn, _) when expr_name fn = "$derived" -> [] (* tracked via IConstant items *)
| ELet (lhs, rhs, _) ->
(match extract_pattern_var lhs with
| Some var_name when expr_name rhs = "$derived" -> [var_name]
| _ -> []) @ walk rhs
| EApp (fn, args) -> walk fn @ List.concat_map walk args
| EBlock es -> List.concat_map walk es
| EIf (_, then_, else_) -> walk then_ @ (match else_ with Some e -> walk e | None -> [])
| ECase (_, branches) -> List.concat_map (fun (_, e) -> walk e) branches
| EFn (_, body) -> walk body
| _ -> []
in
List.concat_map (fun item ->
match item.item_value with
| IConstant (PVar name, _, body) ->
(match body.expr_value with
| ELet (lhs, rhs, _) ->
(match extract_pattern_var lhs, rhs.expr_value with
| Some var_name, EApp (fn, _) when expr_name fn = "$derived" -> [var_name]
| _ -> [])
| EApp (fn, _) when expr_name fn = "$derived" -> [name]
| _ -> [])
| IFunction (_, _, _, body) -> walk body
| _ -> []
) items

(* ── $derived reassignment check ─────────────────────────────────────── *)

(** Check for assignment to $derived variables *)
let check_derived_reassignment (items : item list) (path : string) : T.finding list =
let derived_vars = find_derived_vars items in

List.map (fun line ->
{ T.file = path; line; rule_id = "svelte5-derived-reassignment";
severity = T.Error;
message = "Cannot reassign $derived variable — $derived values are read-only";
suggestion = Some "Use $state() for mutable values, or recalculate with $derived" }
)
(List.filter_map (fun item ->
match item.item_value with
| IConstant (PVar name, _, _) when
String.length name > 13 &&
String.sub name 0 13 = "__assignment:" &&
List.mem (String.sub name 13 (String.length name - 13)) derived_vars ->
Some item.item_location.start.line
| _ -> None
) items)

(* ── Main analyzer ─────────────────────────────────────────────────── *)

let analyze_module (mod_ : Catseye_ast.Types.t) : T.finding list =
let all_apps = walk_items_for_apps mod_.mod_items in
let all_vars = walk_items_for_vars mod_.mod_items in
let path = mod_.mod_path in

check_svelte4_patterns all_vars all_apps path
@ check_xss all_apps all_vars path
@ check_reactive_antipatterns all_apps path
@ check_svelte_hallucinations all_apps path
@ check_effect_cleanup mod_.mod_items path
@ check_derived_reassignment mod_.mod_items path
