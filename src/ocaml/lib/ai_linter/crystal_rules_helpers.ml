(* src/ocaml/lib/ai_linter/crystal_rules_helpers.ml
   Shared helpers for crystal rule detectors

   Provides is_test_or_spec_file, list_sort_uniq, and the AST walking
   primitives (get_name_chain, get_full_name, collect_app_names) used
   by every category module.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

(* String comparison operators — override Base's polymorphic
   versions with Stdlib's. Category modules inherit these via include. *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

(* Module aliases — included by every category file so they can use
   List/String/Hashtbl/etc. without redeclaring them. *)
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl
module Printf = Stdlib.Printf
module Float = Stdlib.Float
module Int = Stdlib.Int
module Char = Stdlib.Char

(* ── String helpers (used by is_test_or_spec_file and the AST
   combinators below) ──────────────────────────────────────────────── *)

(** Check if a string contains a substring (Naive O(n*m); use sparingly). *)
let string_contains (haystack : string) (needle : string) : bool =
  let hlen = String.length haystack in
  let nlen = String.length needle in
  if nlen = 0 then true
  else if nlen > hlen then false
  else
    let rec check i =
      if i + nlen > hlen then false
      else if String.sub haystack i nlen = needle then true
      else check (i + 1)
    in
    check 0

(** Check if a call name starts with any of the given prefixes. *)
let name_starts_with_any (name : string) (prefixes : string list) : bool =
  List.exists (fun prefix ->
    String.length name >= String.length prefix &&
    String.sub name 0 (String.length prefix) = prefix
  ) prefixes

(** Check if a call name ends with any of the given suffixes. *)
let name_ends_with_any (name : string) (suffixes : string list) : bool =
  let nlen = String.length name in
  List.exists (fun suffix ->
    let slen = String.length suffix in
    nlen >= slen &&
    String.sub name (nlen - slen) slen = suffix
  ) suffixes

(** Check if a call name equals one of the given strings, OR is
    "<receiver>.<suffix>" for some receiver (i.e. name ends with
    ".<suffix>"). Used by debug-print and similar detectors. *)
let name_matches (name : string) (suffixes : string list) : bool =
  List.exists (fun suffix ->
    name = suffix ||
    (String.length name > String.length suffix + 1 &&
     String.sub name (String.length name - String.length suffix - 1)
       (String.length suffix + 1) = "." ^ suffix)
  ) suffixes

(* ── File path helpers ──────────────────────────────────────────────── *)

let is_test_or_spec_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  let path_markers = ["/test/"; "/spec/"; "/benchmark/"; "/bench/"; "/example/"; "/examples/"; "/tests/"] in
  let file_suffixes = ["_test.cr"; "_spec.cr"; "_bench.cr"; "_tests.cr"] in
  let name_prefixes = ["test_"; "spec_"; "smell_"] in
  List.exists (string_contains lower) path_markers
  || List.exists (fun suf -> name_ends_with_any lower [suf]) file_suffixes
  || List.exists (fun p -> name_starts_with_any lower [p]) name_prefixes

let list_sort_uniq cmp l =
  let sorted = Stdlib.List.sort (fun a b -> cmp a b) l in
  let rec dedup acc = function
    | [] -> List.rev acc
    | [x] -> List.rev (x :: acc)
    | x :: (y :: _ as rest) when cmp x y = 0 -> dedup acc (y :: rest)
    | x :: rest -> dedup (x :: acc) rest
  in
  dedup [] sorted

(* ── Expression helpers ─────────────────────────────────────────────── *)

let rec get_name_chain (e : expr) : string list =
  match e.expr_value with
  | EFieldAccess (recv, field) -> get_name_chain recv @ [field]
  | EVar name -> [name]
  | _ -> []

let get_full_name (e : expr) : string =
  String.concat "." (get_name_chain e)

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
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body; _ } ->
      let rescue_calls = List.concat_map (fun rc -> collect_app_names rc.rescue_body) rescue_clauses in
      let ensure_calls = match ensure_body with Some e -> collect_app_names e | None -> [] in
      let else_calls = match else_body with Some e -> collect_app_names e | None -> [] in
      collect_app_names try_body @ rescue_calls @ ensure_calls @ else_calls
  | _ -> []

(* ── Detector combinators ────────────────────────────────────────────── *)
(* Eliminates the `List.concat_map (fun item -> match ... | IFunction ... -> ...
   | _ -> [])` boilerplate that 30+ detectors repeat. *)

(** Run f on the body of every IFunction in the module and concatenate
    the results. IModule/IClass members are also visited (their items
    are processed recursively). The callback receives the function name,
    its body, and the source line of the IFunction itself (useful for
    detectors that report at the function's location rather than at a
    call site within the body). *)
let map_functions (m : t) (f : string -> expr -> int -> (string * int) list)
    : (string * int) list =
  let rec items (xs : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (name, _, _, body) -> f name body item.item_location.start.line
      | IModule (_, inner) | IClass (_, inner) -> items inner
      | _ -> []
    ) xs
  in
  items m.mod_items

(** Generic pre-order walk of all subexpressions of [e]. The visitor
    receives every expression in the tree, including [e] itself.
    Visits: EBlock, ELet, ELetAssert, EIf, ECase, EApp, EFn, ETryCatchFinally.
    Leaves (ELiteral, EVar, EFieldAccess at top, EUnit, EError) are visited
    only as [e] itself. *)
let iter_subexpressions (f : expr -> unit) (e : expr) : unit =
  let rec walk (e : expr) =
    f e;
    match e.expr_value with
    | EBlock es -> List.iter walk es
    | ELet (_, e1, e2) -> walk e1; walk e2
    | ELetAssert (_, e1, e2) -> walk e1; walk e2
    | EIf (cond, then_, else_) ->
        walk cond; walk then_;
        (match else_ with Some e -> walk e | None -> ())
    | ECase (scrut, branches) ->
        walk scrut;
        List.iter (fun (_, e) -> walk e) branches
    | EApp (fn, args) -> walk fn; List.iter walk args
    | EFn (_, body) -> walk body
    | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body; _ } ->
        walk try_body;
        List.iter (fun rc -> walk rc.rescue_body) rescue_clauses;
        (match ensure_body with Some e -> walk e | None -> ());
        (match else_body with Some e -> walk e | None -> ())
    | _ -> ()
  in
  walk e

(** Map f over every subexpression of [e] and concatenate results. *)
let map_subexpressions (f : expr -> 'a list) (e : expr) : 'a list =
  let acc = ref [] in
  iter_subexpressions (fun e -> acc := !acc @ f e) e;
  !acc
(** Collect all string literal expressions in [e] as (expr, string) pairs.
    The expr is included so callers can recover the source line.
    Filters out the empty string (which is usually a default, not data). *)
let collect_string_literals (e : expr) : (expr * string) list =
  map_subexpressions (fun e ->
    match e.expr_value with
    | ELiteral (LString s) -> [(e, s)]
    | _ -> []
  ) e
