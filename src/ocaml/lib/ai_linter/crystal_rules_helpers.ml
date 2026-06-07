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

(* File path helpers *)

let is_test_or_spec_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  let rec contains_substr str pat =
    let plen = String.length pat in
    let slen = String.length str in
    if plen > slen then false
    else if String.sub str 0 plen = pat then true
    else contains_substr (String.sub str 1 (slen - 1)) pat
  in
  let matched = List.exists (fun pat ->
    let plen = String.length pat in
    if String.length lower >= plen then
      let suffix = String.sub lower (String.length lower - plen) plen in
      pat = suffix || (pat = "test_" && String.length lower >= 5 && String.sub lower 0 5 = "test_")
      || contains_substr lower pat
    else false
  ) [
    "/test/"; "/spec/"; "/benchmark/"; "/bench/";
    "/example/"; "/examples/"; "/tests/";
    "_test.cr"; "_spec.cr"; "_bench.cr";
    "_test."; "_spec."; "_bench.";
    "_tests.cr"; "test_"; "spec_";
    "smell_";
  ] in
  matched

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
