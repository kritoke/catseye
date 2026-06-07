(* src/ocaml/lib/ai_linter/crystal_rules_foreigner.ml
   Category 2: The Foreigner

   Detects Crystal code that looks like it was ported from another
   language (manual loops, primitive obsession with 3+ params).

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_manual_loop (m : t) =
  
  
  
  let has_suffix s suffix =
    let sslen = String.length s in
    let slen = String.length suffix in
    sslen >= slen && String.sub s (sslen - slen) slen = suffix
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let has_while = List.exists (fun (n, _) -> n = "while") calls in
      let has_counter = List.exists (fun (n, _) ->
        has_suffix n "+= 1" || has_suffix n "+=1" ||
        n = "i += 1" || n = "idx += 1" || n = "index += 1") calls in
      if has_while && has_counter then
        [let line = match List.find_opt (fun (n, _) -> n = "while") calls with
          | Some (_, l) -> l | None -> item.item_location.start.line
        in ("Manual while loop with counter — consider using .each, .map, or .each_with_index", line)]
      else []
    | _ -> []
  ) m.mod_items

(** Rule 2.3: Primitive Obsession (3+ params) *)

let detect_primitive_obsession (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let params = List.filter (function PVar _ -> true | _ -> false) patterns in
      if List.length params >= 3
      then Some (Printf.sprintf "Function '%s' has %d parameters - consider domain types" name (List.length params), item.item_location.start.line)
      else None
    | _ -> None
  ) m.mod_items

(* ── Category 3: The Happy Path ──────────────────────────────────────── *)

(** Rule 3.1: Nil-chaser (unchecked nil access)
    Uses type inference DB to detect when a call that returns T | Nil
    is accessed without a nil guard (e.g. user.name where user comes
    from Hash#[]? or Array#first?). Also detects .not_nil!, .as(Type)
    casts, and .try(&.x) as code smells. *)