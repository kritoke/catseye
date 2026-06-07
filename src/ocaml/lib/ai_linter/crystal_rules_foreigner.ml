(* src/ocaml/lib/ai_linter/crystal_rules_foreigner.ml
   Category 2: The Foreigner

   Detects Crystal code that looks like it was ported from another
   language (manual loops, primitive obsession with 3+ params).
 *)



open Catseye_ast.Types

include Crystal_rules_helpers

(** Rule 2.1: Manual Loops vs Iterators

    Detect while loops with counter variable and index access patterns
    that could be replaced with .each, .map, .select, etc. *)
let detect_manual_loop (m : t) =
  let is_counter_call n =
    let suffixes = ["+= 1"; "+=1"; "i += 1"; "idx += 1"; "index += 1"] in
    List.exists (fun s -> n = s || name_ends_with_any n [s]) suffixes
  in
  map_functions m (fun _name body _line ->
    let calls = collect_app_names body in
    let has_while = List.exists (fun (n, _) -> n = "while") calls in
    let has_counter = List.exists (fun (n, _) -> is_counter_call n) calls in
    if has_while && has_counter then
      let line = match List.find_opt (fun (n, _) -> n = "while") calls with
        | Some (_, l) -> l | None -> 0
      in
      [("Manual while loop with counter — consider using .each, .map, or .each_with_index", line)]
    else []
  )

(** Rule 2.3: Primitive Obsession (3+ params) *)
let detect_primitive_obsession (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let count = List.length (List.filter (function PVar _ -> true | _ -> false) patterns) in
      if count >= 3 then
        Some (Printf.sprintf "Function '%s' has %d parameters - consider domain types" name count,
              item.item_location.start.line)
      else None
    | _ -> None
  ) m.mod_items
