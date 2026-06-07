(* src/ocaml/lib/ai_linter/crystal_rules_ghost.ml
   Category 1: Ghost Scent

   Detects AI-hallucinated standard library methods and deprecated
   Crystal syntax patterns. The hallucinated method database lives in
   crystal_hallucinations.ml.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

open Crystal_hallucinations
let detect_hallucinated_stdlib (m : t) =
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun (name, line) ->
        match check_hallucinated name with
        | Some entry ->
          let source_lang = match entry.lang with
            | `Ruby -> "Ruby" | `JS -> "JavaScript" | `Elixir -> "Elixir" | `Crystal -> "Crystal"
          in
          let msg = Printf.sprintf "%s does not exist in Crystal stdlib — %s (confused with %s)"
              entry.name entry.correct source_lang
          in
          collected := (msg, line) :: !collected
        | None -> ()
      ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  list_sort_uniq (fun (m1, l1) (m2, l2) ->
    let c = compare l1 l2 in if c <> 0 then c else String.compare m1 m2
  ) !collected

(** Rule 1.2: Legacy/Deprecated Syntax *)

let detect_deprecated_syntax (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "puts" then [("puts used for debugging", line)]
        else if name = "p" then [("p used for debugging", line)]
        else if name = "pp" then [("pp used for debugging", line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(* ── Category 2: The Foreigner ──────────────────────────────────────── *)

(** Rule 2.1: Manual Loops vs Iterators
    Detect while loops with counter variable and index access patterns
    that could be replaced with .each, .map, .select, etc. *)