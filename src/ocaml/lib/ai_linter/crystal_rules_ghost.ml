(* src/ocaml/lib/ai_linter/crystal_rules_ghost.ml
   Category 1: Ghost Scent

   Detects AI-hallucinated standard library methods and deprecated
   Crystal syntax patterns. The hallucinated method database lives in
   crystal_hallucinations.ml.
 *)



open Catseye_ast.Types

include Crystal_rules_helpers
open Crystal_hallucinations

(** Rule 1.1: Hallucinated Standard Library Methods (database-driven) *)
let detect_hallucinated_stdlib (m : t) =
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      match check_hallucinated call_name with
      | Some entry ->
        let source_lang = match entry.lang with
          | `Ruby -> "Ruby" | `JS -> "JavaScript" | `Elixir -> "Elixir" | `Crystal -> "Crystal"
        in
        Some (Printf.sprintf "%s does not exist in Crystal stdlib — %s (confused with %s)"
                entry.name entry.correct source_lang, line)
      | None -> None
    ) (collect_app_names body)
  )

(** Rule 1.2: Legacy/Deprecated Syntax *)
let detect_deprecated_syntax (m : t) =
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      match call_name with
      | "puts" -> Some ("puts used for debugging", line)
      | "p"    -> Some ("p used for debugging", line)
      | "pp"   -> Some ("pp used for debugging", line)
      | _ -> None
    ) (collect_app_names body)
  )
