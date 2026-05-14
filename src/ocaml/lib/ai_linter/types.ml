(* src/ocaml/lib/ai_linter/types.ml
   AI Linter types - severity and findings
*)

(** Severity levels *)
type severity = Hint | Warning | Error

let severity_to_string = function
  | Hint -> "hint"
  | Warning -> "warning"
  | Error -> "error"

let severity_to_level = function
  | Hint -> 1
  | Warning -> 2
  | Error -> 3