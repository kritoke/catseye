(* src/ocaml/lib/ai_linter/types.ml
   AI Linter types - severity and findings
 *)

open Base

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

(** A lint finding - unified across all rule modules *)
type finding = {
  file : string;
  line : int;
  rule_id : string;
  severity : severity;
  message : string;
  suggestion : string option;
}