(* lib/catseye_rules/types.ml *)

open Base

(** How a sink pattern matches a call name.

    - [Substring] (default): the call name contains the pattern as a substring.
      Backward-compatible with the original [is_substring] behavior. Safe for
      fully-qualified patterns like ["File.read"] and [$var] metavariables.
    - [Exact]: the call name must equal the pattern exactly. Prevents substring
      FPs on short patterns like ["read"] matching ["already_read"] or ["try"]
      matching ["retry_after"]. *)
type match_mode =
  | Substring
  | Exact

type sink_def = {
  pattern : string;
  match_mode : match_mode;
  sanitizers : string list;
  requires_field : string option;
  arg_pos : int option;  (** When [Some n], only flag if tainted data is in argument position n (0-indexed) *)
  fix_template : string option;  (** Optional autofix template with {arg0}, {arg1}, {sink} placeholders *)
}

type source_def = {
  name : string;
  field : string option;
}

type conditions = {
  requires_tainted_args : bool;
  skip_all_literals : bool;
  check_args_contain : string list;  (* flag if any arg contains one of these *)
  check_args_missing : string list; (* flag if NO arg contains one of these *)
  exclude_languages : string list;  (* skip rule for these languages *)
  include_languages : string list;  (* only apply to these languages (empty = all) *)
  extensions : (string * string) list;
}

type rule_def = {
  id : string;
  severity : string;
  sinks : sink_def list;
  sources : source_def list;
  conditions : conditions;
  message_template : string;
}

type t = rule_def

let default_conditions () : conditions = {
  requires_tainted_args = true;
  skip_all_literals = true;
  check_args_contain = [];
  check_args_missing = [];
  exclude_languages = [];
  include_languages = [];
  extensions = [];
}
