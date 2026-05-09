(* lib/catseye_rules/types.ml *)

type sink_def = {
  pattern : string;
  sanitizers : string list;
  requires_field : string option;
}

type source_def = {
  name : string;
  field : string option;
}

type conditions = {
  requires_tainted_args : bool;
  skip_all_literals : bool;
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
  extensions = [];
}
