(* lib/catseye_rules/interpreter.ml *)

open Types
open Catseye_types

(* Check if a call name matches a sink pattern (substring match, like Gleam engine) *)
let matches_sink (pattern : string) (name : string) : bool =
  let plen = String.length pattern in
  let nlen = String.length name in
  (* Check if pattern is a substring of name *)
  let rec check i =
    if i + plen > nlen then false
    else if String.sub name i plen = pattern then true
    else check (i + 1)
  in
  check 0

(* Check if a call name matches a sanitizer pattern (substring) *)
let matches_sanitizer (patterns : string list) (name : string) : bool =
  List.exists (fun p ->
    let plen = String.length p in
    let nlen = String.length name in
    let rec check i =
      if i + plen > nlen then false
      else if String.sub name i plen = p then true
      else check (i + 1)
    in
    check 0
  ) patterns

(* Check if any arg is a variable (not literal) *)
let has_var_args (node : Security_node.t) : bool =
  List.exists (fun a -> a.Security_node.arg_type = Security_node.ArgVar) node.Security_node.args

(* Check if all args are literals *)
let all_args_literal (node : Security_node.t) : bool =
  match node.Security_node.args with
  | [] -> false
  | args -> List.for_all (fun a -> a.Security_node.arg_type = Security_node.ArgLiteral) args

(* Check if any arg is a sanitizer call *)
let has_sanitized_args (node : Security_node.t) (sanitizers : string list) : bool =
  List.exists (fun a ->
    a.Security_node.arg_type = Security_node.ArgCall
    && matches_sanitizer sanitizers a.Security_node.value
  ) node.Security_node.args

(* Get variable names from args *)
let var_names_from_args (args : Security_node.arg list) : string =
  args
  |> List.filter (fun a -> a.Security_node.arg_type = Security_node.ArgVar)
  |> List.map (fun a -> a.Security_node.value)
  |> String.concat ", "

(* Check if a node is suspect for a given sink and tainted var list *)
let is_suspect (node : Security_node.t) (tainted : string list)
    (sink : sink_def) : bool =
  let has_sanitized = has_sanitized_args node sink.sanitizers in
  if has_sanitized then false
  else
    (node.Security_node.taint
     || List.exists (fun a ->
          a.Security_node.arg_type = Security_node.ArgVar
          && List.mem a.Security_node.value tainted
        ) node.Security_node.args)
    && not (all_args_literal node)

(* Run a single rule against all nodes *)
let check_rule (rule : rule_def) (nodes : Security_node.t list)
    (tainted : string list) : Finding.t list =
  List.concat_map (fun sink_def ->
    nodes
    |> List.filter (fun n ->
      n.Security_node.node_type = Security_node.Call
      && matches_sink sink_def.pattern n.Security_node.name
      && is_suspect n tainted sink_def
    )
    |> List.map (fun n ->
      let vars = var_names_from_args n.Security_node.args in
      let msg = rule.message_template in
      let msg = String.concat "" [
        String.sub msg 0 (min (String.length msg) 20);
        n.Security_node.name;
        " called with variable argument(s): ";
        vars
      ] in
      { Finding.rule = rule.id
      ; severity = rule.severity
      ; file = n.Security_node.file
      ; line = n.Security_node.line
      ; message = msg
      ; flow = []  (* filled in by DAG builder later *)
      ; language = ""
      ; dependency = None
      }
    )
  ) rule.sinks

(* Run all rules against all nodes *)
let run_all (rules : rule_def list) (nodes : Security_node.t list)
    (tainted : string list) : Finding.t list =
  List.concat_map (fun rule -> check_rule rule nodes tainted) rules
