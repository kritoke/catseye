(* lib/catseye_rules/interpreter.ml *)

open Types
open Catseye_types

(* ── Shared Utilities ───────────────────────────────────────────────── *)

(** Single substring check implementation — reused by all pattern matching *)
let is_substring ~(pattern : string) ~(in_ : string) : bool =
  let plen = String.length pattern in
  let slen = String.length in_ in
  plen > 0 && (
    let rec check i =
      i + plen <= slen && (
        String.equal (String.sub in_ i plen) pattern || check (i + 1)
      )
    in
    check 0
  )

(* Re-export for external use *)
let contains_substring ~pattern ~in_ = is_substring ~pattern ~in_

(* Substitute {var} placeholders in a message template *)
let substitute_template (template : string) ~(sink : string) ~(vars : string) : string =
  let substitute s what with_ =
    let wlen = String.length what in
    let rec loop acc i =
      let len = String.length s in
      if i + wlen > len then
        (* No match at or after i; done — prepend accumulated parts *)
        let rest = if i < len then String.sub s i (len - i) else "" in
        String.concat "" (List.rev (rest :: acc))
      else if String.sub s i wlen = what then
        (* Found match: prepend everything before + replacement, then
           continue scanning the remainder for further occurrences *)
        let before = if i > 0 then String.sub s 0 i else "" in
        loop (before :: with_ :: acc) (i + wlen)
      else
        loop acc (i + 1)
    in
    loop [] 0
  in
  template
  |> substitute "{sink}" sink
  |> substitute "{tainted_vars}" vars

(* ── Sink / Sanitizer Matching ─────────────────────────────────────── *)

(** Check if a call name matches a sink pattern (substring match) *)
let matches_sink ~(pattern : string) ~(name : string) : bool =
  is_substring ~pattern ~in_:name

(** Check if any sanitizer pattern matches a call name *)
let matches_sanitizer (patterns : string list) (name : string) : bool =
  List.exists (fun p -> is_substring ~pattern:p ~in_:name) patterns

(* ── Arg Analysis ───────────────────────────────────────────────────── *)

(** Check if any arg is a variable (not literal) *)
let has_var_args (node : Security_node.t) : bool =
  List.exists (fun a -> a.Security_node.arg_type = Security_node.ArgVar) node.Security_node.args

(** Check if all args are literals *)
let all_args_literal (node : Security_node.t) : bool =
  match node.Security_node.args with
  | [] -> false
  | args -> List.for_all (fun a -> a.Security_node.arg_type = Security_node.ArgLiteral) args

(** Check if any arg is a sanitizer call *)
let has_sanitized_args (node : Security_node.t) (sanitizers : string list) : bool =
  List.exists (fun a ->
    a.Security_node.arg_type = Security_node.ArgCall
    && matches_sanitizer sanitizers a.Security_node.value
  ) node.Security_node.args

(** Get variable names from args *)
let var_names_from_args (args : Security_node.arg list) : string =
  args
  |> List.filter (fun a -> a.Security_node.arg_type = Security_node.ArgVar)
  |> List.map (fun a -> a.Security_node.value)
  |> String.concat ", "

(* ── Rule Condition Evaluation ──────────────────────────────────────── *)

(** Check if any arg value contains any of the given patterns *)
let rec args_contain_any (args : Security_node.arg list) (patterns : string list) : bool =
  List.exists (fun a ->
    List.exists (fun p -> is_substring ~pattern:p ~in_:a.Security_node.value) patterns
  ) args

(** Check if args exist but none contain any of the given patterns *)
and args_missing_all (args : Security_node.arg list) (patterns : string list) : bool =
  args <> [] && not (args_contain_any args patterns)

(** Check if a node matches a rule based on its conditions *)
and evaluate_rule_conditions (node : Security_node.t) (rule : rule_def) (sink : sink_def) 
    (tainted : string list) : bool =
  if rule.conditions.check_args_contain <> [] then
    args_contain_any node.Security_node.args rule.conditions.check_args_contain
  else if rule.conditions.check_args_missing <> [] then
    args_missing_all node.Security_node.args rule.conditions.check_args_missing
  else if not rule.conditions.requires_tainted_args then
    (* Pattern-only rules: flag any call matching the sink, regardless of taint *)
    true
  else
    (* Taint-based rules *)
    is_suspect node tainted sink

(* ── Taint Analysis ─────────────────────────────────────────────────── *)

(** Check if a node is suspect for a given sink and tainted var list *)
and is_suspect (node : Security_node.t) (tainted : string list)
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

(* ── Rule Checking ──────────────────────────────────────────────────── *)

(** Check if a node should be flagged by a sink pattern *)
let node_matches_sink (n : Security_node.t) (sink : sink_def) : bool =
  n.Security_node.node_type = Security_node.Call
  && matches_sink ~pattern:sink.pattern ~name:n.Security_node.name

(** Run a single rule against all nodes *)
let check_rule (rule : rule_def) (nodes : Security_node.t list)
    (tainted : string list) : Finding.t list =
  List.concat_map (fun sink ->
    nodes
    |> List.filter (fun n -> node_matches_sink n sink)
    |> List.filter (fun n -> evaluate_rule_conditions n rule sink tainted)
    |> List.map (fun n ->
      let vars = var_names_from_args n.Security_node.args in
      let msg = substitute_template rule.message_template ~sink:n.Security_node.name ~vars in
      { Finding.rule = rule.id
      ; severity = rule.severity
      ; file = n.Security_node.file
      ; line = n.Security_node.line
      ; message = msg
      ; flow = []
      ; language = n.Security_node.language
      ; dependency = None
      }
    )
  ) rule.sinks

(* ── Deduplication ───────────────────────────────────────────────────── *)

(** Run all rules against all nodes, deduplicating findings *)
let run_all (rules : rule_def list) (nodes : Security_node.t list)
    (tainted : string list) : Finding.t list =
  let raw = List.concat_map (fun rule -> check_rule rule nodes tainted) rules in
  let seen = Hashtbl.create 64 in
  List.filter (fun (f : Finding.t) ->
    let key = f.Finding.rule ^ ":" ^ f.Finding.file ^ ":" ^ string_of_int f.Finding.line in
    if Hashtbl.mem seen key then false
    else (Hashtbl.replace seen key true; true)
  ) raw
