(* lib/catseye_rules/interpreter.ml *)

open Types
open Catseye_types

(* ── Shared Utilities ───────────────────────────────────────────────── *)

(** Single substring check implementation - reused by all pattern matching *)
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
    if wlen = 0 then s  (* empty pattern → no substitution *)
    else
      let result = Buffer.create (String.length s + String.length with_) in
      let rec scan i =
        let len = String.length s in
        if i + wlen > len then
          Buffer.add_substring result s i (len - i)
        else if String.sub s i wlen = what then begin
          Buffer.add_substring result s i 0;  (* add nothing - already past *)
          Buffer.add_string result with_;
          scan (i + wlen)
        end else begin
          Buffer.add_char result s.[i];
          scan (i + 1)
        end
      in
      scan 0;
      Buffer.contents result
  in
  let r1 = substitute template "{sink}" sink in
  substitute r1 "{tainted_vars}" vars

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

(* ── Taint Context ──────────────────────────────────────────────────── *)

(** File-scoped taint context. Replaces flat string list to avoid
    cross-file taint bleed (same var name in different files). *)
type taint_context = {
  global : string list;
  by_file : (string * string list) list;
}

(** Build a taint context from the taint DB and the set of files in scope. *)
let make_taint_context ~(global : string list)
    ~(by_file : (string * string list) list) : taint_context = {
  global;
  by_file;
}

(** Get the tainted variable list for a specific file.
    Falls back to the global list if the file has no scoped entries. *)
let tainted_for_file (ctx : taint_context) (file : string) : string list =
  match List.find_opt (fun (f, _) -> f = file) ctx.by_file with
  | Some (_, vars) -> vars
  | None -> ctx.global

(* ── Rule Condition Evaluation ──────────────────────────────────────── *)

(** Check if a file contains timeout setter calls (read_timeout=, connect_timeout=)
    Used to suppress MissingTimeout FPs when timeout is set in the caller scope. *)
let file_has_timeout_setters (file : string) (nodes : Security_node.t list) : bool =
  List.exists (fun n ->
    n.Security_node.file = file
    && n.Security_node.node_type = Security_node.Call
    && (is_substring ~pattern:"read_timeout" ~in_:n.Security_node.name
        || is_substring ~pattern:"connect_timeout" ~in_:n.Security_node.name
        || is_substring ~pattern:"write_timeout" ~in_:n.Security_node.name)
  ) nodes

(** Check if a file is a non-HTTP entry point (scripts, config, tasks) *)
let is_non_http_context (file : string) : bool =
  let lowercase = String.lowercase_ascii file in
  List.exists (fun segment ->
    is_substring ~pattern:segment ~in_:lowercase
  ) ["/scripts/"; "/config/"; "/tasks/"; "/migrations/"; "/bin/"]

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
    (ctx : taint_context) (nodes : Security_node.t list) : bool =
  (* Metadata-based suppression: parameterized queries are safe from SQL injection *)
  if rule.id = "SQLInjection" && Security_node.has_metadata_flag node "parameterized_query" then
    false
  (* Metadata-based suppression: HTTP clients with timeout config are safe *)
  else if rule.id = "MissingTimeout" && Security_node.has_metadata_flag node "has_timeout_config" then
    false
  (* MissingTimeout: suppress if timeout is set anywhere in the same file —
     the client may be returned from a helper and configured by the caller *)
  else if rule.id = "MissingTimeout" && file_has_timeout_setters node.Security_node.file nodes then
    false
  (* Path traversal: suppress for non-HTTP contexts (scripts, config) *)
  else if rule.id = "PathTraversal" && is_non_http_context node.Security_node.file then
    false
  else if rule.conditions.check_args_contain <> [] then
    args_contain_any node.Security_node.args rule.conditions.check_args_contain
  else if rule.conditions.check_args_missing <> [] then
    args_missing_all node.Security_node.args rule.conditions.check_args_missing
  else if not rule.conditions.requires_tainted_args then
    (* Pattern-only rules: flag any call matching the sink, regardless of taint *)
    true
  else
    (* Taint-based rules: use file-scoped taint *)
    is_suspect node ctx sink

(* ── Taint Analysis ─────────────────────────────────────────────────── *)

(** Check if a node is suspect for a given sink, using file-scoped taint.
    Also considers scent metadata: nodes with scent=true are always suspect
    for ScentLeakage rules regardless of regular taint. *)
and is_suspect (node : Security_node.t) (ctx : taint_context)
    (sink : sink_def) : bool =
  let has_sanitized = has_sanitized_args node sink.sanitizers in
  if has_sanitized then false
  else
    (* Scent metadata: if node carries scent=true, it's suspect for any sink *)
    let has_scent = Security_node.has_metadata_flag node "scent" in
    if has_scent then true
    else
      let tainted = tainted_for_file ctx node.Security_node.file in
      (node.Security_node.taint
       || List.exists (fun a ->
            (a.Security_node.arg_type = Security_node.ArgVar
             || a.Security_node.arg_type = Security_node.ArgCall)
            && List.exists (fun tainted_var ->
              (* Exact match or prefix: "uri" matches "uri.request_target" *)
              a.Security_node.value = tainted_var
              || (String.length a.Security_node.value > String.length tainted_var
                  && String.sub a.Security_node.value 0 (String.length tainted_var) = tainted_var
                  && a.Security_node.value.[String.length tainted_var] = '.')
            ) tainted
          ) node.Security_node.args)
      && not (all_args_literal node)

(* ── Rule Checking ──────────────────────────────────────────────────── *)

(** Check if a node should be flagged by a sink pattern *)
let node_matches_sink (n : Security_node.t) (sink : sink_def) : bool =
  n.Security_node.node_type = Security_node.Call
  && matches_sink ~pattern:sink.pattern ~name:n.Security_node.name

(** Check if a rule should apply to a given node based on language filters *)
let language_allows (rule : rule_def) (node : Security_node.t) : bool =
  let lang = node.Security_node.language in
  (* If include_languages is set, node must match one *)
  if rule.conditions.include_languages <> [] then
    List.mem lang rule.conditions.include_languages
  else
    (* If exclude_languages is set, node must NOT match any *)
    not (List.mem lang rule.conditions.exclude_languages)

(** Run a single rule against all nodes *)
let check_rule (rule : rule_def) (nodes : Security_node.t list)
    (ctx : taint_context) : Finding.t list =
  List.concat_map (fun sink ->
    nodes
    |> List.filter (fun n -> language_allows rule n)
    |> List.filter (fun n -> node_matches_sink n sink)
    |> List.filter (fun n -> evaluate_rule_conditions n rule sink ctx nodes)
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
      ; reachability = None
      ; suggestion = None
      }
    )
  ) rule.sinks

(* ── Deduplication ───────────────────────────────────────────────────── *)

(** Run all rules against all nodes, deduplicating findings *)
let run_all (rules : rule_def list) (nodes : Security_node.t list)
    (ctx : taint_context) : Finding.t list =
  let raw = List.concat_map (fun rule -> check_rule rule nodes ctx) rules in
  let seen = Hashtbl.create 64 in
  List.filter (fun (f : Finding.t) ->
    let key = f.Finding.rule ^ ":" ^ f.Finding.file ^ ":" ^ string_of_int f.Finding.line in
    if Hashtbl.mem seen key then false
    else (Hashtbl.replace seen key true; true)
  ) raw
