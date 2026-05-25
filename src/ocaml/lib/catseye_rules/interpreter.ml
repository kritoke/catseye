(* lib/catseye_rules/interpreter.ml *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
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
        String.equal (String.sub in_ ~pos:i ~len:plen) pattern || check (i + 1)
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
          Buffer.add_substring result s ~pos:i ~len:(len - i)
        else if String.sub s ~pos:i ~len:wlen = what then begin
          Buffer.add_substring result s ~pos:i ~len:0;  (* add nothing - already past *)
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

(** Check if a pattern starts with [$] — a metavariable that matches any receiver prefix.
    ["$client.get"] matches [http.get], [client.get], [conn.get], [my_client.get], etc.
    The [$] captures everything before the first [.] in the pattern, and matches
    everything before the first [.] in the name.
    If the pattern has no [.] (e.g., ["$fn"]), it matches any single name.
    Patterns without [$] use the existing substring match (backward compatible). *)
let matches_metavar ~(pattern : string) ~(name : string) : bool =
  if String.length pattern = 0 || pattern.[0] <> '$' then false
  else
    (* Extract the suffix after [$var]: e.g., "$client.get" → ".get" *)
    let suffix =
      match String.index pattern '.' with
      | Some idx -> String.sub pattern ~pos:idx ~len:(String.length pattern - idx)
      | None -> ""
    in
    if suffix = "" then
      (* Pattern is "$fn" with no dot — matches any name *)
      true
    else
      (* Name must end with the same suffix, and have something before the dot *)
      let name_has_dot = String.length suffix <= String.length name in
      name_has_dot
      && let name_suffix_start = String.length name - String.length suffix in
         String.sub name ~pos:name_suffix_start ~len:(String.length suffix) = suffix
         && (name_suffix_start = 0
             || name.[name_suffix_start - 1] = '.'
             || name.[name_suffix_start] = '.')

(** Check if a call name matches a sink pattern.
    - Patterns starting with [$] use metavariable matching (receiver wildcard)
    - All other patterns use substring matching (backward compatible) *)
let matches_sink ~(pattern : string) ~(name : string) : bool =
  if String.length pattern > 0 && pattern.[0] = '$' then
    matches_metavar ~pattern ~name
  else
    is_substring ~pattern ~in_:name

(** Check if any sanitizer pattern matches a call name *)
let matches_sanitizer (patterns : string list) (name : string) : bool =
  List.exists ~f:(fun p -> is_substring ~pattern:p ~in_:name) patterns

(* ── Autofix Template Instantiation ──────────────────────────────────── *)

(** Instantiate a fix template by replacing {arg0}, {arg1}, ... with the
    corresponding tainted argument values, and {sink} with the sink name.
    Returns [None] if the template is [None] or has no placeholders. *)
let instantiate_fix (template : string) ~(sink_name : string)
    (tainted_args : Security_node.arg list) : string =
  let tainted_arr = Array.of_list (
    tainted_args
    |> List.filter ~f:(fun a -> a.Security_node.arg_type = Security_node.ArgVar
                             || a.Security_node.arg_type = Security_node.ArgCall)
    |> List.map ~f:(fun a -> a.Security_node.value)
  ) in
  let result = Buffer.create (String.length template + 64) in
  let i = ref 0 in
  let len = String.length template in
  while !i < len do
    if template.[!i] = '{' then begin
      (* Try to parse {argN} or {sink} *)
      let j = ref (!i + 1) in
      let found_end = ref false in
      while !j < len && template.[!j] <> '}' do Int.incr j done;
      if !j < len && template.[!j] = '}' then begin
        found_end := true;
        let placeholder = String.sub template ~pos:(!i + 1) ~len:(!j - !i - 1) in
        if placeholder = "sink" then
          Buffer.add_string result sink_name
        else if String.length placeholder >= 4
                && String.sub placeholder ~pos:0 ~len:3 = "arg"
        then
          let idx_str = String.sub placeholder ~pos:3 ~len:(String.length placeholder - 3) in
          (try
            let idx = Int.of_string idx_str in
            if idx < Array.length tainted_arr then
              Buffer.add_string result tainted_arr.(idx)
            else
              Buffer.add_string result ("{arg" ^ idx_str ^ "}")
          with _ ->
            Buffer.add_string result ("{" ^ placeholder ^ "}"))
        else
          Buffer.add_string result ("{" ^ placeholder ^ "}");
        i := !j + 1
      end;
      if not !found_end then begin
        Buffer.add_char result template.[!i];
        Int.incr i
      end
    end else begin
      Buffer.add_char result template.[!i];
      Int.incr i
    end
  done;
  Buffer.contents result

(** Check if any arg is a variable (not literal) *)
let has_var_args (node : Security_node.t) : bool =
  List.exists ~f:(fun a -> a.Security_node.arg_type = Security_node.ArgVar) node.Security_node.args

(** Check if all args are literals *)
let all_args_literal (node : Security_node.t) : bool =
  match node.Security_node.args with
  | [] -> false
  | args -> List.for_all ~f:(fun a -> a.Security_node.arg_type = Security_node.ArgLiteral) args

(** Check if any arg is a sanitizer call *)
let has_sanitized_args (node : Security_node.t) (sanitizers : string list) : bool =
  List.exists ~f:(fun a ->
    a.Security_node.arg_type = Security_node.ArgCall
    && matches_sanitizer sanitizers a.Security_node.value
  ) node.Security_node.args

(** Check if the arg at a specific position is tainted.
    When [sink.arg_pos] is [Some n], only arg index [n] is checked for taint.
    When [None], any tainted arg suffices (backward compatible). *)
let arg_pos_tainted (node : Security_node.t) (sink : sink_def)
    (tainted_vars : string list) : bool =
  match sink.arg_pos with
  | None -> true  (* No position restriction *)
  | Some pos ->
    (* Check that the arg at position [pos] is a tainted variable *)
    let args = node.Security_node.args in
    if pos >= List.length args then false
    else
      let arg = Option.value_exn (List.nth args pos) in
      (arg.Security_node.arg_type = Security_node.ArgVar
       || arg.Security_node.arg_type = Security_node.ArgCall)
      && List.exists ~f:(fun tv ->
        arg.Security_node.value = tv
        || (String.length arg.Security_node.value > String.length tv
            && String.sub arg.Security_node.value ~pos:0 ~len:(String.length tv) = tv
            && arg.Security_node.value.[String.length tv] = '.')
      ) tainted_vars

(** Get variable names from args *)
let var_names_from_args (args : Security_node.arg list) : string =
  args
  |> List.filter ~f:(fun a -> a.Security_node.arg_type = Security_node.ArgVar)
  |> List.map ~f:(fun a -> a.Security_node.value)
  |> String.concat ~sep:", "

(* ── Taint Context ──────────────────────────────────────────────────── *)

(** File-scoped taint context. Replaces flat string list to avoid
    cross-file taint bleed (same var name in different files). *)
type taint_context = {
  global : string list;
  by_file : (string * string list) list;
  import_map : (string, string list) Stdlib.Hashtbl.t;  (* file -> resolved import paths *)
}

(** Build a taint context from the taint DB and the set of files in scope. *)
let make_taint_context ~(global : string list)
    ~(by_file : (string * string list) list)
    ?(import_map = Stdlib.Hashtbl.create 0)
    () : taint_context = {
  global;
  by_file;
  import_map;
}

(** Get the tainted variable list for a specific file.
    Falls back to the global list if the file has no scoped entries. *)
let tainted_for_file (ctx : taint_context) (file : string) : string list =
  match List.find ~f:(fun (f, _) -> f = file) ctx.by_file with
  | Some (_, vars) -> vars
  | None -> ctx.global

(* ── Rule Condition Evaluation ──────────────────────────────────────── *)

(** Check if a file contains timeout setter calls (read_timeout=, connect_timeout=)
    Used to suppress MissingTimeout FPs when timeout is set in the caller scope. *)
let file_has_timeout_setters (file : string) (nodes : Security_node.t list) : bool =
  List.exists ~f:(fun n ->
    n.Security_node.file = file
    && n.Security_node.node_type = Security_node.Call
    && (is_substring ~pattern:"read_timeout" ~in_:n.Security_node.name
        || is_substring ~pattern:"connect_timeout" ~in_:n.Security_node.name
        || is_substring ~pattern:"write_timeout" ~in_:n.Security_node.name)
  ) nodes

(** Check if a file is a non-HTTP entry point (scripts, config, tasks) *)
let is_non_http_context (file : string) : bool =
  let lowercase = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun segment ->
    is_substring ~pattern:segment ~in_:lowercase
  ) ["/scripts/"; "/config/"; "/tasks/"; "/migrations/"; "/bin/"]

(** Check if a file contains SSRF validation (check_ssrf call).
    Files that call check_ssrf before HTTP requests are considered to have
    SSRF protection, so we suppress false positives for known-valid patterns.
    Currently matches: check_ssrf, resolve_and_validate (URLValidator) *)
let file_has_ssrf_validation (file : string) (nodes : Security_node.t list) : bool =
  List.exists ~f:(fun n ->
    n.Security_node.file = file
    && n.Security_node.node_type = Security_node.Call
    && (is_substring ~pattern:"check_ssrf" ~in_:n.Security_node.name
        || is_substring ~pattern:"resolve_and_validate" ~in_:n.Security_node.name)
  ) nodes

(** Check if any arg value contains any of the given patterns *)
let rec args_contain_any (args : Security_node.arg list) (patterns : string list) : bool =
  List.exists ~f:(fun a ->
    List.exists ~f:(fun p -> is_substring ~pattern:p ~in_:a.Security_node.value) patterns
  ) args

(** Check if args exist but none contain any of the given patterns *)
and args_missing_all (args : Security_node.arg list) (patterns : string list) : bool =
  args <> [] && not (args_contain_any args patterns)

(** Check if a node is a safe HTTP client call (validated client like CrestHttpClient).
    Calls to validated HTTP clients (like http_client.get, client.get) are considered safe
    because the HTTP client does its own URL validation internally (check_ssrf).
    
    This suppression is intentionally broad: any call to a known-safe HTTP client pattern
    is suppressed because these clients are designed to handle potentially untrusted URLs.
    The alternative would be to mark individual calls with metadata flags, but that's
    more invasive to the codebase. *)
and is_safe_http_client_call (node : Security_node.t) : bool =
  (* Check if this is a known-safe HTTP client method *)
  let safe_patterns = ["http_client."; "client."; "conn."; "connection."] in
  List.exists ~f:(fun p -> is_substring ~pattern:p ~in_:node.Security_node.name) safe_patterns

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
  (* SSRF: suppress calls to validated HTTP client wrappers (client methods).
     Methods like http_client.get, client.get, conn.get are validated wrappers that
     implement check_ssrf internally, so they handle potentially untrusted URLs safely. *)
  else if rule.id = "SSRF" && is_safe_http_client_call node then
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
       || (List.exists ~f:(fun a ->
              (a.Security_node.arg_type = Security_node.ArgVar
               || a.Security_node.arg_type = Security_node.ArgCall)
              && List.exists ~f:(fun tainted_var ->
                (* Exact match or prefix: "uri" matches "uri.request_target" *)
                a.Security_node.value = tainted_var
                || (String.length a.Security_node.value > String.length tainted_var
                    && String.sub a.Security_node.value ~pos:0 ~len:(String.length tainted_var) = tainted_var
                    && a.Security_node.value.[String.length tainted_var] = '.')
              ) tainted
            ) node.Security_node.args
            && arg_pos_tainted node sink tainted))
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
    List.mem rule.conditions.include_languages ~equal:String.equal lang
  else
    not (List.mem rule.conditions.exclude_languages ~equal:String.equal lang)

(** Run a single rule against all nodes *)
let check_rule (rule : rule_def) (nodes : Security_node.t list)
    (ctx : taint_context) : Finding.t list =
  List.concat_map ~f:(fun sink ->
    nodes
    |> List.filter ~f:(fun n -> language_allows rule n)
    |> List.filter ~f:(fun n -> node_matches_sink n sink)
    |> List.filter ~f:(fun n -> evaluate_rule_conditions n rule sink ctx nodes)
    |> List.map ~f:(fun n ->
      let vars = var_names_from_args n.Security_node.args in
      let msg = substitute_template rule.message_template ~sink:n.Security_node.name ~vars in
      let suggestion = match sink.fix_template with
        | Some tmpl -> Some (instantiate_fix tmpl ~sink_name:n.Security_node.name n.Security_node.args)
        | None -> None
      in
      { Finding.rule = rule.id
      ; severity = rule.severity
      ; file = n.Security_node.file
      ; line = n.Security_node.line
      ; message = msg
      ; flow = []
      ; language = n.Security_node.language
      ; dependency = None
      ; reachability = None
      ; suggestion
      }
    )
  ) rule.sinks

(* ── Deduplication ───────────────────────────────────────────────────── *)

(** Run all rules against all nodes, deduplicating findings *)
let run_all (rules : rule_def list) (nodes : Security_node.t list)
    (ctx : taint_context) : Finding.t list =
  let raw = List.concat_map ~f:(fun rule -> check_rule rule nodes ctx) rules in
  let seen = Hashtbl.create (module String) ~size:64 in
  List.filter ~f:(fun (f : Finding.t) ->
    let key = f.Finding.rule ^ ":" ^ f.Finding.file ^ ":" ^ Int.to_string f.Finding.line in
    if Hashtbl.mem seen key then false
    else (Hashtbl.set seen ~key ~data:true; true)
  ) raw
