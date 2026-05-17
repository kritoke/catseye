(* lib/catseye_engine/path_sensitivity.ml *)

(** Path-sensitive taint analysis.
    Tracks guard conditions that may sanitize values before they're used at sinks.
    This reduces false positives when variables have been validated before use.
*)

open Catseye_types

(* ── Validation types ──────────────────────────────────────────────── *)

type validation_kind =
  | Regex of string
  | MethodCall
  | SchemeCheck
  | ContainsCheck
  | Allowlist
  | Equality

type validation = {
  var_name : string;
  file : string;
  start_line : int;
  end_line : int;
  kind : validation_kind;
  validated_by : string;
}

(* ── Helper functions ──────────────────────────────────────────────── *)

let ends_with (name : string) (suffix : string) : bool =
  let nlen = String.length name in
  let slen = String.length suffix in
  nlen >= slen && String.sub name (nlen - slen) slen = suffix

let starts_with_lowercase (name : string) : bool =
  String.length name > 0 &&
  let c = name.[0] in c >= 'a' && c <= 'z'

let contains_substring (name : string) (sub : string) : bool =
  let nlen = String.length name in
  let slen = String.length sub in
  if nlen < slen then false
  else
    let rec check i =
      if i + slen > nlen then false
      else if String.sub name i slen = sub then true
      else check (i + 1)
    in
    check 0

(* ── Pattern detection ─────────────────────────────────────────────── *)

let is_validation_method (name : string) : bool =
  ends_with name "valid?" || ends_with name "safe?" ||
  ends_with name "secure?" || ends_with name "allowed?" ||
  (starts_with_lowercase name && (
    contains_substring name "validate" ||
    contains_substring name "sanitize" ||
    contains_substring name "check" ||
    contains_substring name "verify"
  ))

let rec detect_validation (call_name : string) : (validation_kind * string option) option =
  if is_validation_method call_name then Some (MethodCall, None)
  else if ends_with call_name "starts_with?" then Some (SchemeCheck, extract_receiver call_name)
  else if ends_with call_name "end_with?" then Some (SchemeCheck, extract_receiver call_name)
  else if ends_with call_name "includes?" then Some (ContainsCheck, extract_receiver call_name)
  else if call_name = "=~" || ends_with call_name ".match" then Some (Regex "unknown", None)
  else None

and extract_receiver (call_name : string) : string option =
  try
    let dot_pos = String.rindex call_name '.' in
    Some (String.sub call_name 0 dot_pos)
  with Not_found -> None

(* ── Scope building ─────────────────────────────────────────────────── *)

let build_validation_scopes (nodes : Security_node.t list) : validation list =
  let scopes = ref [] in
  
  (* Group by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun n ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    let defs = List.filter (fun n -> n.Security_node.node_type = Security_node.Def) sorted in
    
    List.iter (fun node ->
      if node.Security_node.node_type = Security_node.Call then
        (match detect_validation node.Security_node.name with
         | Some (kind, receiver_opt) ->
             (* Use receiver if available (e.g., 'path' from 'path.starts_with?') *)
             (match receiver_opt with
              | Some receiver ->
                  let enclosing = List.find_opt (fun d -> d.Security_node.line < node.Security_node.line) (List.rev defs) in
                  (match enclosing with
                   | Some _def ->
                       let end_line = node.Security_node.line + 50 in
                       scopes := { var_name = receiver; file = node.Security_node.file; 
                                   start_line = node.Security_node.line; end_line; 
                                   kind; validated_by = node.Security_node.name } :: !scopes
                   | None -> ())
              | None -> ())
         | None -> ())
    ) sorted
  ) by_file;
  
  List.rev !scopes

(* ── Query functions ────────────────────────────────────────────────── *)

let should_suppress (finding : Finding.t) (scopes : validation list) : bool =
  let rule = finding.Finding.rule in
  (* Only suppress SSRF and path traversal findings *)
  if not (rule = "ssrf" || rule = "path_traversal" || rule = "PathTraversal") then false
  else
    List.exists (fun scope ->
      scope.file = finding.Finding.file &&
      scope.start_line <= finding.Finding.line &&
      finding.Finding.line < scope.end_line &&
      match scope.kind with
      | SchemeCheck -> true   (* starts_with?, end_with? *)
      | MethodCall -> true    (* valid_*, safe_*, check_* *)
      | Regex _ -> true       (* regex match *)
      | Allowlist -> true     (* explicit allowlist check *)
      | Equality -> true      (* == comparison *)
      | ContainsCheck -> false (* includes? is not a strong guard *)
    ) scopes

let analyze (nodes : Security_node.t list) : validation list =
  build_validation_scopes nodes