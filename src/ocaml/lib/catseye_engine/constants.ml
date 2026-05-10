(* lib/catseye_engine/constants.ml
   Shared constants for the taint engine — no dependencies. *)

let known_sources = [
  "params"; "request"; "req"; "get_body"; "query"; "io.get_line";
  "dynamic.unsafe_coerce"; "request.get_body"; "user_url"; "user_input";
  "url"; "path"; "cmd"; "command"; "input"; "env"; "ARGV"; "STDIN"; "gets";
]

let known_sanitizers = [
  "URI.parse"; "URI.encode"; "URI.decode"; "Path.posix"; "Path.basename";
  "Path.dirname"; "String.strip"; "String.trim"; "String.slice"; "Int.parse";
  "Float.parse"; "validator."; "sanitize."; "escape."; "encode."; "cgi.escape";
  "html.escape";
]

(* Prefix match: [name] starts with one of the known source prefixes.
   Handles both plain names like "params" and qualified names like "req.params". *)
let is_source ?(extra = []) name =
  List.exists (fun s ->
    let len = String.length s in
    String.length name >= len && String.sub name 0 len = s
  ) (known_sources @ extra)

(* Prefix match: [name] starts with one of the known sanitizer prefixes. *)
let is_sanitizer ?(extra = []) name =
  List.exists (fun s -> String.starts_with ~prefix:s name)
    (known_sanitizers @ extra)