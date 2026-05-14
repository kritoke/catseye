(* lib/catseye_engine/constants.ml
   Shared constants for the taint engine — no dependencies. *)

let known_sources = [
  "params"; "request"; "req"; "get_body"; "query"; "io.get_line";
  "dynamic.unsafe_coerce"; "request.get_body"; "user_url"; "user_input";
  "url"; "path"; "cmd"; "command"; "input"; "env"; "ARGV"; "STDIN"; "gets";
  (* Additional common taint sources — B3 expansion *)
  "event"; "payload"; "body"; "data"; "msg"; "message";
  "headers"; "cookie"; "session";
  "form"; "form_data"; "raw_params";
]

let known_sanitizers = [
  "URI.encode"; "URI.decode"; "Path.posix"; "Path.basename";
  "Path.dirname"; "String.strip"; "String.trim"; "String.slice"; "Int.parse";
  "Float.parse"; "validator."; "sanitize."; "escape."; "encode."; "cgi.escape";
  "html.escape";
  (* Hash/digest functions produce deterministic output — safe for filenames *)
  "Digest::MD5.hexdigest"; "Digest::SHA256.hexdigest";
  "Base64.encode"; "Base64.strict_encode";
  "File.expand_path";
  (* OpenSSL digest methods — deterministic output *)
  "OpenSSL::Digest";
  (* Common hash/digest function patterns *)
  "hash_for_url"; "hash_for";
  "hexdigest"; "hexstring";
  "favicon_hash";
  (* Functions that return sanitized/validated paths *)
  "get_or_fetch";
  (* Safe path/tempfile generation — output is not user-controlled *)
  "Random::Secure";
  "Tempfile";
  "Dir.mktmpdir";
  "File.tempname";
  "mkstemp";
  (* Validation functions — validate_path!, validate_and_resolve_path!, etc. *)
  "validate_";
]

(* Prefix match: [name] starts with one of the known source prefixes.
   Handles both plain names like "params" and qualified names like "req.params". *)
let is_source ?(extra = []) name =
  List.exists (fun s ->
    let len = String.length s in
    String.length name >= len && String.sub name 0 len = s
  ) (known_sources @ extra)

(* Substring match: [name] contains one of the known sanitizer patterns.
   This handles both plain names and qualified names like "FaviconStorage.get_or_fetch". *)
let is_sanitizer ?(extra = []) name =
  List.exists (fun s ->
    let slen = String.length s in
    let nlen = String.length name in
    slen > 0 && (
      (* Prefix match for patterns ending with '.' (wildcard-like) *)
      (s.[slen - 1] = '.' && nlen >= slen && String.sub name 0 slen = s)
      (* Substring match for exact patterns *)
      || (let rec check i =
            i + slen <= nlen && (
              String.sub name i slen = s || check (i + 1)
            )
          in check 0)
    )
  ) (known_sanitizers @ extra)