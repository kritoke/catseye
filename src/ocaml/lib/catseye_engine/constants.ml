(* lib/catseye_engine/constants.ml
   Shared constants for the taint engine — no dependencies. *)

open Base
let ( = ) = Stdlib.( = )

let known_sources = [
  "params"; "request"; "req"; "get_body"; "query"; "io.get_line";
  "dynamic.unsafe_coerce"; "request.get_body"; "user_url"; "user_input";
  "url"; "path"; "cmd"; "command"; "input"; "env"; "ARGV"; "STDIN"; "gets";
  (* Additional common taint sources — B3 expansion *)
  "event"; "payload"; "body"; "data"; "msg"; "message";
  "headers"; "cookie"; "session";
  "form"; "form_data"; "raw_params";
  (* Nim stdlib taint sources *)
  "os.getEnv"; "os.getEnvOrDefault"; "os.commandLineParams"; "os.paramStr"; "os.paramCount";
  "stdin.readLine"; "readLine"; "readFile";
  "httpclient.getContent"; "httpclient.postContent"; "httpclient.get"; "httpclient.post";
  "net.recv"; "net.recvFrom"; "net.recvLine"; "asyncnet.recv"; "asyncnet.recvLine";
  "streams.readLine"; "streams.readAll"; "streams.readStr";
  "uri.parseUri"; "json.parseJson";
]

let known_sanitizers = [
  "URI.encode"; "URI.decode"; "Path.posix"; "Path.basename";
  "Path.dirname"; "String.strip"; "String.trim"; "String.slice"; "Int.parse";
  "Float.parse"; "validator."; "sanitize."; "escape."; "encode."; "cgi.escape";
  "html.escape";
  (* SSRF validation functions — these sanitize URLs *)
  "check_ssrf"; "check_ssrf_url"; "validate_url"; "is_valid_url"; "allowlisted_url?"; "valid_url?"; "url_valid?";
  (* Generic validation function patterns — matches validate_*, check_*, verify_*, guard_* functions.
     When a validation function returns successfully, the data is considered sanitized. *)
  "validate_"; "check_"; "verify_"; "guard_"; "validate"; "check"; "verify"; "guard";
  (* Hash/digest functions produce deterministic output — safe for filenames and cache keys.
     Cryptographic hashes break taint because the output is not controllable by input
     beyond collision resistance. A SHA256 hash cannot contain ../ or other traversal.
     This covers: Digest::MD5.hexdigest, Digest::SHA256.hexdigest,
     OpenSSL::Digest.new("SHA256").update(x).hexdigest, Base64.encode, etc. *)
  "Digest::MD5.hexdigest"; "Digest::SHA256.hexdigest";
  "Base64.encode"; "Base64.strict_encode";
  "File.expand_path";
  (* OpenSSL digest methods — deterministic output *)
  "OpenSSL::Digest";
  (* Common hash/digest function patterns — hex digest output is bounded *)
  "hash_for_url"; "hash_for";
  "favicon_hash";
  "hexdigest"; "hexstring"; "to_hex";
  "SHA256"; "SHA512"; "SHA1"; "MD5";
  (* Functions that return sanitized/validated paths *)
  "get_or_fetch";
  (* Safe path/tempfile generation — output is not user-controlled *)
  "Random::Secure";
  "Tempfile";
  "Dir.mktmpdir";
  "File.tempname";
  "mkstemp";
  (* Schema/config validation — parsing trusted config files is safe *)
  "Config.from_json"; "Config.from_yaml"; "Config.parse";
  "validate_yaml_structure"; "validate_config";
  "load_config"; "read_config";
]

(* Prefix match: [name] starts with one of the known source prefixes.
   Handles both plain names like "params" and qualified names like "req.params". *)
let is_source ?(extra = []) name =
  List.exists ~f:(fun s ->
    let len = String.length s in
    String.length name >= len && Stdlib.String.sub name 0 len = s
  ) (known_sources @ extra)

(* Substring match: [name] contains one of the known sanitizer patterns.
   This handles both plain names and qualified names like "FaviconStorage.get_or_fetch". *)
let is_sanitizer ?(extra = []) name =
  List.exists ~f:(fun s ->
    let slen = String.length s in
    let nlen = String.length name in
    slen > 0 && (
      (s.[slen - 1] = '.' && nlen >= slen && Stdlib.String.sub name 0 slen = s)
      || (let rec check i =
            i + slen <= nlen && (
              Stdlib.String.sub name i slen = s || check (i + 1)
            )
          in check 0)
    )
  ) (known_sanitizers @ extra)