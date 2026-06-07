(* src/ocaml/lib/ai_linter/crystal_rules_security.ml
   Categories 5 & 6: The Mute Trap / The Copier (Security)

   Detects hardcoded secrets, hardcoded URLs/IPs, and string
   interpolation in queries (injection vector).
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(* Rule 4.1: Redundant Conversions
   String.new removed — valid Crystal for Bytes/Slice(UInt8) -> String conversion.
   Kept as placeholder for future redundant conversion patterns. *)
let detect_redundant_conversion (_m : t) = []

(* Rule 5.1: Hardcoded Secrets *)
let detect_hardcoded_secrets (m : t) =
  let pem_marker = "-----BEGIN RSA PRIVATE KEY-----" in
  let secret_prefixes = [
    "sk_"; "sk_live_"; "sk_test_";
    "ghp_"; "gho_"; "ghu_"; "ghs_";
    "AKIA"; "ASIA";
    "AIza";
    "xoxb-"; "xoxp-"; "xoxa-";
    "eyJ";
    pem_marker;
  ] in
  let is_likely_secret s =
    String.length s >= 20 &&
    List.exists (fun prefix ->
      String.length prefix <= String.length s &&
      String.sub s 0 (String.length prefix) = prefix
    ) secret_prefixes
  in
  map_functions m (fun fname body _line ->
    List.concat_map (fun (e, s) ->
      match e.expr_value with
      | ELiteral (LString _) when is_likely_secret s ->
        let masked = String.sub s 0 (min 8 (String.length s)) ^ "..." in
        [Printf.sprintf "Potential hardcoded secret in '%s': %s — use environment variables or config"
           fname masked, e.expr_location.start.line]
      | _ -> []
    ) (collect_string_literals body)
  )

(* Rule 6.3: Hardcoded URLs/IPs *)
let detect_hardcoded_urls (m : t) =
  let is_urlish s =
    String.length s >= 8 &&
    (String.sub s 0 7 = "http://" || String.sub s 0 8 = "https://") &&
    not (s = "http://" || s = "https://" || s = "http://www." || s = "https://www.")
  in
  let is_loopback_or_meta s =
    List.mem s ["0.0.0.0"; "127.0.0.1"; "255.255.255.255"; "0.0.0.1"]
  in
  let is_ipish s =
    let parts = String.split_on_char '.' s in
    List.length parts = 4 &&
    List.for_all (fun p -> try ignore (Stdlib.int_of_string p); true with _ -> false) parts &&
    not (is_loopback_or_meta s)
  in
  let collect_suspicious_strings (e : expr) : (string * int) list =
    List.concat_map (fun (e, s) ->
      if is_urlish s || is_ipish s then [(s, e.expr_location.start.line)]
      else []
    ) (collect_string_literals e)
  in
  map_functions m (fun _name body _line ->
    List.map (fun (s, line) ->
      Printf.sprintf "Hardcoded URL/IP: %s — use config or environment variable" s, line
    ) (collect_suspicious_strings body)
  )

(* Rule 7.1: String Interpolation in Query
   Detects string interpolation or concatenation patterns that build
   SQL/HTML/shell commands — a classic injection vector. *)
let detect_string_interpolation_in_query (m : t) =
  let query_methods = [
    "DB.query"; "DB.exec"; "DB.query_one"; "DB.query_one?";
    "database.query"; "db.query"; "repo.query"; "repo.exec";
  ] in
  let is_query name = name_ends_with_any name query_methods in
  let has_interpolation name =
    name = "String.interpolation" || name = "String.concat" || name = "sprintf"
  in
  map_functions m (fun _name body _line ->
    let calls = collect_app_names body in
    let has_interp = List.exists (fun (n, _) -> has_interpolation n) calls in
    let has_q = List.exists (fun (n, _) -> is_query n) calls in
    if has_interp && has_q then
      let line = match List.find_opt (fun (n, _) -> is_query n) calls with
        | Some (_, l) -> l | None -> 0
      in
      [("String interpolation used near database query — use parameterized queries instead", line)]
    else []
  )
