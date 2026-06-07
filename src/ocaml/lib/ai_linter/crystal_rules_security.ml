(* src/ocaml/lib/ai_linter/crystal_rules_security.ml
   Categories 5 & 6: The Mute Trap / The Copier (Security)

   Detects hardcoded secrets, hardcoded URLs/IPs, and string
   interpolation in queries (injection vector).

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_redundant_conversion (_m : t) =
  []

(* ── Category 5: The Mute Trap (Security) ───────────────────────────── *)

(* ── Category 5: The Mute Trap (Security) ───────────────────────────── *)

(** Rule 5.1: Hardcoded Secrets *)

let detect_hardcoded_secrets (m : t) =
  let pem_marker = String.make 5 '-' ^ "BEGIN RSA PRIVATE KEY" ^ String.make 5 '-' in
  let secret_prefixes = [
    "sk_"; "sk_live_"; "sk_test_";
    "ghp_"; "gho_"; "ghu_"; "ghs_";
    "AKIA"; "ASIA";
    "AIza";
    "xoxb-"; "xoxp-"; "xoxa-";
    "eyJ";
    pem_marker;
  ] in
  
  let is_likely_secret (s : string) =
    String.length s >= 20 &&
    List.exists (fun prefix ->
      String.length prefix <= String.length s &&
      String.sub s 0 (String.length prefix) = prefix
    ) secret_prefixes
  in
  let rec collect_string_literals (e : expr) : (string * int) list =
    match e.expr_value with
    | ELiteral (LString s) when is_likely_secret s ->
      [(s, e.expr_location.start.line)]
    | ELiteral _ -> []
    | EApp (fn, args) ->
      collect_string_literals fn @ List.concat_map collect_string_literals args
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_string_literals e1 @ collect_string_literals e2
    | EIf (_, then_, else_) ->
      collect_string_literals then_ @
      (match else_ with Some e -> collect_string_literals e | None -> [])
    | EBlock es -> List.concat_map collect_string_literals es
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      List.concat_map (fun (s, line) ->
        let masked = String.sub s 0 (min 8 (String.length s)) ^ "..." in
        [Printf.sprintf "Potential hardcoded secret in '%s': %s — use environment variables or config" name masked, line]
      ) (collect_string_literals body)
    | _ -> []
  ) m.mod_items

(* ── Category 6: The Copier (Copy-Paste) ────────────────────────────── *)

(** Rule 6.3: Hardcoded URLs/IPs *)

let detect_hardcoded_urls (m : t) =
  let is_urlish (s : string) =
    String.length s >= 8 &&
    (String.sub s 0 7 = "http://" || String.sub s 0 8 = "https://") &&
    not (s = "http://" || s = "https://" || s = "http://www." || s = "https://www.")
  in
  let is_loopback_or_meta (s : string) =
    s = "0.0.0.0" || s = "127.0.0.1" || s = "255.255.255.255" || s = "0.0.0.1"
  in
  let is_ipish (s : string) =
    let parts = String.split_on_char '.' s in
    List.length parts = 4 &&
    List.for_all (fun p -> try let _ = Stdlib.int_of_string p in true with _ -> false) parts &&
    not (is_loopback_or_meta s)
  in
  let rec collect_suspicious_strings (e : expr) : (string * int) list =
    match e.expr_value with
    | ELiteral (LString s) when is_urlish s || is_ipish s ->
      [(s, e.expr_location.start.line)]
    | ELiteral _ -> []
    | EApp (fn, args) ->
      collect_suspicious_strings fn @ List.concat_map collect_suspicious_strings args
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_suspicious_strings e1 @ collect_suspicious_strings e2
    | EBlock es -> List.concat_map collect_suspicious_strings es
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := List.concat_map (fun (s, line) ->
        [Printf.sprintf "Hardcoded URL/IP: %s — use config or environment variable" s, line]
      ) (collect_suspicious_strings body) @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 7: The Confused (Language Feature Misuse) ─────────────── *)

(** Rule 7.1: Blanket Rescue
    Detects bare `rescue` or `rescue ex` without specifying an exception type.
    AI often generates blanket rescues that swallow all errors silently. *)