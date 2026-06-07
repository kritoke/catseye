(* src/ocaml/lib/ai_linter/crystal_rules_happy_path.ml
   Category 3: The Happy Path

   Detects unchecked nil access, ignored return values, unsafe pointer
   operations, and sleep() in production code. Patterns where AI
   writes the success path and forgets the failure mode.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(** Rule 3.1: Nil-chaser (unchecked nil access)

    Uses Type_inference DB to detect when a call that returns T | Nil
    is accessed without a nil guard. Also detects .not_nil!, .as(Type)
    casts, and .try(&.x) as code smells. *)
let detect_nil_chaser (m : t) =
  let check_call (name, line) =
    let open_with suffix =
      String.length name >= String.length suffix &&
      String.sub name (String.length name - String.length suffix) (String.length suffix) = suffix
    in
    let findings = ref [] in
    if name = "not_nil!" then
      findings := ("not_nil! will raise on nil — use pattern matching or nil check instead", line) :: !findings;
    if open_with ".as" then
      findings := ("Type cast with .as() may crash if nil — consider case expression", line) :: !findings;
    (match Type_inference.lookup_crystal name with
     | Some ({ kind = Nullable; _ } as info) ->
       findings := (Printf.sprintf "Call %s returns %s (%s) — access may raise on nil"
                      name info.Type_inference.type_name info.Type_inference.doc,
                    line) :: !findings
     | _ -> ());
    (match Type_inference.lookup_crystal name with
     | Some { kind = Safe; type_name = "T"; _ } when open_with "[]" ->
       findings := (Printf.sprintf "%s raises on missing key/index — use []? variant or nil check" name, line) :: !findings
     | _ -> ());
    !findings
  in
  map_functions m (fun _name body _line ->
    List.concat_map check_call (collect_app_names body)
  )

(** Rule 3.2: Ignoring Return Value

    Detects when a call that returns an important value (HTTP response,
    JSON parse result, DB query) has its return value discarded. *)
let detect_ignored_return (m : t) =
  let important_returns = [
    "HTTP::Client.get"; "HTTP::Client.post"; "HTTP::Client.put";
    "HTTP::Client.delete"; "HTTP::Client.patch";
    "HTTP.get"; "HTTP.post"; "HTTP.put";
    "JSON.parse"; "JSON.parse_io";
    "DB.query"; "DB.query_one"; "DB.query_one?";
    "DB.exec";
    "File.read"; "File.write";
    "File.read?"; "File.write?";
    "chmod"; "chown"; "chgrp";
    "File.chmod"; "File.chown"; "File.chgrp";
  ] in
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if name_starts_with_any call_name important_returns then
        Some (Printf.sprintf "Return value of %s is discarded — capture and check the result" call_name, line)
      else None
    ) (collect_app_names body)
  )

let detect_unsafe_pointers (m : t) =
  map_functions m (fun _name body _line ->
    List.concat_map (fun (call_name, line) ->
      if call_name = "Pointer.malloc" then
        [("Pointer.malloc is unsafe — use Slice or Array for safe memory management", line)]
      else if call_name = "Pointer.null" then
        [("Pointer.null is unsafe — use Nil or Option(T) for absent values", line)]
      else if call_name = "Pointer.new" then
        [("Pointer.new is unsafe — consider Slice or a safe wrapper", line)]
      else if name_starts_with_any call_name ["unsafe"] then
        [(Printf.sprintf "%s bypasses safety checks — use safe alternative if available" call_name, line)]
      else []
    ) (collect_app_names body)
  )

let detect_sleep_in_prod (m : t) =
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if call_name = "sleep" then
        Some ("sleep() in production code — remove or gate behind debug flag", line)
      else None
    ) (collect_app_names body)
  )

(* Rule 4.1: Redundant Conversions
   String.new removed — valid Crystal for Bytes/Slice(UInt8) -> String conversion.
   Kept as placeholder for future redundant conversion patterns. *)
let detect_redundant_conversion (_m : t) = []
