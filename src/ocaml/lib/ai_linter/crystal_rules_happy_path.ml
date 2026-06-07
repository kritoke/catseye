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

let detect_nil_chaser (m : t) =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        let findings = [] in
        (* Pattern 1: .not_nil! — forced unwrap *)
        let findings = if name = "not_nil!" then
          ("not_nil! will raise on nil — use pattern matching or nil check instead", line) :: findings
        else findings in
        (* Pattern 2: .as( — type cast that crashes on nil *)
        let findings = if String.length name >= 3 &&
          String.sub name (String.length name - 3) 3 = ".as" then
          ("Type cast with .as() may crash if nil — consider case expression", line) :: findings
        else findings in
        (* Pattern 3: Nullable-returning call accessed without guard *)
        let findings = (match Type_inference.lookup_crystal name with
          | Some ({ kind = Nullable; doc; _ } as info) ->
            (Printf.sprintf "Call %s returns %s (%s) — access may raise on nil"
              name info.Type_inference.type_name doc, line) :: findings
          | _ -> findings) in
        (* Pattern 4: Raising accessor used without rescue *)
        let findings = (match Type_inference.lookup_crystal name with
          | Some { kind = Safe; type_name = "T"; _ } when
              String.length name >= 2 &&
              String.sub name (String.length name - 2) 2 = "[]" ->
            (Printf.sprintf "%s raises on missing key/index — use []? variant or nil check" name, line) :: findings
          | _ -> findings) in
        findings
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule 3.2: Ignoring Return Value
    Detects when a call that returns an important value (HTTP response,
    JSON parse result, DB query) has its return value discarded (no let binding).
    AI often writes `HTTP::Client.get(url)` without capturing the response. *)

let detect_ignored_return (m : t) =
  let important_returns = [
    (* HTTP/DB - errors should be handled *)
    "HTTP::Client.get"; "HTTP::Client.post"; "HTTP::Client.put";
    "HTTP::Client.delete"; "HTTP::Client.patch";
    "HTTP.get"; "HTTP.post"; "HTTP.put";
    "JSON.parse"; "JSON.parse_io";
    "DB.query"; "DB.query_one"; "DB.query_one?";
    "DB.exec";
    (* File I/O - errors should be handled *)
    "File.read"; "File.write";
    "File.read?"; "File.write?";
    (* Permission operations - failures should not be silent *)
    "chmod"; "chown"; "chgrp";
    "File.chmod"; "File.chown"; "File.chgrp";
  ] in
  
  let is_important (name : string) =
    List.exists (fun prefix ->
      String.length name >= String.length prefix &&
      String.sub name 0 (String.length prefix) = prefix
    ) important_returns
  in
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.concat_map (fun (name, line) ->
          if is_important name then
            [Printf.sprintf "Return value of %s is discarded — capture and check the result" name, line]
          else []
        ) (collect_app_names body)
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

let detect_unsafe_pointers (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "Pointer.malloc" then
          [("Pointer.malloc is unsafe — use Slice or Array for safe memory management", line)]
        else if name = "Pointer.null" then
          [("Pointer.null is unsafe — use Nil or Option(T) for absent values", line)]
        else if name = "Pointer.new" then
          [("Pointer.new is unsafe — consider Slice or a safe wrapper", line)]
        else if String.length name >= 6 && String.sub name 0 6 = "unsafe" then
          [(Printf.sprintf "%s bypasses safety checks — use safe alternative if available" name, line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule: Sleep in production code *)

let detect_sleep_in_prod (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "sleep" then [("sleep() in production code — remove or gate behind debug flag", line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(* ── Category 4: The Tangle ─────────────────────────────────────────── *)

(** Rule 4.1: Redundant Conversions
    String.new removed — valid Crystal for Bytes/Slice(UInt8) -> String conversion.
    Kept as placeholder for future redundant conversion patterns. *)