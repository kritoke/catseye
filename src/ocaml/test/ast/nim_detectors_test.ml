(* test/ast/nim_detectors_test.ml
   Positive/negative golden test for the expanded Nim AI-linter detectors.

   Asserts every NEW rule fires at least once on the fixture, and that the
   system-builtins-only proc produces zero hallucinated-function findings
   (REQ-6: no FPs on valid Nim stdlib).

   Skips gracefully when the Nim grammar is unavailable. *)

let () =
  Printf.printf "=== Nim detector expansion test ===\n";

  let grammar = try Some (Sys.getenv "TREE_SITTER_NIM_GRAMMAR")
    with Not_found ->
      let home = try Sys.getenv "HOME" with Not_found -> "" in
      let p = Filename.concat home ".tree-sitter/nim.so" in
      if Sys.file_exists p then Some p else None
  in
  (match grammar with
   | None -> Printf.printf "SKIP: nim grammar not available\n"; exit 0
   | Some g -> Unix.putenv "TREE_SITTER_NIM_GRAMMAR" g);

  let candidates = [
    "tests/fixtures/nim/detectors_fixture.nim";
    "../../tests/fixtures/nim/detectors_fixture.nim";
    "../../../tests/fixtures/nim/detectors_fixture.nim";
    "../../../../tests/fixtures/nim/detectors_fixture.nim";
  ] in
  let fixture =
    match Stdlib.List.find_opt Sys.file_exists candidates with
    | Some f -> f
    | None -> Printf.printf "SKIP: fixture missing\n"; exit 0
  in

  match Catseye_ast.Parse.parse_file ~extractor_cmds:None ~path:fixture with
  | Error e -> Printf.printf "FAIL: parse error: %s\n" e.Catseye_ast.Error.message; exit 1
  | Ok mod_ ->
    let findings = Ai_linter.Nim_rules.analyze_module mod_ in
    let rules_of r = List.length (Stdlib.List.filter (fun (f : Ai_linter.Types.finding) ->
      f.Ai_linter.Types.rule_id = r) findings) in

    Printf.printf "total findings: %d\n" (Stdlib.List.length findings);

    (* Every new detector must fire at least once *)
    let new_rules = [
      "nim-unused-param"; "nim-shadowed-var"; "nim-empty-rescue";
      "nim-debug-leftover"; "nim-deprecated-api"; "nim-mass-assignment";
      "nim-eval-usage";
    ] in
    let missing = Stdlib.List.filter (fun r -> rules_of r = 0) new_rules in
    Stdlib.List.iter (fun r -> Printf.printf "  %-22s %d\n" r (rules_of r)) new_rules;
    if missing <> [] then begin
      Printf.printf "FAIL: detectors did not fire: %s\n" (String.concat ", " missing);
      exit 1
    end;

    (* Old detectors still present *)
    (if rules_of "nim-bare-except" = 0 then begin
       Printf.printf "FAIL: nim-bare-except regressed\n"; exit 1
     end);

    (* REQ-6: system builtins must not be flagged as hallucinations.
       The fixture's `systemBuiltinsOnly` uses len/contains/startsWith/
       endsWith/add/open/raise. Assert the global hallucination count is 0 —
       the fixture contains no intentional hallucinations. *)
    let hall = rules_of "nim-hallucinated-function" in
    Printf.printf "nim-hallucinated-function: %d (must be 0 on this fixture)\n" hall;
    if hall > 0 then begin
      Stdlib.List.iter (fun (f : Ai_linter.Types.finding) ->
        if f.Ai_linter.Types.rule_id = "nim-hallucinated-function" then
          Printf.printf "  FP: %d %s\n" f.Ai_linter.Types.line f.Ai_linter.Types.message)
        findings;
      Printf.printf "FAIL: hallucination FPs on valid Nim stdlib\n";
      exit 1
    end;

    Printf.printf "PASS: all new detectors fire; stdlib builtins clean\n"
