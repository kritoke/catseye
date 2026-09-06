(* test/nim_nimalyzer_test.ml
   Test nimalyzer output parsing and finding conversion.
*)

let () =
  Printf.printf "=== Testing nimalyzer output parsing ===\n";

  (* Test 1: Parse nimalyzer output *)
  let sample_output = {|
# nimalyzer output
src/main.nim:15: hasPragma: error: Procedure 'main' doesn't have pragma 'raises'
src/main.nim:23: complexity: notice: Procedure 'process' has cyclomatic complexity 25
src/main.nim:45: hasDoc: error: Public procedure 'calculate' has no documentation
src/utils.nim:10: namingConv: notice: Variable 'myVar' doesn't follow convention
|} in

  let findings = Catseye_cli.Nimalyzer.parse_output ~output:sample_output in
  Printf.printf "Parsed %d findings\n" (List.length findings);

  List.iter (fun (f : Catseye_cli.Nimalyzer.nimalyzer_finding) ->
    Printf.printf "  %s:%d [%s] %s: %s\n" f.file f.line f.severity f.rule f.message
  ) findings;

  (* Verify parsing *)
  if List.length findings <> 4 then begin
    Printf.printf "FAIL: expected 4 findings, got %d\n" (List.length findings);
    exit 1
  end;

  let first = List.hd findings in
  if first.file <> "src/main.nim" then begin
    Printf.printf "FAIL: expected file 'src/main.nim', got '%s'\n" first.file;
    exit 1
  end;
  if first.line <> 15 then begin
    Printf.printf "FAIL: expected line 15, got %d\n" first.line;
    exit 1
  end;
  if first.rule <> "hasPragma" then begin
    Printf.printf "FAIL: expected rule 'hasPragma', got '%s'\n" first.rule;
    exit 1
  end;
  if first.severity <> "high" then begin
    Printf.printf "FAIL: expected severity 'high', got '%s'\n" first.severity;
    exit 1
  end;

  Printf.printf "Parsing assertions: OK\n";

  (* Test 2: Convert to Catseye findings *)
  let catseye_findings = Catseye_cli.Nimalyzer.to_catseye_findings ~findings ~language:"nim" in
  Printf.printf "Converted %d findings to Catseye format\n" (List.length catseye_findings);

  List.iter (fun (f : Catseye_types.Finding.t) ->
    Printf.printf "  %s:%d [%s] %s: %s\n" f.file f.line f.severity f.rule f.message
  ) catseye_findings;

  let first_cs = List.hd catseye_findings in
  if first_cs.rule <> "nimalyzer.hasPragma" then begin
    Printf.printf "FAIL: expected rule 'nimalyzer.hasPragma', got '%s'\n" first_cs.rule;
    exit 1
  end;
  if first_cs.language <> "nim" then begin
    Printf.printf "FAIL: expected language 'nim', got '%s'\n" first_cs.language;
    exit 1
  end;

  Printf.printf "Conversion assertions: OK\n";

  (* Test 3: Empty output *)
  let empty_findings = Catseye_cli.Nimalyzer.parse_output ~output:"" in
  if List.length empty_findings <> 0 then begin
    Printf.printf "FAIL: expected 0 findings for empty output, got %d\n" (List.length empty_findings);
    exit 1
  end;

  Printf.printf "Empty output test: OK\n";

  (* Test 4: Comment-only output *)
  let comment_findings = Catseye_cli.Nimalyzer.parse_output ~output:"# just a comment\n# another comment\n" in
  if List.length comment_findings <> 0 then begin
    Printf.printf "FAIL: expected 0 findings for comment output, got %d\n" (List.length comment_findings);
    exit 1
  end;

  Printf.printf "Comment output test: OK\n";

  Printf.printf "\n=== All nimalyzer tests passed ===\n"
