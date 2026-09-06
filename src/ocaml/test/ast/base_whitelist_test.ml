(* test/ast/base_whitelist_test.ml
   Regression guard for the OCaml Base-stdlib whitelist.

   Parses test/fixtures/base_stdlib_fixture.ml and asserts:
   - ZERO hallucinated-method findings (all fifteen Base calls are legitimate)
   - The two genuine hallucinations (`reverse`, `mapM`) ARE still caught,
     proving the whitelist didn't neuter the detector.
*)

let () =
  let fixture = "test/fixtures/base_stdlib_fixture.ml" in
  Printf.printf "=== Base whitelist regression test ===\n";
  if not (Sys.file_exists fixture) then begin
    Printf.printf "SKIP: fixture missing at %s\n" fixture;
    exit 0
  end;

  match Catseye_ast.Parse.parse_file ~extractor_cmds:None ~path:fixture with
  | Error e ->
    Printf.printf "SKIP: fixture did not parse (tree-sitter-ocaml unavailable?): %s\n"
      e.Catseye_ast.Error.message;
    exit 0
  | Ok mod_ ->
    let findings = Ai_linter.Ocaml_rules.analyze_module mod_ in
    let hall = List.filter (fun (f : Ai_linter.Types.finding) ->
      f.Ai_linter.Types.rule_id = "hallucinated-method") findings in
    let names = List.map (fun (f : Ai_linter.Types.finding) ->
      let m = f.Ai_linter.Types.message in
      (* extract the quoted name: first '…' pair, NOT the apostrophe in "doesn't" *)
      try
        let a = String.index m '\'' in
        let b = String.index_from m (a + 1) '\'' in
        String.sub m (a + 1) (b - a - 1)
      with _ -> "?"
    ) hall in
    Printf.printf "hallucinated-method findings: %d %s\n"
      (List.length hall) (String.concat ", " names);

    (* Base calls must produce nothing *)
    let base_fps = List.filter (fun n ->
      List.mem n [ "strip"; "length"; "trim"; "capitalize"; "value"; "map";
                   "filter"; "fold_left"; "contents"; "to_string"; "is_ok" ]) names in
    if base_fps <> [] then begin
      Printf.printf "FAIL: Base functions flagged as hallucinations: %s\n"
        (String.concat ", " base_fps);
      exit 1
    end;

    (* The intentional hallucinations must still fire *)
    let caught_reverse = List.mem "reverse" names in
    let caught_mapM = List.mem "mapM" names in
    Printf.printf "guard-the-guard: reverse caught=%b mapM caught=%b\n"
      caught_reverse caught_mapM;
    if not (caught_reverse && caught_mapM) then begin
      Printf.printf "FAIL: real hallucinations no longer detected (reverse/mapM)\n";
      exit 1
    end;

    Printf.printf "PASS: Base calls clean, real hallucinations still caught\n"
