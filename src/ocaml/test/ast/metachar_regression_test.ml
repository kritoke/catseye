(* test/ast/metachar_regression_test.ml
   Regression guard for the command-injection fix in tree-sitter invocations.

   The fixture files in test/fixtures/metachar/ have names containing shell
   metacharacters (`'; touch catseye-pwned-marker; '.nim`). If a shell-command
   construction site ever regresses to unquoted interpolation, the embedded
   `touch` executes and creates ./catseye-pwned-marker in the test's CWD.
   This test asserts that never happens.

   Fixed sites: crystal_ts.ml parse_xml_file, nim_mapper.ml parse_file
   (and, by pattern, every mapper using Filename.quote).
*)

let marker = "catseye-pwned-marker"

(* dune's cwd differs between run styles: probe both candidate locations *)
let fixture_dir =
  match List.find_opt Sys.file_exists [
    "test/fixtures/metachar";          (* cwd = src/ocaml *)
    "fixtures/metachar";                (* cwd = src/ocaml/test *)
    "../fixtures/metachar";             (* cwd = src/ocaml/test/ast *)
    "../../test/fixtures/metachar";     (* cwd = src/ocaml/lib/... (defensive) *)
  ] with
  | Some d -> d
  | None -> "test/fixtures/metachar"

let nim_fixture = Filename.concat fixture_dir ("'; touch " ^ marker ^ "; '.nim")
let cr_fixture = Filename.concat fixture_dir ("'; touch " ^ marker ^ "; '.cr")

let () =
  (* Clean any stale marker first *)
  (try Sys.remove marker with _ -> ());

  Printf.printf "=== Metacharacter filename regression test ===\n";
  Printf.printf "nim fixture: %s\n" nim_fixture;
  Printf.printf "cr fixture:  %s\n" cr_fixture;
  Printf.printf "nim fixture exists: %b\n" (Sys.file_exists nim_fixture);
  Printf.printf "cr fixture exists:  %b\n" (Sys.file_exists cr_fixture);

  (* Part 1: Nim path — exercises Nim_mapper.parse_file's tree-sitter command *)
  (match Sys.file_exists nim_fixture with
   | false -> Printf.printf "SKIP: nim fixture missing\n"
   | true ->
     (* Grammar resolution mirrors the mapper: env var, then ~/.tree-sitter/nim.so *)
     let grammar = try Some (Sys.getenv "TREE_SITTER_NIM_GRAMMAR")
                   with Not_found ->
                     let home = try Sys.getenv "HOME" with Not_found -> "" in
                     let p = Filename.concat home ".tree-sitter/nim.so" in
                     if Sys.file_exists p then Some p else None
     in
     match grammar with
     | None -> Printf.printf "SKIP: nim grammar not available\n"
     | Some g ->
       Unix.putenv "TREE_SITTER_NIM_GRAMMAR" g;
       (match Catseye_ast.Parse.parse_file ~extractor_cmds:None ~path:nim_fixture with
        | Ok m ->
          Printf.printf "nim parse: OK (%s, %d items)\n"
            (Catseye_ast.Types.lang_to_string m.Catseye_ast.Types.mod_lang)
            (List.length m.Catseye_ast.Types.mod_items)
        | Error e ->
          (* Parse errors are acceptable — a metachar-named file may not parse.
             The guard is the marker file, not parse success. *)
          Printf.printf "nim parse: Error (acceptable): %s\n" e.Catseye_ast.Error.message));

  (* Part 2: Crystal tree-sitter path — exercises Crystal_ts.parse_xml_file's
     fixed command construction (crystal_ts.ml). *)
  (match Sys.file_exists cr_fixture with
   | false -> Printf.printf "SKIP: cr fixture missing\n"
   | true ->
     let home = try Sys.getenv "HOME" with Not_found -> "" in
     let grammar = Filename.concat home ".tree-sitter/crystal/parser.so" in
     if not (Sys.file_exists grammar) then
       Printf.printf "SKIP: crystal grammar not available at %s\n" grammar
     else begin
       Unix.putenv "TREE_SITTER_CRYSTAL_GRAMMAR" grammar;
       (try
          let _ = Catseye_engine.Crystal_ts.parse_xml_file cr_fixture in
          Printf.printf "crystal ts parse: OK\n"
        with e ->
          (* failwith/parse failure acceptable — marker is the guard *)
          Printf.printf "crystal ts parse: raised (acceptable): %s\n"
            (Printexc.to_string e))
     end);

  (* THE assertion: the embedded command must never have executed *)
  if Sys.file_exists marker then begin
    (try Sys.remove marker with _ -> ());
    Printf.printf "FAIL: %s was created — shell injection regression!\n" marker;
    exit 1
  end;
  Printf.printf "PASS: no marker file created — quoting holds\n";
  Printf.printf "=== All metachar regression checks passed ===\n"
