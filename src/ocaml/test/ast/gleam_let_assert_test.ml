(* test/ast/gleam_let_assert_test.ml
   Regression test for catseye-iru.2: detect_let_assert must skip test files.

   The old local is_test_file compared a 9-char substring against the 11-char
   string "_test.gleam" and its other disjunct required a bare "_test" suffix
   (no extension), so it never matched real Gleam paths — let assert in
   *_test.gleam files was still flagged as an error.

   Hermetic: constructs the CatseyeAST module record directly, so no
   tree-sitter grammar or fixture files are required. The module path is
   controlled explicitly because the repo's own tests/ directory trips the
   shared is_test_file "/tests/" marker. *)

open Catseye_ast.Types

let pos ~line : Position.t =
  { line; column = 1; byte_offset = 0 }

let rng ~line : range =
  { start = pos ~line; end_ = pos ~line }

(* fn crashy() { let assert Ok(x) = fetch() } *)
let let_assert_fn : item =
  let body =
    { expr_value =
        EBlock
          [ { expr_value =
                ELetAssert
                  ( PVar "x",
                    { expr_value =
                        EApp
                          ( { expr_value = EVar "fetch"; expr_location = rng ~line:3 },
                            [] );
                      expr_location = rng ~line:3 },
                    { expr_value = EUnit; expr_location = rng ~line:3 } );
              expr_location = rng ~line:3 } ]
    ; expr_location = rng ~line:3 }
  in
  { item_value = IFunction ("crashy", [], None, body)
  ; item_location = rng ~line:2 }

let analyze ~path : Ai_linter.Types.finding list =
  let m : t =
    { mod_lang = Gleam; mod_path = path; mod_items = [ let_assert_fn ]
    ; parse_errors = [] }
  in
  Ai_linter.Gleam_rules.analyze_module m

let has_rule (findings : Ai_linter.Types.finding list) (rule_id : string) : bool =
  List.exists (fun f -> f.Ai_linter.Types.rule_id = rule_id) findings

let failures = ref []

let check (label : string) (cond : bool) =
  if cond then Printf.printf "PASS: %s\n" label
  else begin
    Printf.printf "FAIL: %s\n" label;
    failures := label :: !failures
  end

let () =
  (* src file: let assert outside tests must be flagged *)
  let src_findings = analyze ~path:"/project/src/handler.gleam" in
  check "let assert in src file is flagged" (has_rule src_findings "let-assert");

  (* test file (the case the old is_test_file never matched): must be silent *)
  let test_findings = analyze ~path:"/project/test/handler_test.gleam" in
  check "let assert in test/ file is not flagged" (not (has_rule test_findings "let-assert"));

  (* tests/ directory spelling as well *)
  let tests_dir_findings = analyze ~path:"/project/tests/handler_test.gleam" in
  check "let assert in tests/ file is not flagged"
    (not (has_rule tests_dir_findings "let-assert"));

  if !failures <> [] then begin
    Printf.printf "%d failure(s)\n" (List.length !failures);
    exit 1
  end;
  Printf.printf "All let-assert path checks passed\n"
