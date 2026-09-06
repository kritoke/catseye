(* test/ast/gleam_ignored_result_test.ml
   Regression test for catseye-iru.4: detect_ignored_result must only fire
   when the Result-returning call's value is actually dropped.

   The old version collected every application in the function body and
   reported the first one present in the Gleam type DB — so properly handled
   calls (case int.parse(x) { ... } or let r = int.parse(x)) were flagged
   "ignored result" too.

   Hermetic: constructs the CatseyeAST module record directly. *)

open Catseye_ast.Types

let pos ~line : Position.t = { line; column = 1; byte_offset = 0 }
let rng ~line : range = { start = pos ~line; end_ = pos ~line }

let var ~line (name : string) : expr =
  { expr_value = EVar name; expr_location = rng ~line }

(* int.parse(x) — call known to return Result in the Gleam type DB *)
let parse_call ~line : expr =
  { expr_value =
      EApp
        ( { expr_value = EVar "int.parse"; expr_location = rng ~line },
          [ var ~line "x" ] )
  ; expr_location = rng ~line }

let analyze ~(body : expr) : Ai_linter.Types.finding list =
  let m : t =
    { mod_lang = Gleam; mod_path = "/project/src/handler.gleam"
    ; mod_items =
        [ { item_value = IFunction ("run", [], None, body)
          ; item_location = rng ~line:2 } ]
    ; parse_errors = [] }
  in
  Ai_linter.Gleam_rules.analyze_module m

let has_ignored_result (findings : Ai_linter.Types.finding list) : bool =
  List.exists (fun f -> f.Ai_linter.Types.rule_id = "ignored-result") findings

let failures = ref []
let check (label : string) (cond : bool) =
  if cond then Printf.printf "PASS: %s\n" label
  else begin
    Printf.printf "FAIL: %s\n" label;
    failures := label :: !failures
  end

let () =
  (* 1. handled via case — the scrutinee value IS handled: not flagged *)
  let handled_case =
    { expr_value =
        ECase
          ( parse_call ~line:3,
            [ ( PVar "r",
                { expr_value = EVar "r"; expr_location = rng ~line:3 } ) ] )
    ; expr_location = rng ~line:3 }
  in
  check "case int.parse(x) is not flagged as ignored"
    (not (has_ignored_result (analyze ~body:handled_case)));

  (* 2. captured in a binding — the value is assigned, not dropped *)
  let captured =
    { expr_value =
        ELet ( PVar "r",
               parse_call ~line:4,
               { expr_value = EBlock [ var ~line:4 "r" ]
               ; expr_location = rng ~line:4 } )
    ; expr_location = rng ~line:4 }
  in
  check "let r = int.parse(x) is not flagged as ignored"
    (not (has_ignored_result (analyze ~body:captured)));

  (* 3. final expression — the value is the function's return: not flagged *)
  check "int.parse(x) as final/return expression is not flagged"
    (not (has_ignored_result (analyze ~body:(parse_call ~line:5))));

  (* 4. bare non-final statement — the value IS dropped: flagged *)
  let dropped =
    { expr_value =
        EBlock
          [ parse_call ~line:6;
            { expr_value = ELiteral (LString "done")
            ; expr_location = rng ~line:7 } ]
    ; expr_location = rng ~line:6 }
  in
  check "bare int.parse(x) statement is flagged as ignored"
    (has_ignored_result (analyze ~body:dropped));

  (* 5. non-final statement inside a lambda body block: flagged *)
  let dropped_in_lambda =
    { expr_value =
        EBlock
          [ { expr_value =
                EFn
                  ( [ PVar "y" ],
                    { expr_value =
                        EBlock
                          [ parse_call ~line:8;
                            { expr_value = ELiteral (LString "ok")
                            ; expr_location = rng ~line:9 } ]
                    ; expr_location = rng ~line:8 } )
            ; expr_location = rng ~line:8 };
            { expr_value = ELiteral (LString "done")
            ; expr_location = rng ~line:10 } ]
    ; expr_location = rng ~line:8 }
  in
  check "dropped Result call inside lambda body is flagged"
    (has_ignored_result (analyze ~body:dropped_in_lambda));

  if !failures <> [] then begin
    Printf.printf "%d failure(s)\n" (List.length !failures);
    exit 1
  end;
  Printf.printf "All ignored-result checks passed\n"
