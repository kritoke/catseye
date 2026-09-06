(* test/ast/gleam_result_in_map_test.ml
   Regression test for catseye-iru.3: detect_result_in_map must gate on the
   callee name.

   The old version matched ANY single-argument call whose argument was a
   lambda returning Result — so `each(items, fn(x) { int.parse(x) })` was
   mislabeled "list.map with Result-returning lambda" — while genuine
   two-argument list.map(items, fn) calls fell through the single-arg match
   entirely and were never reported.

   Hermetic: constructs the CatseyeAST module record directly. *)

open Catseye_ast.Types

let pos ~line : Position.t = { line; column = 1; byte_offset = 0 }
let rng ~line : range = { start = pos ~line; end_ = pos ~line }

(* fn(x) { int.parse(x) } — lambda whose body returns Result *)
let result_lambda ~line : expr =
  { expr_value =
      EFn
        ( [ PVar "x" ],
          { expr_value =
              EApp
                ( { expr_value = EVar "int.parse"; expr_location = rng ~line },
                  [ { expr_value = EVar "x"; expr_location = rng ~line } ] );
            expr_location = rng ~line } )
  ; expr_location = rng ~line }

(* fn(x) { x + 1 } — lambda whose body does NOT return Result *)
let plain_lambda ~line : expr =
  { expr_value =
      EFn
        ( [ PVar "x" ],
          { expr_value =
              EBinOp
                ( { expr_value = EVar "x"; expr_location = rng ~line },
                  "+",
                  { expr_value = ELiteral (LInt "1"); expr_location = rng ~line } );
            expr_location = rng ~line } )
  ; expr_location = rng ~line }

let call ~line (fn : expr) (args : expr list) : expr =
  { expr_value = EApp (fn, args); expr_location = rng ~line }

let var ~line (name : string) : expr =
  { expr_value = EVar name; expr_location = rng ~line }

let dotted ~line (recv : string) (field : string) : expr =
  { expr_value = EFieldAccess (var ~line recv, field)
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

let has_result_in_map (findings : Ai_linter.Types.finding list) : bool =
  List.exists (fun f -> f.Ai_linter.Types.rule_id = "result-in-map") findings

let failures = ref []
let check (label : string) (cond : bool) =
  if cond then Printf.printf "PASS: %s\n" label
  else begin
    Printf.printf "FAIL: %s\n" label;
    failures := label :: !failures
  end

let () =
  (* 1. two-arg list.map(items, fn) with Result lambda — must be flagged
        (the old single-arg match missed this shape entirely) *)
  let case1 =
    call ~line:3 (dotted ~line:3 "list" "map")
      [ var ~line:3 "items"; result_lambda ~line:3 ]
  in
  check "list.map(items, fn) with Result lambda is flagged"
    (has_result_in_map (analyze ~body:case1));

  (* 2. non-map callee with a single lambda argument — must NOT be flagged
        (the old code mislabeled this as list.map) *)
  let case2 = call ~line:4 (var ~line:4 "each") [ result_lambda ~line:4 ] in
  check "each(fn) with Result lambda is not mislabeled as list.map"
    (not (has_result_in_map (analyze ~body:case2)));

  (* 3. bare map(fn) via import gleam/list.{map} — still flagged *)
  let case3 = call ~line:5 (var ~line:5 "map") [ result_lambda ~line:5 ] in
  check "bare map(fn) with Result lambda is flagged"
    (has_result_in_map (analyze ~body:case3));

  (* 4. list.map with a non-Result lambda — must not be flagged *)
  let case4 =
    call ~line:6 (dotted ~line:6 "list" "map")
      [ var ~line:6 "items"; plain_lambda ~line:6 ]
  in
  check "list.map(items, fn) with non-Result lambda is not flagged"
    (not (has_result_in_map (analyze ~body:case4)));

  if !failures <> [] then begin
    Printf.printf "%d failure(s)\n" (List.length !failures);
    exit 1
  end;
  Printf.printf "All result-in-map checks passed\n"
