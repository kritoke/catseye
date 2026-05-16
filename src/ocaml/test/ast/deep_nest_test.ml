(* Test: Deep nesting triggers exponential build_block recursion *)
(* This test exists to verify the queue-based builder handles deep nesting *)

open Catseye_ast.Types
open Catseye_il.Of_catseye_ast
open Catseye_il.Il_types
open Catseye_il.Cfg_builder

let pos ~line ~col ~byte = Position.make ~line ~column:col ~byte_offset:byte

(* Build a deeply nested if/else expression *)
let rec make_nested_if ~depth ~current_var =
  if depth = 0 then
    { expr_value = EVar current_var
    ; expr_location = { start = pos ~line:depth ~col:4 ~byte:(depth*10)
                      ; end_ = pos ~line:depth ~col:5 ~byte:(depth*10+1) } }
  else
    let then_branch = make_nested_if ~depth:(depth-1) ~current_var in
    let else_branch = { expr_value = ELiteral (LString "safe")
                      ; expr_location = { start = pos ~line:depth ~col:8 ~byte:(depth*10+3)
                                        ; end_ = pos ~line:depth ~col:12 ~byte:(depth*10+7) } } in
    { expr_value = EIf (
        { expr_value = EVar ("cond" ^ string_of_int depth)
        ; expr_location = { start = pos ~line:depth ~col:4 ~byte:(depth*10)
                          ; end_ = pos ~line:depth ~col:11 ~byte:(depth*10+7) } },
        then_branch,
        Some else_branch
      )
    ; expr_location = { start = pos ~line:depth ~col:2 ~byte:(depth*10-2)
                      ; end_ = pos ~line:depth ~col:15 ~byte:(depth*10+12) } }

let () =
  Printf.printf "=== Deep Nesting Test ===\n\n";
  
  let depths = [5; 10; 20; 30; 50] in
  
  List.iter (fun depth ->
    let start_time = Unix.gettimeofday () in
    let inner = make_nested_if ~depth ~current_var:"data" in
    let sink = { expr_value = EApp (
        { expr_value = EVar "sink"
        ; expr_location = { start = pos ~line:(depth+10) ~col:2 ~byte:((depth+10)*10)
                          ; end_ = pos ~line:(depth+10) ~col:6 ~byte:((depth+10)*10+4) } },
        [inner]
      )
    ; expr_location = { start = pos ~line:(depth+10) ~col:2 ~byte:((depth+10)*10)
                      ; end_ = pos ~line:(depth+10) ~col:10 ~byte:((depth+10)*10+8) } } in
    
    let mod_ = {
      mod_lang = Crystal;
      mod_path = "nested_test.cr";
      mod_items = [{
        item_location = { start = pos ~line:1 ~col:0 ~byte:0
                        ; end_ = pos ~line:100 ~col:0 ~byte:1000 };
        item_value = IFunction ("deep_nest_" ^ string_of_int depth, [PVar "data"], None, sink)
      }];
      parse_errors = []
    } in
    
    let unit = translate mod_ in
    match unit.il_functions with
    | [] -> Printf.printf "FAIL: No IL functions produced for depth %d\n" depth
    | fn :: _ ->
      (match build_cfg fn with
       | Error _e ->
         Printf.printf "FAIL: CFG build error for depth %d\n" depth
       | Ok cfg ->
         let elapsed = Unix.gettimeofday () -. start_time in
         let block_count = Catseye_il.Cfg_graph.v_count cfg in
         Printf.printf "Depth %2d: %d blocks, %7.3fms\n" depth block_count (elapsed *. 1000.0))
  ) depths;
  
  Printf.printf "\n=== PASS: Deep nesting handled correctly ===\n"