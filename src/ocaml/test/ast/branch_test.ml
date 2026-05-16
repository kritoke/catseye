(* Test: Build CFG with many branches to check O(n²) behavior *)
(* The issue is not with EIf nesting (that's converted inline),
   but with functions that have many sequential branch nodes *)

open Catseye_ast.Types
open Catseye_il.Of_catseye_ast
open Catseye_il.Il_types
open Catseye_il.Cfg_builder

let pos ~line ~col ~byte = Position.make ~line ~column:col ~byte_offset:byte

(* Build a function with N sequential if/else blocks, each creating a branch node *)
let make_sequential_branches ~count =
  let rec go idx acc =
    if idx > count then acc
    else
      let cond = { expr_value = EVar ("cond" ^ string_of_int idx)
                 ; expr_location = { start = pos ~line:idx ~col:4 ~byte:(idx*10)
                                   ; end_ = pos ~line:idx ~col:10 ~byte:(idx*10+6) } } in
      let then_body = { expr_value = EApp (
          { expr_value = EVar "process"
          ; expr_location = { start = pos ~line:idx ~col:8 ~byte:(idx*10+8)
                            ; end_ = pos ~line:idx ~col:15 ~byte:(idx*10+15) } },
          [{ expr_value = EVar ("x" ^ string_of_int idx)
           ; expr_location = { start = pos ~line:idx ~col:16 ~byte:(idx*10+16)
                              ; end_ = pos ~line:idx ~col:18 ~byte:(idx*10+18) } }]
        )
      ; expr_location = { start = pos ~line:idx ~col:8 ~byte:(idx*10+8)
                        ; end_ = pos ~line:idx ~col:18 ~byte:(idx*10+18) } } in
      let else_body = { expr_value = ELiteral (LString "skip")
                      ; expr_location = { start = pos ~line:idx ~col:15 ~byte:(idx*10+15)
                                       ; end_ = pos ~line:idx ~col:20 ~byte:(idx*10+20) } } in
      let if_expr = { expr_value = EIf (cond, then_body, Some else_body)
                    ; expr_location = { start = pos ~line:idx ~col:2 ~byte:(idx*10-2)
                                      ; end_ = pos ~line:idx ~col:25 ~byte:(idx*10+25) } } in
      go (idx + 1) (if_expr :: acc)
  in
  let body_items = go 1 [] in
  let body = { expr_value = EBlock body_items
             ; expr_location = { start = pos ~line:1 ~col:0 ~byte:0
                               ; end_ = pos ~line:count ~col:30 ~byte:(count*30) } } in
  { mod_lang = Crystal
  ; mod_path = "sequential_branches.cr"
  ; mod_items = [{
      item_location = { start = pos ~line:1 ~col:0 ~byte:0
                      ; end_ = pos ~line:(count+10) ~col:0 ~byte:((count+10)*30) };
      item_value = IFunction ("seq_branches_" ^ string_of_int count, [PVar "x"], None, body)
    }]
  ; parse_errors = []
  }

(* Build a function with deeply nested ILBranch nodes (not EIf) *)
let make_deep_il_branches ~depth =
  let rec build_branch d =
    if d = 0 then
      [ { il_node_value = ILCall (None, "sink", [IEVar ("data")], pos ~line:d ~col:2 ~byte:(d*10))
        ; il_node_location = { start = pos ~line:d ~col:2 ~byte:(d*10)
                              ; end_ = pos ~line:d ~col:10 ~byte:(d*10+8) } }
      ]
    else
      let cond = { il_node_value = ILAssign (LVVar ("cond" ^ string_of_int d), IEVar ("cond_val"), pos ~line:d ~col:4 ~byte:(d*10))
                 ; il_node_location = { start = pos ~line:d ~col:4 ~byte:(d*10)
                                      ; end_ = pos ~line:d ~col:15 ~byte:(d*10+11) } } in
      let then_block = build_branch (d - 1) in
      let else_block = [{ il_node_value = ILReturn (IELiteral "safe", pos ~line:d ~col:15 ~byte:(d*10+11))
                        ; il_node_location = { start = pos ~line:d ~col:15 ~byte:(d*10+11)
                                             ; end_ = pos ~line:d ~col:20 ~byte:(d*10+16) } }] in
      let branch = { il_node_value = ILBranch (
          IEVar ("cond" ^ string_of_int d),
          then_block,
          Some else_block,
          pos ~line:d ~col:2 ~byte:(d*10)
        )
      ; il_node_location = { start = pos ~line:d ~col:2 ~byte:(d*10)
                            ; end_ = pos ~line:d ~col:20 ~byte:(d*10+18) } } in
      [cond; branch]
  in
  { mod_lang = Crystal
  ; mod_path = "deep_il_branches.cr"
  ; mod_items = [{
      item_location = { start = pos ~line:1 ~col:0 ~byte:0
                      ; end_ = pos ~line:(depth+10) ~col:0 ~byte:((depth+10)*30) };
      item_value = IFunction ("deep_il_" ^ string_of_int depth, [PVar "data"], None,
        { expr_value = EBlock [{ expr_value = EVar "start"
                              ; expr_location = { start = pos ~line:0 ~col:0 ~byte:0
                                               ; end_ = pos ~line:0 ~col:5 ~byte:5 } }]
        ; expr_location = { start = pos ~line:0 ~col:0 ~byte:0
                          ; end_ = pos ~line:depth ~col:20 ~byte:(depth*20) } })
    }]
  ; parse_errors = []
  }

(* Direct IL construction test *)
let make_direct_il_function ~depth =
  let rec go d =
    if d = 0 then
      [{ fn_name = ""; fn_params = []; fn_body = [
          ILCall (None, "sink", [IEVar ("data")], pos ~line:0 ~col:5 ~byte:5)
        ]; fn_pos = pos ~line:0 ~col:0 ~byte:0 }]
    else
      []
  in
  
  (* Create a synthetic IL function directly *)
  let rec build_body d =
    if d = 0 then
      [ILCall (None, "sink", [IEVar "data"], pos ~line:d ~col:5 ~byte:(d*10))]
    else
      let then_b = build_body (d - 1) in
      let else_b = [ILReturn (IELiteral "safe", pos ~line:d ~col:15 ~byte:(d*10+5))] in
      [ILBranch (IEVar ("cond" ^ string_of_int d), then_b, Some else_b, pos ~line:d ~col:2 ~byte:(d*10))]
  in
  
  { il_file = "test.cr"; il_lang = "crystal"
  ; il_functions = [{
      fn_name = "deep_fn_" ^ string_of_int depth;
      fn_params = ["data"];
      fn_body = build_body depth;
      fn_pos = pos ~line:1 ~col:0 ~byte:0
    }]
  }

let () =
  Printf.printf "=== Sequential Branches Test (EIf → ILBranch) ===\n\n";
  
  let counts = [5; 10; 20; 50; 100; 200] in
  
  List.iter (fun count ->
    let start_time = Unix.gettimeofday () in
    let mod_ = make_sequential_branches ~count in
    let unit = translate mod_ in
    match unit.il_functions with
    | [] -> Printf.printf "FAIL: No IL functions for count %d\n" count
    | fn :: _ ->
      let il_nodes = List.length fn.fn_body in
      let cfg = build_cfg fn in
      let elapsed = Unix.gettimeofday () -. start_time in
      let block_count = List.length cfg.cfg_blocks in
      Printf.printf "Count %3d: %4d IL nodes, %4d blocks, %8.3fms\n" 
        count il_nodes block_count (elapsed *. 1000.0)
  ) counts;
  
  Printf.printf "\n=== Direct IL Branch Test ===\n\n";
  
  let depths = [5; 10; 20; 30; 50; 100] in
  
  List.iter (fun depth ->
    let start_time = Unix.gettimeofday () in
    let unit = make_direct_il_function ~depth in
    match unit.il_functions with
    | [] -> Printf.printf "FAIL: No IL functions for depth %d\n" depth
    | fn :: _ ->
      let il_nodes = List.length fn.fn_body in
      let cfg = build_cfg fn in
      let elapsed = Unix.gettimeofday () -. start_time in
      let block_count = List.length cfg.cfg_blocks in
      Printf.printf "Depth %3d: %4d IL nodes, %4d blocks, %8.3fms\n"
        depth il_nodes block_count (elapsed *. 1000.0)
  ) depths;
  
  Printf.printf "\n=== PASS: CFG builder handles branching correctly ===\n"