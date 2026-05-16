(* Test: CFG builder performance with many ILBranch nodes *)
(* Direct test of build_cfg to find O(n²) behavior *)

open Catseye_il.Il_types
open Catseye_il.Cfg_builder

let pos ~line ~col = { line; col }

(* Create a function with N sequential ILBranch nodes *)
let make_seq_branches_fn ~count =
  let rec go idx =
    if idx > count then []
    else
      let then_block = [ILCall (None, "process", [IEVar ("x" ^ string_of_int idx)], pos ~line:idx ~col:10)] in
      let else_block = [ILReturn (IELiteral "skip", pos ~line:idx ~col:15)] in
      let branch = ILBranch (
        IEVar ("cond" ^ string_of_int idx),
        then_block,
        Some else_block,
        pos ~line:idx ~col:2
      ) in
      branch :: go (idx + 1)
  in
  { fn_name = "seq_branches_" ^ string_of_int count
  ; fn_params = []
  ; fn_body = go 1
  ; fn_pos = pos ~line:0 ~col:0
  }

(* Create a function with N deeply nested ILBranch nodes *)
let make_nested_branches_fn ~depth =
  let rec go d =
    if d = 0 then
      [ILCall (None, "sink", [IEVar "data"], pos ~line:d ~col:5)]
    else
      let then_b = go (d - 1) in
      let else_b = [ILReturn (IELiteral "safe", pos ~line:d ~col:15)] in
      [ILBranch (IEVar ("cond" ^ string_of_int d), then_b, Some else_b, pos ~line:d ~col:2)]
  in
  { fn_name = "nested_branches_" ^ string_of_int depth
  ; fn_params = ["data"]
  ; fn_body = go depth
  ; fn_pos = pos ~line:0 ~col:0
  }

(* Create a function with a SINGLE block containing N linear nodes *)
let make_large_linear_fn ~count =
  let rec go idx =
    if idx >= count then []
    else
      let node = ILAssign (
        LVVar ("v" ^ string_of_int idx),
        IEVar ("v" ^ string_of_int (idx - 1)),
        pos ~line:idx ~col:2
      ) in
      node :: go (idx + 1)
  in
  let init = [ILAssign (LVVar "v0", IELiteral "0", pos ~line:0 ~col:2)] in
  { fn_name = "large_linear_" ^ string_of_int count
  ; fn_params = []
  ; fn_body = init @ go 1
  ; fn_pos = pos ~line:0 ~col:0
  }

let () =
  Printf.printf "=== CFG Builder Performance Tests ===\n\n";
  
  (* Test 1: Sequential branches (worst case for recursive builder) *)
  Printf.printf "--- Sequential Branches (O(n²) in old builder) ---\n";
  let counts = [5; 10; 20; 50; 100; 200; 500] in
  List.iter (fun count ->
    let start_time = Unix.gettimeofday () in
    let fn = make_seq_branches_fn ~count in
    let _cfg = build_cfg fn in
    let elapsed = Unix.gettimeofday () -. start_time in
    let node_count = List.length fn.fn_body in
    Printf.printf "  %3d branches: %4d nodes, %9.3fms\n"
      count node_count (elapsed *. 1000.0)
  ) counts;
  
  (* Test 2: Nested branches *)
  Printf.printf "\n--- Nested Branches (deep recursion) ---\n";
  let depths = [5; 10; 20; 30; 50; 75; 100] in
  List.iter (fun depth ->
    let start_time = Unix.gettimeofday () in
    let fn = make_nested_branches_fn ~depth in
    let _cfg = build_cfg fn in
    let elapsed = Unix.gettimeofday () -. start_time in
    Printf.printf "  depth %2d: %3d nodes, %9.3fms\n"
      depth (List.length fn.fn_body) (elapsed *. 1000.0)
  ) depths;
  
  (* Test 3: Large linear block (should be fast) *)
  Printf.printf "\n--- Large Linear Block (control) ---\n";
  let counts = [100; 500; 1000; 5000; 10000] in
  List.iter (fun count ->
    let start_time = Unix.gettimeofday () in
    let fn = make_large_linear_fn ~count in
    let _cfg = build_cfg fn in
    let elapsed = Unix.gettimeofday () -. start_time in
    Printf.printf "  %5d nodes: %6.3fms\n"
      count (elapsed *. 1000.0)
  ) counts;
  
  Printf.printf "\n=== End of CFG Builder Tests ===\n"