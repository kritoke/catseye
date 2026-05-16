(* Test: Full CFG taint analysis to find performance issues *)
(* This tests analyze_cfg with many blocks and taint propagation *)

open Catseye_il.Il_types
open Catseye_il.Cfg_builder
open Catseye_il.Cfg_taint

let pos ~line ~col = { line; col }

(* Create a large CFG with many blocks *)
let make_large_cfg_fn ~block_count ~nodes_per_block =
  let rec go block_idx acc =
    if block_idx >= block_count then List.rev acc
    else
      let nodes = 
        let rec gen_nodes i acc =
          if i >= nodes_per_block then List.rev acc
          else
            let n = ILAssign (
              LVVar ("v" ^ string_of_int (block_idx * nodes_per_block + i)),
              IEVar ("v" ^ string_of_int (block_idx * nodes_per_block + i - 1)),
              pos ~line:block_idx ~col:2
            ) in
            gen_nodes (i + 1) (n :: acc)
        in
        let init = if block_idx = 0 then 
          [ILAssign (LVVar "v0", IELiteral "0", pos ~line:0 ~col:2)] 
        else [] in
        init @ gen_nodes (if block_idx = 0 then 1 else 0) []
      in
      let call = if block_idx mod 10 = 9 then
        [ILCall (None, "HTTP::Client.get", [IEVar ("url" ^ string_of_int block_idx)], pos ~line:block_idx ~col:5)]
      else [] in
      go (block_idx + 1) ((nodes @ call) :: acc)
  in
  { fn_name = "large_cfg_" ^ string_of_int block_count
  ; fn_params = []
  ; fn_body = List.concat (go 0 [])
  ; fn_pos = pos ~line:0 ~col:0
  }

(* Create a CFG with many taint sources *)
let make_taint_cfg_fn ~source_count =
  let rec go idx acc =
    if idx >= source_count then List.rev acc
    else
      let source = ILAssign (
        LVVar ("user_input" ^ string_of_int idx),
        IECall ("params.[]", [IELiteral ("key" ^ string_of_int idx)], pos ~line:idx ~col:2),
        pos ~line:idx ~col:2
      ) in
      let use = ILCall (None, "process", [IEVar ("user_input" ^ string_of_int idx)], pos ~line:idx ~col:10) in
      go (idx + 1) (source :: use :: acc)
  in
  { fn_name = "taint_cfg_" ^ string_of_int source_count
  ; fn_params = []
  ; fn_body = go 0 []
  ; fn_pos = pos ~line:0 ~col:0
  }

(* Create a CFG with many sinks *)
let make_sink_cfg_fn ~sink_count =
  let rec go idx acc =
    if idx >= sink_count then List.rev acc
    else
      let assign = ILAssign (
        LVVar ("url"),
        IEVar ("user_url"),
        pos ~line:idx ~col:2
      ) in
      let sink = ILCall (None, "HTTP::Client.get", [IEVar "url"], pos ~line:idx ~col:15) in
      go (idx + 1) (assign :: sink :: acc)
  in
  { fn_name = "sink_cfg_" ^ string_of_int sink_count
  ; fn_params = []
  ; fn_body = go 0 []
  ; fn_pos = pos ~line:0 ~col:0
  }

(* Mock sources and rules for testing *)
let test_sources = [
  { Catseye_rules.Types.name = "params"; field = None }
]

let default_conditions = Catseye_rules.Types.default_conditions

let test_rules = [
  { Catseye_rules.Types.id = "SSRF"
  ; severity = "High"
  ; sinks = [
      { Catseye_rules.Types.pattern = "HTTP::Client.get"; sanitizers = []; requires_field = None; arg_pos = None }
    ]
  ; sources = test_sources
  ; conditions = { (default_conditions ()) with requires_tainted_args = true }
  ; message_template = "SSRF: {tainted_vars} flows to {sink}" }
]

let () =
  Printf.printf "=== CFG Taint Analysis Performance Tests ===\n\n";
  
  (* Test 1: Many blocks *)
  Printf.printf "--- Many Blocks (block_count x nodes_per_block) ---\n";
  let configs = [
    (10, 10);
    (50, 10);
    (100, 10);
    (200, 10);
    (500, 5);
  ] in
  List.iter (fun (blocks, nodes_per) ->
    let start_time = Unix.gettimeofday () in
    let fn = make_large_cfg_fn ~block_count:blocks ~nodes_per_block:nodes_per in
    (match build_cfg fn with
     | Error _ -> Printf.printf "  ERROR: build_cfg failed\n"
     | Ok cfg ->
       let _findings = analyze_cfg cfg test_sources test_rules "test.cr" "crystal" in
       let elapsed = Unix.gettimeofday () -. start_time in
       Printf.printf "  %3d blocks x %2d nodes: %7.3fms\n"
        blocks nodes_per (elapsed *. 1000.0))
  ) configs;
  
  (* Test 2: Many taint sources *)
  Printf.printf "\n--- Many Taint Sources ---\n";
  let counts = [10; 50; 100; 200; 500] in
  List.iter (fun count ->
    let start_time = Unix.gettimeofday () in
    let fn = make_taint_cfg_fn ~source_count:count in
    (match build_cfg fn with
     | Error _ -> Printf.printf "  ERROR: build_cfg failed\n"
     | Ok cfg ->
       let _findings = analyze_cfg cfg test_sources test_rules "test.cr" "crystal" in
       let elapsed = Unix.gettimeofday () -. start_time in
       Printf.printf "  %3d sources: %7.3fms\n"
        count (elapsed *. 1000.0))
  ) counts;
  
  (* Test 3: Many sinks *)
  Printf.printf "\n--- Many Sinks ---\n";
  let counts = [10; 50; 100; 200; 500] in
  List.iter (fun count ->
    let start_time = Unix.gettimeofday () in
    let fn = make_sink_cfg_fn ~sink_count:count in
    (match build_cfg fn with
     | Error _ -> Printf.printf "  ERROR: build_cfg failed\n"
     | Ok cfg ->
       let _findings = analyze_cfg cfg test_sources test_rules "test.cr" "crystal" in
       let elapsed = Unix.gettimeofday () -. start_time in
       Printf.printf "  %3d sinks: %7.3fms\n"
        count (elapsed *. 1000.0))
  ) counts;
  
  Printf.printf "\n=== End of Taint Analysis Tests ===\n"