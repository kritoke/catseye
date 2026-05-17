(* Debug script — trace rule matching *)

let () =
  (* Load rules *)
  Printf.printf "CWD: %s\n" (Sys.getcwd ());
  Printf.printf "rules/ exists: %b\n" (Sys.file_exists "rules");
  let rules = match Catseye_rules.Loader.load_rules "rules" with
    | Ok r -> 
      Printf.printf "Rules loaded: %d\n" (List.length r);
      List.iter (fun r ->
        Printf.printf "  Rule: %s severity=%s sinks=%d\n"
          r.Catseye_rules.Types.id r.Catseye_rules.Types.severity
          (List.length r.Catseye_rules.Types.sinks);
        List.iter (fun s ->
          Printf.printf "    sink: %s sanitizers=%d\n"
            s.Catseye_rules.Types.pattern (List.length s.Catseye_rules.Types.sanitizers)
        ) r.Catseye_rules.Types.sinks
      ) r;
      r
    | Error (`Msg msg) ->
      Printf.printf "Rule load error: %s\n" msg;
      []
  in
  
  (* Run crystal extractor on vulnerable.cr *)
  let cmd = "CRYSTAL_HAS_WRAPPER=1 crystal run ../../src/extractor/extractor.cr -- ../../test/samples/vulnerable.cr 2>/dev/null" in
  let (stdout_ch, stdin_ch, stderr_ch) = Unix.open_process_full cmd (Unix.environment ()) in
  let output = Buffer.create 4096 in
  (try while true do Buffer.add_channel output stdout_ch 4096 done
   with End_of_file -> ());
  let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
  let json_str = Buffer.contents output in
  let nodes = Catseye_types.Security_node.decode_many (Yojson.Safe.from_string json_str) in
  Printf.printf "\nNodes extracted: %d\n" (List.length nodes);
  
  (* Show call nodes *)
  let call_nodes = List.filter (fun n ->
    n.Catseye_types.Security_node.node_type = Catseye_types.Security_node.Call
  ) nodes in
  Printf.printf "Call nodes: %d\n" (List.length call_nodes);
  List.iter (fun n ->
    Printf.printf "  call: %s taint=%b line=%d args=%d\n"
      n.Catseye_types.Security_node.name n.Catseye_types.Security_node.taint
      n.Catseye_types.Security_node.line (List.length n.Catseye_types.Security_node.args)
  ) call_nodes;
  
  (* Build taint DB *)
  let db = Catseye_engine.Engine.build_taint_db nodes in
  let tainted = Catseye_engine.Db.get_tainted_vars db in
  Printf.printf "\nTainted vars: %d\n" (List.length tainted);
  List.iter (Printf.printf "  %s\n") tainted;
  
  (* Build taint context for rule engine *)
  let files = List.fold_left (fun acc n ->
    let f = n.Catseye_types.Security_node.file in
    if List.mem f acc then acc else f :: acc
  ) [] nodes in
  let by_file = List.map (fun f -> (f, Catseye_engine.Db.get_tainted_vars_in_file db f)) files in
  let ctx = Catseye_rules.Interpreter.make_taint_context
    ~global:tainted ~by_file
    ~import_map:(Catseye_engine.Symbol_table.build_import_map nodes)
    () in
  
  (* Run rules *)
  let findings = Catseye_rules.Interpreter.run_all rules nodes ctx in
  Printf.printf "\nFindings: %d\n" (List.length findings);
  List.iter (fun f ->
    Printf.printf "  [%s] %s %s:%d\n" f.Catseye_types.Finding.rule f.Catseye_types.Finding.severity
      f.Catseye_types.Finding.file f.Catseye_types.Finding.line
  ) findings
