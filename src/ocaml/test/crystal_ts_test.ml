(* test/crystal_ts_test.ml - Full extraction test *)
let () =
  Printf.printf "=== Crystal TS Full Extraction Test ===\n"; flush stdout;
  
  let test_file = "/tmp/catseye_test/test.cr" in
  if not (Sys.file_exists test_file) then begin
    Printf.printf "Test file not found: %s\n" test_file; flush stdout;
    exit 1
  end;
  
  (try
    let nodes = Catseye_engine.Crystal_ts.extract ~path:test_file in
    Printf.printf "Found %d security nodes:\n" (List.length nodes); flush stdout;
    List.iter (fun n ->
      let node_type = match n.Catseye_types.Security_node.node_type with
        | Catseye_types.Security_node.IgnoredReturn -> "ignored_return"
        | Catseye_types.Security_node.NonAtomicFileOp -> "non_atomic_file_op"
        | Catseye_types.Security_node.UnboundedRead -> "unbounded_read"
        | Catseye_types.Security_node.TOCTOU -> "toctou"
        | _ -> "other"
      in
      Printf.printf "  Line %d: %s - %s\n" n.line node_type n.name
    ) nodes
  with e ->
    Printf.printf "Error: %s\n" (Printexc.to_string e); flush stdout)