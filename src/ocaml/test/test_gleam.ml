let () =
  match Catseye_engine.Gleam.extract "../../test/samples/vulnerable.gleam" with
  | Ok nodes ->
    let module SN = Catseye_types.Security_node in
    Printf.printf "Extracted %d nodes:\n" (List.length nodes);
    List.iter (fun n ->
      Printf.printf "  [%s] %s line=%d taint=%b\n"
        (SN.string_of_node_type n.SN.node_type)
        n.SN.name n.SN.line n.SN.taint
    ) nodes
  | Error (`Msg m) -> Printf.printf "Error: %s\n" m
