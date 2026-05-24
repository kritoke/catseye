(* test/test_gleam.ml - Debug version *)
let () =
  let path = if Array.length Sys.argv > 1 then Sys.argv.(1) else "/workspaces/catseye/test/samples/vulnerable.gleam" in
  Printf.printf "Testing Gleam extractor on: %s\n" path;
  flush stdout;
  
  (* Debug grammar path *)
  match Catseye_engine.Gleam.grammar_path () with
  | Ok p -> Printf.printf "Gleam grammar: %s\n" p
  | Error (`Msg m) -> Printf.eprintf "Gleam grammar error: %s\n" m;
  flush stdout;
  
  match Catseye_engine.Gleam.extract path with
  | Ok nodes ->
    let module SN = Catseye_types.Security_node in
    Printf.printf "Extracted %d nodes:\n" (List.length nodes);
    List.iter (fun n ->
      Printf.printf "  [%s] %s line=%d taint=%b\n"
        (SN.string_of_node_type n.SN.node_type)
        n.SN.name n.SN.line n.SN.taint
    ) nodes
  | Error (`Msg m) -> Printf.printf "Error: %s\n" m