(* test/ast/composite_taint_test.ml
   Golden test for composite-arg taint propagation.

   Before the change: `execShellCmd("ls " & param)` produced an ArgUnknown for
   the composite argument, so taint never reached the sink.
   After: the EBinOp is decomposed and `param` rides along as an extra ArgVar,
   so the Nim command-injection / SSRF rules fire.

   Skips gracefully when the Nim tree-sitter grammar is unavailable.
*)

let kdl_rules = {|
rule "NimCommandInjection" severity="High" {
    sinks {
        sink "os.execShellCmd" arg=0 { fix "quote args" }
        sink "execShellCmd" arg=0 { fix "quote args" }
        sink "os.execCmd" arg=0 { fix "use execProcess" }
        sink "execCmd" arg=0 { fix "use execProcess" }
    }
    message "Potential command injection via {sink}."
}

rule "NimSSRF" severity="Medium" {
    sinks {
        sink "httpclient.getContent" arg=0 { fix "validate URL" }
        sink "getContent" arg=0 { fix "validate URL" }
    }
    message "HTTP request to {sink} with potentially user-controlled URL."
}
|}

let run fixture =
  match Catseye_ast.Parse.parse_file ~extractor_cmds:None ~path:fixture with
  | Error e ->
    Printf.printf "FAIL: parse error: %s\n" e.Catseye_ast.Error.message;
    exit 1
  | Ok mod_ ->
    (* Derive security nodes *)
    let nodes = Catseye_ast.To_security_node.derive mod_ in
    Printf.printf "derived %d security nodes\n" (List.length nodes);

    (* Assert the decomposition itself: the execShellCmd call carries an
       ArgVar for the concatenated variable *)
    let shell_calls = List.filter (fun (n : Catseye_types.Security_node.t) ->
      n.Catseye_types.Security_node.name = "os.execShellCmd"
      || n.Catseye_types.Security_node.name = "execShellCmd") nodes in
    let shell_vars = List.concat_map (fun (n : Catseye_types.Security_node.t) ->
      List.filter_map (fun (a : Catseye_types.Security_node.arg) ->
        if a.Catseye_types.Security_node.arg_type = Catseye_types.Security_node.ArgVar
        then Some a.Catseye_types.Security_node.value else None)
        n.Catseye_types.Security_node.args) shell_calls in
    Printf.printf "execShellCmd composite vars: [%s]\n" (String.concat "; " shell_vars);
    if not (List.mem "userInput" shell_vars) then begin
      Printf.printf "FAIL: 'userInput' not surfaced through the concat argument\n";
      exit 1
    end;

    (* Run the taint engine with inline KDL rules *)
    (match Catseye_rules.Loader.parse_string kdl_rules with
     | Error (`Msg m) -> Printf.printf "FAIL: rule parse: %s\n" m; exit 1
     | Ok rules ->
       let findings = Catseye_engine.Engine.analyze ~extra_sources:[] rules nodes in
       let by_rule r = List.filter (fun (f : Catseye_types.Finding.t) ->
         f.Catseye_types.Finding.rule = r) findings in
       let ci = by_rule "NimCommandInjection" in
       let ssrf = by_rule "NimSSRF" in
       Printf.printf "NimCommandInjection: %d finding(s)\n" (List.length ci);
       Printf.printf "NimSSRF: %d finding(s)\n" (List.length ssrf);
       (if ci = [] then begin
          Printf.printf "FAIL: composite arg did not trigger NimCommandInjection\n";
          exit 1
        end);
       (if ssrf = [] then begin
          Printf.printf "FAIL: composite arg did not trigger NimSSRF\n";
          exit 1
        end);
       List.iter (fun (f : Catseye_types.Finding.t) ->
         Printf.printf "  [%s] %s:%d %s\n" f.Catseye_types.Finding.severity
           f.Catseye_types.Finding.file f.Catseye_types.Finding.line
           f.Catseye_types.Finding.message) (ci @ ssrf);
       Printf.printf "PASS: composite-arg taint reaches sinks\n")

let () =
  (* dune's cwd differs between run styles: probe both candidate locations *)
  let candidates = [
    "tests/fixtures/nim/composite_taint.nim";          (* cwd = repo root *)
    "../../tests/fixtures/nim/composite_taint.nim";    (* cwd = src/ocaml *)
    "../../../tests/fixtures/nim/composite_taint.nim"; (* cwd = src/ocaml/test *)
    "../../../../tests/fixtures/nim/composite_taint.nim"; (* cwd = src/ocaml/test/ast *)
  ] in
  let fixture =
    match List.find_opt Sys.file_exists candidates with
    | Some f -> f
    | None -> "" in
  Printf.printf "=== Composite-arg taint golden test ===\n";
  if fixture = "" then begin
    Printf.printf "SKIP: fixture missing (probed: %s)\n"
      (String.concat ", " candidates);
    exit 0
  end;

  (* Grammar availability mirrors the mapper resolution *)
  let grammar = try Some (Sys.getenv "TREE_SITTER_NIM_GRAMMAR")
    with Not_found ->
      let home = try Sys.getenv "HOME" with Not_found -> "" in
      let p = Filename.concat home ".tree-sitter/nim.so" in
      if Sys.file_exists p then Some p else None
  in
  match grammar with
  | None -> Printf.printf "SKIP: nim grammar not available\n"
  | Some g ->
    Unix.putenv "TREE_SITTER_NIM_GRAMMAR" g;
    run fixture
