let () =
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR"
    "crystal run /workspaces/catseye/src/extractor/hierarchical_extractor.cr --";
  let registry = Catseye_engine.Extractor_registry.create
    ~flat_env:(Some "crystal run /workspaces/catseye/src/extractor/extractor.cr --")
    ~hier_env:(Some "crystal run /workspaces/catseye/src/extractor/hierarchical_extractor.cr --")
    () in

  let test_file path label =
    Printf.printf "=== %s (%s) ===\n" label path;
    match Catseye_ast.Parse.parse_file ~extractor_registry:(Some registry) ~path with
    | Error err -> Printf.eprintf "ERROR: %s\n%!" err.Catseye_ast.Error.message
    | Ok mod_ ->
      Printf.printf "Items: %d, Lang: %s\n"
        (List.length mod_.Catseye_ast.Types.mod_items)
        (match mod_.Catseye_ast.Types.mod_lang with
         | Catseye_ast.Types.Crystal -> "Crystal"
         | Catseye_ast.Types.Gleam -> "Gleam"
         | _ -> "Other");
      List.iter (fun item ->
        let line = item.Catseye_ast.Types.item_location.start.line in
        match item.Catseye_ast.Types.item_value with
        | Catseye_ast.Types.IFunction (name, params, _, body) ->
          Printf.printf "  Line %d: fn %s(%d params) body=" line name (List.length params);
          (match body.Catseye_ast.Types.expr_value with
           | Catseye_ast.Types.EBlock es -> Printf.printf "block(%d)\n" (List.length es)
           | Catseye_ast.Types.EUnit -> Printf.printf "unit\n"
           | Catseye_ast.Types.EIf _ -> Printf.printf "if\n"
           | Catseye_ast.Types.EApp _ -> Printf.printf "call\n"
           | Catseye_ast.Types.ECase _ -> Printf.printf "case\n"
           | _ -> Printf.printf "other\n")
        | Catseye_ast.Types.IImport (mod_path, _) ->
          Printf.printf "  Line %d: import(%s)\n" line mod_path
        | Catseye_ast.Types.IClass (name, items) ->
          Printf.printf "  Line %d: class %s (%d members)\n" line name (List.length items)
        | Catseye_ast.Types.IModule (name, _) ->
          Printf.printf "  Line %d: module %s\n" line name
        | Catseye_ast.Types.IUnknown s ->
          Printf.printf "  Line %d: unknown(%s)\n" line s
        | _ -> Printf.printf "  Line %d: other\n" line
      ) mod_.Catseye_ast.Types.mod_items;
      (* Test AST complexity counting *)
      let modules = [mod_] in
      let config = Catseye_claws.Types.default_config in
      let findings = Catseye_claws.Complexity_ast.analyze modules config in
      if findings <> [] then begin
        Printf.printf "  Complexity findings:\n";
        List.iter (fun f ->
          Printf.printf "    [%s] %s:%d - %s\n"
            f.Catseye_types.Finding.rule
            f.Catseye_types.Finding.file
            f.Catseye_types.Finding.line
            f.Catseye_types.Finding.message
        ) findings
      end
  in

  test_file "/workspaces/catseye/test/samples/vulnerable.cr" "VulnerableApp";
  test_file "/workspaces/catseye/test/samples/smell_samples/complex.cr" "Complex function";
  test_file "/workspaces/catseye/test/samples/smell_samples/god.cr" "GodObject";
  test_file "/workspaces/catseye/test/samples/smell_samples/params.cr" "Long params"
