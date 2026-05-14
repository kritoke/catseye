let () =
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR" "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
  let path = "/tmp/test_crystal/test_antipatterns.cr" in
  match Catseye_ast.Parse.parse_file ~path with
  | Error err -> Printf.eprintf "ERROR: %s\n%!" err.Catseye_ast.Error.message
  | Ok mod_ ->
    Printf.printf "Items: %d\n" (List.length mod_.Catseye_ast.Types.mod_items);
    List.iter (fun item ->
      let line = item.Catseye_ast.Types.item_location.start.line in
      match item.Catseye_ast.Types.item_value with
      | Catseye_ast.Types.IFunction (name, params, _, body) ->
        Printf.printf "  Line %d: fn %s(%d params) body=" line name (List.length params);
        (match body.Catseye_ast.Types.expr_value with
         | Catseye_ast.Types.EBlock es -> Printf.printf "block(%d)\n" (List.length es)
         | Catseye_ast.Types.EUnit -> Printf.printf "unit\n"
         | _ -> Printf.printf "other\n")
      | Catseye_ast.Types.IImport _ -> Printf.printf "  Line %d: import\n" line
      | Catseye_ast.Types.IClass (name, _) -> Printf.printf "  Line %d: class %s\n" line name
      | Catseye_ast.Types.IModule (name, _) -> Printf.printf "  Line %d: module %s\n" line name
      | Catseye_ast.Types.IUnknown s -> Printf.printf "  Line %d: unknown(%s)\n" line s
      | _ -> Printf.printf "  Line %d: other\n" line
    ) mod_.Catseye_ast.Types.mod_items;
    Printf.printf "\nFindings:\n";
    let findings = Ai_linter.Crystal_rules.analyze_module mod_ in
    List.iter (fun f ->
      Printf.printf "  [%s] line %d - %s\n" f.Ai_linter.Types.rule_id f.Ai_linter.Types.line f.Ai_linter.Types.message
    ) findings
