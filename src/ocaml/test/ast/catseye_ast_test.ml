(* Test binary for Gleam parsing and AI linter *)

open Catseye_ast.Types
open Catseye_ast.Parse

let () =
  (* Set environment variables *)
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR" "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
  Unix.putenv "TREE_SITTER_GLEAM_GRAMMAR" "/workspaces/catseye";
  let registry = Catseye_engine.Extractor_registry.create
    ~flat_env:(Some "crystal run /workspaces/catseye/src/extractor/extractor.cr --")
    ~hier_env:(Some "crystal run /workspaces/catseye/src/extractor/extractor.cr --")
    () in

  let sample = "/workspaces/catseye/test/samples/ai_antipatterns.gleam" in
  Printf.printf "=== Testing Gleam CatseyeAST parsing ===\n";
  Printf.printf "File: %s\n" sample;

  match parse_file ~extractor_registry:(Some registry) ~path:sample with
  | Error err ->
      Printf.printf "ERROR: %s\n" err.message
  | Ok mod_ ->
      Printf.printf "Parsed %s (%s)\n" mod_.mod_path
        (match mod_.mod_lang with Gleam -> "Gleam" | Crystal -> "Crystal");
      Printf.printf "Items: %d\n" (List.length mod_.mod_items);

      List.iter (fun item ->
        let line = item.item_location.start.line in
        match item.item_value with
        | IFunction (name, params, _, body) ->
            Printf.printf "  Line %d: function %s(%d params)\n" line name (List.length params);
            (* Show body expression type *)
            let body_desc = match body.expr_value with
              | EBlock _ -> "block"
              | EApp _ -> "app"
              | EVar _ -> "var"
              | EUnit -> "unit"
              | _ -> "other"
            in
            Printf.printf "    body: %s\n" body_desc
        | IImport (name, _) ->
            Printf.printf "  Line %d: import %s\n" line name
        | ITypeDef (name, _, _) ->
            Printf.printf "  Line %d: type %s\n" line name
        | IUnknown s ->
            Printf.printf "  Line %d: unknown (%s)\n" line s
        | _ ->
            Printf.printf "  Line %d: other\n" line
      ) mod_.mod_items;

      (* Test Gleam AI linter *)
      Printf.printf "\n=== Gleam AI Linter Findings ===\n";
      let findings = Ai_linter.Gleam_rules.analyze_module mod_ in
      if findings = [] then
        Printf.printf "  (no violations found)\n"
      else
        List.iter (fun f ->
          Printf.printf "  [%s] %s:%d - %s\n"
            f.Ai_linter.Types.rule_id
            f.Ai_linter.Types.file
            f.Ai_linter.Types.line
            f.Ai_linter.Types.message
        ) findings;

      (* Test AST structural rules *)
      Printf.printf "\n=== AST Structural Findings ===\n";
      let violations = Ai_linter.Ast_rules.analyze_module mod_ in
      if violations = [] then
        Printf.printf "  (no violations found)\n"
      else
        List.iter (fun (v : Ai_linter.Ast_rules.violation) ->
          Printf.printf "  [%s] line %d - %s\n"
            v.Ai_linter.Ast_rules.rule_id
            v.Ai_linter.Ast_rules.location.start.line
            v.Ai_linter.Ast_rules.message
        ) violations
