(* Test binary for Gleam parsing and AI linter *)

open Catseye_ast.Types
open Catseye_ast.Parse
module Ast_rules = Ai_linter.Ast_rules
module Gleam_rules = Ai_linter.Gleam_rules

let () =
  (* Set environment variables *)
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR" "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
  Unix.putenv "TREE_SITTER_GLEAM_GRAMMAR" "/workspaces/catseye/third_party/tree-sitter";
  
  let sample = "/workspaces/catseye/test/samples/ai_antipatterns.gleam" in
  Printf.printf "=== Testing Gleam CatseyeAST parsing ===\n";
  Printf.printf "File: %s\n" sample;
  
  match parse_file ~path:sample with
  | Error err ->
      Printf.printf "ERROR: %s\n" err.message
  | Ok mod_ ->
      Printf.printf "Parsed %s (%s)\n" mod_.mod_path 
        (match mod_.mod_lang with Gleam -> "Gleam" | Crystal -> "Crystal");
      Printf.printf "Items: %d\n" (List.length mod_.mod_items);
      
      List.iter (fun item ->
        let line = item.item_location.start.line in
        match item.item_value with
        | IFunction (name, params, _, _) ->
            Printf.printf "  Line %d: function %s(%d params)\n" line name (List.length params)
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
      let findings = Gleam_rules.analyze_module mod_ in
      if findings = [] then
        Printf.printf "  (no violations found)\n"
      else
        List.iter (fun f ->
          let rule_id = (Obj.obj (Obj.field (Obj.repr f) 2) : string) in
          let file = (Obj.obj (Obj.field (Obj.repr f) 0) : string) in
          let line = (Obj.obj (Obj.field (Obj.repr f) 1) : int) in
          let msg = (Obj.obj (Obj.field (Obj.repr f) 4) : string) in
          Printf.printf "  [%s] %s:%d - %s\n" rule_id file line msg
        ) findings;
      
      (* Test AST structural rules *)
      Printf.printf "\n=== AST Structural Findings ===\n";
      let violations = Ast_rules.analyze_module mod_ in
      if violations = [] then
        Printf.printf "  (no violations found)\n"
      else
        List.iter (fun v ->
          let rule_id = (Obj.obj (Obj.field (Obj.repr v) 0) : string) in
          let line = (Obj.obj (Obj.field (Obj.repr v) 3) : range).start.line in
          let msg = (Obj.obj (Obj.field (Obj.repr v) 2) : string) in
          Printf.printf "  [%s] line %d - %s\n" rule_id line msg
        ) violations