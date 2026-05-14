(* Test binary for catseye_ast parsing *)
(* Tests Crystal extractor integration and AI linter rules *)

open Catseye_ast.Types
open Catseye_ast.Parse

module Ast_rules = Ai_linter.Ast_rules
module Crystal_rules = Ai_linter.Crystal_rules

let () =
  (* Test Crystal AI anti-patterns *)
  let sample = "/workspaces/catseye/test/samples/ai_antipatterns.cr" in
  let extractor = "crystal run /workspaces/catseye/src/extractor/extractor.cr --" in
  Printf.printf "=== Testing CatseyeAST parsing ===\n";
  Printf.printf "File: %s\n" sample;
  Printf.printf "Extractor: %s\n" extractor;
  
  (* Set the extractor env var *)
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR" extractor;
  
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
        | IClass (name, _) ->
            Printf.printf "  Line %d: class %s\n" line name
        | IModule (name, _) ->
            Printf.printf "  Line %d: module %s\n" line name
        | IUnknown s ->
            Printf.printf "  Line %d: unknown (%s)\n" line s
        | _ ->
            Printf.printf "  Line %d: other\n" line
      ) mod_.mod_items;
      
      (* Test Crystal AI linter *)
      Printf.printf "\n=== AI Linter Findings ===\n";
      let findings = Crystal_rules.analyze_module mod_ in
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