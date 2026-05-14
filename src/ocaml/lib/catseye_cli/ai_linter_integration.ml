(* src/ocaml/lib/catseye_cli/ai_linter_integration.ml
   Integration between CLI and AI Linter
   
   Bridges CatseyeAST.t parsing with ai_linter rules.
*)

open Catseye_ast.Types
open Catseye_ast.Error
open Catseye_ast.Parse

module Ast_rules = Ai_linter.Ast_rules
module Gleam_rules = Ai_linter.Gleam_rules
module Types = Ai_linter.Types

(** AI finding output format *)
type ai_finding = {
  file : string;
  line : int;
  rule : string;
  severity : string;
  message : string;
}

(** Convert parse error to finding *)
let error_to_finding (err : parse_error) =
  { file = err.file;
    line = Option.value err.line ~default:0;
    rule = "parse-error";
    severity = "error";
    message = err.message; }

(** Convert ai_linter violation to finding *)
let violation_to_finding (v : Ast_rules.violation) =
  { file = "";
    line = v.location.start.line;
    rule = v.rule_id;
    severity = (match v.severity with
      | Types.Hint -> "hint"
      | Types.Warning -> "warning"
      | Types.Error -> "error");
    message = v.message; }

(** Convert ai_linter finding to finding *)
let finding_to_finding (f : Gleam_rules.finding) =
  { file = f.file;
    line = f.line;
    rule = f.rule_id;
    severity = f.severity;
    message = f.message; }

(** Parse and analyze a file *)
let analyze_file ~(path : string) =
  match parse_file ~path with
  | Error err -> [error_to_finding err]
  | Ok mod_ ->
      let gleam_findings = match mod_.mod_lang with
        | Gleam -> List.map finding_to_finding (Gleam_rules.analyze_module mod_)
        | Crystal -> []  (* Crystal rules not yet implemented *)
      in
      let ast_findings = List.map (fun v ->
        let base = violation_to_finding v in
        { base with file = path }
      ) (Ast_rules.analyze_module mod_)
      in
      gleam_findings @ ast_findings

(** Print findings to stdout *)
let print_finding (f : ai_finding) =
  Printf.printf "[%s] %s:%d - %s\n" f.rule f.file f.line f.message