(* src/ocaml/lib/catseye_cli/ai_linter_integration.ml
   Integration between CLI and AI Linter
   
   Bridges CatseyeAST.t parsing with ai_linter rules.
*)

open Catseye_ast.Types
open Catseye_ast.Error
open Catseye_ast.Parse
open Catseye_types.Finding

module Ast_rules = Ai_linter.Ast_rules
module Gleam_rules = Ai_linter.Gleam_rules
module Crystal_rules = Ai_linter.Crystal_rules
module Javascript_rules = Ai_linter.Javascript_rules
module Svelte_rules = Ai_linter.Svelte_rules
module Ocaml_rules = Ai_linter.Ocaml_rules
module Types = Ai_linter.Types

(** AI finding type (alias for Finding.t) *)
type ai_finding = Catseye_types.Finding.t

(** Convert parse error to finding *)
let error_to_finding (err : parse_error) : ai_finding =
  { rule = "parse-error";
    severity = "error";
    file = err.file;
    line = Option.value err.line ~default:0;
    message = err.message;
    flow = [];
    language = "";
    dependency = None;
    reachability = None;
    suggestion = None; }

(** Convert ai_linter violation to finding *)
let violation_to_finding (v : Ast_rules.violation) : ai_finding =
  { rule = v.rule_id;
    severity = (match v.severity with
      | Types.Hint -> "hint"
      | Types.Warning -> "warning"
      | Types.Error -> "error");
    file = "";
    line = v.location.start.line;
    message = v.message;
    flow = [];
    language = "";
    dependency = None;
    reachability = None;
    suggestion = None; }

(** Convert Gleam finding to ai_finding *)
let gleam_finding_to_finding (f : Types.finding) : ai_finding =
  { rule = f.rule_id;
    severity = Types.severity_to_string f.severity;
    file = f.file;
    line = f.line;
    message = f.message;
    flow = [];
    language = "gleam";
    dependency = None;
    reachability = None;
    suggestion = f.suggestion; }

(** Convert Crystal finding to ai_finding *)
let crystal_finding_to_finding (f : Types.finding) : ai_finding =
  { rule = f.rule_id;
    severity = Types.severity_to_string f.severity;
    file = f.file;
    line = f.line;
    message = f.message;
    flow = [];
    language = "crystal";
    dependency = None;
    reachability = None;
    suggestion = f.suggestion; }

(** Parse and analyze a file *)
let analyze_file ~(extractor_registry : Catseye_engine.Extractor_registry.t option) ~(path : string) : ai_finding list =
  match parse_file ~extractor_registry ~path with
  | Error err -> [error_to_finding err]
  | Ok mod_ ->
      let lang_findings = match mod_.mod_lang with
        | Gleam -> List.map gleam_finding_to_finding (Gleam_rules.analyze_module mod_)
        | Crystal -> List.map crystal_finding_to_finding (Crystal_rules.analyze_module mod_)
        | JavaScript | TypeScript ->
          List.map (fun (f : Ai_linter.Types.finding) ->
            { rule = f.rule_id; severity = Ai_linter.Types.severity_to_string f.severity;
              file = f.file; line = f.line; message = f.message;
              flow = []; language = "javascript"; dependency = None;
              reachability = None; suggestion = f.suggestion }
          ) (Javascript_rules.analyze_module mod_)
        | Svelte ->
          List.map (fun (f : Ai_linter.Types.finding) ->
            { rule = f.rule_id; severity = Ai_linter.Types.severity_to_string f.severity;
              file = f.file; line = f.line; message = f.message;
              flow = []; language = "svelte"; dependency = None;
              reachability = None; suggestion = f.suggestion }
          ) (Svelte_rules.analyze_module mod_)
        | Other "ocaml" ->
          List.map (fun (f : Ai_linter.Types.finding) ->
            { rule = f.rule_id; severity = Ai_linter.Types.severity_to_string f.severity;
              file = f.file; line = f.line; message = f.message;
              flow = []; language = "ocaml"; dependency = None;
              reachability = None; suggestion = f.suggestion }
          ) (Ocaml_rules.analyze_module mod_)
        | _ -> []  (* Future language rules *)
      in
      let ast_findings = List.map (fun v ->
        let base = violation_to_finding v in
        { base with file = path }
      ) (Ast_rules.analyze_module mod_)
      in
      lang_findings @ ast_findings

(** Print findings to stdout *)
let print_finding (f : ai_finding) =
  Printf.printf "[%s] %s:%d - %s\n" f.rule f.file f.line f.message