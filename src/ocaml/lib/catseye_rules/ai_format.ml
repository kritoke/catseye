(* lib/catseye_rules/ai_format.ml *)
(* AI-friendly rule export for knowledge base population *)

open Base
open Types

(* Serialize a string for JSON, escaping special characters *)
let json_escape s =
  let b = Buffer.create (String.length s * 2) in
  String.iter s ~f:(fun c ->
    match c with
    | '"' -> Buffer.add_string b "\\\""
    | '\\' -> Buffer.add_string b "\\\\"
    | '\n' -> Buffer.add_string b "\\n"
    | '\r' -> Buffer.add_string b "\\r"
    | '\t' -> Buffer.add_string b "\\t"
    | c when Char.to_int c < 32 -> Buffer.add_string b (Stdlib.Printf.sprintf "\\u%04x" (Char.to_int c))
    | c -> Buffer.add_char b c
  );
  Buffer.contents b

let json_string s = "\"" ^ json_escape s ^ "\""

let json_list items =
  "[" ^ String.concat ~sep:", " items ^ "]"

let json_object fields =
  "{" ^ String.concat ~sep:", " fields ^ "}"

(* Convert a single sink to JSON *)
let sink_to_json (sink : sink_def) : string =
  let fields = [
    json_string "function" ^ ": " ^ json_string sink.pattern;
    json_string "argument_index" ^ ": " ^ (match sink.arg_pos with Some n -> Int.to_string n | None -> "null");
    json_string "sanitizers" ^ ": " ^ json_list (List.map ~f:json_string sink.sanitizers);
    json_string "fix" ^ ": " ^ (match sink.fix_template with Some f -> json_string f | None -> "null")
  ] in
  json_object fields

(* Convert a single source to JSON *)
let source_to_json (source : source_def) : string =
  let open Stdlib in
  let fields = [
    json_string "name" ^ ": " ^ json_string source.name;
    json_string "field" ^ ": " ^ (match source.field with Some f -> json_string f | None -> "null")
  ] in
  json_object fields

(* Convert a rule definition to AI-friendly JSON *)
let rule_to_json (rule : rule_def) : string =
  let sinks_json = json_list (List.map ~f:sink_to_json rule.sinks) in
  let sources_json = json_list (List.map ~f:source_to_json rule.sources) in
  let fields = [
    json_string "id" ^ ": " ^ json_string rule.id;
    json_string "name" ^ ": " ^ json_string rule.id;
    json_string "severity" ^ ": " ^ json_string rule.severity;
    json_string "category" ^ ": " ^ (
      (* Infer category from rule ID *)
      if String.is_prefix ~prefix:"Elixir" rule.id then json_string "Elixir Security"
      else if String.is_prefix ~prefix:"CommandInjection" rule.id then json_string "Command Injection"
      else if String.is_prefix ~prefix:"SSRF" rule.id then json_string "SSRF"
      else if String.is_prefix ~prefix:"SQL" rule.id then json_string "SQL Injection"
      else if String.is_prefix ~prefix:"XSS" rule.id then json_string "XSS"
      else if String.is_prefix ~prefix:"Path" rule.id then json_string "Path Traversal"
      else if String.is_prefix ~prefix:"Deserialization" rule.id then json_string "Deserialization"
      else if String.is_prefix ~prefix:"Hardcoded" rule.id then json_string "Hardcoded Secrets"
      else if String.is_prefix ~prefix:"ReDoS" rule.id then json_string "ReDoS"
      else if String.is_prefix ~prefix:"OpenRedirect" rule.id then json_string "Open Redirect"
      else json_string "Security"
    );
    json_string "languages" ^ ": " ^ json_list (
      (if List.is_empty rule.conditions.include_languages 
       then ["crystal"; "elixir"; "gleam"; "javascript"; "typescript"; "ocaml"; "rust"]
       else rule.conditions.include_languages)
      |> List.filter ~f:(fun l -> not (List.mem rule.conditions.exclude_languages l ~equal:String.equal))
      |> List.map ~f:json_string
    );
    json_string "sinks" ^ ": " ^ sinks_json;
    json_string "sources" ^ ": " ^ sources_json;
    json_string "message_template" ^ ": " ^ json_string rule.message_template;
    json_string "conditions" ^ ": " ^ json_object [
      json_string "requires_tainted_args" ^ ": " ^ (if rule.conditions.requires_tainted_args then "true" else "false");
      json_string "skip_all_literals" ^ ": " ^ (if rule.conditions.skip_all_literals then "true" else "false");
      json_string "check_args_contain" ^ ": " ^ json_list (List.map ~f:json_string rule.conditions.check_args_contain);
      json_string "check_args_missing" ^ ": " ^ json_list (List.map ~f:json_string rule.conditions.check_args_missing)
    ]
  ] in
  json_object fields

(* Convert a list of rules to AI-friendly JSON *)
let rules_to_json (rules : rule_def list) : string =
  json_object [
    json_string "version" ^ ": " ^ json_string "1.0";
    json_string "schema_url" ^ ": " ^ json_string "https://catseye.dev/rules/schema/v1";
    json_string "total_rules" ^ ": " ^ Int.to_string (List.length rules);
    json_string "rules" ^ ": " ^ json_list (List.map ~f:rule_to_json rules)
  ]

(* Filter rules by language *)
let filter_by_language (rules : rule_def list) (lang : string) : rule_def list =
  List.filter ~f:(fun rule ->
    (* If include_languages is empty, rule applies to all languages (except excludes) *)
    let included = 
      if List.is_empty rule.conditions.include_languages then true
      else List.mem rule.conditions.include_languages lang ~equal:String.equal
    in
    let not_excluded = not (List.mem rule.conditions.exclude_languages lang ~equal:String.equal) in
    included && not_excluded
  ) rules

(* Get supported languages from rules *)
let get_supported_languages (rules : rule_def list) : string list =
  let langs = [
    "crystal"; "elixir"; "gleam"; "javascript"; "typescript"; "svelte"; "ocaml"; "rust"
  ] in
  (* Filter to languages that have at least one rule *)
  List.filter ~f:(fun lang ->
    not (List.is_empty (filter_by_language rules lang))
  ) langs

(* Get rules with statistics per language *)
let rules_stats_json (rules : rule_def list) : string =
  let langs = get_supported_languages rules in
  let stats = List.map ~f:(fun lang ->
    let filtered = filter_by_language rules lang in
    let by_sev = List.fold_left ~init:[] ~f:(fun acc r ->
      (r.severity, List.length r.sinks) :: acc
    ) filtered in
    let critical = List.sum (module Int) ~f:snd (List.filter ~f:(fun (s, _) -> String.equal s "Critical") by_sev) in
    let high = List.sum (module Int) ~f:snd (List.filter ~f:(fun (s, _) -> String.equal s "High") by_sev) in
    let medium = List.sum (module Int) ~f:snd (List.filter ~f:(fun (s, _) -> String.equal s "Medium") by_sev) in
    let low = List.sum (module Int) ~f:snd (List.filter ~f:(fun (s, _) -> String.equal s "Low") by_sev) in
    json_object [
      json_string "language" ^ ": " ^ json_string lang;
      json_string "total_rules" ^ ": " ^ Int.to_string (List.length filtered);
      json_string "total_sinks" ^ ": " ^ Int.to_string (
        List.fold_left ~init:0 ~f:(fun acc r -> acc + List.length r.sinks) filtered
      );
      json_string "severity_breakdown" ^ ": " ^ json_object [
        json_string "critical" ^ ": " ^ Int.to_string critical;
        json_string "high" ^ ": " ^ Int.to_string high;
        json_string "medium" ^ ": " ^ Int.to_string medium;
        json_string "low" ^ ": " ^ Int.to_string low
      ]
    ]
  ) langs in
  json_object [
    json_string "version" ^ ": " ^ json_string "1.0";
    json_string "total_languages" ^ ": " ^ Int.to_string (List.length langs);
    json_string "total_rules" ^ ": " ^ Int.to_string (List.length rules);
    json_string "languages" ^ ": " ^ json_list stats
  ]