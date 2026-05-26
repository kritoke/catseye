(* lib/catseye_cli/elixir_tools.ml *)
(* Elixir tool integration for Catseye: Sobelow, Credo, Reach *)

open Unix
open Yojson.Safe
open Base
let ( = ) = Stdlib.( = )

(** Tool status for discovery *)
type tool_status =
  | Available
  | NotInstalled
  | ProjectNotMix

type tool_info = {
  name : string;
  version : string option;
  status : tool_status;
}

(** Elixir-specific configuration *)
type elixir_config = {
  enabled : bool;
  run_sobelow : bool;
  run_credo : bool;
  run_reach : bool;
  threshold : [ `Low | `Medium | `High ];
}

let default_elixir_config = {
  enabled = true;
  run_sobelow = true;
  run_credo = true;
  run_reach = true;
  threshold = `Low;
}

(* ── Utility Functions ──────────────────────────────────────────────── *)

(** Check if file contains a substring *)
let file_contains path pattern =
  try
    let ic = Stdlib.open_in path in
    let content = Stdio.In_channel.input_all ic in
    Stdlib.close_in ic;
    let plen = String.length pattern in
    let slen = String.length content in
    let rec check i =
      i + plen <= slen && (Stdlib.String.sub content i plen = pattern || check (i + 1))
    in
    check 0
  with _ -> false

(** Check if a command exists in PATH *)
let command_exists cmd =
  let cmd_str = Stdlib.Printf.sprintf "bash -c 'command -v %s >/dev/null 2>&1'" cmd in
  if Stdlib.Sys.command cmd_str = 0 then true
  else
    let cmd_str2 = Stdlib.Printf.sprintf "bash -c 'which %s >/dev/null 2>&1'" cmd in
    Stdlib.Sys.command cmd_str2 = 0

(** Run command and collect output *)
let run_cmd cmd =
  let ch = Unix.open_process_in cmd in
  let rec read_all acc =
    try read_all (Stdlib.input_line ch :: acc) with Stdlib.End_of_file -> List.rev acc
  in
  let lines = read_all [] in
  let status = Unix.close_process_in ch in
  (status, lines)

(* ── Project Detection ───────────────────────────────────────────────── *)

let is_mix_project dir =
  Stdlib.Sys.file_exists (Stdlib.Filename.concat dir "mix.exs")

let has_sobelow_exs () =
  command_exists "sobelow"

let has_reach_exs () =
  command_exists "reach"

let has_credo_dep dir =
  if not (command_exists "mix") then false
  else
    let mix_exs = Stdlib.Filename.concat dir "mix.exs" in
    if Stdlib.Sys.file_exists mix_exs then
      file_contains mix_exs "credo" || file_contains mix_exs ":credo"
    else false

(* ── Tool Discovery ─────────────────────────────────────────────────── *)

let check_tools ?(mix_path = "mix") (dir : string) =
  let _ = mix_path in
  let elixir_available = command_exists "elixir" || command_exists "erl" in
  let mix_available = command_exists "mix" in
  let sobelow_version =
    if has_sobelow_exs () then
      let (_, lines) = run_cmd "sobelow --version 2>&1" in
      (match lines with [] -> None | h :: _ -> Some h)
    else None
  in
  let reach_version =
    if has_reach_exs () then
      let (_, lines) = run_cmd "reach --version 2>&1" in
      (match lines with [] -> None | h :: _ -> Some h)
    else None
  in
  let credo_available = has_credo_dep dir in
  [
    { name = "elixir"; version = if elixir_available then Some "detected" else None;
      status = if elixir_available then Available else NotInstalled };
    { name = "mix"; version = if mix_available then Some "detected" else None;
      status = if mix_available then Available else NotInstalled };
    { name = "sobelow"; version = sobelow_version;
      status = if has_sobelow_exs () then Available else NotInstalled };
    { name = "credo"; version = None;
      status = if credo_available then Available else NotInstalled };
    { name = "reach"; version = reach_version;
      status = if has_reach_exs () then Available else NotInstalled };
  ]

(* ── Sobelow Output Parser ───────────────────────────────────────────── *)

(** Get string value from JSON object *)
let get_str fields key =
  match List.Assoc.find ~equal:String.equal fields key with
  | Some (`String s) -> s
  | _ -> ""

(** Get int value from JSON object *)
let get_int fields key =
  match List.Assoc.find ~equal:String.equal fields key with
  | Some (`Int n) -> n
  | Some (`Float f) -> Stdlib.int_of_float f
  | Some (`String s) -> (try Stdlib.int_of_string s with _ -> 0)
  | _ -> 0

(** Parse Sobelow JSON output into findings.
    Handles the format: { "findings": { "high_confidence": [], ... }, ... } *)
let parse_sobelow_json json_str =
  try
    let json = from_string json_str in
    match json with
    | `Assoc fields ->
      (* Sobelow format: { "findings": { "high_confidence": [], "low_confidence": [], ... } } *)
      (let severity_of_category cat =
        match String.lowercase cat with
        | "high_confidence" -> "Critical"
        | "medium_confidence" -> "High"
        | _ -> "Medium"
      in
      let parse_finding category item =
        match item with
        | `Assoc item_fields ->
          let sev = severity_of_category category in
          let var = try " in `" ^ get_str item_fields "variable" ^ "`"
                   with _ -> "" in
          let t = get_str item_fields "type" in
          Some Catseye_types.Finding.{
            rule = "Sobelow." ^ t;
            severity = sev;
            file = get_str item_fields "file";
            line = get_int item_fields "line";
            message = t ^ var;
            flow = [];
            language = "elixir";
            dependency = None;
            reachability = None;
            suggestion = None;
          }
        | _ -> None
      in
      let parse_category findings category =
        match List.Assoc.find ~equal:String.equal findings category with
        | Some (`List items) -> List.filter_map ~f:(parse_finding category) items
        | _ -> []
      in
      match List.Assoc.find ~equal:String.equal fields "findings" with
      | Some (`Assoc findings) ->
        parse_category findings "high_confidence"
        @ parse_category findings "medium_confidence"
        @ parse_category findings "low_confidence"
      | _ -> [])
    | `List items ->
      (* Flat list format *)
      List.filter_map ~f:(fun item ->
        match item with
        | `Assoc fields ->
          (try
            Some Catseye_types.Finding.{
              rule = "Sobelow." ^ get_str fields "type";
              severity = "Medium";
              file = get_str fields "file";
              line = get_int fields "line";
              message = get_str fields "details";
              flow = [];
              language = "elixir";
              dependency = None;
              reachability = None;
              suggestion = None;
            }
          with _ -> None)
        | _ -> None
      ) items
    | _ -> []
  with _ -> []

(** Run Sobelow scan *)
let run_sobelow_cmd ?(threshold = `Low) project_dir =
  let threshold_str = match threshold with
    | `Low -> "Low"
    | `Medium -> "Medium"
    | `High -> "High"
  in
  (* Find sobelow path or use default *)
  let sobelow_cmd =
    if command_exists "sobelow" then "sobelow"
    else "/home/kritoke/.mix/escripts/sobelow"
  in
  let cmd = Stdlib.Printf.sprintf
    "cd %s && %s --format json --threshold %s 2>&1"
    (Stdlib.Filename.quote project_dir)
    sobelow_cmd
    threshold_str
  in
  let (status, lines) = run_cmd cmd in
  match status with
  | WEXITED 0 | WEXITED _ ->
    let json = String.concat ~sep:"\n" lines in
    if json = "" || json = "[]" then [] else parse_sobelow_json json
  | _ -> []

(* ── Credo Output Parser ────────────────────────────────────────────── *)

(** Parse Credo JSON output into findings *)
let parse_credo_json json_str =
  try
    let json = from_string json_str in
    match json with
    | `Assoc fields ->
      let issues =
        match List.Assoc.find ~equal:String.equal fields "issues" with
        | Some (`List items) -> items
        | _ -> []
      in
      List.filter_map ~f:(fun item ->
        match item with
        | `Assoc ifields ->
          (try
            let category = get_str ifields "category" in
            let sev = match String.lowercase category with
              | "refactor" | "warning" -> "Warning"
              | _ -> "Info"
            in
            Some Catseye_types.Finding.{
              rule = "Credo." ^ get_str ifields "check";
              severity = sev;
              file = get_str ifields "filename";
              line = get_int ifields "line";
              message = get_str ifields "message";
              flow = [];
              language = "elixir";
              dependency = None;
              reachability = None;
              suggestion = None;
            }
          with _ -> None)
        | _ -> None
      ) issues
    | _ -> []
  with _ -> []

(** Run Credo scan *)
let run_credo_cmd ?(strict = false) project_dir =
  let strict_flag = if strict then " --strict" else "" in
  let cmd = Stdlib.Printf.sprintf
    "cd %s && mix credo --format json%s 2>&1"
    (Stdlib.Filename.quote project_dir)
    strict_flag
  in
  let (status, lines) = run_cmd cmd in
  match status with
  | WEXITED 0 ->
    let json = String.concat ~sep:"\n" lines in
    if json = "" then [] else parse_credo_json json
  | _ -> []

(* ── Reach Output Parser ────────────────────────────────────────────── *)

(** Parse Reach JSON output into findings *)
let parse_reach_json json_str =
  try
    let json = from_string json_str in
    match json with
    | `Assoc fields ->
      let findings =
        match List.Assoc.find ~equal:String.equal fields "findings" with
        | Some (`List items) -> items
        | _ -> []
      in
      List.filter_map ~f:(fun item ->
        match item with
        | `Assoc ifields ->
          (try
            Some Catseye_types.Finding.{
              rule = "Reach." ^ get_str ifields "type";
              severity = "Info";
              file = get_str ifields "file";
              line = get_int ifields "line";
              message = get_str ifields "message";
              flow = [];
              language = "elixir";
              dependency = None;
              reachability = None;
              suggestion = None;
            }
          with _ -> None)
        | _ -> None
      ) findings
    | _ -> []
  with _ -> []

(** Run Reach check *)
let run_reach_cmd ?(checks = ["arch"; "smells"]) project_dir =
  let check_args = String.concat ~sep:" " (List.map ~f:(fun c -> "--" ^ c) checks) in
  let cmd = Stdlib.Printf.sprintf
    "cd %s && mix reach.check %s --format json 2>&1"
    (Stdlib.Filename.quote project_dir)
    check_args
  in
  let (status, lines) = run_cmd cmd in
  match status with
  | WEXITED 0 ->
    let json = String.concat ~sep:"\n" lines in
    if json = "" then [] else parse_reach_json json
  | _ -> []

(* ── Public API ─────────────────────────────────────────────────────── *)

let run_sobelow ?(config = default_elixir_config) ~project_dir () =
  if not config.enabled || not config.run_sobelow then []
  else if not (is_mix_project project_dir) then []
  else run_sobelow_cmd ~threshold:config.threshold project_dir

let run_credo ?(config = default_elixir_config) ~project_dir () =
  if not config.enabled || not config.run_credo then []
  else if not (is_mix_project project_dir) then []
  else run_credo_cmd project_dir

let run_reach ?(config = default_elixir_config) ~project_dir () =
  if not config.enabled || not config.run_reach then []
  else if not (is_mix_project project_dir) then []
  else if not (has_reach_exs ()) then []
  else run_reach_cmd project_dir

let run_all_tools ?(config = default_elixir_config) ~project_dir () =
  if not config.enabled then []
  else
    let sobelow_findings = run_sobelow ~config ~project_dir () in
    let credo_findings = run_credo ~config ~project_dir () in
    let reach_findings = run_reach ~config ~project_dir () in
    sobelow_findings @ credo_findings @ reach_findings

(* ── Reporting ──────────────────────────────────────────────────────── *)

let report_tool_status tools =
  List.iter ~f:(fun ti ->
    let status_str = match ti.status with
      | Available -> "[available]"
      | NotInstalled -> "[not installed]"
      | ProjectNotMix -> "[not a mix project]"
    in
    let ver_str = match ti.version with
      | Some v -> " " ^ v
      | None -> ""
    in
    Stdlib.Printf.printf "  %s %s%s\n" ti.name status_str ver_str
  ) tools