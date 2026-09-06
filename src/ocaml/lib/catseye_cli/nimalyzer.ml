(* lib/catseye_cli/nimalyzer.ml
   nimalyzer integration — optional sidecar for Nim static analysis.
   
   nimalyzer checks: complexity, naming conventions, pragma enforcement,
   documentation coverage, code patterns.
*)

open Base

type nimalyzer_finding = {
  file : string;
  line : int;
  rule : string;
  severity : string;
  message : string;
  suggestion : string option;
}

(** Run nimalyzer with the given config file.
    Returns stdout output or an error message. *)
let run_nimalyzer ~(config_path : string) : (string, string) Result.t =
  let cmd = Stdlib.Printf.sprintf "nimalyzer %s 2>&1"
    (Stdlib.Filename.quote config_path) in
  try
    let ic = Unix.open_process_in cmd in
    let buffer = Stdlib.Buffer.create 4096 in
    (try while true do
      Stdlib.Buffer.add_channel buffer ic 4096
    done with Stdlib.End_of_file -> ());
    let status = Unix.close_process_in ic in
    match status with
    | Unix.WEXITED 0 | Unix.WEXITED 1 ->
      Ok (Stdlib.Buffer.contents buffer)
    | Unix.WEXITED code ->
      Error (Stdlib.Printf.sprintf "nimalyzer exited with code %d" code)
    | Unix.WSIGNALED _ ->
      Error "nimalyzer terminated by signal"
    | Unix.WSTOPPED _ ->
      Error "nimalyzer stopped"
  with e ->
    Error (Stdlib.Printf.sprintf "nimalyzer execution failed: %s" (Exn.to_string e))

(** Parse nimalyzer's text output into structured findings.
    
    nimalyzer output format (from check/search rules):
      <file>:<line>: <rule>: <level>: <message>
    
    Example:
      src/main.nim:15: hasPragma: error: Procedure 'main' doesn't have pragma 'raises'
      src/main.nim:23: complexity: notice: Procedure 'process' has cyclomatic complexity 25
*)
let parse_output ~(output : string) : nimalyzer_finding list =
  let lines = String.split ~on:'\n' output in
  List.filter_map ~f:(fun line ->
    let trimmed = String.strip line in
    if String.is_empty trimmed || Char.equal trimmed.[0] '#' then None
    else
      (* Try to match: file:line: rule: level: message *)
      match Stdlib.String.index_opt trimmed ':' with
      | None -> None
      | Some first_colon ->
        let before = Stdlib.String.sub trimmed 0 first_colon in
        let after = Stdlib.String.sub trimmed (first_colon + 1) (String.length trimmed - first_colon - 1) in
        (* Check if this looks like a file path (contains .nim or /) *)
        if not (String.is_substring ~substring:".nim" before
                || String.is_substring ~substring:"/" before) then
          None
        else
          (* Parse file:line *)
          match Stdlib.String.index_opt after ':' with
          | None -> None
          | Some second_colon ->
            let line_str = String.strip (Stdlib.String.sub after 0 second_colon) in
            let rest = Stdlib.String.sub after (second_colon + 1) (String.length after - second_colon - 1) in
            match Stdlib.String.index_opt rest ':' with
            | None -> None
            | Some third_colon ->
              let rule = String.strip (Stdlib.String.sub rest 0 third_colon) in
              let msg_rest = Stdlib.String.sub rest (third_colon + 1) (String.length rest - third_colon - 1) in
              (* Parse severity: message *)
              let (severity, message) =
                match Stdlib.String.index_opt msg_rest ':' with
                | None -> ("info", String.strip msg_rest)
                | Some fourth_colon ->
                  let sev = String.strip (Stdlib.String.sub msg_rest 0 fourth_colon) in
                  let msg = String.strip (Stdlib.String.sub msg_rest (fourth_colon + 1) (String.length msg_rest - fourth_colon - 1)) in
                  (sev, msg)
              in
              let line_num = match Stdlib.int_of_string_opt line_str with
                | Some n -> n
                | None -> 0
              in
              let normalized_severity = match String.lowercase severity with
                | "error" | "check" -> "high"
                | "notice" | "search" -> "medium"
                | "count" | "info" -> "low"
                | _ -> severity
              in
              Some { file = before; line = line_num; rule; severity = normalized_severity; message; suggestion = None }
  ) lines

(** Convert nimalyzer findings to Catseye Finding.t format *)
let to_catseye_findings ~(findings : nimalyzer_finding list) ~(language : string) : Catseye_types.Finding.t list =
  List.map ~f:(fun f ->
    { Catseye_types.Finding.rule = "nimalyzer." ^ f.rule;
      severity = f.severity;
      file = f.file;
      line = f.line;
      message = f.message;
      flow = [];
      language;
      dependency = None;
      reachability = None;
      suggestion = f.suggestion;
    }
  ) findings

(** Run nimalyzer integration if configured.
    Returns findings list (empty if disabled or failed).
    
    @param enabled Whether nimalyzer is enabled
    @param config_path Path to nimalyzer config file
    @param is_terminal Whether to print status messages
*)
let run_if_configured ~enabled ~config_path ~is_terminal ~language : Catseye_types.Finding.t list =
  if not enabled then []
  else
    match config_path with
    | None ->
      if is_terminal then
        Stdlib.Printf.eprintf "  [nimalyzer] No config file found — skipping\n%!";
      []
    | Some config_path ->
      if is_terminal then
        Stdlib.Printf.eprintf "  [nimalyzer] Running with config: %s\n%!" config_path;
      (match run_nimalyzer ~config_path with
       | Error msg ->
         Stdlib.Printf.eprintf "  [nimalyzer] Warning: %s\n%!" msg;
         []
       | Ok output ->
         let raw_findings = parse_output ~output in
         if is_terminal && not (List.is_empty raw_findings) then
           Stdlib.Printf.eprintf "  [nimalyzer] Found %d findings\n%!" (List.length raw_findings);
         to_catseye_findings ~findings:raw_findings ~language)
