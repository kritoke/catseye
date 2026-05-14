(* lib/catseye_claws/ameba_hook.ml *)

(** Ameba linter integration (optional, Crystal only).

    Shells out to [ameba --format json] on Crystal files, parses the
    JSON output, and converts issues to Finding.t. If Ameba is not in
    $PATH, silently returns an empty list.
*)

open Catseye_types

(* ── Ameba JSON parsing ─────────────────────────────────────────────── *)

type ameba_issue = {
  rule_name : string;
  severity : string;
  message : string;
  file : string;
  line : int;
}

type ameba_result = {
  issues : ameba_issue list;
}

(** Parse a single Ameba issue from JSON. *)
let parse_issue (json : Yojson.Safe.t) : ameba_issue option =
  match json with
  | `Assoc dict ->
    let get key = try Some (List.assoc key dict) with Not_found -> None in
    let get_s key = match get key with Some (`String s) -> s | _ -> "" in
    let get_i key = match get key with Some (`Int i) -> i | _ -> 0 in
    let rule_name = get_s "rule_name" in
    if rule_name = "" then None
    else Some {
      rule_name;
      severity = get_s "severity";
      message = get_s "message";
      file = get_s "location" (* Ameba uses nested location, simplified here *);
      line = get_i "line";
    }
  | _ -> None

(** Parse Ameba JSON output into issues.

    Ameba JSON format (simplified):
    { "sources": [ { "issues": [ { "rule_name": "...", "severity": "...",
        "message": "...", "location": { "file": "...", "line": N } } ] } ] }
*)
let parse_output (json_str : string) : ameba_issue list =
  try
    let json = Yojson.Safe.from_string json_str in
    let sources = match json with
      | `Assoc dict ->
        (match List.assoc_opt "sources" dict with
         | Some (`List srcs) -> srcs
         | _ -> [])
      | _ -> []
    in
    List.concat_map (fun (src : Yojson.Safe.t) ->
      match src with
      | `Assoc dict ->
        (match List.assoc_opt "issues" dict with
         | Some (`List issues) ->
           List.filter_map parse_issue issues
         | _ -> [])
      | _ -> []
    ) sources
  with _ -> []

(** Extract the flat issue list from Ameba's nested JSON.

    Ameba also has a flat format we should handle:
    { "issues": [ { "rule_name": "...", "severity": "...", "message": "...",
                    "location": { "file": "...", "line": N, "column": N } } ] }
*)
let parse_flat_output (json_str : string) : ameba_issue list =
  try
    let json = Yojson.Safe.from_string json_str in
    let get_s key dict = match List.assoc_opt key dict with
      | Some (`String s) -> s | _ -> ""
    in
    let get_i key dict = match List.assoc_opt key dict with
      | Some (`Int i) -> i | _ -> 0
    in
    let issues_json = match json with
      | `Assoc dict ->
        (match List.assoc_opt "issues" dict with
         | Some (`List items) -> items
         | _ -> [])
      | _ -> []
    in
    List.filter_map (fun (item : Yojson.Safe.t) ->
      match item with
      | `Assoc dict ->
        let rule_name = get_s "rule_name" dict in
        if rule_name = "" then None
        else begin
          let file, line = match List.assoc_opt "location" dict with
            | Some (`Assoc loc) -> (get_s "file" loc, get_i "line" loc)
            | _ -> ("", 0)
          in
          Some {
            rule_name;
            severity = get_s "severity" dict;
            message = get_s "message" dict;
            file;
            line;
          }
        end
      | _ -> None
    ) issues_json
  with _ -> []

(* ── Finding conversion ─────────────────────────────────────────────── *)

(** Map Ameba severity to Catseye severity. *)
let map_severity (s : string) : string =
  match String.lowercase_ascii s with
  | "error" | "convention" -> "High"
  | "warning" | "refactor" -> "Medium"
  | "info" | "pedantic" -> "Low"
  | _ -> "Medium"

(** Convert Ameba issues to Catseye findings. *)
let to_findings (issues : ameba_issue list) : Finding.t list =
  List.filter_map (fun (issue : ameba_issue) ->
    if issue.file = "" then None
    else Some {
      Finding.rule = "Ameba:" ^ issue.rule_name;
      severity = map_severity issue.severity;
      file = issue.file;
      line = issue.line;
      message = issue.message;
      flow = [ {
        Finding.file = issue.file;
        line = issue.line;
        message = Printf.sprintf "%s: %s" issue.rule_name issue.message;
      } ];
      language = "crystal";
      dependency = None;
      reachability = None; suggestion = None;
    }
  ) issues

(* ── Runner ─────────────────────────────────────────────────────────── *)

(** Run Ameba on Crystal files, return findings.

    Returns [] if:
    - Ameba is not enabled in config
    - Ameba binary is not found in $PATH
    - No Crystal files in the node list
    - Ameba exits with an error
*)
let run (config : Types.claws_config) (nodes : Security_node.t list)
    : Finding.t list =
  if not config.ameba_enabled then []
  else begin
    (* Collect unique Crystal file paths *)
    let crystal_files = Hashtbl.create 16 in
    List.iter (fun (n : Security_node.t) ->
      if n.Security_node.language = "crystal" then
        Hashtbl.replace crystal_files n.Security_node.file true
    ) nodes;
    let files = Hashtbl.fold (fun f _ acc -> f :: acc) crystal_files [] in
    if files = [] then []
    else begin
      (* Check if ameba is available *)
      let which_cmd = Printf.sprintf "which %s >/dev/null 2>&1"
        (Filename.quote config.ameba_path) in
      if Sys.command which_cmd <> 0 then []
      else begin
        (* Run ameba *)
        let cmd = Printf.sprintf "%s --format json %s 2>/dev/null"
          (Filename.quote config.ameba_path)
          (String.concat " " (List.map Filename.quote files)) in
        let (stdout_ch, stdin_ch, stderr_ch) =
          Unix.open_process_full cmd (Unix.environment ()) in
        let output = Buffer.create 8192 in
        (try while true do Buffer.add_channel output stdout_ch 8192 done
         with End_of_file -> ());
        let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
        let json_str = Buffer.contents output in
        if json_str = "" then []
        else begin
          (* Try flat format first, then nested sources format *)
          let issues = match parse_flat_output json_str with
            | [] -> parse_output json_str
            | issues -> issues
          in
          to_findings issues
        end
      end
    end
  end
