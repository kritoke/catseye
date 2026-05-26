(* lib/catseye_cli/elixir_extractor.ml *)
(* OCaml interface to the Elixir AST extractor *)

[@@@ocaml.warning "-69"]

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
open Unix
open Yojson.Safe

type call_data = {
  call_name : string;
  call_line : int;
  [@live] call_args : string list;
}

type fn_data = {
  fn_name : string;
  fn_arity : int;
  [@live] fn_params : string list;
  fn_line : int;
  [@live] fn_calls : call_data list;
  fn_sinks : call_data list;
  [@live] fn_sources : string list;
}

type mod_data = {
  mod_file : string;
  [@live] mod_language : string;
  [@live] mod_name : string option;
  mod_functions : fn_data list;
}

(* Parse call from JSON *)
let parse_call json =
  match json with
  | `Assoc fields ->
    (try
      let name = match Stdlib.List.assoc "name" fields with `String s -> s | _ -> "" in
      let line = match Stdlib.List.assoc "line" fields with `Int n -> n | _ -> 0 in
      let args = match Stdlib.List.assoc "args" fields with `List l -> List.filter_map ~f:(function `String s -> Some s | _ -> None) l | _ -> [] in
      Some { call_name = name; call_line = line; call_args = args }
    with _ -> None)
  | _ -> None

(* Parse function from JSON *)
let parse_fn json =
  match json with
  | `Assoc fields ->
    (try
      let name = match Stdlib.List.assoc "name" fields with `String s -> s | _ -> "" in
      let arity = match Stdlib.List.assoc "arity" fields with `Int n -> n | _ -> 0 in
      let line = match Stdlib.List.assoc "line" fields with `Int n -> n | _ -> 0 in
      let params = match Stdlib.List.assoc "params" fields with `List l -> List.filter_map ~f:(function `String s -> Some s | _ -> None) l | _ -> [] in
      let calls = match Stdlib.List.assoc "calls" fields with `List l -> List.filter_map ~f:parse_call l | _ -> [] in
      let sinks = match Stdlib.List.assoc "sinks" fields with `List l -> List.filter_map ~f:parse_call l | _ -> [] in
      let sources = match Stdlib.List.assoc "sources" fields with `List l -> List.filter_map ~f:(function `String s -> Some s | _ -> None) l | _ -> [] in
      Some { fn_name = name; fn_arity = arity; fn_params = params; fn_line = line;
             fn_calls = calls; fn_sinks = sinks; fn_sources = sources }
    with _ -> None)
  | _ -> None

(* Parse module from JSON *)
let parse_module_json json_str =
  try
    let json = from_string json_str in
    match json with
    | `Assoc fields ->
      let file = try Stdlib.List.assoc "file" fields |> function `String s -> s | _ -> "" with _ -> "" in
      let language = try Stdlib.List.assoc "language" fields |> function `String s -> s | _ -> "elixir" with _ -> "elixir" in
      let module_name = match Stdlib.List.assoc "module" fields with
        | `String s when String.length s > 7 -> Some (Stdlib.String.sub s 7 (String.length s - 7))
        | _ -> None
      in
      let functions = match Stdlib.List.assoc "functions" fields with
        | `List flist -> List.filter_map ~f:parse_fn flist
        | _ -> []
      in
      { mod_file = file; mod_language = language; mod_name = module_name; mod_functions = functions }
    | _ -> { mod_file = ""; mod_language = "elixir"; mod_name = None; mod_functions = [] }
  with _ -> { mod_file = ""; mod_language = "elixir"; mod_name = None; mod_functions = [] }

(* Determine severity based on sink type *)
let determine_severity (name : string) : string =
  if String.length name >= 10 && Stdlib.String.sub name 0 10 = "HTTPoison" then "High"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Ecto" then "Critical"
  else if String.length name >= 8 && Stdlib.String.sub name 0 8 = "Phoenix" then "High"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Tesla" then "High"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Req." then "High"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Code." then "Critical"
  else "Medium"

(* Get rule name based on sink *)
let get_rule_name (name : string) : string =
  if String.length name >= 10 && Stdlib.String.sub name 0 10 = "HTTPoison" then "SSRF"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Ecto" then "SQLi"
  else if String.length name >= 8 && Stdlib.String.sub name 0 8 = "Phoenix" then "XSS"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Tesla" then "SSRF"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Req." then "SSRF"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Code." then "CodeExec"
  else "Security"

(* Get category for message *)
let get_category (name : string) : string =
  if String.length name >= 10 && Stdlib.String.sub name 0 10 = "HTTPoison" then "HTTP client (SSRF)"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Ecto" then "database (SQLi)"
  else if String.length name >= 8 && Stdlib.String.sub name 0 8 = "Phoenix" then "HTML rendering (XSS)"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Tesla" then "HTTP client (SSRF)"
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Req." then "HTTP client (SSRF)"
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Code." then "code execution"
  else "unknown"

(* Get suggestion text *)
let get_suggestion (name : string) : string =
  if String.length name >= 10 && Stdlib.String.sub name 0 10 = "HTTPoison" then
    "Consider validating the URL against a allowlist of permitted domains."
  else if String.length name >= 4 && Stdlib.String.sub name 0 4 = "Ecto" then
    "Use parameterized queries or Ecto.Changeset for input validation."
  else if String.length name >= 8 && Stdlib.String.sub name 0 8 = "Phoenix" then
    "Ensure raw content is properly sanitized before rendering."
  else if String.length name >= 5 && Stdlib.String.sub name 0 5 = "Code." then
    "Avoid dynamic code execution. Consider using alternative approaches."
  else "Review input handling for this sink."

(* Helper to format sink call into a finding message *)
let format_sink_message (category : string) (fn_name : string) (fn_arity : int) : string =
  let arity_str = Int.to_string fn_arity in
  "Tainted " ^ category ^ " call in " ^ fn_name ^ "/" ^ arity_str

(* Convert extractor output to Catseye findings *)
let sinks_to_findings (mod_info : mod_data) : Catseye_types.Finding.t list =
  let results = [] in
  let results = List.fold_left ~init:results ~f:(fun results fn_info ->
    List.fold_left ~init:results ~f:(fun results call ->
      let sink_name = call.call_name in
      let sink_line = call.call_line in
      let fn_name = fn_info.fn_name in
      let fn_arity = fn_info.fn_arity in
      let severity = determine_severity sink_name in
      let rule = "Elixir." ^ get_rule_name sink_name in
      let category = get_category sink_name in
      let msg = format_sink_message category fn_name fn_arity in
      let sugg = get_suggestion sink_name in
      let finding = {
        Catseye_types.Finding.rule;
        severity;
        file = mod_info.mod_file;
        line = sink_line;
        message = msg;
        flow = [];
        language = "elixir";
        dependency = None;
        reachability = None;
        suggestion = Some sugg;
      } in
      finding :: results
    ) fn_info.fn_sinks
  ) mod_info.mod_functions in
  results

(* Run command and collect output *)
let run_cmd (cmd : string) : (process_status * string list) =
  let ch = Unix.open_process_in cmd in
  let rec read_all (acc : string list) =
    try read_all (Stdlib.input_line ch :: acc) with Stdlib.End_of_file -> List.rev acc
  in
  let lines = read_all [] in
  let status = Unix.close_process_in ch in
  (status, lines)

(* Find the catseye root - first try binary location, then search upward from CWD *)
let find_catseye_root (start_dir : string) : string option =
  (* Try binary's location first *)
  let exe_dir = Stdlib.Filename.dirname Stdlib.Sys.executable_name in
  let try_dir dir =
    let mix_path = Stdlib.Filename.concat dir "scripts/elixir-extractor/mix.exs" in
    Stdlib.Sys.file_exists mix_path
  in
  (* Check binary's directory and parent *)
  if try_dir exe_dir then Some exe_dir
  else
    let parent_exe = Stdlib.Filename.concat exe_dir ".." in
    if try_dir parent_exe then Some parent_exe
    else
      (* Search upward from current directory *)
      let rec search dir depth =
        if depth > 20 then None
        else
          let mix_path = Stdlib.Filename.concat dir "scripts/elixir-extractor/mix.exs" in
          if Stdlib.Sys.file_exists mix_path then Some dir
          else
            let parent = Stdlib.Filename.concat dir ".." in
            if parent = dir then None
            else search parent (depth + 1)
      in
      search start_dir 0

(* Convert relative path to absolute using shell realpath *)
let realpath (path : string) : string =
  let cmd = Stdlib.Printf.sprintf "realpath %s 2>/dev/null || echo %s"
    (Stdlib.Filename.quote path)
    (Stdlib.Filename.quote path)
  in
  let ch = Unix.open_process_in cmd in
  let rec read_all acc =
    try read_all (Stdlib.input_line ch :: acc) with Stdlib.End_of_file -> List.rev acc
  in
  let lines = read_all [] in
  let _ = Unix.close_process_in ch in
  match lines with
  | [line] -> String.strip line
  | _ -> path

(* Run extractor and return both sink findings and raw JSON for Claws analysis *)
let extract_with_data (project_dir : string) : (Catseye_types.Finding.t list * Yojson.Safe.t list) =
  (* Find our extractor script by traversing up from current working dir *)
  let catseye_root = match find_catseye_root (Stdlib.Sys.getcwd ()) with
    | Some dir -> dir
    | None -> Stdlib.Sys.getcwd ()
  in
  (* Get absolute paths to avoid cd issues with relative paths *)
  let catseye_root_abs = realpath catseye_root in
  let extractor_dir = Stdlib.Filename.concat catseye_root_abs "scripts/elixir-extractor" in
  let extractor_dir_abs = realpath extractor_dir in
  let has_extractor = Stdlib.Sys.file_exists (Stdlib.Filename.concat extractor_dir_abs "mix.exs") in
  let (status, lines) =
    if has_extractor then
      let cmd = Stdlib.Printf.sprintf "cd %s && MIX_ENV=prod mix run -e 'CatseyeExtractor.run_dir(\"%s\")' 2>&1"
        (Stdlib.Filename.quote extractor_dir_abs)
        (Stdlib.Filename.quote project_dir)
      in
      run_cmd cmd
    else
      let cmd = Stdlib.Printf.sprintf "cd %s && MIX_ENV=prod mix run -e 'CatseyeExtractor.run' 2>&1"
        (Stdlib.Filename.quote project_dir)
      in
      run_cmd cmd
  in
  match status with
  | WEXITED 0 ->
    let json_data = List.fold_left ~init:[] ~f:(fun acc line ->
      if String.length line > 10 && Stdlib.String.sub line 0 1 = "{" then
        try Yojson.Safe.from_string line :: acc
        with _ -> acc
      else acc
    ) lines in
    let sink_findings = List.fold_left ~init:[] ~f:(fun acc line ->
      if String.length line > 10 && Stdlib.String.sub line 0 1 = "{" then
        match parse_module_json line with
        | mod_info when mod_info.mod_functions <> [] ->
          (sinks_to_findings mod_info) @ acc
        | _ -> acc
      else acc
    ) lines in
    (sink_findings, json_data)
  | WEXITED n ->
    (Stdlib.Printf.eprintf "Elixir extractor command failed with exit code %d\n" n;
     ([], []))
  | _ ->
    (Stdlib.Printf.eprintf "Elixir extractor command failed with non-WEXITED status\n";
     ([], []))

(* Main extraction function - runs Elixir extractor and returns findings *)
let extract (project_dir : string) : Catseye_types.Finding.t list =
  let (sink_findings, _json_data) = extract_with_data project_dir in
  sink_findings

(* Run extractor on a single file *)
let extract_file (file : string) : Catseye_types.Finding.t list =
  let cmd = Stdlib.Printf.sprintf "MIX_ENV=prod mix run -e 'CatseyeExtractor.run_file(\"%s\")' 2>&1"
    (Stdlib.Filename.quote file)
  in
  let (status, lines) = run_cmd cmd in
  match status with
  | WEXITED 0 ->
    (match parse_module_json (String.concat ~sep:"\n" lines) with
     | mod_info when mod_info.mod_functions <> [] -> sinks_to_findings mod_info
     | _ -> [])
  | _ -> []