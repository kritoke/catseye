(* lib/catseye_cli/orchestrator.ml *)

open Config
open Catseye_types
open Discovery

let version = Catseye_engine.Engine.version

(* ANSI color codes *)
let bold = "\027[1m"
let dim = "\027[2m"
let red = "\027[31m"
let yellow = "\027[33m"
let green = "\027[32m"
let cyan = "\027[36m"
let reset = "\027[0m"

let styled color config text =
  if config.color then color ^ text ^ reset else text

let run_crystal_extractor (extractor : string) (file_path : string) : (string, int) result =
  let cmd = Printf.sprintf "CRYSTAL_HAS_WRAPPER=1 crystal run %s -- %s 2>/dev/null"
    (Filename.quote extractor) (Filename.quote file_path)
  in
  let exit_code = Sys.command cmd in
  if exit_code = 0 then
    try
      let ic = open_in (Printf.sprintf "/tmp/catseye-extract-%d.out" (Unix.getpid ())) in
      let len = in_channel_length ic in
      let buf = Bytes.create len in
      really_input ic buf 0 len;
      close_in ic;
      Ok (Bytes.to_string buf)
    with _ -> Error exit_code
  else Error exit_code

let extract_file (config : t) (src : source_file) : Security_node.t list option =
  match src.lang with
  | "crystal" ->
    let cmd = Printf.sprintf "%s %s 2>/dev/null"
      (Filename.quote config.crystal_extractor)
      (Filename.quote src.path)
    in
    let (stdout_ch, stdin_ch, stderr_ch) = Unix.open_process_full cmd (Unix.environment ()) in
    let output = Buffer.create 4096 in
    (try while true do Buffer.add_channel output stdout_ch 4096 done
     with End_of_file -> ());
    let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
    let json_str = Buffer.contents output in
    if json_str <> "" then
      try Some (Security_node.decode_many (Yojson.Safe.from_string json_str))
      with _ -> None
    else None
  | "gleam" ->
    (try
      let nodes = Catseye_engine.Gleam.extract src.path in
      (match nodes with
       | Ok ns -> Some ns
       | Error (`Msg msg) ->
         Printf.eprintf "Gleam extraction failed: %s\n" msg;
         None)
     with e ->
       Printf.eprintf "Gleam extraction error: %s\n" (Printexc.to_string e);
       None)
  | _ -> None

let print_banner (config : t) (cr_count : int) (gleam_count : int) (dep_count : int) =
  Printf.printf "%s\n" (styled (bold ^ cyan) config
    "╔══════════════════════════════════════╗");
  Printf.printf "%s\n" (styled (bold ^ cyan) config
    (Printf.sprintf "║            Catseye v%s           ║" version));
  Printf.printf "%s\n" (styled (bold ^ cyan) config
    "╚══════════════════════════════════════╝");
  Printf.printf "  Target:   %s\n" (styled green config config.target_dir);
  Printf.printf "  Files:    %d Crystal, %d Gleam%s\n"
    cr_count gleam_count
    (if dep_count > 0 then Printf.sprintf " (%d dependencies)" dep_count else "");
  Printf.printf "  Engine:   OCaml (taint v3)\n";
  Printf.printf "\n"

let severity_color = function
  | "critical" | "high" | "Critical" | "High" -> red
  | "medium" | "Medium" -> yellow
  | _ -> cyan

let print_finding (config : t) (f : Finding.t) =
  let c = severity_color f.severity in
  Printf.printf "%s[%s] %s  %s:%d%s\n"
    (styled (bold ^ c) config "")
    f.rule f.severity f.file f.line reset;
  Printf.printf "%s  %s%s\n"
    (styled dim config "") f.message (styled reset config "");
  List.iter (fun ({ Finding.file = sf; line = sl; message = sm } : Finding.flow_step) ->
    let loc = if sf <> "" && sl > 0
      then Printf.sprintf "  (%s:%d)" sf sl
      else ""
    in
    Printf.printf "%s    ← %s%s%s\n"
      (styled dim config "") sm loc (styled reset config "")
  ) f.flow;
  Printf.printf "\n"

let output_json (config : t) (sources : source_file list)
    (nodes : Security_node.t list) (findings : Finding.t list) (cache_hits : int) =
  let output = `Assoc [
    ("version", `String version);
    ("target", `String config.target_dir);
    ("files_scanned", `Int (List.length sources));
    ("nodes_extracted", `Int (List.length nodes));
    ("cache_hits", `Int cache_hits);
    ("findings_count", `Int (List.length findings));
    ("findings", Finding.encode_many findings);
  ] in
  let json_str = Yojson.Safe.pretty_to_string output in
  if config.output_path <> "" then begin
    let rec mkdir_p d =
      if not (Sys.file_exists d) then begin
        mkdir_p (Filename.dirname d);
        Unix.mkdir d 0o755
      end
    in
    let dir = Filename.dirname config.output_path in
    mkdir_p dir;
    let oc = open_out config.output_path in
    output_string oc json_str;
    output_string oc "\n";
    close_out oc;
    Printf.printf "Results written to %s\n" config.output_path
  end else
    print_string json_str

let run (config : t) : int =
  let config = Config.load config in
  (* Step 1: Discover sources *)
  let sources = discover_sources config.target_dir config.lang_filter config.exclude_dirs in
  if sources = [] then begin
    Printf.printf "No .cr or .gleam files found in %s\n" config.target_dir;
    exit 0
  end;
  let cr_count = List.length (List.filter (fun s -> s.lang = "crystal") sources) in
  let gleam_count = List.length (List.filter (fun s -> s.lang = "gleam") sources) in
  let dep_count = List.length (List.filter (fun s -> s.is_dependency) sources) in
  if config.format = Terminal then print_banner config cr_count gleam_count dep_count;

  (* Step 2: Extract (with cache) *)
  let all_nodes = ref [] in
  let cache_hits = ref 0 in
  List.iter (fun src ->
    if config.no_cache then begin
      (* No cache — always extract *)
      if config.format = Terminal then
        Printf.printf "%s→ Extracting: %s%s\n" (styled cyan config "") src.path (styled reset config "");
      match (try extract_file config src with Sys_error _ -> None) with
      | Some nodes -> all_nodes := nodes @ !all_nodes
      | None -> ()
    end else begin
      (* Check cache first *)
      match Catseye_engine.Cache.check src.path with
      | Some cached ->
        incr cache_hits;
        all_nodes := cached @ !all_nodes
      | None ->
        if config.format = Terminal then
          Printf.printf "%s→ Extracting: %s%s\n" (styled cyan config "") src.path (styled reset config "");
        (match (try extract_file config src with Sys_error _ -> None) with
         | Some nodes ->
           Catseye_engine.Cache.store src.path nodes;
           all_nodes := nodes @ !all_nodes
         | None -> ())
    end
  ) sources;
  let nodes = !all_nodes in
  if nodes = [] then begin
    Printf.printf "\nNo AST nodes extracted. Nothing to analyze.\n";
    exit 0
  end;

  (* Step 3: Load rules *)
  let rules = match Catseye_rules.Loader.load_rules config.rules_dir with
    | Ok r -> r
    | Error (`Msg msg) ->
      Printf.eprintf "Warning: %s\n" msg;
      []
  in

  (* Step 4: Analyze *)
  if config.format = Terminal then
    Printf.printf "\n%s→ Running analysis engine (%d nodes)...\n\n"
      (styled cyan config "") (List.length nodes);
  let findings = Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes in

  (* Step 5: Report *)
  match config.format with
  | Terminal ->
    List.iter (print_finding config) findings;
    Printf.printf "──────────────────────────────────────────────────────────────\n";
    if findings <> [] then begin
      Printf.printf "%sFound %d issue(s) across %d file(s).%s\n"
        (styled red config "")
        (List.length findings) (List.length sources) (styled reset config "");
      1
    end else begin
      Printf.printf "%sNo issues found across %d file(s). ✨%s\n"
        (styled green config "") (List.length sources) (styled reset config "");
      0
    end
  | Json ->
    output_json config sources nodes findings !cache_hits;
    if findings <> [] then 1 else 0
  | Sarif ->
    (* TODO: Phase 4 — SARIF output from DAG *)
    Printf.printf "{\"error\": \"SARIF output not yet implemented in OCaml engine\"}\n";
    1
  | Markdown ->
    (* TODO: Phase 4 — Markdown output from DAG *)
    Printf.printf "# Catseye Security Report\n\n*SARIF output not yet implemented*\n";
    1
