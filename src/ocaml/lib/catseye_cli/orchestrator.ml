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

(* ── Hunter Persona ─────────────────────────────────────────────────── *)

(* Catseye severity levels: terminal-only presentation layer *)
let catseye_level = function
  | "critical" | "high" | "Critical" | "High" -> "HISS"
  | "medium" | "low" | "Medium" | "Low" -> "MEOW"
  | _ -> "PURR"

let catseye_icon = function
  | "critical" | "high" | "Critical" | "High" -> "🐱⚡ "
  | "medium" | "low" | "Medium" | "Low" -> "🐾 "
  | _ -> "😸 "

(* Atmospheric scent lines — one chosen at random per scan *)
let scent_lines = [|
  "Fresh code detected";
  "Many files to patrol";
  "Something rustles in the undergrowth...";
  "The codebase stirs.";
  "Scent trail picked up.";
  "The tall grass parts...";
|]

let random_scent () =
  let idx = Random.int (Array.length scent_lines) in
  scent_lines.(idx)

(* ── Extractors ─────────────────────────────────────────────────────── *)

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

(** Extract nodes from a source file, handling logging and caching.
    Returns nodes if extraction succeeded, or None on failure. *)
let extract_with_log (config : t) (src : source_file)
    : Security_node.t list option =
  if config.format = Terminal then begin
    if config.persona then
      Printf.printf "  🐾 Stalking %s\n" src.path
    else
      Printf.printf "%s→ Extracting: %s%s\n"
        (styled cyan config "") src.path (styled reset config "")
  end;
  try extract_file config src with Sys_error _ -> None

(* ── Banner ─────────────────────────────────────────────────────────── *)

let print_banner_persona (config : t) (cr_count : int) (gleam_count : int) (dep_count : int) =
  Printf.printf " ╭──────────────────────────────────────────╮\n";
  Printf.printf " │  🐈‍⬛  Catseye v%-6s                     │\n" version;
  Printf.printf " │     The Hunter enters the tall grass...  │\n";
  Printf.printf " ╰──────────────────────────────────────────╯\n";
  Printf.printf "  Target:   %s\n" (styled green config config.target_dir);
  Printf.printf "  Files:    %d Crystal, %d Gleam%s\n"
    cr_count gleam_count
    (if dep_count > 0 then Printf.sprintf " (%d dependencies)" dep_count else "");
  Printf.printf "  Scent:    %s\n" (random_scent ());
  Printf.printf "\n"

let print_banner_plain (config : t) (cr_count : int) (gleam_count : int) (dep_count : int) =
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

let print_banner (config : t) (cr_count : int) (gleam_count : int) (dep_count : int) =
  if config.persona then
    print_banner_persona config cr_count gleam_count dep_count
  else
    print_banner_plain config cr_count gleam_count dep_count

(* ── Finding output ─────────────────────────────────────────────────── *)

let severity_color = function
  | "critical" | "high" | "Critical" | "High" -> red
  | "medium" | "Medium" -> yellow
  | _ -> cyan

let print_finding (config : t) (f : Finding.t) =
  let c = severity_color f.severity in
  if config.persona then begin
    let icon = catseye_icon f.severity in
    let level = catseye_level f.severity in
    Printf.printf "  %s%s %s  %s:%d%s\n"
      (styled (bold ^ c) config icon)
      level f.rule f.file f.line (styled reset config "");
    Printf.printf "%s       %s%s\n"
      (styled dim config "") f.message (styled reset config "")
  end else begin
    Printf.printf "%s[%s] %s  %s:%d%s\n"
      (styled (bold ^ c) config "")
      f.rule f.severity f.file f.line reset;
    Printf.printf "%s  %s%s\n"
      (styled dim config "") f.message (styled reset config "")
  end;
  List.iter (fun ({ Finding.file = sf; line = sl; message = sm } : Finding.flow_step) ->
    let loc = if sf <> "" && sl > 0
      then Printf.sprintf "  (%s:%d)" sf sl
      else ""
    in
    Printf.printf "%s    ← %s%s%s\n"
      (styled dim config "") sm loc (styled reset config "")
  ) f.flow;
  Printf.printf "\n"

(* ── Summary helpers ────────────────────────────────────────────────── *)

let count_by_severity (findings : Finding.t list) =
  let hiss = ref 0 in
  let meow = ref 0 in
  List.iter (fun f ->
    match catseye_level f.Finding.severity with
    | "HISS" -> incr hiss
    | "MEOW" -> incr meow
    | _ -> ()
  ) findings;
  (!hiss, !meow)

(* ── JSON output ────────────────────────────────────────────────────── *)

let output_json (config : t) (sources : source_file list)
    (nodes : Security_node.t list) (findings : Finding.t list) (cache_hits : int)
    ?(supply_chain : Yojson.Safe.t option) () =
  let base = [
    ("version", `String version);
    ("target", `String config.target_dir);
    ("files_scanned", `Int (List.length sources));
    ("nodes_extracted", `Int (List.length nodes));
    ("cache_hits", `Int cache_hits);
    ("findings_count", `Int (List.length findings));
    ("findings", Finding.encode_many findings);
  ] in
  let with_supply = match supply_chain with
    | Some sc -> ("supply_chain", sc) :: base
    | None -> base
  in
  let output = `Assoc with_supply in
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

(* ── Crow's Nest integration ────────────────────────────────────────── *)

let run_crows_nest (config : t) : Catseye_crowsnest.Aggregator.dep_result list option =
  if not config.crows_nest then None
  else begin
    let manifests = Catseye_crowsnest.Manifest.find_manifests_recursive config.target_dir in
    if manifests = [] then None
    else begin
      let cache_path = Filename.concat config.cache_dir "crowsnest.db" in
      let cache =
        try Some (Catseye_crowsnest.Cache.open_db cache_path)
        with _ -> None
      in
      let results = match cache with
        | Some c -> Catseye_crowsnest.Aggregator.audit manifests ~cache:c ()
        | None -> Catseye_crowsnest.Aggregator.audit manifests ()
      in
      (match cache with
       | Some c -> Catseye_crowsnest.Cache.close c
       | None -> ());
      Some results
    end
  end

let crows_nest_to_json (target_dir : string) (results : Catseye_crowsnest.Aggregator.dep_result list) : Yojson.Safe.t =
  let dep_to_json (r : Catseye_crowsnest.Aggregator.dep_result) =
    let level_str = match r.level with
      | `Hiss -> "hiss" | `Meow -> "meow" | `Purr -> "purr"
    in
    let osv_json = match r.osv with
      | Catseye_crowsnest.Osv.No_known_cves -> `Assoc [("status", `String "clean")]
      | Catseye_crowsnest.Osv.Vulnerabilities vulns ->
        `Assoc [
          ("status", `String "vulnerable");
          ("vulnerabilities", `List (List.map (fun v ->
            `Assoc [
              ("id", `String v.Catseye_crowsnest.Osv.id);
              ("summary", `String v.Catseye_crowsnest.Osv.summary);
              ("severity", match v.Catseye_crowsnest.Osv.severity with
                | Some s -> `String s | None -> `Null);
              ("patched_versions", `List (List.map (fun pv -> `String pv)
                v.Catseye_crowsnest.Osv.patched_versions));
            ]
          ) vulns));
        ]
      | Catseye_crowsnest.Osv.Query_failed msg ->
        `Assoc [("status", `String "failed"); ("error", `String msg)]
    in
    `Assoc [
      ("name", `String r.name);
      ("version", match r.version with Some v -> `String v | None -> `Null);
      ("ecosystem", `String r.ecosystem);
      ("level", `String level_str);
      ("osv", osv_json);
    ]
  in
  let hiss = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Hiss) results) in
  let meow = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Meow) results) in
  let purr = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Purr) results) in
  `Assoc [
    ("manifests", `List (List.map (fun m ->
      let (path, kind) = match m with
        | Catseye_crowsnest.Manifest.Shard_yml (p, _) -> (p, "shard.yml")
        | Catseye_crowsnest.Manifest.Gleam_toml (p, _) -> (p, "gleam.toml")
      in
      `Assoc [("path", `String path); ("kind", `String kind)]
    ) (Catseye_crowsnest.Manifest.find_manifests_recursive
         (if Sys.is_directory target_dir then target_dir
          else Filename.dirname target_dir))));
    ("dependencies", `List (List.map dep_to_json results));
    ("summary", `Assoc [
      ("hiss", `Int hiss); ("meow", `Int meow); ("purr", `Int purr)
    ]);
  ]

(* ── Timing helper ──────────────────────────────────────────────────── *)

let time_phase label f =
  let t0 = Unix.gettimeofday () in
  let result = f () in
  let t1 = Unix.gettimeofday () in
  Printf.eprintf "  [timing] %s: %.3fs\n" label (t1 -. t0);
  result

(* ── Main pipeline ──────────────────────────────────────────────────── *)

let run (config : t) : int =
  Random.self_init ();
  let config = Config.load config in

  (* Step 0: Crow's Nest (runs in parallel with taint analysis conceptually) *)
  let crows_nest_results = run_crows_nest config in

  (* Step 1: Discover sources *)
  let sources = time_phase "discovery" (fun () ->
    discover_sources config.target_dir config.lang_filter config.exclude_dirs) in
  if sources = [] then begin
    (* Still print Crow's Nest if we have results *)
    (match crows_nest_results with
     | Some results when results <> [] ->
       if config.format = Terminal then
         Crowsnest_format.print_crows_nest config results
     | _ -> ());
    Printf.printf "No .cr or .gleam files found in %s\n" config.target_dir;
    exit 0
  end;
  let cr_count = List.length (List.filter (fun s -> s.lang = "crystal") sources) in
  let gleam_count = List.length (List.filter (fun s -> s.lang = "gleam") sources) in
  let dep_count = List.length (List.filter (fun s -> s.is_dependency) sources) in
  if config.format = Terminal then print_banner config cr_count gleam_count dep_count;

  (* Step 2: Extract (with cache, optional parallel) *)
  let (nodes, cache_hits) = time_phase "extraction" (fun () ->
    let all_nodes = ref [] in
    let cache_hits = ref 0 in
    let uncached = ref [] in
    (* Phase 1: Check cache for all files *)
    List.iter (fun src ->
      if config.no_cache then
        uncached := src :: !uncached
      else
        match Catseye_engine.Cache.check src.path with
        | Some cached ->
          incr cache_hits;
          List.iter (fun n -> all_nodes := n :: !all_nodes) cached
        | None ->
          uncached := src :: !uncached
    ) sources;
    (* Phase 2: Extract uncached files — parallel if parallelism > 0 *)
    let extract_one src =
      match extract_with_log config src with
      | Some ns ->
        if not config.no_cache then
          Catseye_engine.Cache.store src.path ns;
        Some ns
      | None -> None
    in
    if config.parallelism > 0 && List.length !uncached > 1 then begin
      (* Parallel extraction using Domains *)
      let results = Catseye_engine.Parallel.extract_parallel extract_one !uncached in
      List.iter (fun ns -> all_nodes := List.rev_append ns !all_nodes) results
    end else
      List.iter (fun src ->
        match extract_one src with
        | Some ns -> all_nodes := List.rev_append ns !all_nodes
        | None -> ()
      ) !uncached;
    (List.rev !all_nodes, !cache_hits)
  ) in
  if nodes = [] then begin
    Printf.printf "\nNo AST nodes extracted. Nothing to analyze.\n";
    exit 0
  end;

  (* Step 3: Load rules *)
  let rules = time_phase "rules" (fun () ->
    match Catseye_rules.Loader.load_rules config.rules_dir with
    | Ok r -> r
    | Error (`Msg msg) ->
      Printf.eprintf "Warning: %s\n" msg;
      [])
  in

  (* Step 4: Analyze *)
  if config.format = Terminal then begin
    if config.persona then begin
      Printf.printf "\n  👀 Watching... %d nodes to inspect\n" (List.length nodes);
      Printf.printf "  🎯 Pouncing on taint flows...\n\n"
    end else
      Printf.printf "\n%s→ Running analysis engine (%d nodes)...\n\n"
        (styled cyan config "") (List.length nodes)
  end;

  let findings = time_phase "analysis" (fun () ->
    Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes) in

  (* Step 4b: Predator Vision — reachability analysis *)
  let reachability = if config.predator_vision && findings <> [] then begin
    let reach = Catseye_engine.Reachability.analyze nodes findings ~custom_patterns:[] in
    (* Tag findings with reachability *)
    let tagged = List.map2 (fun f r ->
      { f with Finding.reachability = Some {
        status = (match r.Catseye_engine.Reachability.status with
          | `Live -> Finding.Live
          | `Dormant -> Finding.Dormant
          | `Safe -> Finding.Safe);
        entry_point = r.Catseye_engine.Reachability.entry_point;
        entry_function = r.Catseye_engine.Reachability.entry_function;
        path_length = r.Catseye_engine.Reachability.path_length;
        path = r.Catseye_engine.Reachability.path;
      }}
    ) findings reach in
    if config.format = Terminal then
      Heatmap.print_heatmap config tagged reach;
    tagged
  end else findings in

  (* Step 4c: Crow's Nest dep reachability (when both --crows-nest and --predator-vision) *)
  let crows_nest_results = match crows_nest_results with
    | Some results when config.predator_vision && results <> [] ->
      (* Build reachable file set from Predator Vision analysis *)
      let reachable_files =
        List.filter_map (fun (f : Finding.t) ->
          match f.reachability with
          | Some r -> (match r.status with
            | Finding.Live | Finding.Dormant ->
              Some f.file
            | Finding.Safe -> None)
          | None -> None
        ) reachability
      in
      (* Also include all files with defs (they're potentially reachable) *)
      let def_files = List.filter_map (fun (n : Security_node.t) ->
        if n.node_type = Security_node.Def then Some n.file else None
      ) nodes in
      let all_reachable =
        List.fold_left (fun s f ->
          Catseye_crowsnest.Dep_reachability.StringSet.add f s
        ) Catseye_crowsnest.Dep_reachability.StringSet.empty
          (reachable_files @ def_files)
      in
      (* Scan source files for imports and compute reachability *)
      let dep_names = List.map (fun (r : Catseye_crowsnest.Aggregator.dep_result) ->
        r.name
      ) results in
      let file_lang_pairs = List.map (fun (s : source_file) ->
        (s.path, s.lang)
      ) sources in
      let dep_imports = Catseye_crowsnest.Dep_reachability.scan_imports
        file_lang_pairs dep_names in
      let dep_reach = Catseye_crowsnest.Dep_reachability.compute_reachability
        all_reachable dep_imports in
      (* Enrich dep results with reachability info *)
      let get_dep_name (r : Catseye_crowsnest.Aggregator.dep_result) = r.name in
      let enriched = Catseye_crowsnest.Dep_reachability.enrich_with_reachability
        results ~get_name:get_dep_name dep_reach
      in
      (* Store enriched results for formatters — reachability data available per dep *)
      Some (List.map fst enriched)
    | other -> other
  in

  (* Step 4d: Claws — code smell analysis *)
  let all_findings = if config.claws then begin
    let claws_findings = Catseye_claws.Smells.analyze nodes
      config.claws_config in
    if config.format = Terminal && claws_findings <> [] then begin
      if config.persona then
        Printf.printf "\n  🐾 Sniffing out code smells...\n\n"
      else
        Printf.printf "\n%s→ Code smell analysis:%s\n\n"
          (styled cyan config "") (styled reset config "")
    end;
    reachability @ claws_findings
  end else reachability in

  (* Step 5: Report *)
  match config.format with
  | Terminal ->
    (* Print Crow's Nest results if available *)
    (match crows_nest_results with
     | Some results when results <> [] ->
       Crowsnest_format.print_crows_nest config results
     | _ -> ());

    List.iter (print_finding config) all_findings;
    Printf.printf "──────────────────────────────────────────────────────────────\n";
    if all_findings <> [] then begin
      if config.persona then begin
        let (hiss, meow) = count_by_severity all_findings in
        Printf.printf "  🐱 Found %d Hiss, %d Meow across %d files.\n"
          hiss meow (List.length sources);
        Printf.printf "  The Hunter has prey. Review the findings above.\n"
      end else
        Printf.printf "%sFound %d issue(s) across %d file(s).%s\n"
          (styled red config "")
          (List.length all_findings) (List.length sources) (styled reset config "");
      1
    end else begin
      if config.persona then begin
        Printf.printf "  😸 PURR  The codebase is clean.\n";
        Printf.printf "       %d files patrolled. Nothing lurking in the grass.\n\n"
          (List.length sources);
        Printf.printf "  The Hunter rests.\n"
      end else
        Printf.printf "%sNo issues found across %d file(s). ✨%s\n"
          (styled green config "") (List.length sources) (styled reset config "");
      0
    end
  | Json ->
    let supply_chain = match crows_nest_results with
      | Some results -> Some (crows_nest_to_json config.target_dir results)
      | None -> None
    in
    output_json config sources nodes all_findings cache_hits
      ?supply_chain ();
    if all_findings <> [] then 1 else 0
  | Sarif ->
    let supply_chain = match crows_nest_results with
      | Some results -> Some (crows_nest_to_json config.target_dir results)
      | None -> None
    in
    let content = Sarif.to_sarif all_findings ?supply_chain () in
    if config.output_path <> "" then begin
      let oc = open_out config.output_path in
      output_string oc content; output_string oc "\n";
      close_out oc;
      Printf.printf "Results written to %s\n" config.output_path
    end else
      print_string content;
    if all_findings <> [] then 1 else 0
  | Markdown ->
    let supply_chain = match crows_nest_results with
      | Some results -> Some (crows_nest_to_json config.target_dir results)
      | None -> None
    in
    let content = Markdown.to_markdown all_findings config.target_dir ?supply_chain () in
    if config.output_path <> "" then begin
      let oc = open_out config.output_path in
      output_string oc content; output_string oc "\n";
      close_out oc;
      Printf.printf "Results written to %s\n" config.output_path
    end else
      print_string content;
    if all_findings <> [] then 1 else 0
  | Dot ->
    Dot.output_dot nodes all_findings
      ~custom_patterns:config.extra_sources
      config.output_path;
    0
