(* lib/catseye_cli/orchestrator.ml *)

open Catseye_types
open Config
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

(* ── Severity helpers ────────────────────────────────────────────────── *)

let severity_label = function
  | "critical" | "high" | "Critical" | "High" -> "Error"
  | "medium" | "low" | "Medium" | "Low" -> "Warning"
  | _ -> "Info"

let severity_icon = function
  | "critical" | "high" | "Critical" | "High" -> "🔴 "
  | "medium" | "low" | "Medium" | "Low" -> "⚠️  "
  | _ -> "ℹ️  "

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
  if config.ast_bridge then begin
    (* Bridge path: parse → CatseyeAST.t → Security_node.t *)
    try
      match Catseye_ast.Parse.parse_file ~extractor_registry:config.extractor_registry ~path:src.path with
      | Ok mod_ ->
          let nodes = Catseye_ast.To_security_node.derive mod_ in
          Some nodes
      | Error err ->
          Printf.eprintf "Bridge parse error: %s:%d: %s\n" err.file
            (Option.value err.line ~default:0) err.message;
          None
    with e ->
      Printf.eprintf "Bridge error: %s\n" (Printexc.to_string e);
      None
  end else
  match src.lang with
  | "crystal" ->
    (match config.extractor_registry with
     | None -> None  (* Crystal not available *)
     | Some reg ->
       let cmd = Printf.sprintf "%s %s 2>/dev/null"
         (Filename.quote (Catseye_engine.Extractor_registry.flat_cmd reg))
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
       else None)
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
  if config.format = Terminal then
    Printf.printf "%s→ Extracting: %s%s\n"
      (styled cyan config "") src.path (styled reset config "");
  try extract_file config src with Sys_error _ -> None

(* ── Banner ─────────────────────────────────────────────────────────── *)

let print_banner (config : t) (cr_count : int) (gleam_count : int) (dep_count : int) =
  Printf.printf "
  %sCatseye v%s%s
" (styled (bold ^ cyan) config "") version (styled reset config "");
  Printf.printf "  Target:   %s
" (styled green config config.target_dir);
  Printf.printf "  Files:    %d Crystal, %d Gleam%s
"
    cr_count gleam_count
    (if dep_count > 0 then Printf.sprintf " (%d dependencies)" dep_count else "");
  Printf.printf "
"

(* ── Finding output ─────────────────────────────────────────────────── *)

let severity_color = function
  | "critical" | "high" | "Critical" | "High" -> red
  | "medium" | "Medium" -> yellow
  | _ -> cyan

let print_finding (config : t) (f : Finding.t) =
  let c = severity_color f.severity in
  let icon = severity_icon f.severity in
  let label = severity_label f.severity in
  Printf.printf "  %s%s %s  %s:%d%s\n"
    (styled (bold ^ c) config icon)
    label f.rule f.file f.line (styled reset config "");
  Printf.printf "%s       %s%s\n"
    (styled dim config "") f.message (styled reset config "");
  List.iter (fun ({ Finding.file = sf; line = sl; message = sm } : Finding.flow_step) ->
    let loc = if sf <> "" && sl > 0
      then Printf.sprintf "  (%s:%d)" sf sl
      else ""
    in
    Printf.printf "%s    ← %s%s%s\n"
      (styled dim config "") sm loc (styled reset config "")
  ) f.flow;
  (match f.Finding.suggestion with
   | Some fix ->
     Printf.printf "%s  💡 Suggestion: %s%s%s\n"
       (styled green config "") fix (styled reset config "") ""
   | None -> ());
  Printf.printf "\n"

(* ── Summary helpers ────────────────────────────────────────────────── *)

let count_by_severity (findings : Finding.t list) =
  let errors = ref 0 in
  let warnings = ref 0 in
  List.iter (fun f ->
    match severity_label f.Finding.severity with
    | "Error" -> incr errors
    | "Warning" -> incr warnings
    | _ -> ()
  ) findings;
  (!errors, !warnings)

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
      | `Critical -> "critical" | `Warning -> "warning" | `Clean -> "clean"
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
  let errors = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Critical) results) in
  let warnings = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Warning) results) in
  let clean = List.length (List.filter (fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Clean) results) in
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
      ("critical", `Int errors); ("warning", `Int warnings); ("clean", `Int clean)
    ]);
  ]

(* ── Timing helper ──────────────────────────────────────────────────── *)

let time_phase label f =
  let t0 = Unix.gettimeofday () in
  let result = f () in
  let t1 = Unix.gettimeofday () in
  Printf.eprintf "  [timing] %s: %.3fs\n" label (t1 -. t0);
  result

(* ── Timeout helper ─────────────────────────────────────────────────── *)

let with_timeout ~ms f =
  if ms <= 0 then f ()
  else
    let deadline = Unix.gettimeofday () +. (float ms /. 1000.0) in
    let check_and_run () =
      if Unix.gettimeofday () > deadline then
        raise (Failure ("timeout: exceeded " ^ string_of_int ms ^ "ms"))
    in
    try (check_and_run (); f ()) with
    | Failure msg when String.length msg >= 7 && String.sub msg 0 7 = "timeout" ->
      raise (Failure msg)
    | e -> raise e

(* ── Main pipeline ──────────────────────────────────────────────────── *)

let run (config : t) : int =
  Random.self_init ();
  let config = Config.load config in

  (* Step 0: Crow's Nest (runs in parallel with taint analysis conceptually) *)
  let crows_nest_results = run_crows_nest config in

  (* Step 1: Discover sources *)
  let sources = time_phase "discovery" (fun () ->
    discover_sources ~include_deps:config.include_deps ~lang_filter:config.lang_filter config.target_dir config.exclude_dirs) in
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
  if config.format = Terminal && not config.crystal_available then
    Printf.eprintf "  [info] Crystal toolchain not detected — Crystal extraction disabled\n%!";

  (* Step 1b: Handle --clear-cache *)
  if config.clear_cache then begin
    Catseye_engine.Cache.delete_cache config.cache_dir;
    if config.format = Terminal then
      Printf.printf "  Cache cleared.\n"
  end;

  (* Step 1c: Open persistent cache *)
  let cache = Catseye_engine.Cache.open_cache
    ~no_cache:config.no_cache ~cache_dir:config.cache_dir in

  (* Step 2: Extract (with cache, optional worker pool or parallel) *)
  let (nodes, cache_hits) = time_phase "extraction" (fun () ->
    let all_nodes = ref [] in
    let cache_hits = ref 0 in
    let uncached = ref [] in
    (* Phase 1: Check cache for all files *)
    List.iter (fun src ->
      match Catseye_engine.Cache.check cache src.path with
      | Some cached ->
        incr cache_hits;
        List.iter (fun n -> all_nodes := n :: !all_nodes) cached
      | None ->
        uncached := src :: !uncached
    ) sources;
    (* Split uncached by language *)
    let uncached_crystal = List.filter (fun s -> s.lang = "crystal") !uncached in
    let uncached_other = List.filter (fun s -> s.lang <> "crystal") !uncached in
    (* Phase 2a: Extract Crystal files via worker pool if configured *)
    if config.crystal_workers > 1 && uncached_crystal <> [] then begin
      (match config.extractor_registry with
       | None -> ()  (* Crystal not available *)
       | Some reg ->
       let pool = Catseye_engine.Worker_pool.create
        (Catseye_engine.Extractor_registry.flat_cmd reg) config.crystal_workers in
      List.iter (fun src ->
        match Catseye_engine.Worker_pool.extract_with_recovery pool src.path with
        | Some ns ->
          Catseye_engine.Cache.store cache src.path ns;
          List.iter (fun n -> all_nodes := n :: !all_nodes) ns
        | None -> ()
      ) uncached_crystal;
      Catseye_engine.Worker_pool.shutdown pool)
    end else
      (* No worker pool — extract Crystal files normally *)
      List.iter (fun src ->
        match extract_with_log config src with
        | Some ns ->
          Catseye_engine.Cache.store cache src.path ns;
          List.iter (fun n -> all_nodes := n :: !all_nodes) ns
        | None -> ()
      ) uncached_crystal;
    (* Phase 2b: Extract non-Crystal files (Gleam, etc.) *)
    let extract_one src =
      match extract_with_log config src with
      | Some ns ->
        Catseye_engine.Cache.store cache src.path ns;
        Some ns
      | None -> None
    in
    if config.parallelism > 0 && List.length uncached_other > 1 then
      (* Parallel extraction using Domains for non-Crystal files *)
      let results = Catseye_engine.Parallel.extract_parallel extract_one uncached_other in
      List.iter (fun ns -> all_nodes := List.rev_append ns !all_nodes) results
    else
      List.iter (fun src ->
        match extract_one src with
        | Some ns -> all_nodes := List.rev_append ns !all_nodes
        | None -> ()
      ) uncached_other;
    (List.rev !all_nodes, !cache_hits)
  ) in
  if nodes = [] then begin
    Catseye_engine.Cache.close cache;
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

  (* Apply --no-cfg override: flat engine has more predictable performance *)
  let config = if config.no_cfg_use then { config with use_cfg = false } else config in

  (* Step 4: Analyze *)
  if config.format = Terminal then
    Printf.printf "\n  → Running analysis engine (%d nodes)...\n\n" (List.length nodes);

  let do_analysis () =
    if config.use_cfg then begin
      (* CFG-based taint analysis *)
      if config.format = Terminal then
        Printf.printf "  [cfg] Using IL/CFG-based taint engine\n";
      let all_sources = List.concat_map (fun (r : Catseye_rules.Types.rule_def) ->
        r.sources
      ) rules in
      let analyzed = ref 0 in
      List.concat_map (fun src ->
        incr analyzed;
        if config.format = Terminal && !analyzed mod 10 = 0 then
          Printf.eprintf "  [progress] Analyzed %d/%d files...\n" !analyzed (List.length sources);
        try
          match Catseye_ast.Parse.parse_file ~extractor_registry:config.extractor_registry ~path:src.path with
          | Error _ -> []
          | Ok mod_ ->
            let unit = Catseye_il.Of_catseye_ast.translate mod_ in
            let opts : Catseye_il.Cfg_taint.analyze_opts = {
              cfg_max_blocks = config.cfg_max_blocks;
              cfg_timeout_ms = config.cfg_timeout_ms;
            } in
            let result = Catseye_il.Cfg_taint.analyze_unit ~opts unit all_sources rules in
            (match result.skipped_functions with
             | [] -> ()
             | fns ->
               Printf.eprintf "  [warn] Skipped %d functions due to CFG bounds in %s\n"
                 (List.length fns) src.path);
            result.findings
        with e ->
          Printf.eprintf "  [warn] CFG analysis failed for %s: %s\n" src.path (Printexc.to_string e);
          []
      ) sources
    end else begin
      (* Flat taint engine — more predictable performance *)
      if config.format = Terminal then
        Printf.printf "  [engine] Using flat taint engine\n";
      Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes
    end
  in
  let findings = time_phase "analysis" (fun () ->
    match config.analysis_timeout_ms with
    | 0 -> do_analysis ()  (* No timeout *)
    | ms ->
      Printf.eprintf "  [timeout] Analysis timeout set to %dms\n" ms;
      try with_timeout ~ms do_analysis with
      | Failure msg when String.length msg >= 7 && String.sub msg 0 7 = "timeout" ->
        Printf.eprintf "\n  [timeout] Analysis exceeded limit. Falling back to flat engine...\n";
        Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes
  ) in

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

  (* Step 4d: AI Linter — Gleam & Crystal antipattern detection *)
  let ai_findings = if config.ai_lint then begin
    if config.format = Terminal then
      Printf.printf "\n  → AI antipattern detection:\n\n";
    let ai_lint_findings = List.concat_map (fun src ->
      (try
        match Catseye_ast.Parse.parse_file ~extractor_registry:config.extractor_registry ~path:src.path with
        | Error err -> [Catseye_types.Finding.{ rule = "parse-error"; severity = "error"; file = err.file;
            line = Option.value err.line ~default:0; message = err.message;
            flow = []; language = ""; dependency = None; reachability = None; suggestion = None; }]
        | Ok mod_ ->
          (match mod_.mod_lang with
           | Gleam ->
            let convert_finding (f : Ai_linter.Types.finding) =
              { Catseye_types.Finding.rule = f.rule_id;
                severity = Ai_linter.Types.severity_to_string f.severity;
                file = f.file;
                line = f.line; message = f.message;
                flow = []; language = "gleam"; dependency = None; reachability = None;
                suggestion = f.suggestion; }
            in
            List.map convert_finding (Ai_linter.Gleam_rules.analyze_module mod_)
           | Crystal -> []
           | _ -> [])
      with exn -> Printf.eprintf "AI lint error: %s\n" (Printexc.to_string exn); [])
    ) sources in
    if config.format = Terminal && ai_lint_findings <> [] then begin
      List.iter (fun (f : Catseye_types.Finding.t) ->
        Printf.printf "  [ai:%s] %s:%d - %s\n" f.rule f.file f.line f.message
      ) ai_lint_findings
    end;
    ai_lint_findings
  end else [] in

  (* Step 4e: Claws — code smell analysis *)
  let all_findings = if config.claws then begin
    (* Parse ASTs for files that support it (Gleam always, Crystal via bridge) *)
    let ast_modules = List.filter_map (fun src ->
      try match Catseye_ast.Parse.parse_file ~extractor_registry:config.extractor_registry ~path:src.path with
        | Ok mod_ -> Some mod_
        | Error _ -> None
      with _ -> None
    ) sources in
    let claws_findings =
      if ast_modules <> [] then
        Catseye_claws.Smells.analyze_ast ast_modules config.claws_config
      else
        Catseye_claws.Smells.analyze nodes config.claws_config
    in
    (* Merge with flat-engine findings for detectors not yet on AST path *)
    let flat_claws = Catseye_claws.Smells.analyze nodes config.claws_config in
    (* Only add findings from flat engine for rules the AST path doesn't cover yet *)
    let ast_rules = Hashtbl.create 8 in
    List.iter (fun (f : Finding.t) ->
      Hashtbl.replace ast_rules f.Finding.rule true
    ) claws_findings;
    let extra_flat = List.filter (fun (f : Finding.t) ->
      not (Hashtbl.mem ast_rules f.Finding.rule)
    ) flat_claws in
    let all_claws = claws_findings @ extra_flat in
    if config.format = Terminal && all_claws <> [] then
        Printf.printf "\n  → Code smell analysis:\n\n";
    reachability @ all_claws @ ai_findings
  end else reachability @ ai_findings in

  (* Apply taint suppression from [taint.suppress] in .catseye.toml *)
  let all_findings =
    let sup = config.taint_suppress in
    if Hashtbl.length sup = 0 then all_findings
    else List.filter (fun (f : Finding.t) ->
      match Hashtbl.find_opt sup f.Finding.rule with
      | None -> true
      | Some patterns ->
        not (List.exists (fun pat ->
          Catseye_claws.Smells.glob_match pat f.Finding.file
        ) patterns)
    ) all_findings
  in

  (* Step 5: Report *)
  Catseye_engine.Cache.close cache;
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
      let (errors, warnings) = count_by_severity all_findings in
      Printf.printf "  Found %d Error(s), %d Warning(s) across %d files.\n"
        errors warnings (List.length sources);
      Printf.printf "  Review the findings above.\n";
      1
    end else begin
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
