(* lib/catseye_cli/orchestrator.ml *)

open Base
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

let severity_label sev =
  match String.lowercase sev with
  | "critical" | "high" -> "Error"
  | "medium" | "low" -> "Warning"
  | _ -> "Info"


let severity_icon sev =
  match String.lowercase sev with
  | "critical" | "high" -> "🔴 "
  | "medium" | "low" -> "⚠️  "
  | _ -> "ℹ️  "

(* ── List Rules (AI-friendly export) ──────────────────────────────────── *)

let run_list_rules (config : Config.t) : int =
  (* Load rules from the rules directory *)
  let rules_result = Catseye_rules.Loader.load_rules config.rules_dir in
  match rules_result with
  | Error (`Msg msg) ->
    Format.eprintf "Error loading rules: %s\n" msg;
    1
  | Ok rules ->
    (* Filter by language if specified *)
    let filtered = match config.list_rules_lang with
      | None -> rules
      | Some lang ->
        Catseye_rules.Ai_format.filter_by_language rules lang
    in
    (* Serialize to AI-friendly JSON *)
    let json_output = Catseye_rules.Ai_format.rules_to_json filtered in
    (* Output to file or stdout *)
    if config.output_path <> "" then begin
      let oc = Stdlib.open_out config.output_path in
      Stdlib.output_string oc json_output;
      Stdlib.output_string oc "\n";
      Stdlib.close_out oc;
      Format.printf "Rules exported to %s (%d rules)\n" 
        config.output_path (List.length filtered)
    end else begin
      Stdio.Out_channel.output_string Stdio.stdout json_output;
      Stdio.Out_channel.output_string Stdio.stdout "\n"
    end;
    0

(* ── Extractors ─────────────────────────────────────────────────────── *)

let run_crystal_extractor (extractor : string) (file_path : string) : (string, int) Result.t =
  let cmd = Printf.sprintf "CRYSTAL_HAS_WRAPPER=1 crystal run %s -- %s 2>/dev/null"
    (Stdlib.Filename.quote extractor) (Stdlib.Filename.quote file_path)
  in
  let exit_code = Stdlib.Sys.command cmd in
  if exit_code = 0 then
    try
      let tmp_file, oc = Stdlib.Filename.open_temp_file ~perms:0o600 "catseye-extract-" ".out" in
      (* SECURE: open_temp_file creates atomically with random suffix *)
      Stdlib.close_out oc;
      let ic = Stdlib.open_in tmp_file in
      let len = Stdlib.in_channel_length ic in
      let buf = Stdlib.Bytes.create len in
      Stdlib.really_input ic buf 0 len;
      Stdlib.close_in ic;
      let content = Stdlib.Bytes.to_string buf in
      Stdlib.Sys.remove tmp_file;
      Ok content
    with
    | Sys_error _ -> Error (-2)
    | End_of_file -> Error (-3)
    | _ -> Error (-4)
  else
    Error exit_code

let extract_file (config : t) (src : source_file) : Security_node.t list option =
  (* JS/TS/Svelte/OCaml always use AST bridge — they have no flat extractor *)
  let use_bridge = config.ast_bridge || match src.lang with "javascript" | "typescript" | "svelte" | "ocaml" | "elixir" -> true | _ -> false in
  if use_bridge then begin
    (* Bridge path: parse → CatseyeAST.t → Security_node.t *)
    try
      match Catseye_ast.Parse.parse_file ~extractor_cmds:config.extractor_cmds ~path:src.path with
      | Ok mod_ ->
          let nodes = Catseye_ast.To_security_node.derive mod_ in
          Some nodes
      | Error err ->
          Format.eprintf "Bridge parse error: %s:%d: %s\n" err.file
            (Option.value err.line ~default:0) err.message;
          None
    with e ->
      Format.eprintf "Bridge error: %s\n" (Exn.to_string e);
      None
  end else
  match src.lang with
  | "crystal" ->
    (match config.extractor_registry with
     | None -> None  (* Crystal not available *)
     | Some reg ->
       try
         (* Prefer compiled binary over 'crystal run' to avoid nested compiler process *)
         let extractor = if Catseye_engine.Extractor_registry.flat_is_compiled reg
           then Catseye_engine.Extractor_registry.flat_cmd reg
           else (
             let exe_dir = Stdlib.Filename.dirname Stdlib.Sys.executable_name in
             let rec search_upward dir attempts =
               if attempts > 6 then None
               else (
                 let parent = Stdlib.Filename.dirname dir in
                 let candidate = parent ^ "/bin/catseye-crystal-extractor" in
                 if Stdlib.Sys.file_exists candidate then Some candidate
                 else search_upward parent (attempts + 1)
               )
             in
             match search_upward exe_dir 0 with
             | Some path -> path
             | None -> Catseye_engine.Extractor_registry.flat_cmd reg
           )
         in
         (* POSIX pipe + create_process: blocks natively, no select timeout races *)
         let (pipe_read, pipe_write) = Unix.pipe () in
         Unix.set_close_on_exec pipe_read;
         let pid = Unix.create_process
           extractor
           [| extractor; src.path |]
           Unix.stdin
           pipe_write
           Unix.stderr
         in
         (* CRITICAL: Close parent's write end immediately so EOF can happen naturally *)
         Unix.close pipe_write;
         (* Native blocking read: Unix.read blocks until Crystal closes the pipe.
            Returns 0 ONLY when Crystal exits and all data is drained—no timing races. *)
         let buffer = Buffer.create 16384 in
         let chunk = Bytes.create 4096 in
         let rec drain_all () =
           match Unix.read pipe_read chunk 0 4096 with
           | 0 -> ()  (* True EOF: child exited, safe to proceed *)
           | n -> Buffer.add_subbytes buffer chunk 0 n; drain_all ()
         in
         (try drain_all () with _ -> ());
         Unix.close pipe_read;
         (* Reap AFTER draining to avoid 64KB pipe buffer deadlock *)
         match Unix.waitpid [] pid with
         | (_, Unix.WEXITED 0) ->
           let json_str = Buffer.contents buffer in
           if json_str <> "" then
             (try Some (Security_node.decode_many (Yojson.Safe.from_string json_str))
              with
              | Yojson.Safe.Util.Type_error (_, _) -> None
              | Yojson.Json_error _ -> None
              | Failure _ -> None)
           else None
         | (_, Unix.WEXITED code) ->
           Format.eprintf "Extractor exited with code %d\n" code;
           None
         | _ ->
           Format.eprintf "Extractor terminated by signal\n";
           None
       with exn ->
         Format.eprintf "Crystal extraction error: %s\n" (Exn.to_string exn);
         None)
  | "gleam" ->
    (try
      let nodes = Catseye_engine.Gleam.extract src.path in
      (match nodes with
       | Ok ns -> Some ns
       | Error (`Msg msg) ->
         Format.eprintf "Gleam extraction failed: %s\n" msg;
         None)
     with e ->
       Format.eprintf "Gleam extraction error: %s\n" (Exn.to_string e);
       None)
  | "javascript" | "typescript" | "svelte" | "ocaml" | "rust" ->
    (* New languages: parse via tree-sitter → CatseyeAST → Security_node *)
    (try
      match Catseye_ast.Parse.parse_file ~extractor_cmds:None ~path:src.path with
      | Ok mod_ ->
        let nodes = Catseye_ast.To_security_node.derive mod_ in
        Some nodes
      | Error err ->
        Format.eprintf "Parse error: %s:%d: %s\n" err.file
          (Option.value err.line ~default:0) err.message;
        None
     with e ->
      Format.eprintf "Extraction error: %s\n" (Exn.to_string e);
      None)
  | _ -> None

(** Extract nodes from a source file, handling logging and caching.
    Returns nodes if extraction succeeded, or None on failure. *)
let extract_with_log (config : t) (src : source_file)
    : Security_node.t list option =
  if config.format = Terminal then
    Format.printf "%s→ Extracting: %s%s\n"
      (styled cyan config "") src.path (styled reset config "");
  try extract_file config src with Sys_error _ -> None

(* ── Banner ─────────────────────────────────────────────────────────── *)

let print_banner (config : t) (cr_count : int) (gleam_count : int) (js_count : int) (ts_count : int) (svelte_count : int) (ocaml_count : int) (ex_count : int) (dep_count : int) =
  Format.printf "
  %sCatseye v%s%s
" (styled (bold ^ cyan) config "") version (styled reset config "");
  Format.printf "  Target:   %s
" (styled green config config.target_dir);
  let lang_parts = [] in
  let lang_parts = if cr_count > 0 then (Printf.sprintf "%d Crystal" cr_count) :: lang_parts else lang_parts in
  let lang_parts = if gleam_count > 0 then (Printf.sprintf "%d Gleam" gleam_count) :: lang_parts else lang_parts in
  let lang_parts = if js_count > 0 then (Printf.sprintf "%d JavaScript" js_count) :: lang_parts else lang_parts in
  let lang_parts = if ts_count > 0 then (Printf.sprintf "%d TypeScript" ts_count) :: lang_parts else lang_parts in
  let lang_parts = if svelte_count > 0 then (Printf.sprintf "%d Svelte" svelte_count) :: lang_parts else lang_parts in
  let lang_parts = if ocaml_count > 0 then (Printf.sprintf "%d OCaml" ocaml_count) :: lang_parts else lang_parts in
  let lang_parts = if ex_count > 0 then (Printf.sprintf "%d Elixir" ex_count) :: lang_parts else lang_parts in
  let files_str = match lang_parts with
    | [] -> "0 files"
    | parts -> String.concat ~sep:", " (List.rev parts)
  in
  Format.printf "  Files:    %s%s
"
    files_str
    (if dep_count > 0 then Printf.sprintf " (%d dependencies)" dep_count else "");
  Format.printf "
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
  Format.printf "  %s%s %s  %s:%d%s\n"
    (styled (bold ^ c) config icon)
    label f.rule f.file f.line (styled reset config "");
  Format.printf "%s       %s%s\n"
    (styled dim config "") f.message (styled reset config "");
  List.iter ~f:(fun ({ Finding.file = sf; line = sl; message = sm } : Finding.flow_step) ->
    let loc = if sf <> "" && sl > 0
      then Printf.sprintf "  (%s:%d)" sf sl
      else ""
    in
    Format.printf "%s    ← %s%s%s\n"
      (styled dim config "") sm loc (styled reset config "")
  ) f.flow;
  (match f.Finding.suggestion with
   | Some fix ->
     Format.printf "%s  💡 Suggestion: %s%s%s\n"
       (styled green config "") fix (styled reset config "") ""
   | None -> ());
  Format.printf "\n"

(* ── Summary helpers ────────────────────────────────────────────────── *)

let count_by_severity (findings : Finding.t list) =
  let errors = ref 0 in
  let warnings = ref 0 in
  List.iter ~f:(fun f ->
    match severity_label f.Finding.severity with
    | "Error" -> Int.incr errors
    | "Warning" -> Int.incr warnings
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
      if not (Stdlib.Sys.file_exists d) then begin
        mkdir_p (Stdlib.Filename.dirname d);
        Unix.mkdir d 0o755
      end
    in
    let dir = Stdlib.Filename.dirname config.output_path in
    mkdir_p dir;
    let oc = Stdio.Out_channel.create config.output_path in
    Stdio.Out_channel.output_string oc json_str;
    Stdio.Out_channel.output_string oc "\n";
    Stdio.Out_channel.close oc;
    Format.printf "Results written to %s\n" config.output_path
  end else
    Stdio.Out_channel.output_string Stdio.stdout json_str

(* ── Crow's Nest integration ────────────────────────────────────────── *)

let run_crows_nest (config : t) : Catseye_crowsnest.Aggregator.dep_result list option =
  if not config.crows_nest then None
  else begin
    let manifests = Catseye_crowsnest.Manifest.find_manifests_recursive config.target_dir in
    if manifests = [] then None
    else begin
      let cache_path = Stdlib.Filename.concat config.cache_dir "crowsnest.db" in
      let cache =
        try Some (Catseye_crowsnest.Cache.open_db cache_path)
        with
        | Sys_error _ -> None
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
          ("vulnerabilities", `List (List.map ~f:(fun v ->
            `Assoc [
              ("id", `String v.Catseye_crowsnest.Osv.id);
              ("summary", `String v.Catseye_crowsnest.Osv.summary);
              ("severity", match v.Catseye_crowsnest.Osv.severity with
                | Some s -> `String s | None -> `Null);
              ("patched_versions", `List (List.map ~f:(fun pv -> `String pv)
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
  let errors = List.length (List.filter ~f:(fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Critical) results) in
  let warnings = List.length (List.filter ~f:(fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Warning) results) in
  let clean = List.length (List.filter ~f:(fun (r : Catseye_crowsnest.Aggregator.dep_result) -> r.level = `Clean) results) in
  `Assoc [
    ("manifests", `List (List.map ~f:(fun m ->
      let (path, kind) = match m with
        | Catseye_crowsnest.Manifest.Shard_yml (p, _) -> (p, "shard.yml")
        | Catseye_crowsnest.Manifest.Gleam_toml (p, _) -> (p, "gleam.toml")
      in
      `Assoc [("path", `String path); ("kind", `String kind)]
    ) (Catseye_crowsnest.Manifest.find_manifests_recursive
         (if Stdlib.Sys.is_directory target_dir then target_dir
          else Stdlib.Filename.dirname target_dir))));
    ("dependencies", `List (List.map ~f:dep_to_json results));
    ("summary", `Assoc [
      ("critical", `Int errors); ("warning", `Int warnings); ("clean", `Int clean)
    ]);
  ]

(* ── Timing helper ──────────────────────────────────────────────────── *)

let time_phase label f =
  let t0 = Unix.gettimeofday () in
  let result = f () in
  let t1 = Unix.gettimeofday () in
  Format.eprintf "  [timing] %s: %.3fs\n" label (t1 -. t0);
  result

(* ── Timeout helper ─────────────────────────────────────────────────── *)

let with_timeout ~ms f =
  if ms <= 0 then f ()
  else
    let deadline = Unix.gettimeofday () +. (Float.of_int ms /. 1000.0) in
    let check_and_run () =
      if Float.(Unix.gettimeofday () > deadline) then
        raise (Failure ("timeout: exceeded " ^ Int.to_string ms ^ "ms"))
    in
    try (check_and_run (); f ()) with
    | Failure msg when String.length msg >= 7 && String.sub msg ~pos:0 ~len:7 = "timeout" ->
      raise (Failure msg)
    | e -> raise e

(* ── AI finding converter ───────────────────────────────────────────── *)

(** Converts an Ai_linter.Types.finding to Catseye_types.Finding.t *)
let convert_ai_finding ~lang (f : Ai_linter.Types.finding) =
  { Catseye_types.Finding.rule = f.rule_id;
    severity = Ai_linter.Types.severity_to_string f.severity;
    file = f.file;
    line = f.line; message = f.message;
    flow = []; language = lang; dependency = None; reachability = None;
    suggestion = f.suggestion; }


(* ── Main pipeline ──────────────────────────────────────────────────── *)

let run (config : t) : int =
  (* Handle --list-rules mode early (no scanning needed) *)
  if config.list_rules then
    run_list_rules config
  else begin
    Random.self_init ();
  
    (* Normal scan mode - load config and run analysis *)
    let config = Config.load config in

    (* Step 0: Crow's Nest (runs in parallel with taint analysis conceptually) *)
    let crows_nest_results = run_crows_nest config in

    (* Step 1: Discover sources *)
    let sources = time_phase "discovery" (fun () ->
      discover_sources ~include_deps:config.include_deps ~lang_filter:config.lang_filter ~recurse:config.recurse config.target_dir config.exclude_dirs) in
    if sources = [] then begin
      (* Still print Crow's Nest if we have results *)
      (match crows_nest_results with
       | Some results when results <> [] ->
         if config.format = Terminal then
           Crowsnest_format.print_crows_nest config results
       | _ -> ());
      Format.printf "No source files found in %s\n" config.target_dir;
      Stdlib.exit 0
    end;
    let cr_count = List.length (List.filter ~f:(fun s -> s.lang = "crystal") sources) in
  let gleam_count = List.length (List.filter ~f:(fun s -> s.lang = "gleam") sources) in
  let js_count = List.length (List.filter ~f:(fun s -> s.lang = "javascript") sources) in
  let ts_count = List.length (List.filter ~f:(fun s -> s.lang = "typescript") sources) in
  let svelte_count = List.length (List.filter ~f:(fun s -> s.lang = "svelte") sources) in
  let ocaml_count = List.length (List.filter ~f:(fun s -> s.lang = "ocaml") sources) in
  let ex_count = List.length (List.filter ~f:(fun s -> s.lang = "elixir") sources) in
  let dep_count = List.length (List.filter ~f:(fun s -> s.is_dependency) sources) in
  if config.format = Terminal then print_banner config cr_count gleam_count js_count ts_count svelte_count ocaml_count ex_count dep_count;
  if config.format = Terminal && not config.crystal_available then
    Format.eprintf "  [info] Crystal toolchain not detected — Crystal extraction disabled\n%!";

  (* Step 1b: Handle --clear-cache *)
  if config.clear_cache then begin
    Catseye_engine.Cache.delete_cache config.cache_dir;
    if config.format = Terminal then
      Format.printf "  Cache cleared.\n"
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
    List.iter ~f:(fun src ->
      match Catseye_engine.Cache.check cache src.path with
      | Some cached ->
        Int.incr cache_hits;
        List.iter ~f:(fun n -> all_nodes := n :: !all_nodes) cached
      | None ->
        uncached := src :: !uncached
    ) sources;
    (* Split uncached by language *)
    let uncached_crystal = List.filter ~f:(fun s -> s.lang = "crystal") !uncached in
    let uncached_other = List.filter ~f:(fun s -> s.lang <> "crystal") !uncached in
    (* Phase 2a: Extract Crystal files via worker pool if configured *)
    if config.crystal_workers > 1 && uncached_crystal <> [] then begin
      (match config.extractor_registry with
       | None -> ()  (* Crystal not available *)
       | Some reg ->
       let pool = Catseye_engine.Worker_pool.create
        (Catseye_engine.Extractor_registry.flat_cmd reg) config.crystal_workers in
      List.iter ~f:(fun src ->
        match Catseye_engine.Worker_pool.extract_with_recovery pool src.path with
        | Some ns ->
          Catseye_engine.Cache.store cache src.path ns;
          List.iter ~f:(fun n -> all_nodes := n :: !all_nodes) ns
        | None -> ()
      ) uncached_crystal;
      Catseye_engine.Worker_pool.shutdown pool)
    end else
      (* No worker pool — extract Crystal files normally *)
      List.iter ~f:(fun src ->
        match extract_with_log config src with
        | Some ns ->
          Catseye_engine.Cache.store cache src.path ns;
          List.iter ~f:(fun n -> all_nodes := n :: !all_nodes) ns
        | None -> ()
      ) uncached_crystal;
    (* Phase 2b: Extract non-Crystal files using native Domain parallelism *)
    let extract_one src =
      match extract_with_log config src with
      | Some ns ->
        Catseye_engine.Cache.store cache src.path ns;
        Some ns
      | None -> None
    in
    if config.parallelism > 0 && List.length uncached_other > 1 then
      (* Native OCaml 5 Domain-based parallel extraction *)
      let num_domains = Domain.recommended_domain_count () in
      let scan_cfg : Catseye_engine.Parallel.scan_config = {
        max_domains = num_domains;
        chunk_size = 1;
        timeout_ms = None;
      } in
      (* Build a map from path to source_file for lookup *)
      let src_by_path = List.fold ~f:(fun acc src -> Map.set acc ~key:src.path ~data:src) ~init:(Map.empty (module String)) uncached_other in
      (* Extract paths to pass to parallel scan *)
      let paths = List.map ~f:(fun s -> s.path) uncached_other in
      let extract_fn (path : string) =
        match Map.find src_by_path path with
        | Some src -> extract_one src
        | None -> None
      in
      let (results, errors) = Catseye_engine.Parallel.parallel_workspace_scan
        ~config:scan_cfg
        extract_fn
        paths
      in
      (* Log any domain-level errors gracefully *)
      (match errors with
       | [] -> ()
       | errs ->
         if config.format = Terminal then
           Format.eprintf "  [parallel] %d file(s) failed in domain workers:\n" (List.length errs);
         List.iter ~f:(fun (path, err) ->
           Format.eprintf "    ✗ %s: %s\n" path err
         ) errs);
      List.iter ~f:(fun ns -> all_nodes := List.rev_append ns !all_nodes) results
    else
      List.iter ~f:(fun src ->
        match extract_one src with
        | Some ns -> all_nodes := List.rev_append ns !all_nodes
        | None -> ()
      ) uncached_other;
    (List.rev !all_nodes, !cache_hits)
  ) in
  if nodes = [] && not config.ai_lint && not config.claws then begin
    Catseye_engine.Cache.close cache;
    Format.printf "\nNo AST nodes extracted. Nothing to analyze.\n";
    Stdlib.exit 0
  end;

  (* Step 3: Load rules *)
  let rules = time_phase "rules" (fun () ->
    match Catseye_rules.Loader.load_rules config.rules_dir with
    | Ok r -> r
    | Error (`Msg msg) ->
      Format.eprintf "Warning: %s\n" msg;
      [])
  in

  (* Apply --no-cfg override: flat engine has more predictable performance *)
  let config = if config.no_cfg_use then { config with use_cfg = false } else config in

  (* Step 4: Analyze *)
  if config.format = Terminal then
    Format.printf "\n  → Running analysis engine (%d nodes)...\n\n" (List.length nodes);

  let do_analysis () =
    if config.use_cfg then begin
      (* CFG-based taint analysis *)
      if config.format = Terminal then
        Format.printf "  [cfg] Using IL/CFG-based taint engine\n";
      let all_sources = List.concat_map ~f:(fun (r : Catseye_rules.Types.rule_def) ->
        r.sources
      ) rules in
      let analyzed = ref 0 in
      List.concat_map ~f:(fun src ->
        Int.incr analyzed;
        if config.format = Terminal && !analyzed mod 10 = 0 then
          Format.eprintf "  [progress] Analyzed %d/%d files...\n" !analyzed (List.length sources);
        try
          match Catseye_ast.Parse.parse_file ~extractor_cmds:config.extractor_cmds ~path:src.path with
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
               Format.eprintf "  [warn] Skipped %d functions due to CFG bounds in %s\n"
                 (List.length fns) src.path);
            result.findings
        with e ->
          Format.eprintf "  [warn] CFG analysis failed for %s: %s\n" src.path (Exn.to_string e);
          []
      ) sources
    end else begin
      (* Flat taint engine — more predictable performance *)
      if config.format = Terminal then
        Format.printf "  [engine] Using flat taint engine\n";
      Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes
    end
  in
  let findings = time_phase "analysis" (fun () ->
    match config.analysis_timeout_ms with
    | 0 -> do_analysis ()  (* No timeout *)
    | ms ->
      Format.eprintf "  [timeout] Analysis timeout set to %dms\n" ms;
      try with_timeout ~ms do_analysis with
      | Failure msg when String.length msg >= 7 && String.sub msg ~pos:0 ~len:7 = "timeout" ->
        Format.eprintf "\n  [timeout] Analysis exceeded limit. Falling back to flat engine...\n";
        Catseye_engine.Engine.analyze ~extra_sources:config.extra_sources rules nodes
  ) in

  (* Step 4b: Predator Vision — reachability analysis *)
  let reachability = if config.predator_vision && findings <> [] then begin
    let reach = Catseye_engine.Reachability.analyze nodes findings ~custom_patterns:[] in
    (* Tag findings with reachability *)
    let tagged = match List.map2 ~f:(fun f r ->
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
    ) findings reach with
    | List.Or_unequal_lengths.Ok tagged -> tagged
    | List.Or_unequal_lengths.Unequal_lengths -> findings  (* Fallback *)
    in
    if config.format = Terminal then
      Heatmap.print_heatmap config tagged reach;
    tagged
  end else findings in

  (* Step 4c: Crow's Nest dep reachability (when both --crows-nest and --predator-vision) *)
  let crows_nest_results = match crows_nest_results with
    | Some results when config.predator_vision && results <> [] ->
      (* Build reachable file set from Predator Vision analysis *)
      let reachable_files =
        List.filter_map ~f:(fun (f : Finding.t) ->
          match f.reachability with
          | Some r -> (match r.status with
            | Finding.Live | Finding.Dormant ->
              Some f.file
            | Finding.Safe -> None)
          | None -> None
        ) reachability
      in
      (* Also include all files with defs (they're potentially reachable) *)
      let def_files = List.filter_map ~f:(fun (n : Security_node.t) ->
        if n.node_type = Security_node.Def then Some n.file else None
      ) nodes in
      let all_reachable =
        List.fold ~f:(fun s f ->
          Set.Poly.add s f
        ) ~init:Set.Poly.empty
          (reachable_files @ def_files)
      in
      (* Scan source files for imports and compute reachability *)
      let dep_names = List.map ~f:(fun (r : Catseye_crowsnest.Aggregator.dep_result) ->
        r.name
      ) results in
      let file_lang_pairs = List.map ~f:(fun (s : source_file) ->
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
      Some (List.map ~f:(fun (a, _) -> a) enriched)
    | other -> other
  in

  (* Step 4d: AI Linter — Gleam & Crystal antipattern detection *)
  let ai_findings = if config.ai_lint then begin
    if config.format = Terminal then
      Format.printf "\n  → AI antipattern detection:\n\n";
    let ai_lint_findings = List.concat_map ~f:(fun src ->
      (try
        (* Skip Crystal files - they were already extracted in Step 2 *)
        if src.lang = "crystal" then []
        else match Catseye_ast.Parse.parse_file ~extractor_cmds:config.extractor_cmds ~path:src.path with
        | Error err -> [Catseye_types.Finding.{ rule = "parse-error"; severity = "error"; file = err.file;
            line = Option.value err.line ~default:0; message = err.message;
            flow = []; language = ""; dependency = None; reachability = None; suggestion = None; }]
        | Ok mod_ ->
          (match mod_.mod_lang with
           | Gleam ->
            List.map ~f:(convert_ai_finding ~lang:"gleam") (Ai_linter.Gleam_rules.analyze_module mod_)
           | JavaScript | TypeScript ->
            List.map ~f:(convert_ai_finding ~lang:"javascript") (Ai_linter.Javascript_rules.analyze_module mod_)
           | Svelte ->
            List.map ~f:(convert_ai_finding ~lang:"svelte") (Ai_linter.Svelte_rules.analyze_module mod_)
           | Rust ->
            List.map ~f:(convert_ai_finding ~lang:"rust") (Ai_linter.Rust_rules.analyze_module mod_)
           | Other "ocaml" ->
            List.map ~f:(convert_ai_finding ~lang:"ocaml") (Ai_linter.Ocaml_rules.analyze_module mod_)
           | _ -> [])
      with exn -> Format.eprintf "AI lint error: %s\n" (Exn.to_string exn); [])
    ) sources in
    (* Apply --suppress and ai_suppress (per-rule file globs) to AI findings *)
    let suppressed = config.suppress in
    let ai_suppress = config.ai_suppress in
    let ai_lint_findings = List.filter ~f:(fun (f : Catseye_types.Finding.t) ->
      (* Skip if rule is globally suppressed *)
      if List.mem suppressed ~equal:String.equal f.rule then false
      (* Check per-rule file glob suppressions *)
      else if Map.mem ai_suppress f.rule then
        let patterns = Option.value (Map.find ai_suppress f.rule) ~default:[] in
        not (List.exists ~f:(fun pat ->
          (* Glob matching: ** matches anything including /, * matches within a segment *)
          let star = '*' and quest = '?' and slash = '/' in
          let rec glob_match p_idx s_idx =
            let plen = String.length pat in
            let flen = String.length f.file in
            if p_idx >= plen then s_idx >= flen
            else if s_idx >= flen then (
              (* At end of file - only * can match empty *)
              if pat.[p_idx] = star then
                if p_idx + 1 < plen && pat.[p_idx + 1] = star then
                  glob_match (p_idx + 2) s_idx  (* ** matches empty *)
                else glob_match (p_idx + 1) s_idx  (* * matches empty *)
              else false
            ) else match pat.[p_idx], f.file.[s_idx] with
              | c, _ when c = star ->
                  if p_idx + 1 < plen && pat.[p_idx + 1] = star then
                    (* Double star ** *)
                    if p_idx + 2 < plen && pat.[p_idx + 2] = slash then
                      (* **/ - match zero or more directories *)
                      if p_idx + 3 < plen then
                        if glob_match (p_idx + 3) s_idx then true
                        else if s_idx < flen then
                          let rec skip_to_next_slash idx =
                            if idx >= flen then flen
                            else if f.file.[idx] = slash then idx + 1
                            else skip_to_next_slash (idx + 1)
                          in
                          let after_slash = skip_to_next_slash s_idx in
                          if after_slash > s_idx then glob_match p_idx after_slash
                          else false
                        else false
                      else s_idx >= flen
                    else if glob_match (p_idx + 2) s_idx then true
                    else if s_idx < flen then glob_match p_idx (s_idx + 1)
                    else false
                  else
                    (* Single star * - match within a segment *)
                    let rec try_match consumed =
                      let new_s = s_idx + consumed in
                      if new_s > flen then false
                      else if consumed > 0 && f.file.[new_s - 1] = slash then false
                      else if glob_match (p_idx + 1) new_s then true
                      else try_match (consumed + 1)
                    in
                    try_match 0
              | c, _ when c = quest -> glob_match (p_idx + 1) (s_idx + 1)
              | c1, c2 when c1 = c2 -> glob_match (p_idx + 1) (s_idx + 1)
              | _ -> false
          in
          glob_match 0 0
        ) patterns)
      else true
    ) ai_lint_findings in
    if config.format = Terminal && ai_lint_findings <> [] then begin
      List.iter ~f:(fun (f : Catseye_types.Finding.t) ->
        Format.printf "  [ai:%s] %s:%d - %s\n" f.rule f.file f.line f.message
      ) ai_lint_findings
    end;
    ai_lint_findings
  end else [] in

  (* Step 4e: Claws — code smell analysis *)
  let all_findings = if config.claws then begin
    (* Parse ASTs for files that support it (Gleam always, Crystal via bridge) *)
    let ast_modules = List.filter_map ~f:(fun src ->
      try match Catseye_ast.Parse.parse_file ~extractor_cmds:config.extractor_cmds ~path:src.path with
        | Ok mod_ -> Some mod_
        | Error _ -> None
      with
      | Sys_error _ -> None
      | Failure _ -> None
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
    let ast_rules = Hashtbl.create ~size:8 (module String) in
    List.iter ~f:(fun (f : Finding.t) ->
      Hashtbl.set ast_rules ~key:f.Finding.rule ~data:true
    ) claws_findings;
    let extra_flat = List.filter ~f:(fun (f : Finding.t) ->
      not (Hashtbl.mem ast_rules f.Finding.rule)
    ) flat_claws in
    let all_claws = claws_findings @ extra_flat in
    if config.format = Terminal && all_claws <> [] then
        Format.printf "\n  → Code smell analysis:\n\n";
    let base_findings = reachability @ all_claws @ ai_findings in
    base_findings
  end else reachability @ ai_findings in

  (* Step 4e: Elixir tools + AST extraction (Sobelow, Credo, Reach, sink detection, Claws) *)
  let all_findings =
    if config.elixir_enabled then begin
      let elixir_findings =
        if Elixir_tools.is_mix_project config.target_dir then begin
          let elixir_config = { Elixir_tools.enabled = true;
                               run_sobelow = List.mem config.elixir_tools ~equal:String.equal "sobelow";
                               run_credo = List.mem config.elixir_tools ~equal:String.equal "credo";
                               run_reach = List.mem config.elixir_tools ~equal:String.equal "reach";
                               threshold = `Low } in
          if config.format = Terminal then Format.printf "\n  → Elixir tools scan:\n\n";
          let findings = Elixir_tools.run_all_tools ~config:elixir_config ~project_dir:config.target_dir () in
          if config.format = Terminal then begin
            if findings <> [] then Format.printf "  Found %d Elixir tool findings\n\n" (List.length findings)
            else Format.printf "  No Elixir tool findings\n\n"
          end;
          findings
        end else []
      in
      (* Step 4f: Elixir AST extraction + Claws (sink/source detection + code smells)
         Only run if this is actually an Elixir project — avoid launching BEAM
         on non-Elixir projects just because mix happens to be on PATH. *)
      let has_elixir_sources = List.exists ~f:(fun (s : source_file) -> s.lang = "elixir") sources in
      let (sink_findings, json_data) =
        if has_elixir_sources || Elixir_tools.is_mix_project config.target_dir then
          Elixir_extractor.extract_with_data config.target_dir
        else
          ([], [])
      in
      let claws_findings = Elixir_claws.analyze json_data in
      let extractor_findings = sink_findings @ claws_findings in
      (* Filter Elixir findings to only include files that were actually discovered
         (excludes deps/, _build/, and other excluded directories) *)
      let extractor_findings = List.filter ~f:(fun (f : Finding.t) ->
        (* Filter out deps/, _build/, test/ — keep everything else.
           The extractor uses absolute paths while discover_sources returns
           relative paths, so direct Hashtbl lookup doesn't work reliably.
           Instead, exclude known non-project directories. *)
        not (String.is_substring ~substring:"/deps/" f.Finding.file
             || String.is_substring ~substring:"/_build/" f.Finding.file
             || String.is_substring ~substring:"/test/" f.Finding.file)
      ) extractor_findings in
      if config.format = Terminal && extractor_findings <> [] then begin
        Format.printf "\n  → Elixir AST analysis:\n\n";
        List.iter ~f:(print_finding config) extractor_findings;
        Format.printf "\n  Found %d Elixir findings\n\n" (List.length extractor_findings)
      end;
      all_findings @ elixir_findings @ extractor_findings
    end else all_findings in

  (* Apply --suppress from CLI and [taint.suppress] from .catseye.toml *)
  let all_findings =
    let suppressed = config.suppress in
    let filtered = if suppressed = [] then all_findings
      else List.filter ~f:(fun (f : Finding.t) ->
        not (List.mem suppressed ~equal:String.equal f.Finding.rule)
      ) all_findings in
    let sup = config.taint_suppress in
    let sup = config.taint_suppress in
    if Map.is_empty sup then filtered
    else List.filter ~f:(fun (f : Finding.t) ->
      match Map.find sup f.Finding.rule with
      | None -> true
      | Some patterns ->
        not (List.exists ~f:(fun pat ->
          Catseye_claws.Smells.glob_match pat f.Finding.file
        ) patterns)
    ) filtered
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

    List.iter ~f:(print_finding config) all_findings;
    Format.printf "──────────────────────────────────────────────────────────────\n";
    if all_findings <> [] then begin
      let (errors, warnings) = count_by_severity all_findings in
      Format.printf "  Found %d Error(s), %d Warning(s) across %d files.\n"
        errors warnings (List.length sources);
      Format.printf "  Review the findings above.\n";
      1
    end else begin
      Format.printf "%sNo issues found across %d file(s). ✨%s\n"
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
      let oc = Stdio.Out_channel.create config.output_path in
      Stdio.Out_channel.output_string oc content; Stdio.Out_channel.output_string oc "\n";
      Stdio.Out_channel.close oc;
      Format.printf "Results written to %s\n" config.output_path
    end else
      Stdio.Out_channel.output_string Stdio.stdout content;
    if all_findings <> [] then 1 else 0
  | Markdown ->
    let supply_chain = match crows_nest_results with
      | Some results -> Some (crows_nest_to_json config.target_dir results)
      | None -> None
    in
    let content = Markdown.to_markdown all_findings config.target_dir ?supply_chain () in
    if config.output_path <> "" then begin
      let oc = Stdio.Out_channel.create config.output_path in
      Stdio.Out_channel.output_string oc content; Stdio.Out_channel.output_string oc "\n";
      Stdio.Out_channel.close oc;
      Format.printf "Results written to %s\n" config.output_path
    end else
      Stdio.Out_channel.output_string Stdio.stdout content;
    if all_findings <> [] then 1 else 0
  | Dot ->
    Dot.output_dot nodes all_findings
      ~custom_patterns:config.extra_sources
      config.output_path;
    0
  | AiJson ->
    (* AiJson format for scan mode — output findings as structured JSON *)
    let content = Yojson.Safe.pretty_to_string (
      `Assoc [
        ("version", `String version);
        ("format", `String "ai-json");
        ("findings_count", `Int (List.length all_findings));
        ("findings", Finding.encode_many all_findings)
      ]
    ) in
    if config.output_path <> "" then begin
      let oc = Stdio.Out_channel.create config.output_path in
      Stdio.Out_channel.output_string oc content;
      Stdio.Out_channel.output_string oc "\n";
      Stdio.Out_channel.close oc;
      Format.printf "Results written to %s\n" config.output_path
    end else
      Stdio.Out_channel.output_string Stdio.stdout content;
    if all_findings <> [] then 1 else 0
  end
