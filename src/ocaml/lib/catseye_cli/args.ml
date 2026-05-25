(* lib/catseye_cli/args.ml *)
(* Type-safe CLI using Cmdliner *)

open Base
open Config

(* ── Format and Language Helpers ─────────────────────────────────────── *)

let format_term : format Cmdliner.Term.t =
  let doc = "Output format: terminal (default), json, sarif, markdown, dot" in
  Cmdliner.Arg.(
    value & opt string "terminal" & info ["format"; "f"] ~docv:"FMT" ~doc
  )

let lang_term : lang_filter Cmdliner.Term.t =
  let doc = "Language filter: all (default), crystal, gleam, or comma-separated list" in
  Cmdliner.Arg.(
    value & opt string "all" & info ["lang"] ~docv:"LANGS" ~doc
  )

let output_term : string Cmdliner.Arg.t =
  let doc = "Write results to file" in
  Cmdliner.Arg.(value & opt (some string) None & info ["output"; "o"] ~docv:"PATH" ~doc)

let config_path_term : string option Cmdliner.Arg.t =
  let doc = "Config file path (default: .catseye.toml in target or parents)" in
  Cmdliner.Arg.(value & opt (some string) None & info ["config"] ~docv:"PATH" ~doc)

let rules_dir_term : string option Cmdliner.Arg.t =
  let doc = "Rules directory (default: rules/)" in
  Cmdliner.Arg.(value & opt (some string) None & info ["rules"; "r"] ~docv:"PATH" ~doc)

let cache_dir_term : string option Cmdliner.Arg.t =
  let doc = "Cache directory (default: .catseye)" in
  Cmdliner.Arg.(value & opt (some string) None & info ["cache-dir"] ~docv:"PATH" ~doc)

let suppress_term : string list Cmdliner.Arg.t =
  let doc = "Comma-separated rule IDs to suppress (e.g., unused-let,InsecureRandom)" in
  Cmdliner.Arg.(value & opt (some string) None & info ["suppress"] ~docv:"RULES" ~doc)

let analysis_timeout_term : int Cmdliner.Arg.t =
  let doc = "Timeout for analysis phase in ms (0=disabled)" in
  Cmdliner.Arg.(value & opt (some int) None & info ["analysis-timeout"] ~docv:"MS" ~doc)

let cfg_max_blocks_term : int Cmdliner.Arg.t =
  let doc = "Max blocks per function CFG (default: 500)" in
  Cmdliner.Arg.(value & opt (some int) None & info ["cfg-max-blocks"] ~docv:"N" ~doc)

let cfg_timeout_ms_term : int Cmdliner.Arg.t =
  let doc = "Timeout per function CFG build in ms (default: 5000)" in
  Cmdliner.Arg.(value & opt (some int) None & info ["cfg-timeout-ms"] ~docv:"MS" ~doc)

let parallelism_term : int Cmdliner.Arg.t =
  let doc = "Parallel workers (0 = auto)" in
  Cmdliner.Arg.(value & opt (some int) None & info ["parallelism"; "p"] ~docv:"N" ~doc)

(* Boolean flags *)
let no_color_term : bool Cmdliner.Arg.t =
  let doc = "Disable colored output" in
  Cmdliner.Arg.(value & flag & info ["no-color"] ~doc)

let no_cache_term : bool Cmdliner.Arg.t =
  let doc = "Disable extraction cache" in
  Cmdliner.Arg.(value & flag & info ["no-cache"] ~doc)

let clear_cache_term : bool Cmdliner.Arg.t =
  let doc = "Clear cache and run full scan" in
  Cmdliner.Arg.(value & flag & info ["clear-cache"] ~doc)

let predator_vision_term : bool Cmdliner.Arg.t =
  let doc = "Enable reachability heatmap" in
  Cmdliner.Arg.(value & flag & info ["predator-vision"; "pv"] ~doc)

let crows_nest_term : bool Cmdliner.Arg.t =
  let doc = "Enable supply chain audit" in
  Cmdliner.Arg.(value & flag & info ["crows-nest"; "cn"] ~doc)

let claws_term : bool Cmdliner.Arg.t =
  let doc = "Enable code smell & DRY detection" in
  Cmdliner.Arg.(value & flag & info ["claws"; "cl"] ~doc)

let ai_lint_term : bool Cmdliner.Arg.t =
  let doc = "Enable AI antipattern detection (Gleam & Crystal)" in
  Cmdliner.Arg.(value & flag & info ["ai-lint"; "ai"] ~doc)

let bridge_term : bool Cmdliner.Arg.t =
  let doc = "Force AST bridge for extraction" in
  Cmdliner.Arg.(value & flag & info ["bridge"] ~doc)

let include_deps_term : bool Cmdliner.Arg.t =
  let doc = "Include shard dependencies in scan (Crystal only)" in
  Cmdliner.Arg.(value & flag & info ["include-deps"] ~doc)

let cfg_term : bool Cmdliner.Arg.t =
  let doc = "Use IL/CFG-based taint engine (faster, fewer FPs)" in
  Cmdliner.Arg.(value & flag & info ["cfg"] ~doc)

let no_cfg_term : bool Cmdliner.Arg.t =
  let doc = "Use flat taint engine (default)" in
  Cmdliner.Arg.(value & flag & info ["no-cfg"] ~doc)

let elixir_term : bool Cmdliner.Arg.t =
  let doc = "Enable Elixir tool integration (Sobelow, Credo, Reach)" in
  Cmdliner.Arg.(value & flag & info ["elixir"; "ex"] ~doc)

let no_elixir_term : bool Cmdliner.Arg.t =
  let doc = "Disable Elixir tool integration" in
  Cmdliner.Arg.(value & flag & info ["no-elixir"] ~doc)

let version_term : bool Cmdliner.Arg.t =
  let doc = "Show version" in
  Cmdliner.Arg.(value & flag & info ["version"; "v"] ~doc)

(* Target directory positional argument *)
let target_term : string Cmdliner.Arg.t =
  let doc = "Target directory to scan" in
  Cmdliner.Arg.(required & pos 0 (some string) None & info [] ~docv:"DIRECTORY" ~doc)

(* ── Path Resolution ─────────────────────────────────────────────────── *)

(** Resolve a path to absolute, using [base] as the reference directory.
    If already absolute, return as-is. *)
let resolve_path ~base path =
  if Filename.is_relpath path then Filename.concat base path
  else path

(** Get executable directory for finding bundled extractors.
    Uses Sys.executable_name to locate the running binary. *)
let get_exe_dir () =
  Filename.dirname Sys.executable_name

(* ── Converters ─────────────────────────────────────────────────────── *)

let format_of_string = function
  | "json" -> Json
  | "sarif" -> Sarif
  | "markdown" | "md" -> Markdown
  | "dot" | "graphviz" -> Dot
  | "terminal" | "text" -> Terminal
  | s -> `Error (Format.sprintf "Unknown format: %s" s)

let lang_filter_of_string = function
  | "all" -> All
  | s -> Only (String.split_on_char ',' s)

(* ── Config Builder ─────────────────────────────────────────────────── *)

let build_config
    target_dir
    format lang output config_path rules_dir
    no_color no_cache clear_cache cache_dir
    predator_vision crows_nest claws ai_lint
    bridge include_deps
    suppress
    cfg no_cfg
    analysis_timeout cfg_max_blocks cfg_timeout_ms
    elixir no_elixir
    parallelism version
  : t Cmdliner.Term.ret =
  
  (* Handle version flag *)
  if version then (
    Printf.printf "Catseye v%s\n" Catseye_engine.Engine.version;
    exit 0
  );
  
  (* Validate target directory *)
  if not (Sys.is_directory target_dir) then
    `Error (Format.sprintf "Not a directory: %s" target_dir)
  else begin
    (* Parse optional values *)
    let ( >>= ) = Result.bind in
    let format = format_of_string format >>= Fun.id in
    let suppress_list = match suppress with
      | Some s -> String.split_on_char ',' s
      | None -> []
    in
    
    let cwd = Sys.getcwd () in
    let exe_dir = get_exe_dir () in
    let default_rules = Filename.concat cwd "rules" in
    
    (* Resolve rules_dir - try CWD first, then exe dir for global installs *)
    let rules_dir = match rules_dir with
      | Some r -> resolve_path ~base:cwd r
      | None ->
        if Sys.file_exists default_rules then default_rules
        else Filename.concat exe_dir "rules"
    in
    
    `Ok {
      target_dir;
      format;
      lang_filter = lang_filter_of_string lang;
      output_path = Option.value_map output ~default:"" ~f:(resolve_path ~base:cwd);
      config_path = Option.map (resolve_path ~base:cwd) config_path;
      rules_dir;
      color = not no_color;
      no_cache;
      clear_cache;
      cache_dir = Option.value_map cache_dir ~default:".catseye" ~f:(resolve_path ~base:cwd);
      predator_vision;
      crows_nest;
      claws;
      ai_lint;
      ast_bridge = bridge;
      include_deps;
      suppress = suppress_list;
      use_cfg = cfg && not no_cfg;
      no_cfg_use = no_cfg;
      analysis_timeout_ms = Option.value analysis_timeout ~default:0;
      cfg_max_blocks = Option.value cfg_max_blocks ~default:500;
      cfg_timeout_ms = Option.value cfg_timeout_ms ~default:5000;
      elixir_enabled = elixir && not no_elixir;
      parallelism = Option.value parallelism ~default:0;
    }
  end

(* ── Man Page ─────────────────────────────────────────────────────────── *)

let man =
  let item text = `P text in
  [
    `S Manpage.s_description;
    item "Catseye v0.4.0 — Static security analysis for Crystal and Gleam applications";
    `S Manpage.s_arguments;
    `S Manpage.s_options;
    `S "OUTPUT FORMATS";
    item "terminal  Colored terminal output (default)";
    item "json      JSON results";
    item "sarif     SARIF format for CI integration";
    item "markdown  Markdown table";
    item "dot       GraphViz DOT format";
    `S "ENABLED MODULES";
    item "--ai-lint     AI antipattern detection (Gleam & Crystal)";
    item "--claws       Code smell & DRY detection";
    item "--crows-nest  Supply chain audit (CVE scanning)";
    item "--predator-vision  Reachability heatmap";
    item "--bridge      Force AST bridge (JS/TS/Svelte/OCaml only)";
    `S "EXAMPLES";
    item "catseye ./src --lang crystal --ai-lint";
    item "catseye ./project --format json -o results.json";
    item "catseye ./src --claws --crows-nest";
    `S "EXIT STATUS";
    item "0   Success";
    item "1   Scan completed with findings";
    item "2   Fatal error";
  ]

(* ── Command Setup ───────────────────────────────────────────────────── *)

let cmd =
  let doc = "Static security analysis for Crystal and Gleam" in
  let info = Cmdliner.Cmd.info "catseye" ~version:Catseye_engine.Engine.version ~doc ~man in
  let term = Cmdliner.Term.(
    const build_config
    $ target_term
    $ format_term
    $ lang_term
    $ output_term
    $ config_path_term
    $ rules_dir_term
    $ no_color_term
    $ no_cache_term
    $ clear_cache_term
    $ cache_dir_term
    $ predator_vision_term
    $ crows_nest_term
    $ claws_term
    $ ai_lint_term
    $ bridge_term
    $ include_deps_term
    $ suppress_term
    $ cfg_term
    $ no_cfg_term
    $ analysis_timeout_term
    $ cfg_max_blocks_term
    $ cfg_timeout_ms_term
    $ elixir_term
    $ no_elixir_term
    $ parallelism_term
    $ version_term
  ) in
  Cmdliner.Cmd.v info term

(* ── Entry Point ─────────────────────────────────────────────────────── *)

let run_command () =
  match Cmdliner.Cmd.eval cmd with
  | `Ok config -> config
  | `Error _ -> Config.default (* Will cause proper error in orchestrator *)
  | `Version | `Help -> exit 0

(* ── Legacy Parser (backward compatibility) ─────────────────────────── *)

let parse_args () : t =
  run_command ()
