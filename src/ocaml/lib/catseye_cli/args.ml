(* lib/catseye_cli/args.ml *)
(* Type-safe CLI using Core.Command *)

open Base

(* ── Format and Language Helpers ─────────────────────────────────────── *)

let format_of_string = function
  | "json" -> Config.Json
  | "sarif" -> Config.Sarif
  | "markdown" | "md" -> Config.Markdown
  | "dot" | "graphviz" -> Config.Dot
  | "terminal" | "text" -> Config.Terminal
  | s -> failwith ("Unknown format: " ^ s)

let lang_of_string = function
  | "all" -> Config.All
  | s -> Config.Only (String.split_on_char ',' s)

(* ── Path Resolution ─────────────────────────────────────────────────── *)

(** Resolve a path to absolute, using [base] as the reference directory.
    If already absolute, return as-is. *)
let resolve_path ~(base : string) (path : string) : string =
  if Filename.is_relative path then Filename.concat base path
  else path

(** Get executable directory for finding bundled extractors.
    Uses Sys.executable_name to locate the running binary. *)
let get_exe_dir () : string =
  Filename.dirname Sys.executable_name

(* ── Core.Command Construction ───────────────────────────────────────── *)

let command =
  let open Command in
  let open Command.Param in
  
  (* Flag definitions *)
  let format_flag =
    flag "--format" ~doc:"FMT Output format: terminal (default), json, sarif, markdown, dot"
      (optional_with_default "terminal" string)
  in
  let lang_flag =
    flag "--lang" ~doc:"LANGS Language filter: all (default), crystal, gleam, or comma-separated list"
      (optional_with_default "all" string)
  in
  let output_flag =
    flag "--output" ~doc:"PATH Write results to file"
      (optional string)
  in
  let config_flag =
    flag "--config" ~doc:"PATH Config file path (default: .catseye.toml)"
      (optional string)
  in
  let rules_flag =
    flag "--rules" ~doc:"PATH Rules directory (default: rules/)"
      (optional string)
  in
  let no_color_flag =
    flag "--no-color" ~doc:" Disable colored output"
      no_arg
  in
  let no_cache_flag =
    flag "--no-cache" ~doc:" Disable extraction cache"
      no_arg
  in
  let clear_cache_flag =
    flag "--clear-cache" ~doc:" Clear cache and run fuller scan"
      no_arg
  in
  let cache_dir_flag =
    flag "--cache-dir" ~doc:"PATH Cache directory (default: .catseye)"
      (optional string)
  in
  let predator_vision_flag =
    flag "--predator-vision" ~aliases:["-pv"] ~doc:" Enable reachability heatmap"
      no_arg
  in
  let crows_nest_flag =
    flag "--crows-nest" ~aliases:["-cn"] ~doc:" Enable supply chain audit"
      no_arg
  in
  let claws_flag =
    flag "--claws" ~aliases:["-cl"] ~doc:" Enable code smell & DRY detection"
      no_arg
  in
  let ai_lint_flag =
    flag "--ai-lint" ~aliases:["-ai"] ~doc:" Enable AI antipattern detection"
      no_arg
  in
  let bridge_flag =
    flag "--bridge" ~doc:" Force AST bridge for extraction"
      no_arg
  in
  let include_deps_flag =
    flag "--include-deps" ~doc:" Include shard dependencies in scan"
      no_arg
  in
  let suppress_flag =
    flag "--suppress" ~doc:"RULES Comma-separated rule IDs to suppress"
      (optional string)
  in
  let cfg_flag =
    flag "--cfg" ~doc:" Use IL/CFG-based taint engine"
      no_arg
  in
  let no_cfg_flag =
    flag "--no-cfg" ~doc:" Use flat taint engine (by default)"
      no_arg
  in
  let analysis_timeout_flag =
    flag "--analysis-timeout" ~doc:"MS Timeout for analysis phase (0=disabled)"
      (optional int)
  in
  let cfg_max_blocks_flag =
    flag "--cfg-max-blocks" ~doc:"N Max blocks per function CFG (default: 500)"
      (optional int)
  in
  let cfg_timeout_ms_flag =
    flag "--cfg-timeout-ms" ~doc:"MS Timeout per function CFG build (default: 5000)"
      (optional int)
  in
  let elixir_flag =
    flag "--elixir" ~aliases:["-ex"] ~doc:" Enable Elixir tool integration"
      no_arg
  in
  let no_elixir_flag =
    flag "--no-elixir" ~doc:" Disable Elixir tool integration"
      no_arg
  in
  let parallelism_flag =
    flag "--parallelism" ~aliases:["-p"] ~doc:"N Parallel workers (0 = auto)"
      (optional int)
  in
  let version_flag =
    flag "--version" ~aliases:["-v"] ~doc:" Show version"
      no_arg
  in
  
  (* Positional argument *)
  let target_arg =
    anon ("TARGET_DIR" %: string)
  in
  
  (* Build config from arguments *)
  let make_config
        ~(format : string)
        ~(lang : string)
        ~(output : string option)
        ~(config : string option)
        ~(rules : string option)
        ~(no_color : bool)
        ~(no_cache : bool)
        ~(clear_cache : bool)
        ~(cache_dir : string option)
        ~(predator_vision : bool)
        ~(crows_nest : bool)
        ~(claws : bool)
        ~(ai_lint : bool)
        ~(bridge : bool)
        ~(include_deps : bool)
        ~(suppress : string option)
        ~(cfg : bool)
        ~(no_cfg : bool)
        ~(analysis_timeout : int option)
        ~(cfg_max_blocks : int option)
        ~(cfg_timeout_ms : int option)
        ~(elixir : bool)
        ~(no_elixir : bool)
        ~(parallelism : int option)
        ~(version : bool)
        (target_dir : string)
        : Config.t =
    
    (* Handle version flag early *)
    if version then (
      Printf.printf "Catseye v%s\n" Catseye_engine.Engine.version;
      exit 0
    );
    
    (* Get reference directories *)
    let cwd = Sys.getcwd () in
    let exe_dir = get_exe_dir () in
    let default_rules = Filename.concat cwd "rules" in
    
    (* Build initial config *)
    let base_cfg = Config.{
      default with
      target_dir;
      format = format_of_string format;
      lang_filter = lang_of_string lang;
      output_path = Option.value_map output ~default:"" ~f:(resolve_path ~base:cwd);
      config_path = Option.map (resolve_path ~base:cwd) config;
      rules_dir = Option.value_map rules ~default:default_rules ~f:(resolve_path ~base:cwd);
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
      suppress = 
        (match suppress with
         | Some s -> String.split_on_char ',' s
         | None -> []);
      use_cfg = cfg && not no_cfg;
      no_cfg_use = no_cfg;
      analysis_timeout_ms = Option.value analysis_timeout ~default:0;
      cfg_max_blocks = Option.value cfg_max_blocks ~default:500;
      cfg_timeout_ms = Option.value cfg_timeout_ms ~default:5000;
      elixir_enabled = elixir && not no_elixir;
      parallelism = Option.value parallelism ~default:0;
    } in
    
    (* Resolve rules_dir - try CWD first, then exe dir for global installs *)
    let rules_exists_in_cwd = Sys.file_exists base_cfg.rules_dir in
    let rules_from_exe = Filename.concat exe_dir "rules" in
    let rules_dir = 
      if rules_exists_in_cwd then base_cfg.rules_dir
      else if Sys.file_exists rules_from_exe then rules_from_exe
      else base_cfg.rules_dir
    in
    
    { base_cfg with rules_dir }
  in
  
  (* Create the command *)
  Command.basic
    ~summary:"Catseye v0.4.0 — Static security analysis"
    (let%map_open.Command
        tgt = target_arg
     and format = format_flag
     and lang = lang_flag
     and output = output_flag
     and config = config_flag
     and rules = rules_flag
     and no_color = no_color_flag
     and no_cache = no_cache_flag
     and clear_cache = clear_cache_flag
     and cache_dir = cache_dir_flag
     and predator_vision = predator_vision_flag
     and crows_nest = crows_nest_flag
     and claws = claws_flag
     and ai_lint = ai_lint_flag
     and bridge = bridge_flag
     and include_deps = include_deps_flag
     and suppress = suppress_flag
     and cfg = cfg_flag
     and no_cfg = no_cfg_flag
     and analysis_timeout = analysis_timeout_flag
     and cfg_max_blocks = cfg_max_blocks_flag
     and cfg_timeout_ms = cfg_timeout_ms_flag
     and elixir = elixir_flag
     and no_elixir = no_elixir_flag
     and parallelism = parallelism_flag
     and version = version_flag
     in
     make_config
       ~format ~lang ~output ~config ~rules
       ~no_color ~no_cache ~clear_cache ~cache_dir
       ~predator_vision ~crows_nest ~claws ~ai_lint
       ~bridge ~include_deps ~suppress
       ~cfg ~no_cfg
       ~analysis_timeout ~cfg_max_blocks ~cfg_timeout_ms
       ~elixir ~no_elixir ~parallelism ~version
       tgt)
    ~readme:(fun () ->
      "Catseye v0.4.0 — Static security analysis for Crystal, Gleam, and beyond.\n\n\
      Usage: catseye [options] <directory>\n\n\
      Options:\n\
        --format <fmt>       Output: terminal (default), json, sarif, markdown, dot\n\
        --lang <langs>       Language filter: all (default), crystal, gleam, comma-separated\n\
        --output <path>      Write results to file\n\
        --config <path>      Config file path (default: .catseye.toml)\n\
        --rules <path>       Rules directory (default: rules/)\n\
        --no-color           Disable colored output\n\
        --no-cache           Disable extraction cache\n\
        --clear-cache        Clear cache and run full scan\n\
        --cache-dir <path>   Cache directory (default: .catseye)\n\
        --predator-vision    Enable reachability heatmap\n\
        --crows-nest         Enable supply chain audit\n\
        --claws              Enable code smell & DRY detection\n\
        --ai-lint            Enable AI antipattern detection\n\
        --cfg                Use IL/CFG-based taint engine\n\
        --include-deps       Include shard dependencies in scan\n\
        --suppress <rules>   Comma-separated rule IDs to suppress\n\
        --analysis-timeout <ms>  Timeout for analysis phase\n\
        --elixir             Enable Elixir tool integration\n\
        --parallelism <n>    Parallel workers (0 = auto)\n\
        --version            Show version\n"
      )

(* ── Entry Point ─────────────────────────────────────────────────────── *)

let run_command () : unit =
  Command.run command

(* ── Backward-compatible parse_args ─────────────────────────────────── *)

(** Parse CLI args and return Config.t.
    Uses Core.Command internally. *)
let parse_args () : Config.t =
  Command.run command
