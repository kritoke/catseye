(* lib/catseye_cli/command.ml *)
(* CLI command definition using Core.Command for type-safe argument parsing *)

open Core
open Catseye_types
open Config

(* ── Custom type conversions ─────────────────────────────────────────── *)

let output_format_of_string s =
  match String.lowercase s with
  | "json" -> Ok Json
  | "sarif" -> Ok Sarif
  | "markdown" | "md" -> Ok Markdown
  | "dot" | "graphviz" -> Ok Dot
  | "terminal" | "text" -> Ok Terminal
  | _ -> Or_error.error_sprintf "Invalid format: %s (expected: terminal, json, sarif, markdown, dot)" s

let lang_filter_of_string s =
  match String.lowercase s with
  | "all" -> Ok All
  | _ ->
    let langs = String.split s ~on:',' in
    Ok (Only langs)

(* ── Command flags ───────────────────────────────────────────────────── *)

let format_flag =
  let open Command.Spec in
  flag "--format" ~doc:"FMT Output format: terminal (default), json, sarif, markdown, dot"
    (optional_with_default "terminal" string)
    |> as_flag_in_command

let lang_flag =
  let open Command.Spec in
  flag "--lang" ~doc:"LANGS Language filter: all (default), or comma-separated: crystal,gleam,javascript,typescript,svelte,ocaml,rust"
    (optional_with_default "all" string)
    |> as_flag_in_command

let rules_flag =
  let open Command.Spec in
  flag "--rules" ~doc:"PATH Rules directory (default: rules/)"
    (optional string)
    |> as_flag_in_command

let output_flag =
  let open Command.Spec in
  flag "-o" ~doc:"PATH Write results to file" "--output"
    (optional string)
    |> as_flag_in_command

let config_flag =
  let open Command.Spec in
  flag "--config" ~doc:"PATH Config file path"
    (optional string)
    |> as_flag_in_command

let cache_dir_flag =
  let open Command.Spec in
  flag "--cache-dir" ~doc:"PATH Cache directory (default: .catseye)"
    (optional string)
    |> as_flag_in_command

let suppress_flag =
  let open Command.Spec in
  flag "--suppress" ~doc:"TAGS Comma-separated rule IDs to suppress"
    (optional string)
    |> as_flag_in_command

let parallelism_flag =
  let open Command.Spec in
  flag "-p" ~doc:"N Parallel workers (0 = auto)" "--parallel"
    (optional_with_default "0" int)
    |> as_flag_in_command

let analysis_timeout_flag =
  let open Command.Spec in
  flag "--analysis-timeout" ~doc:"MS Analysis timeout in milliseconds (0 = disabled)"
    (optional_with_default "0" int)
    |> as_flag_in_command

let cfg_max_blocks_flag =
  let open Command.Spec in
  flag "--cfg-max-blocks" ~doc:"N Max blocks per function CFG (default: 500)"
    (optional_with_default 500 int)
    |> as_flag_in_command

let cfg_timeout_flag =
  let open Command.Spec in
  flag "--cfg-timeout" ~doc:"MS CFG build timeout (default: 5000)"
    (optional_with_default 5000 int)
    |> as_flag_in_command

(* Boolean flags *)
let no_color_flag =
  let open Command.Spec in
  flag "--no-color" ~doc:"Disable colored output"
    no_arg
    |> as_flag_in_command

let no_cache_flag =
  let open Command.Spec in
  flag "--no-cache" ~doc:"Disable extraction cache"
    no_arg
    |> as_flag_in_command

let clear_cache_flag =
  let open Command.Spec in
  flag "--clear-cache" ~doc:"Clear cache before running"
    no_arg
    |> as_flag_in_command

let no_recurse_flag =
  let open Command.Spec in
  flag "--no-recurse" ~doc:"Don't recurse into subdirectories"
    no_arg
    |> as_flag_in_command

let no_cfg_flag =
  let open Command.Spec in
  flag "--no-cfg" ~doc:"Skip CFG-based analysis (use flat taint engine)"
    no_arg
    |> as_flag_in_command

let predator_vision_flag =
  let open Command.Spec in
  flag "--predator-vision" ~doc:"Enable reachability analysis (live/dormant/safe)"
    no_arg
    |> as_flag_in_command

let crows_nest_flag =
  let open Command.Spec in
  flag "--crows-nest" ~doc:"Enable supply chain audit (Crystal shards, Gleam packages)"
    no_arg
    |> as_flag_in_command

let claws_flag =
  let open Command.Spec in
  flag "--claws" ~doc:"Enable code smell detection"
    no_arg
    |> as_flag_in_command

let ai_lint_flag =
  let open Command.Spec in
  flag "--ai-lint" ~doc:"Enable AI antipattern detection"
    no_arg
    |> as_flag_in_command

let ast_bridge_flag =
  let open Command.Spec in
  flag "--ast-bridge" ~doc:"Force AST bridge for JS/TS/Svelte/OCaml"
    no_arg
    |> as_flag_in_command

let include_deps_flag =
  let open Command.Spec in
  flag "--include-deps" ~doc:"Include shard dependencies in scan (Crystal only)"
    no_arg
    |> as_flag_in_command

(* ── Positional argument ─────────────────────────────────────────────── *)

let path_arg =
  let open Command.Spec in
  anon ("PATH" %: string)
  |> with_default_arg ~default:"."

(* ── Build the main command ───────────────────────────────────────────── *)

let catseye_command (run_impl : t -> int) =
  Command.basic
    ~summary:"Catseye - Security analysis tool for Crystal, Gleam, JavaScript, TypeScript, Svelte, OCaml, and Rust"
    Command.Spec.(
      empty
      |> format_flag
      |> lang_flag
      |> rules_flag
      |> output_flag
      |> config_flag
      |> cache_dir_flag
      |> suppress_flag
      |> parallelism_flag
      |> analysis_timeout_flag
      |> cfg_max_blocks_flag
      |> cfg_timeout_flag
      |> no_color_flag
      |> no_cache_flag
      |> clear_cache_flag
      |> no_recurse_flag
      |> no_cfg_flag
      |> predator_vision_flag
      |> crows_nest_flag
      |> claws_flag
      |> ai_lint_flag
      |> ast_bridge_flag
      |> include_deps_flag
      |> path_arg
    )
    (fun fmt lang rules output config_path_arg cache_dir suppress parallelism
         analysis_timeout cfg_max_blocks cfg_timeout
         no_color no_cache clear_cache no_recurse no_cfg
         predator_vision crows_nest claws ai_lint ast_bridge include_deps
         path () ->
      (* CRITICAL: Set SIGPIPE to ignore at startup, BEFORE any domain spawns.
         OCaml 5.4's fast I/O with Domain parallelism can cause SIGPIPE when
         Crystal subprocess stdout is closed before Crystal finishes flushing. *)
      let _ = Sys.signal Sys.sigpipe Sys.Signal_ignore in
      
      (* Build config from parsed arguments *)
      let parse_format s = 
        match output_format_of_string s with
        | Ok f -> f
        | Error e -> failwith (Error.to_string_hum e)
      in
      let parse_lang s =
        match lang_filter_of_string s with
        | Ok l -> l
        | Error e -> failwith (Error.to_string_hum e)
      in
      
      let default_config = Config.default in
      let cfg = {
        default_config with
        target_dir = path;
        format = parse_format fmt;
        lang_filter = parse_lang lang;
        output_path = Option.value output ~default:default_config.output_path;
        config_path = config_path_arg;
        rules_dir = Option.value rules ~default:default_config.rules_dir;
        cache_dir = Option.value cache_dir ~default:default_config.cache_dir;
        color = not no_color;
        no_cache;
        clear_cache;
        parallelism;
        analysis_timeout_ms = analysis_timeout;
        cfg_max_blocks;
        cfg_timeout_ms = cfg_timeout;
        recurse = not no_recurse;
        use_cfg = not no_cfg;
        predator_vision;
        crows_nest;
        claws;
        ai_lint;
        ast_bridge;
        include_deps;
        suppress = Option.map suppress ~f:(fun s -> String.split s ~on:',') 
                   |> Option.value ~default:[];
      } in
      let cfg = Config.load cfg in
      exit (run_impl cfg)
    )

(* Expose for backward compatibility with existing orchestrator *)
let run_with_args run_impl =
  catseye_command run_impl |> Command.run