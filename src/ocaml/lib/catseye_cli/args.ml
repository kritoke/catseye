(* lib/catseye_cli/args.ml *)
(* CLI argument parsing *)

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
  | s -> Config.Only (String.split s ~on:',')

(* ── Path Resolution ─────────────────────────────────────────────────── *)

let resolve_path ~(base : string) (path : string) : string =
  if Stdlib.Filename.is_relative path then Stdlib.Filename.concat base path
  else path

let get_exe_dir () : string =
  Stdlib.Filename.dirname Stdlib.Sys.executable_name

(* ── Help text ───────────────────────────────────────────────────────── *)

let help_text = {|
catseye - Security analysis tool for Crystal and Gleam

Usage:
  catseye [OPTIONS] PATH

General options:
  --help                      Show this help message
  --version                   Show version

Analysis options:
  --format FMT                Output format: terminal (default), json, sarif, markdown, dot
  --lang LANGS                Language filter: all (default), crystal, gleam, or comma-separated
  --rules PATH                Rules directory (default: rules/)
  --ai-lint                   Enable AI-powered linting
  --ast-bridge                Enable AST bridge for JS/TS/Svelte
  --no-color                  Disable colored output
  --include-deps              Include dependency analysis

Performance options:
  --parallel N                Number of parallel workers (default: auto)
  --analysis-timeout MS       Analysis timeout in milliseconds (default: 0 = none)
  --cfg-max-blocks N          Max CFG blocks per function (default: 500)
  --cfg-timeout MS            CFG analysis timeout (default: 5000ms)

Output options:
  --output PATH               Write results to file
  --config PATH               Config file path (default: .catseye.toml)
  --cache-dir PATH            Cache directory (default: .catseye)
  --no-cache                  Disable extraction cache
  --clear-cache               Clear cache before running

Supply chain options:
  --predator-vision           Enable reachability heatmap
  --elixir                    Enable Elixir analysis
  --suppress TAGS             Suppress findings by comma-separated tags

Cache options:
  --no-cfg                    Skip CFG-based analysis
  --no-cfg-use                Don't use cached CFG data
  --no-recurse                Don't recurse into subdirectories
  --claws                     Enable code smell (Claws) analysis

Examples:
  catseye --lang crystal ./src
  catseye --format json --output results.json .
  catseye --predator-vision --ai-lint
|}

(* ── Simple argument parsing ─────────────────────────────────────────── *)

let find_opt key args : string option =
  (* First try --key=value format *)
  let prefix = "--" ^ key ^ "=" in
  match List.find args ~f:(fun s -> String.is_prefix s ~prefix) with
  | Some s -> Some (String.drop_prefix s (String.length prefix))
  | None ->
    (* Then try --key VALUE format (space-separated) *)
    let flag = "--" ^ key in
    let idx = List.findi args ~f:(fun _ s -> String.equal s flag) in
    match idx with
    | Some (i, _) ->
      (match List.nth args (i + 1) with
       | Some v when not (String.is_prefix v ~prefix:"--") -> Some v
       | _ -> None)
    | None -> None

let has_flag key args =
  let flag = "--" ^ key in
  List.exists args ~f:(fun s -> String.equal s flag)

let parse_args () : Config.t =
  let args = Array.to_list Stdlib.Sys.argv in
  let _program = List.hd args |> Option.value ~default:"catseye" in
  let args = List.tl args |> Option.value ~default:[] in
  
  (* Show help if requested *)
  if has_flag "help" args || List.mem ~equal:String.equal args "-h" then begin
    Stdio.print_endline help_text;
    Stdlib.exit 0
  end;
  
  if has_flag "version" args then begin
    Stdio.print_endline "catseye v0.4.3";
    Stdlib.exit 0
  end;
  
  (* Parse optional string values — collect values consumed by multi-arg flags so they aren't mistaken for the target path *)
  let consumed_values = [] in
  let consumed_values = match find_opt "rules" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "output" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "config" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "cache-dir" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "lang" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "format" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "suppress" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "parallel" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "analysis-timeout" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "cfg-max-blocks" args with Some v -> v :: consumed_values | None -> consumed_values in
  let consumed_values = match find_opt "cfg-timeout" args with Some v -> v :: consumed_values | None -> consumed_values in
  
  (* Parse path - first non-flag argument, skipping flag values already consumed above *)
  let non_consumed s =
    not (String.is_prefix s ~prefix:"--") &&
    not (Stdlib.List.mem s consumed_values) in
  let path = 
    match List.find args ~f:non_consumed with
    | Some p -> p
    | None -> "."
  in
  
  (* Parse format *)
  let format = 
    match find_opt "format" args with
    | Some s -> format_of_string s
    | None -> Config.Terminal
  in
  
  (* Parse language filter *)
  let lang_filter = 
    match find_opt "lang" args with
    | Some s -> lang_of_string s
    | None -> Config.All
  in
  
  (* Parse boolean flags *)
  let no_color = has_flag "no-color" args in
  let no_cache = has_flag "no-cache" args in
  let clear_cache = has_flag "clear-cache" args in
  let ai_lint = has_flag "ai-lint" args in
  let ast_bridge = has_flag "ast-bridge" args in
  let include_deps = has_flag "include-deps" args in
  let predator_vision = has_flag "predator-vision" args in
  let elixir = has_flag "elixir" args in
  let no_cfg = has_flag "no-cfg" args in
  let no_cfg_use = has_flag "no-cfg-use" args in
  let no_recurse = has_flag "no-recurse" args in
  let claws = has_flag "claws" args in
  
  (* Parse optional string values *)
  let output_path = find_opt "output" args in
  let config_path = find_opt "config" args in
  let rules_dir = find_opt "rules" args in
  let cache_dir = find_opt "cache-dir" args in
  let suppress = find_opt "suppress" args in
  
  (* Parse integer values *)
  let parallelism = 
    match find_opt "parallel" args with
    | Some s -> (try Int.of_string s with _ -> 0)
    | None -> 0
  in
  let analysis_timeout = 
    match find_opt "analysis-timeout" args with
    | Some s -> (try Int.of_string s with _ -> 0)
    | None -> 0
  in
  let cfg_max_blocks = 
    match find_opt "cfg-max-blocks" args with
    | Some s -> (try Int.of_string s with _ -> 500)
    | None -> 500
  in
  let cfg_timeout = 
    match find_opt "cfg-timeout" args with
    | Some s -> (try Int.of_string s with _ -> 5000)
    | None -> 5000
  in
  
  (* Build config - start with defaults and override *)
  let config = Config.default in
  {
    config with
    target_dir = path;
    format;
    lang_filter;
    output_path = Option.value output_path ~default:config.output_path;
    color = not no_color;
    no_cache;
    clear_cache;
    config_path;
    rules_dir = Option.value rules_dir ~default:config.rules_dir;
    cache_dir = Option.value cache_dir ~default:config.cache_dir;
    ai_lint;
    ast_bridge;
    include_deps;
    parallelism;
    analysis_timeout_ms = analysis_timeout;
    cfg_max_blocks;
    cfg_timeout_ms = cfg_timeout;
    elixir_enabled = elixir;
    predator_vision;
    use_cfg = not no_cfg;
    no_cfg_use;
    recurse = not no_recurse;
    claws;
    suppress = Option.map suppress ~f:(fun s -> String.split s ~on:',') |> Option.value ~default:[];
  }
