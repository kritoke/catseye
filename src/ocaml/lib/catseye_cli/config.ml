(* lib/catseye_cli/config.ml *)

open Base
open Stdio

(* Note: Base shadows some stdlib functions, but most have same or similar names.
   Base.String, Base.List, Base.In_channel provide compatible alternatives.
   Only equality operators need explicit stdlib access since Base's (=) is polymorphic. *)
let ( = ) = Stdlib.( = )
let ( <>) = Stdlib.( <> )
let ( ^ ) = Stdlib.( ^ )

type output_format =
  | Terminal
  | Json
  | Sarif
  | Markdown
  | Dot

type lang_filter =
  | All
  | Only of string list

type t = {
  target_dir : string;
  config_path : string option;  (* explicit --config path, None = auto-discover *)
  format : output_format;
  lang_filter : lang_filter;
  output_path : string;
  color : bool;
  extractor_registry : Catseye_engine.Extractor_registry.t option;  (* Legacy: kept for direct access *)
  extractor_cmds : Catseye_types.Extractor_cmds.t option;  (* New: simple command record for AST layer *)
  crystal_available : bool;  (* Whether Crystal toolchain was detected *)
  rules_dir : string;
  extra_sources : string list;
  extra_sanitizers : string list;
  exclude_dirs : string list;
  parallelism : int;
  cache_dir : string;
  incremental : bool;
  crystal_workers : int;
  no_cache : bool;
  clear_cache : bool;
  predator_vision : bool;
  crows_nest : bool;
  claws : bool;
  ai_lint : bool;  (* Enable AI linter rules *)
  ast_bridge : bool;  (* Use CatseyeAST.t bridge instead of direct extraction *)
  use_cfg : bool;     (* Use IL/CFG-based taint engine *)
  no_cfg_use : bool;   (* Override to use flat engine even when --cfg set *)
  analysis_timeout_ms : int;  (* Timeout for analysis phase in ms *)
  cfg_max_blocks : int;       (* Max blocks per function CFG (safety limit) *)
  cfg_timeout_ms : int;       (* Timeout per function CFG build (safety limit) *)
  claws_config : Catseye_claws.Types.claws_config;
  taint_suppress : string list Map.M(String).t;  (* per-rule file globs to suppress taint findings *)
  suppress : string list;  (* Rule IDs to suppress (--suppress flag) *)
  ai_suppress : string list Map.M(String).t;  (* per-rule file globs to suppress AI lint findings *)
  include_deps : bool;  (* Include shard dependencies in scan (Crystal only) *)
  recurse : bool;  (* Recurse into subdirectories (default: true) *)
  elixir_enabled : bool;  (* Enable Elixir tool integration *)
  elixir_tools : string list;  (* Which Elixir tools to run *)
}

let default = {
  target_dir = "";
  config_path = None;
  format = Terminal;
  lang_filter = All;
  output_path = "";
  color = true;
  extractor_registry = None;
  extractor_cmds = None;
  crystal_available = false;
  rules_dir = "rules";
  extra_sources = [];
  extra_sanitizers = [];
  exclude_dirs = ["node_modules"; ".git"; "vendor"; "spec"; "dist"; ".svelte-kit"; "build"; ".next"; "_build"; "_opam"; "deps"; "test"];
  parallelism = 0;
  cache_dir = ".catseye";
  incremental = true;
  crystal_workers = 2;
  no_cache = false;
  clear_cache = false;
  predator_vision = false;
  crows_nest = false;
  claws = false;
  ai_lint = false;
  ast_bridge = false;
  include_deps = false;
  recurse = true;  (* Recurse into subdirectories by default *)
  use_cfg = false;
  no_cfg_use = false;
  analysis_timeout_ms = 0;  (* 0 = no timeout *)
  cfg_max_blocks = 500;
  cfg_timeout_ms = 5000;
  claws_config = Catseye_claws.Types.default_config;
  taint_suppress = Map.empty (module String);
  suppress = [];
  ai_suppress = Map.empty (module String);
  elixir_enabled = false;
  elixir_tools = ["sobelow"; "credo"; "reach"];
}

(** Walk up from [dir] looking for .catseye.toml. *)
let find_config dir =
  let rec walk d =
    let candidate = Stdlib.Filename.concat d ".catseye.toml" in
    if Stdlib.Sys.file_exists candidate then Some candidate
    else
      let parent = Stdlib.Filename.dirname d in
      if parent = d then None
      else walk parent
  in
  walk dir

(** Read a string list from a TOML table at the given dotted path. *)
let get_string_list table path =
  let keys = String.split path ~on:'.' in
  let rec descend tbl = function
    | [] -> None
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TArray (NodeString lst) -> Some lst
        | _ -> None
      with Not_found_s _ -> None)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> None
      with Not_found_s _ -> None)
  in
  descend table keys

(** Read an integer from a TOML table. *)
let get_int table path default =
  let keys = String.split path ~on:'.' in
  let rec descend tbl = function
    | [] -> default
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TInt n -> n
        | _ -> default
      with Not_found_s _ -> default)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> default
      with Not_found_s _ -> default)
  in
  descend table keys

(** Read a string from a TOML table. *)
let get_string table path default =
  let keys = String.split path ~on:'.' in
  let rec descend tbl = function
    | [] -> default
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TString s -> s
        | _ -> default
      with Not_found_s _ -> default)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> default
      with Not_found_s _ -> default)
  in
  descend table keys

(** Parse a glob pattern list from raw TOML lines.
    Returns a String.Map.t instead of Hashtbl.t for thread-safety. *)
let parse_glob_list_to_map lines section_name =
  let initial_map = Map.empty (module String) in
  let current_section = ref "" in
  let rec process_lines acc = function
    | [] -> acc
    | line :: rest ->
      let trimmed = String.strip line in
      let new_section =
        if String.length trimmed > 0 && trimmed.[0] = '[' then
          match Stdlib.String.index_opt trimmed ']' with
          | Some i -> String.sub trimmed ~pos:1 ~len:(i - 1)
          | None -> !current_section
        else !current_section
      in
      current_section := new_section;
      if new_section = section_name then
        match Stdlib.String.index_opt trimmed '=' with
        | Some eq_pos ->
            let rule_name = String.strip (String.sub trimmed ~pos:0 ~len:eq_pos) in
            let rest_str = String.strip (String.sub trimmed ~pos:(eq_pos + 1) ~len:(String.length trimmed - eq_pos - 1)) in
            if String.length rest_str >= 2 && rest_str.[0] = '[' then
              let close_bracket = match Stdlib.String.rindex_opt rest_str ']' with
              | Some idx -> idx
              | None -> String.length rest_str - 1
            in
            let inner = String.sub rest_str ~pos:1 ~len:(close_bracket - 1) in
              let parts = String.split ~on:',' inner in
              let pats = 
                parts
                |> List.filter ~f:(fun s -> String.length s > 0)
                |> List.map ~f:(fun s ->
                  let s = String.strip s in
                  if String.length s >= 2 && s.[0] = '"' && s.[String.length s - 1] = '"' then
                    String.sub s ~pos:1 ~len:(String.length s - 2)
                  else s
                )
              in
              if not (List.is_empty pats)
              then process_lines (Map.set acc ~key:rule_name ~data:pats) rest
              else process_lines acc rest
            else process_lines acc rest
        | None -> process_lines acc rest
      else process_lines acc rest
  in
  process_lines initial_map lines

(** Load .catseye.toml and overlay onto config. *)
let load_toml (path : string) (cfg : t) : t =
  try
    let table =
      let contents = In_channel.read_all path in
      Toml.Parser.(from_string contents |> unsafe) in
    let get_bool table path default =
      match get_int table path (-1) with
      | 0 -> false
      | 1 -> true
      | _ -> default
    in
    (* Read raw TOML for suppress sections *)
    let raw_toml = In_channel.read_all path in
    let toml_lines = String.split raw_toml ~on:'\n' in
    { cfg with
      lang_filter =
        (match get_string_list table "languages.enabled" with
         | Some langs -> Only langs
         | None ->
           (match get_string_list table "languages.disabled" with
            | Some disabled ->
              (* Filter out disabled languages from All *)
              let all_langs = match cfg.lang_filter with
                | All -> ["crystal"; "gleam"]
                | Only langs -> langs
              in
              Only (List.filter all_langs ~f:(fun l -> not (List.mem disabled l ~equal:String.equal)))
            | None -> cfg.lang_filter))
    ; exclude_dirs =
        (match get_string_list table "scan.exclude" with
         | Some extra ->
           let combined = cfg.exclude_dirs @ extra in
           let sorted = List.sort ~compare:String.compare combined in
           let rec dedup acc = function
             | [] -> List.rev acc
             | [x] -> List.rev (x :: acc)
             | x :: y :: rest when String.equal x y -> dedup acc (y :: rest)
             | x :: rest -> dedup (x :: acc) rest
           in
           dedup [] sorted
         | None -> cfg.exclude_dirs)
    ; extra_sources = (match get_string_list table "analysis.extra_sources" with Some l -> l | None -> [])
    ; extra_sanitizers = (match get_string_list table "analysis.extra_sanitizers" with Some l -> l | None -> [])
    ; parallelism = get_int table "analysis.parallelism" cfg.parallelism
    ; extractor_registry = cfg.extractor_registry  (* resolved at startup, not from TOML *)
    ; crystal_available = cfg.crystal_available
    ; rules_dir = get_string table "scan.rules_dir" cfg.rules_dir
    ; predator_vision = get_bool table "predator_vision.enabled" cfg.predator_vision
    ; crows_nest = get_bool table "crows_nest.enabled" cfg.crows_nest
    ; claws = get_bool table "claws.enabled" cfg.claws
    ; claws_config = {
        complexity_enabled = get_bool table "claws.complexity_enabled" true;
        anatomy_enabled = get_bool table "claws.anatomy_enabled" true;
        dry_enabled = get_bool table "claws.dry_enabled" true;
        ameba_enabled = get_bool table "claws.ameba_enabled" false;
        extra_smells_enabled = get_bool table "claws.extra_smells_enabled" true;
        anti_singleton_enabled = get_bool table "claws.anti_singleton_enabled" true;
        complexity_warning = get_int table "claws.complexity_warning" 10;
        complexity_critical = get_int table "claws.complexity_critical" 20;
        max_params = get_int table "claws.max_params" 5;
        max_params_critical = get_int table "claws.max_params_critical" 8;
        max_nesting = get_int table "claws.max_nesting" 5;
        max_nesting_critical = get_int table "claws.max_nesting_critical" 7;
        max_methods_per_file = get_int table "claws.max_methods_per_file" 20;
        dry_window_size = get_int table "claws.dry_window_size" 8;
        dry_min_occurrences = get_int table "claws.dry_min_occurrences" 4;
        ameba_path = get_string table "claws.ameba_path" "ameba";
        long_method_warning = get_int table "claws.long_method_warning" 30;
        long_method_critical = get_int table "claws.long_method_critical" 50;
        complex_conditional_threshold = get_int table "claws.complex_conditional_threshold" 3;
        message_chain_threshold = get_int table "claws.message_chain_threshold" 5;
        data_clumps_enabled = get_bool table "claws.data_clumps_enabled" true;
        data_clumps_threshold = get_int table "claws.data_clumps_threshold" 3;
        complex_match_warning = get_int table "claws.complex_match_warning" 5;
        complex_match_critical = get_int table "claws.complex_match_critical" 10;
        concurrency_enabled = get_bool table "claws.concurrency_enabled" true;
        lazy_class_enabled = get_bool table "claws.lazy_class_enabled" true;
        large_class_enabled = get_bool table "claws.large_class_enabled" true;
        lazy_class_method_threshold = get_int table "claws.lazy_class_method_threshold" 3;
        large_class_loc_warning = get_int table "claws.large_class_loc_warning" 200;
        large_class_loc_critical = get_int table "claws.large_class_loc_critical" 500;
        suppress = parse_glob_list_to_map toml_lines "claws.suppress";
      };
      ai_suppress = parse_glob_list_to_map toml_lines "ai.suppress";
      taint_suppress = parse_glob_list_to_map toml_lines "taint.suppress";
    }
  with _ -> cfg

(** Check if Crystal toolchain is available.
    Looks for the crystal binary on PATH, or a pre-compiled extractor binary. *)
let detect_crystal () : bool =
  (* Check for pre-compiled extractor binary next to the executable *)
  let exe_dir = Stdlib.Filename.dirname Stdlib.Sys.executable_name in
  let flat_bin = Stdlib.Filename.concat exe_dir "catseye-crystal-extractor" in
  let hier_bin = Stdlib.Filename.concat exe_dir "catseye-hierarchical-extractor" in
  if Stdlib.Sys.file_exists flat_bin || Stdlib.Sys.file_exists hier_bin then true
  else
    (* Check for crystal compiler on PATH *)
    try
      let ic = Unix.open_process_in "which crystal 2>/dev/null" in
      let output = In_channel.input_lines ic |> String.concat ~sep:"\n" in
      let _ = Unix.close_process_in ic in
      not (String.is_empty (String.strip output))
    with _ -> false

(** Check if Elixir toolchain is available.
    Looks for the mix binary on PATH. *)
and detect_elixir () : bool =
  try
    let ic = Unix.open_process_in "which mix 2>/dev/null" in
    let output = In_channel.input_lines ic |> String.concat ~sep:"\n" in
    let _ = Unix.close_process_in ic in
    not (String.is_empty (String.strip output))
  with _ -> false

(** Initialize Crystal extractor registry if toolchain is available.
    Sets extractor_registry and extractor_cmds fields. *)
let init_crystal (cfg : t) : t =
  if detect_crystal () then begin
    let reg = Catseye_engine.Extractor_registry.create () in
    let cmds = Some {
      Catseye_types.Extractor_cmds.default with
      flat = Catseye_engine.Extractor_registry.flat_cmd reg;
      hier = Catseye_engine.Extractor_registry.hier_cmd reg;
    } in
    { cfg with extractor_registry = Some reg; extractor_cmds = cmds; crystal_available = true }
  end else
    { cfg with extractor_registry = None; extractor_cmds = None; crystal_available = false }

(** Initialize Elixir support if toolchain is available.
    Auto-enables elixir_enabled when mix is found on PATH. *)
let init_elixir (cfg : t) : t =
  if detect_elixir () then
    { cfg with elixir_enabled = true }
  else
    cfg

(** Load config: CLI args → TOML overlay → Toolchain detection → final config. *)
let load (cli : t) : t =
  let toml_path = match cli.config_path with
    | Some p -> Some p
    | None -> find_config cli.target_dir
  in
  let with_toml = match toml_path with
    | None -> cli
    | Some path -> load_toml path cli
  in
  init_crystal (init_elixir with_toml)