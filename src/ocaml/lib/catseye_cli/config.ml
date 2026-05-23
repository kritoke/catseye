(* lib/catseye_cli/config.ml *)

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
  extractor_registry : Catseye_engine.Extractor_registry.t option;
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
  taint_suppress : (string, string list) Hashtbl.t;  (* per-rule file globs to suppress taint findings *)
  suppress : string list;  (* Rule IDs to suppress (--suppress flag) *)
  ai_suppress : (string, string list) Hashtbl.t;  (* per-rule file globs to suppress AI lint findings *)
  include_deps : bool;  (* Include shard dependencies in scan (Crystal only) *)
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
  crystal_available = false;
  rules_dir = "rules";
  extra_sources = [];
  extra_sanitizers = [];
  exclude_dirs = ["node_modules"; ".git"; "vendor"; "spec"; "dist"; ".svelte-kit"; "build"; ".next"; "_build"; "_opam"; "test"];
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
  use_cfg = false;
  no_cfg_use = false;
  analysis_timeout_ms = 0;  (* 0 = no timeout *)
  cfg_max_blocks = 500;
  cfg_timeout_ms = 5000;
  claws_config = Catseye_claws.Types.default_config;
  taint_suppress = Hashtbl.create 0;
  suppress = [];
  ai_suppress = Hashtbl.create 0;
  elixir_enabled = false;
  elixir_tools = ["sobelow"; "credo"; "reach"];
}

(** Walk up from [dir] looking for .catseye.toml. *)
let find_config dir =
  let rec walk d =
    let candidate = Filename.concat d ".catseye.toml" in
    if Sys.file_exists candidate then Some candidate
    else
      let parent = Filename.dirname d in
      if parent = d then None
      else walk parent
  in
  walk dir

(** Read a string list from a TOML table at the given dotted path. *)
let get_string_list table path =
  let keys = String.split_on_char '.' path in
  let rec descend tbl = function
    | [] -> None
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TArray (NodeString lst) -> Some lst
        | _ -> None
      with Not_found -> None)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> None
      with Not_found -> None)
  in
  descend table keys

(** Read an integer from a TOML table. *)
let get_int table path default =
  let keys = String.split_on_char '.' path in
  let rec descend tbl = function
    | [] -> default
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TInt n -> n
        | _ -> default
      with Not_found -> default)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> default
      with Not_found -> default)
  in
  descend table keys

(** Read a string from a TOML table. *)
let get_string table path default =
  let keys = String.split_on_char '.' path in
  let rec descend tbl = function
    | [] -> default
    | [k] ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TString s -> s
        | _ -> default
      with Not_found -> default)
    | k :: rest ->
      (try
        let open Toml.Types in
        match Table.find (Toml.Min.key k) tbl with
        | TTable t -> descend t rest
        | _ -> default
      with Not_found -> default)
  in
  descend table keys

(** Parse a glob pattern list from raw TOML lines. Helper for suppress sections. *)
let parse_glob_list lines section_name =
  let sup = Hashtbl.create 8 in
  let current_section = ref "" in
  List.iter (fun line ->
    let trimmed = String.trim line in
    if String.length trimmed > 0 && trimmed.[0] = '[' then
      (let close = String.index_opt trimmed ']' in
       match close with
       | Some i -> current_section := String.sub trimmed 1 (i - 1)
       | None -> ())
    else if !current_section = section_name then begin
      match String.index_opt trimmed '=' with
      | Some eq_pos ->
          let rule_name = String.trim (String.sub trimmed 0 eq_pos) in
          let rest = String.trim (String.sub trimmed (eq_pos + 1) (String.length trimmed - eq_pos - 1)) in
          if String.length rest >= 2 && rest.[0] = '[' then
            (* Find the closing ] for the array *)
            let close_bracket = match String.rindex_opt rest ']' with
              | Some idx -> idx
              | None -> String.length rest - 1
            in
            let inner = String.sub rest 1 (close_bracket - 1) in
            let pats = List.filter (fun s -> String.length s > 0) (List.map (fun s ->
              let s = String.trim s in
              if String.length s >= 2 && s.[0] = '"' && s.[String.length s - 1] = '"' then
                String.sub s 1 (String.length s - 2)
              else s
            ) (String.split_on_char ',' inner)) in
            if pats <> [] then Hashtbl.replace sup rule_name pats
      | None -> ()
    end
  ) lines;
  sup

(** Load .catseye.toml and overlay onto config. *)
let load_toml (path : string) (cfg : t) : t =
  try
    let table =
      let ic = open_in path in
      let len = in_channel_length ic in
      let buf = Bytes.create len in
      really_input ic buf 0 len;
      close_in ic;
      Toml.Parser.(from_string (Bytes.to_string buf) |> unsafe) in
    let get_bool table path default =
      match get_int table path (-1) with
      | 0 -> false
      | 1 -> true
      | _ -> default
    in
    (* Read raw TOML for suppress sections *)
    let raw_toml =
      let ic = open_in path in
      let len = in_channel_length ic in
      let buf = Bytes.create len in
      really_input ic buf 0 len;
      close_in ic;
      Bytes.to_string buf
    in
    let toml_lines = String.split_on_char '\n' raw_toml in
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
              Only (List.filter (fun l -> not (List.mem l disabled)) all_langs)
            | None -> cfg.lang_filter))
    ; exclude_dirs =
        (match get_string_list table "scan.exclude" with
         | Some extra -> List.sort_uniq String.compare (cfg.exclude_dirs @ extra)
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
        suppress = parse_glob_list toml_lines "claws.suppress";
      };
      ai_suppress = parse_glob_list toml_lines "ai.suppress";
      taint_suppress = parse_glob_list toml_lines "taint.suppress";
    }
  with _ -> cfg

(** Check if Crystal toolchain is available.
    Looks for the crystal binary on PATH, or a pre-compiled extractor binary. *)
let detect_crystal () : bool =
  (* Check for pre-compiled extractor binary next to the executable *)
  let exe_dir = Filename.dirname (Sys.executable_name) in
  let flat_bin = exe_dir ^ "/catseye-crystal-extractor" in
  let hier_bin = exe_dir ^ "/catseye-hierarchical-extractor" in
  if Sys.file_exists flat_bin || Sys.file_exists hier_bin then true
  else
    (* Check for crystal compiler on PATH *)
    try
      let ic = Unix.open_process_in "which crystal 2>/dev/null" in
      let buf = Buffer.create 256 in
      (try while true do Buffer.add_channel buf ic 1 done
       with End_of_file -> ());
      let _ = Unix.close_process_in ic in
      Buffer.length buf > 0
    with _ -> false

(** Check if Elixir toolchain is available.
    Looks for the mix binary on PATH. *)
and detect_elixir () : bool =
  try
    let ic = Unix.open_process_in "which mix 2>/dev/null" in
    let buf = Buffer.create 256 in
    (try while true do Buffer.add_channel buf ic 1 done
     with End_of_file -> ());
    let _ = Unix.close_process_in ic in
    Buffer.length buf > 0
  with _ -> false

(** Initialize Crystal extractor registry if toolchain is available.
    Sets extractor_registry and crystal_available fields. *)
let init_crystal (cfg : t) : t =
  if detect_crystal () then begin
    let reg = Catseye_engine.Extractor_registry.create () in
    { cfg with extractor_registry = Some reg; crystal_available = true }
  end else
    { cfg with extractor_registry = None; crystal_available = false }

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