(* lib/catseye_cli/config.ml *)

type output_format =
  | Terminal
  | Json
  | Sarif
  | Markdown
  | Dot

type lang_filter =
  | All
  | Crystal
  | Gleam

type t = {
  target_dir : string;
  format : output_format;
  lang_filter : lang_filter;
  output_path : string;
  color : bool;
  crystal_extractor : string;
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
  claws_config : Catseye_claws.Types.claws_config;
}

let default = {
  target_dir = "";
  format = Terminal;
  lang_filter = All;
  output_path = "";
  color = true;
  crystal_extractor = "bin/catseye-crystal-extractor";
  rules_dir = "rules";
  extra_sources = [];
  extra_sanitizers = [];
  exclude_dirs = ["node_modules"; ".git"; "vendor"; "spec"];
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
  claws_config = Catseye_claws.Types.default_config;
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
    { cfg with
      exclude_dirs =
        (match get_string_list table "scan.exclude" with
         | Some extra -> List.sort_uniq String.compare (cfg.exclude_dirs @ extra)
         | None -> cfg.exclude_dirs)
    ; extra_sources = (match get_string_list table "analysis.extra_sources" with Some l -> l | None -> [])
    ; extra_sanitizers = (match get_string_list table "analysis.extra_sanitizers" with Some l -> l | None -> [])
    ; parallelism = get_int table "analysis.parallelism" cfg.parallelism
    ; crystal_extractor = get_string table "scan.crystal_extractor" cfg.crystal_extractor
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
        suppress =
          let sup = Hashtbl.create 8 in
          (* Parse [claws.suppress] from raw TOML — avoids abstract Key.t issues *)
          (try
            let ic = open_in path in
            let len = in_channel_length ic in
            let buf = Bytes.create len in
            really_input ic buf 0 len;
            close_in ic;
            let raw = Bytes.to_string buf in
            let lines = String.split_on_char '\n' raw in
            let in_suppress = ref false in
            List.iter (fun line ->
              let trimmed = String.trim line in
              if trimmed = "[claws.suppress]" then in_suppress := true
              else if !in_suppress && String.length trimmed > 0 && trimmed.[0] = '[' then
                in_suppress := false
              else if !in_suppress then begin
                match String.index_opt trimmed '=' with
                | Some eq_pos ->
                    let rule_name = String.trim (String.sub trimmed 0 eq_pos) in
                    let rest = String.trim (String.sub trimmed (eq_pos + 1) (String.length trimmed - eq_pos - 1)) in
                    if String.length rest >= 2 && rest.[0] = '[' then begin
                      let inner = String.sub rest 1 (String.length rest - 2) in
                      let pats = List.map (fun s ->
                        let s = String.trim s in
                        if String.length s >= 2 && s.[0] = '\"' && s.[String.length s - 1] = '\"' then
                          String.sub s 1 (String.length s - 2)
                        else s
                      ) (String.split_on_char ',' inner) in
                      Hashtbl.replace sup rule_name pats
                    end
                | None -> ()
              end
            ) lines
          with _ -> ());
          sup;
      }
    }
  with _ -> cfg

(** Load config: CLI args → TOML overlay → final config. *)
let load (cli : t) : t =
  match find_config cli.target_dir with
  | None -> cli
  | Some path -> load_toml path cli
