(* lib/catseye_cli/config.ml *)

type output_format =
  | Terminal
  | Json
  | Sarif
  | Markdown

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
  parallelism : int;
  cache_dir : string;
  incremental : bool;
  crystal_workers : int;
  no_cache : bool;
}

let default = {
  target_dir = "";
  format = Terminal;
  lang_filter = All;
  output_path = "";
  color = true;
  crystal_extractor = "src/extractor/extractor.cr";
  rules_dir = "rules";
  extra_sources = [];
  extra_sanitizers = [];
  parallelism = 0;
  cache_dir = ".catseye";
  incremental = true;
  crystal_workers = 2;
  no_cache = false;
}
