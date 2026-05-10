(* lib/catseye_cli/args.ml *)

open Config

let format_of_string = function
  | "json" -> Json
  | "sarif" -> Sarif
  | "markdown" | "md" -> Markdown
  | "terminal" | "text" -> Terminal
  | s -> failwith (Printf.sprintf "Unknown format: %s" s)

let lang_of_string = function
  | "crystal" | "cr" -> Crystal
  | "gleam" -> Gleam
  | "all" -> All
  | s -> failwith (Printf.sprintf "Unknown language: %s" s)

(** Resolve a path to absolute, using [base] as the reference directory.
    If already absolute, return as-is. *)
let resolve base path =
  if Filename.is_relative path then Filename.concat base path
  else path

(** Parse CLI args using recursive descent over the argument list. *)
let parse_args () : t =
  let args = Array.to_list Sys.argv |> List.tl in
  let cwd = Sys.getcwd () in
  let rec go acc = function
    | [] -> acc
    | ("--format" | "-f") :: fmt :: rest ->
      go { acc with format = format_of_string fmt } rest
    | "--lang" :: lang :: rest ->
      go { acc with lang_filter = lang_of_string lang } rest
    | ("--output" | "-o") :: path :: rest ->
      go { acc with output_path = resolve cwd path } rest
    | "--config" :: path :: rest
    | "--crystal-extractor" :: path :: rest ->
      go { acc with crystal_extractor = resolve cwd path } rest
    | ("--rules" | "-r") :: path :: rest ->
      go { acc with rules_dir = resolve cwd path } rest
    | "--no-color" :: rest ->
      go { acc with color = false } rest
    | "--no-cache" :: rest ->
      go { acc with no_cache = true } rest
    | "--no-persona" :: rest ->
      go { acc with persona = false } rest
    | ("--predator-vision" | "-pv") :: rest ->
      go { acc with predator_vision = true } rest
    | ("--crows-nest" | "-cn") :: rest ->
      go { acc with crows_nest = true } rest
    | ("--parallelism" | "-p") :: n :: rest ->
      go { acc with parallelism = int_of_string n } rest
    | ("--help" | "-h") :: _ ->
      Printf.printf "Catseye v%s — Static security analysis\n\n" Catseye_engine.Engine.version;
      Printf.printf "Usage: catseye [options] <directory>\n\n";
      Printf.printf "Options:\n";
      Printf.printf "  --format <fmt>       Output: terminal (default), json, sarif, markdown\n";
      Printf.printf "  --lang <lang>        Language filter: all (default), crystal, gleam\n";
      Printf.printf "  --output <path>      Write results to file\n";
      Printf.printf "  --rules <path>       Rules directory (default: rules/)\n";
      Printf.printf "  --crystal-extractor  Crystal extractor path\n";
      Printf.printf "  --no-color           Disable colored output\n";
      Printf.printf "  --no-cache           Disable extraction cache\n";
      Printf.printf "  --no-persona         Disable Hunter persona (plain terminal output)\n";
      Printf.printf "  --predator-vision    Enable reachability heatmap\n";
      Printf.printf "  --crows-nest         Enable supply chain audit\n";
      Printf.printf "  --parallelism <n>    Parallel workers (0 = auto)\n";
      Printf.printf "  -h, --help           Show this help\n";
      exit 0
    | opt :: _ when String.starts_with ~prefix:"-" opt ->
      Printf.eprintf "Unknown option: %s\n" opt;
      exit 1
    | dir :: rest when Sys.is_directory dir ->
      (* First positional that's a directory = target *)
      if acc.target_dir <> "" then begin
        Printf.eprintf "Error: too many positional arguments\n"; exit 1
      end;
      go { acc with target_dir = dir } rest
    | unknown :: _ ->
      Printf.eprintf "Error: not a directory: %s\n" unknown;
      exit 1
  in
  let cfg = go default args in
  if cfg.target_dir = "" then begin
    Printf.eprintf "Error: no target directory specified.\nUsage: catseye <directory>\n";
    exit 1
  end;
  (* Resolve relative defaults against cwd *)
  { cfg with
    crystal_extractor = resolve cwd cfg.crystal_extractor
  ; rules_dir = resolve cwd cfg.rules_dir
  }
