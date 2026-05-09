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

let parse_args () : t =
  let config = ref default in
  let args = Array.to_list Sys.argv |> List.tl in
  let positional = ref [] in
  let i = ref 0 in
  while !i < List.length args do
    let arg = List.nth args !i in
    (match arg with
    | "--format" | "-f" ->
      incr i;
      let fmt = List.nth args !i in
      config := { !config with format = format_of_string fmt }
    | "--lang" ->
      incr i;
      let lang = List.nth args !i in
      config := { !config with lang_filter = lang_of_string lang }
    | "--output" | "-o" ->
      incr i;
      let path = List.nth args !i in
      config := { !config with output_path = path }
    | "--config" ->
      incr i;
      let path = List.nth args !i in
      config := { !config with crystal_extractor = path }
    | "--crystal-extractor" ->
      incr i;
      let path = List.nth args !i in
      config := { !config with crystal_extractor = path }
    | "--rules" | "-r" ->
      incr i;
      let path = List.nth args !i in
      config := { !config with rules_dir = path }
    | "--no-color" ->
      config := { !config with color = false }
    | "--no-cache" ->
      config := { !config with no_cache = true }
    | "--parallelism" | "-p" ->
      incr i;
      config := { !config with parallelism = int_of_string (List.nth args !i) }
    | "--help" | "-h" ->
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
      Printf.printf "  --parallelism <n>    Parallel workers (0 = auto)\n";
      Printf.printf "  -h, --help           Show this help\n";
      exit 0
    | s when String.starts_with ~prefix:"-" s ->
      Printf.eprintf "Unknown option: %s\n" s;
      exit 1
    | dir ->
      positional := dir :: !positional
    );
    incr i
  done;
  match List.rev !positional with
  | [dir] ->
    if not (Sys.is_directory dir) then begin
      Printf.eprintf "Error: directory not found: %s\n" dir;
      exit 1
    end;
    { !config with target_dir = dir }
  | [] ->
    Printf.eprintf "Error: no target directory specified.\nUsage: catseye <directory>\n";
    exit 1
  | _ ->
    Printf.eprintf "Error: too many positional arguments\n";
    exit 1
