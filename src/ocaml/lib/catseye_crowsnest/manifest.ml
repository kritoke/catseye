(* lib/catseye_crowsnest/manifest.ml
   Parse shard.yml and gleam.toml for dependency lists. *)

type shard_dep = {
  name : string;
  github : string option;
  version : string option;
}

type hex_dep = {
  name : string;
  version : string option;
}

type manifest =
  | Shard_yml of string * shard_dep list
  | Gleam_toml of string * hex_dep list

(* ── shard.yml parser (simple YAML subset) ──────────────────────────── *)

(** Minimal shard.yml parser. Extracts the [dependencies] section which has
    the structure:
      dependencies:
        name:
          github: user/repo
          version: "1.2.3"

    We parse this with line-by-line scanning — no full YAML parser needed. *)
let parse_shard_yml (path : string) : (shard_dep list, [> `Msg of string ]) result =
  try
    let ic = open_in path in
    let lines = ref [] in
    (try while true do
        let line = input_line ic in
        lines := line :: !lines
      done
    with End_of_file -> ());
    close_in ic;
    let lines = List.rev !lines in

    (* Find the dependencies: section *)
    let rec scan_deps acc = function
      | [] -> List.rev acc
      | line :: rest ->
        let trimmed = String.trim line in
        (* Stop at next top-level key (no leading spaces) *)
        if trimmed <> "" && trimmed.[0] <> '#' &&
           String.length line > 0 && line.[0] <> ' ' && line.[0] <> '\t' &&
           not (String.starts_with ~prefix:"dependencies" trimmed)
        then List.rev acc
        else
          (* Look for a dependency name line: "  name:" (indented, not version/github) *)
          (match String.split_on_char ':' trimmed with
           | [name] when String.length name > 0 && not (String.contains name ' ') ->
             (* This is a dependency name — collect its children *)
             let dep_name = String.trim name in
             let rec collect_children children rest =
               match rest with
               | [] -> children, []
               | c_line :: c_rest ->
                 let c_trim = String.trim c_line in
                 if c_trim = "" then collect_children children c_rest
                 else if String.length c_line > 0 &&
                         (c_line.[0] = ' ' || c_line.[0] = '\t') then
                   (* It's a child line *)
                   collect_children (c_trim :: children) c_rest
                 else children, rest
             in
             let children, remaining = collect_children [] rest in
             let github = List.find_opt (fun c ->
               String.starts_with ~prefix:"github:" c ||
               String.starts_with ~prefix:"git: " c
             ) children |> Option.map (fun c ->
               let parts = String.split_on_char ':' c in
               String.trim (String.concat ":" (List.tl parts))
             ) in
             let version = List.find_opt (fun c ->
               String.starts_with ~prefix:"version:" c
             ) children |> Option.map (fun c ->
               let v = String.sub c 8 (String.length c - 8) in
               String.trim (String.map (fun ch ->
                 if ch = '"' || ch = '\'' then ' ' else ch
               ) v) |> String.trim
             ) in
             scan_deps ({ name = dep_name; github; version } :: acc) remaining
           | _ -> scan_deps acc rest)
    in

    (* Skip to dependencies: section *)
    let rec find_deps = function
      | [] -> []
      | line :: rest ->
        let trimmed = String.trim line in
        if String.starts_with ~prefix:"dependencies:" trimmed then
          scan_deps [] rest
        else find_deps rest
    in

    Ok (find_deps lines)
  with Sys_error msg ->
    Error (`Msg (Printf.sprintf "Failed to read %s: %s" path msg))

(* ── gleam.toml parser ──────────────────────────────────────────────── *)

(** Parse gleam.toml [dependencies] section using the Toml library. *)
let parse_gleam_toml (path : string) : (hex_dep list, [> `Msg of string ]) result =
  try
    let ic = open_in path in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;

    (* Extract [dependencies] section *)
    (* Parse [dependencies] section using line scanning.
       gleam.toml has a simple structure:
         [dependencies]
         gleam_http = { version = "~> 3.7" }
         mist = ">= 4.0.0"
    *)
    let ic = open_in path in
    let lines = ref [] in
    (try while true do
        let line = input_line ic in
        lines := line :: !lines
      done
    with End_of_file -> ());
    close_in ic;
    let lines = List.rev !lines in
    let rec scan_deps acc in_deps = function
      | [] -> List.rev acc
      | line :: rest ->
        let trimmed = String.trim line in
        if String.starts_with ~prefix:"[" trimmed && not (String.starts_with ~prefix:"[dependencies" trimmed) then
          if in_deps then List.rev acc  (* left [dependencies] section *)
          else scan_deps acc false rest
        else if String.starts_with ~prefix:"[dependencies" trimmed then
          scan_deps acc true rest
        else if in_deps && trimmed <> "" && trimmed.[0] <> '#' then begin
          (* Parse: name = { version = "~> 3.7" } or name = ">= 4.0.0" *)
          match String.split_on_char '=' trimmed with
          | name_str :: version_parts ->
            let name = String.trim (String.concat "=" [name_str]) in
            let version_raw = String.trim (String.concat "=" version_parts) in
            let version =
              (* Extract version from { version = "~> 3.7" } format *)
              if String.length version_raw > 0 && version_raw.[0] = '{' then begin
                let inner = String.sub version_raw 1 (String.length version_raw - 2) in
                let parts = String.split_on_char '=' inner in
                match parts with
                | _ :: v_parts ->
                  let v = String.trim (String.concat "=" v_parts) in
                  Some (String.map (fun ch -> if ch = '"' || ch = '\'' then ' ' else ch) v |> String.trim)
                | [] -> None
              end
              (* Simple format: name = ">= 4.0.0" *)
              else
                Some (String.map (fun ch -> if ch = '"' || ch = '\'' then ' ' else ch) version_raw |> String.trim)
            in
            if name <> "" then
              scan_deps ({ name; version } :: acc) true rest
            else scan_deps acc true rest
          | _ -> scan_deps acc true rest
        end
        else scan_deps acc in_deps rest
    in
    let deps = scan_deps [] false lines in
    Ok deps
  with Sys_error msg ->
    Error (`Msg (Printf.sprintf "Failed to read %s: %s" path msg))

(* ── Manifest auto-detection ────────────────────────────────────────── *)

let find_manifests (dir : string) : manifest list =
  let results = ref [] in
  let shard_path = Filename.concat dir "shard.yml" in
  if Sys.file_exists shard_path then begin
    match parse_shard_yml shard_path with
    | Ok deps -> results := Shard_yml (shard_path, deps) :: !results
    | Error _ -> ()
  end;
  let gleam_path = Filename.concat dir "gleam.toml" in
  if Sys.file_exists gleam_path then begin
    match parse_gleam_toml gleam_path with
    | Ok deps -> results := Gleam_toml (gleam_path, deps) :: !results
    | Error _ -> ()
  end;
  List.rev !results

let find_manifests_recursive (dir : string) : manifest list =
  (* Check target dir, then walk up looking for manifests *)
  let results = ref (find_manifests dir) in
  if !results = [] then begin
    let rec walk d =
      if d = Filename.dirname d then None
      else
        let parent = Filename.dirname d in
        let found = find_manifests parent in
        if found <> [] then Some found
        else walk parent
    in
    match walk dir with
    | Some ms -> results := ms
    | None -> ()
  end;
  !results
