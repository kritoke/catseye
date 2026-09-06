(* lib/catseye/crowsnest/manifest.ml
   Parse shard.yml and gleam.toml for dependency lists. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

type shard_dep = {
  name : string;
  github : string option;
  version : string option;
}

type hex_dep = {
  name : string;
  version : string option;
}

(* Nim deps reuse shard_dep: { name; github; version } carries exactly what a
   nimble requires/lock entry needs (github = "user/repo" for URL requires). *)

type manifest =
  | Shard_yml of string * shard_dep list
  | Gleam_toml of string * hex_dep list
  | Nimble of string * shard_dep list         (* *.nimble *)
  | Nimble_lock of string * shard_dep list    (* nimble.lock, exact versions *)

(* ── shard.yml parser (simple YAML subset) ──────────────────────────── *)

(** Minimal shard.yml parser. Extracts the [dependencies] section which has
    the structure:
      dependencies:
        name:
          github: user/repo
          version: "1.2.3"

    We parse this with line-by-line scanning — no full YAML parser needed. *)
let parse_shard_yml (path : string) : (shard_dep list, [> `Msg of string ]) Result.t =
  try
    let ic = Stdlib.open_in path in
    let lines = ref [] in
    (try while true do
        let line = Stdlib.input_line ic in
        lines := line :: !lines
      done
    with End_of_file -> ());
    Stdlib.close_in ic;
    let lines = List.rev !lines in

    (* Find the dependencies: section *)
    let rec scan_deps acc = function
      | [] -> List.rev acc
      | line :: rest ->
        let trimmed = String.strip line in
        (* Stop at next top-level key (no leading spaces) *)
        if trimmed <> "" && trimmed.[0] <> '#' &&
           String.length line > 0 && line.[0] <> ' ' && line.[0] <> '\t' &&
           not (String.is_prefix ~prefix:"dependencies" trimmed)
        then List.rev acc
        else
          (* Look for a dependency name line: "  name:" (indented, not version/github) *)
          (match Stdlib.String.split_on_char ':' trimmed with
           | [name] | [name; _] when Stdlib.String.length name > 0 && not (Stdlib.String.contains name ' ') ->
             (* This is a dependency name — collect its children *)
             (* Calculate dep indent to properly scope child collection *)
             let dep_indent =
               let trimmed = String.strip line in
               String.length line - String.length trimmed
             in
             let dep_name = String.strip name in
             let rec collect_children children rest =
               match rest with
               | [] -> children, []
               | c_line :: c_rest ->
                 let c_trim = String.strip c_line in
                 if c_trim = "" then collect_children children c_rest
                 else if Stdlib.String.length c_line > dep_indent &&
                         (c_line.[dep_indent] = ' ' || c_line.[dep_indent] = '\t') then
                   (* It's a child line *)
                   collect_children (c_trim :: children) c_rest
                 else children, rest
             in
             let children, remaining = collect_children [] rest in
let github = List.find ~f:(fun c ->
                String.is_prefix ~prefix:"github:" c ||
                String.is_prefix ~prefix:"git: " c
) children |> Option.map ~f:(fun c ->
                let parts = Stdlib.String.split_on_char ':' c in
                let rest = match List.rev parts with
                  | [] -> ""
                  | _ :: r -> Stdlib.String.concat ":" (List.rev r)
                in
                String.strip rest)
              in
              let version = List.find ~f:(fun c ->
                String.is_prefix ~prefix:"version:" c
              ) children |> Option.map ~f:(fun c ->
                let v = Stdlib.String.sub c 8 (Stdlib.String.length c - 8) in
                String.strip (Stdlib.String.map (fun ch ->
                  if ch = '"' || ch = '\'' then ' ' else ch
                ) v) |> String.strip
              ) in
             scan_deps ({ name = dep_name; github; version } :: acc) remaining
           | _ -> scan_deps acc rest)
    in

    (* Skip to dependencies: section *)
    let rec find_deps = function
      | [] -> []
      | line :: rest ->
        let trimmed = String.strip line in
        if String.is_prefix ~prefix:"dependencies:" trimmed then
          scan_deps [] rest
        else find_deps rest
    in

    Ok (find_deps lines)
  with Sys_error msg ->
    Error (`Msg (Printf.sprintf "Failed to read %s: %s" path msg))

(* ── gleam.toml parser ──────────────────────────────────────────────── *)

(** Parse gleam.toml [dependencies] section using the Toml library. *)
let parse_gleam_toml (path : string) : (hex_dep list, [> `Msg of string ]) Result.t =
  try
    let ic = Stdlib.open_in path in
    let len = Stdlib.in_channel_length ic in
    let buf = Bytes.create len in
    Stdlib.really_input ic buf 0 len;
    Stdlib.close_in ic;

    (* Extract [dependencies] section *)
    (* Parse [dependencies] section using line scanning.
       gleam.toml has a simple structure:
         [dependencies]
         gleam_http = { version = "~> 3.7" }
         mist = ">= 4.0.0"
    *)
    let ic = Stdlib.open_in path in
    let lines = ref [] in
    (try while true do
        let line = Stdlib.input_line ic in
        lines := line :: !lines
      done
    with End_of_file -> ());
    Stdlib.close_in ic;
    let lines = List.rev !lines in
    let rec scan_deps acc in_deps = function
      | [] -> List.rev acc
      | line :: rest ->
        let trimmed = String.strip line in
        if String.is_prefix ~prefix:"[" trimmed && not (String.is_prefix ~prefix:"[dependencies" trimmed) then
          if in_deps then List.rev acc  (* left [dependencies] section *)
          else scan_deps acc false rest
        else if String.is_prefix ~prefix:"[dependencies" trimmed then
          scan_deps acc true rest
        else if in_deps && trimmed <> "" && trimmed.[0] <> '#' then begin
          (* Parse: name = { version = "~> 3.7" } or name = ">= 4.0.0" *)
          match Stdlib.String.split_on_char '=' trimmed with
          | name_str :: version_parts ->
            let name = String.strip (Stdlib.String.concat "=" [name_str]) in
            let version_raw = String.strip (Stdlib.String.concat "=" version_parts) in
            let version =
              (* Extract version from { version = "~> 3.7" } format *)
              if String.length version_raw > 0 && version_raw.[0] = '{' then begin
                let inner = Stdlib.String.sub version_raw 1 (Stdlib.String.length version_raw - 2) in
                let parts = Stdlib.String.split_on_char '=' inner in
                match parts with
                | _ :: v_parts ->
                  let v = String.strip (Stdlib.String.concat "=" v_parts) in
                  Some (Stdlib.String.map (fun ch -> if ch = '"' || ch = '\'' then ' ' else ch) v |> String.strip)
                | [] -> None
              end
              (* Simple format: name = ">= 4.0.0" *)
              else
                Some (Stdlib.String.map (fun ch -> if ch = '"' || ch = '\'' then ' ' else ch) version_raw |> String.strip)
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

(* ── .nimble parser (INI-like subset) ────────────────────────────────

   Only `requires "…"` lines matter. Three accepted forms:
     requires "httpbeast"                      → bare name
     requires "httpbeast >= 1.0"               → name + version constraint
     requires "https://github.com/user/repo"   → dep name = repo name        *)

let parse_nimble_requires_value (raw : string) : shard_dep option =
  (* raw is the text inside the quotes *)
  let trimmed = String.strip raw in
  if trimmed = "" then None
  else if String.is_prefix ~prefix:"http" trimmed then begin
    (* URL form: last path segment is the repo, second-to-last the owner *)
    let segments =
      Stdlib.List.filter (fun s -> String.strip s <> "") (String.split ~on:'/' trimmed) in
    let rev = Stdlib.List.rev segments in
    let repo = match rev with
      | last :: _ -> String.strip last
      | [] -> ""
    in
    let owner = match rev with
      | _ :: o :: _ -> String.strip o
      | _ -> ""
    in
    if repo = "" then None
    else Some { name = repo; version = None;
                github = if owner = "" then None else Some (owner ^ "/" ^ repo) }
  end
  else
    (* bare name or "name >= 1.0" / "name#hash" *)
    match Stdlib.String.index_opt trimmed ' ' with
    | Some sp when sp > 0 ->
      let name = String.sub trimmed ~pos:0 ~len:sp in
      let version = String.strip (String.sub trimmed ~pos:(sp + 1)
                                    ~len:(String.length trimmed - sp - 1)) in
      Some { name; version = if version = "" then None else Some version; github = None }
    | _ -> Some { name = trimmed; version = None; github = None }

let parse_nimble (path : string) : (shard_dep list, [> `Msg of string ]) Result.t =
  try
    let ic = Stdlib.open_in path in
    let lines = ref [] in
    (try while true do
        let line = Stdlib.input_line ic in
        lines := line :: !lines
      done
    with End_of_file -> ());
    Stdlib.close_in ic;
    let lines = List.rev !lines in
    let deps = ref [] in
    List.iter ~f:(fun line ->
      let t = String.strip line in
      if String.is_prefix ~prefix:"requires" t then begin
        (* Extract every double-quoted string on this line *)
        let rec grab acc i =
          let len = String.length t in
          if i >= len then List.rev acc
          else if t.[i] = '"' then begin
            let rec find_close j =
              if j >= len then len
              else if t.[j] = '"' then j
              else find_close (j + 1)
            in
            let close = find_close (i + 1) in
            let inside = String.sub t ~pos:(i + 1) ~len:(close - i - 1) in
            grab (inside :: acc) (close + 1)
          end
          else grab acc (i + 1)
        in
        let quoted = grab [] 0 in
        List.iter ~f:(fun q ->
          match parse_nimble_requires_value q with
          | Some d -> deps := d :: !deps
          | None -> ()) quoted
      end)
      lines;
    Ok (List.rev !deps)
  with Sys_error msg ->
    Error (`Msg (Printf.sprintf "Failed to read %s: %s" path msg))

(* ── nimble.lock parser (JSON) ────────────────────────────────────────

   Structure: { "version": 2, "packages": { "name": { "name": …, "version": … } } }
   Exact locked versions; callers prefer these over .nimble constraints.   *)

let parse_nimble_lock (path : string) : (shard_dep list, [> `Msg of string ]) Result.t =
  try
    let json = Yojson.Safe.from_file path in
    let packages =
      match json with
      | `Assoc fields ->
        (match Stdlib.List.assoc_opt "packages" fields with
         | Some (`Assoc pkgs) -> pkgs
         | _ -> [])
      | _ -> []
    in
    let to_str v =
      match v with `String s -> s | _ -> "" in
    let deps = Stdlib.List.filter_map (fun (key, v) ->
      match v with
      | `Assoc fields ->
        let name =
          match Stdlib.List.assoc_opt "name" fields with
          | Some (`String s) when s <> "" -> s
          | _ -> key
        in
        let version =
          match Stdlib.List.assoc_opt "version" fields with
          | Some (`String s) -> Some s
          | _ -> None
        in
        if name = "" then None else Some { name; version; github = None }
      | _ -> None
    ) packages in
    Ok deps
  with
  | Sys_error msg -> Error (`Msg (Printf.sprintf "Failed to read %s: %s" path msg))
  | Yojson.Json_error msg -> Error (`Msg (Printf.sprintf "Invalid JSON in %s: %s" path msg))

(* ── Manifest auto-detection ────────────────────────────────────────── *)

let find_manifests (dir : string) : manifest list =
  let results = ref [] in
  let shard_path = Stdlib.Filename.concat dir "shard.yml" in
  if Stdlib.Sys.file_exists shard_path then begin
    match parse_shard_yml shard_path with
    | Ok deps -> results := Shard_yml (shard_path, deps) :: !results
    | Error _ -> ()
  end;
  let gleam_path = Stdlib.Filename.concat dir "gleam.toml" in
  if Stdlib.Sys.file_exists gleam_path then begin
    match parse_gleam_toml gleam_path with
    | Ok deps -> results := Gleam_toml (gleam_path, deps) :: !results
    | Error _ -> ()
  end;
  (* Nim: nimble.lock wins when both lock and .nimble exist (locked versions
     are exact); otherwise parse the .nimble requires lines. *)
  let lock_path = Stdlib.Filename.concat dir "nimble.lock" in
  let has_lock = Stdlib.Sys.file_exists lock_path in
  if has_lock then begin
    match parse_nimble_lock lock_path with
    | Ok deps -> results := Nimble_lock (lock_path, deps) :: !results
    | Error _ -> ()
  end
  else begin
    (* Discover *.nimble (choose the first alphabetically if several) *)
    let entries = (try Stdlib.Sys.readdir dir with Sys_error _ -> [||]) in
    let is_nimble_file (e : string) : bool =
      String.is_suffix e ~suffix:".nimble"
      && not (Stdlib.Sys.is_directory (Stdlib.Filename.concat dir e))
    in
    let nimble_files =
      Stdlib.Array.to_list entries
      |> Stdlib.List.filter is_nimble_file
      |> Stdlib.List.sort (fun (a : string) (b : string) -> Stdlib.compare a b)
    in
    (match nimble_files with
     | first :: _ ->
       let p = Stdlib.Filename.concat dir first in
       (match parse_nimble p with
        | Ok deps -> results := Nimble (p, deps) :: !results
        | Error _ -> ())
     | [] -> ())
  end;
  List.rev !results

let find_manifests_recursive (dir : string) : manifest list =
  (* Check target dir, then walk up looking for manifests *)
  let results = ref (find_manifests dir) in
  if !results = [] then begin
    let rec walk d =
      if d = Stdlib.Filename.dirname d then None
      else
        let parent = Stdlib.Filename.dirname d in
        let found = find_manifests parent in
        if found <> [] then Some found
        else walk parent
    in
    match walk dir with
    | Some ms -> results := ms
    | None -> ()
  end;
  !results
