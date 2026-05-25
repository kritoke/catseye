(* lib/catseye_crowsnest/dep_reachability.ml
   Map dependencies to import sites and determine reachability
   from entry points (Predator Vision integration).

   Phase 3 of the Crow's Nest: cross-references dependency usage
   with the call adjacency / reachability graph to answer "is this
   vulnerable dep actually reachable?" *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

(** StringSet for file sets. *)
module StringSet = Stdlib.Set.Make(Stdlib.String)

(** A dependency import site — where a dependency is used in the code. *)
type import_site = {
  file : string;
  line : int;
  dep_name : string;
}

(** Reachability verdict for a dependency. *)
type reachability = {
  dep_name : string;
  import_sites : import_site list;
  reachable_files : string list;  (* files that import this dep AND are reachable from entry points *)
  is_reachable : bool;
}

(** Extract require/import statements from source text.
    Returns (line_number, dependency_name) pairs.
    Filters out local requires (starting with . or /) and stdlib. *)
let extract_imports ?(lang : string = "crystal") (source : string)
    : (int * string) list =
  let lines = Stdlib.String.split_on_char '\n' source in
  let results = ref [] in
  List.iteri ~f:(fun i line ->
    let trimmed = String.strip line in
    if lang = "crystal" then begin
      (* Crystal: require "dep_name" *)
      let prefix = "require \"" in
      let plen = String.length prefix in
      if String.length trimmed >= plen &&
         Stdlib.String.sub trimmed 0 plen = prefix then begin
        let rest = Stdlib.String.sub trimmed plen (String.length trimmed - plen) in
        (* Extract the quoted string *)
        match Stdlib.String.index_opt rest '"' with
        | Some end_pos ->
          let dep = Stdlib.String.sub rest 0 end_pos in
          (* Skip local requires (./  ../) and stdlib *)
          if String.length dep > 0 && dep.[0] <> '.' && dep.[0] <> '/' then
            results := (i + 1, dep) :: !results
        | None -> ()
      end
    end
    else if lang = "gleam" then begin
      (* Gleam: import dep/module *)
      let prefix = "import " in
      let plen = String.length prefix in
      if String.length trimmed >= plen &&
         Stdlib.String.sub trimmed 0 plen = prefix then begin
        let rest = Stdlib.String.sub trimmed plen (String.length trimmed - plen) in
        (* Extract module name (first word) *)
        let dep = match Stdlib.String.split_on_char ' ' rest with
          | name :: _ -> name
          | [] -> ""
        in
        if dep <> "" then
          results := (i + 1, dep) :: !results
      end
    end
  ) lines;
  List.rev !results

(** Known Crystal stdlib modules — not from dependencies. *)
let crystal_stdlib = [
  "http"; "json"; "yaml"; "xml"; "csv"; "uri"; "openssl";
  "socket"; "thread"; "channel"; "mutex"; "log"; "file_utils";
  "digest"; "base64"; "time"; "io"; "process"; "system";
  "file"; "dir"; "path"; "env"; "signal"; "fiber";
  "compiler"; "regex"; "random"; "math"; "big"; "complex";
  "option_parser"; "exception"; "libc"; "llvm";
]

(** Known Gleam stdlib modules. *)
let gleam_stdlib = [
  "gleam"; "gleam/http"; "gleam/json"; "gleam/dynamic"; "gleam/bool";
  "gleam/float"; "gleam/int"; "gleam/list"; "gleam/map"; "gleam/option";
  "gleam/result"; "gleam/string"; "gleam/io"; "gleam/order"; "gleam/pair";
  "gleam/set"; "gleam/bit_string"; "gleam/uri"; "gleam/dict";
]

(** Check if a module name is from the stdlib. *)
let is_stdlib ?(lang : string = "crystal") (name : string) : bool =
  let stdlib = if lang = "crystal" then crystal_stdlib else gleam_stdlib in
  List.exists ~f:(fun s ->
    String.length name >= String.length s &&
    Stdlib.String.sub name 0 (String.length s) = s
  ) stdlib

(** Match a require/import name against a dependency name.
    Crystal deps match by prefix: require "athena" matches dep "athena"
    and also require "athena/routing" matches dep "athena".
    Gleam deps match by exact name or prefix. *)
let matches_dep ?(lang : string = "crystal") (dep_name : string) (import_name : string)
    : bool =
  if lang = "crystal" then
    (* Crystal: "athena" matches require "athena" or require "athena/routing" *)
    String.length import_name >= String.length dep_name &&
    Stdlib.String.sub import_name 0 (String.length dep_name) = dep_name
    && (String.length import_name = String.length dep_name
        || import_name.[String.length dep_name] = '/')
  else
    (* Gleam: exact match or prefix match *)
    import_name = dep_name ||
    (String.length import_name > String.length dep_name &&
     Stdlib.String.sub import_name 0 (String.length dep_name) = dep_name &&
     import_name.[String.length dep_name] = '/')

(** Scan source files for dependency imports.
    Returns a list of import sites grouped by dependency name. *)
let scan_imports (files : (string * string) list)  (* (path, lang) pairs *)
    (dep_names : string list)
    : (string * import_site list) list =
  let sites = Hashtbl.create (module String) ~size:16 in
  List.iter ~f:(fun (path, lang) ->
    try
      let ic = Stdlib.open_in path in
      let source = Stdlib.really_input_string ic (Stdlib.in_channel_length ic) in
      Stdlib.close_in ic;
      let imports = extract_imports ~lang source in
      List.iter ~f:(fun (line, import_name) ->
        if not (is_stdlib ~lang import_name) then
          List.iter ~f:(fun dep_name ->
            if matches_dep ~lang dep_name import_name then begin
              let site = { file = path; line; dep_name } in
              let existing = match Hashtbl.find sites dep_name with
                | None -> []
                | Some v -> v
              in
              Hashtbl.set sites ~key:dep_name ~data:(site :: existing)
            end
          ) dep_names
      ) imports
    with _ -> ()  (* skip unreadable files *)
  ) files;
  Hashtbl.fold sites ~init:[] ~f:(fun ~key:name ~data:sites acc ->
    (name, List.rev sites) :: acc)
  |> List.sort ~compare:(fun (a, _) (b, _) -> String.compare a b)

(** Determine reachability for each dependency.
    Uses the set of reachable files from Predator Vision to determine
    if a dependency's import sites are on an active code path.

    reachable_files: files reachable from entry points (from Predator Vision)
    dep_imports: dependency → import sites mapping (from scan_imports) *)
let compute_reachability (reachable_files : StringSet.t)
    (dep_imports : (string * import_site list) list)
    : reachability list =
  List.map ~f:(fun (dep_name, sites) ->
    let reachable = List.filter ~f:(fun s ->
      StringSet.mem s.file reachable_files
    ) sites in
    { dep_name;
      import_sites = sites;
      reachable_files = List.map ~f:(fun s -> s.file) reachable;
      is_reachable = reachable <> [];
    }
  ) dep_imports

(** Enrich dep_results with reachability information.
    For each dep_result, attach reachability data if available. *)
let enrich_with_reachability (dep_results : 'a list)
    ~(get_name : 'a -> string)
    (reachability : reachability list)
    : ('a * reachability option) list =
  let reach_map = Hashtbl.create (module String) ~size:16 in
  List.iter ~f:(fun r -> Hashtbl.set reach_map ~key:r.dep_name ~data:r) reachability;
  List.map ~f:(fun dr ->
    let name = get_name dr in
    (dr, Hashtbl.find reach_map name)
  ) dep_results
