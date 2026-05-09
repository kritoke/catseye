(* lib/catseye_cli/discovery.ml *)

open Config

type source_file = {
  path : string;
  lang : string;
  is_dependency : bool;
  dependency_name : string;
}

let is_lib_path (path : string) : bool =
  let len = String.length path in
  let rec check i =
    if i + 4 >= len then false
    else if path.[i] = '/' && path.[i+1] = 'l' && path.[i+2] = 'i'
            && path.[i+3] = 'b' && path.[i+4] = '/'
    then true
    else check (i + 1)
  in
  check 0

let extract_dep_name (path : string) : string =
  let len = String.length path in
  let rec find_lib i =
    if i + 4 >= len then ""
    else if path.[i] = '/' && path.[i+1] = 'l' && path.[i+2] = 'i'
            && path.[i+3] = 'b' && path.[i+4] = '/'
    then begin
      let rest = String.sub path (i + 5) (len - i - 5) in
      match String.index_opt rest '/' with
      | Some idx -> String.sub rest 0 idx
      | None -> rest
    end
    else find_lib (i + 1)
  in
  find_lib 0

let discover_sources (dir : string) (filter : lang_filter) : source_file list =
  let results = ref [] in
  let rec walk path =
    if Sys.is_directory path then begin
      let entries = Sys.readdir path in
      Array.iter (fun entry ->
        let full = Filename.concat path entry in
        walk full
      ) entries
    end else begin
      let is_lib = is_lib_path path in
      let dep_name = if is_lib then extract_dep_name path else "" in
      if Filename.check_suffix path ".cr" && filter <> Gleam then
        results := { path; lang = "crystal"; is_dependency = is_lib; dependency_name = dep_name } :: !results
      else if Filename.check_suffix path ".gleam" && filter <> Crystal then
        results := { path; lang = "gleam"; is_dependency = false; dependency_name = "" } :: !results
    end
  in
  walk dir;
  List.sort (fun a b -> String.compare a.path b.path) !results
