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

let starts_with str prefix =
  let plen = String.length prefix in
  let slen = String.length str in
  plen <= slen && String.sub str 0 plen = prefix

let strip str =
  let len = String.length str in
  let rec find_start i =
    if i >= len || str.[i] <> ' ' && str.[i] <> '\t' then i
    else find_start (i + 1)
  in
  let start = find_start 0 in
  String.sub str start (len - start)

let leading_spaces str =
  let len = String.length str in
  let rec count i =
    if i >= len || str.[i] <> ' ' then i
    else count (i + 1)
  in
  count 0

let parse_shard_yml (dir : string) : (string * string list) =
  let shard_path = Filename.concat dir "shard.yml" in
  if not (Sys.file_exists shard_path) then ("", [])
  else begin
    try
      let ic = open_in shard_path in
      let len = in_channel_length ic in
      let content = really_input_string ic (min 50000 len) in
      close_in ic;
      let lines = String.split_on_char '\n' content in
      let project_name = ref "" in
      let deps = ref [] in
      let in_deps = ref false in
      let current_dep = ref "" in
      let dep_indent = ref 0 in
      
      List.iter (fun line ->
        let trimmed = strip line in
        let indent = leading_spaces line in
        
        if starts_with trimmed "name: " then
          project_name := strip (String.sub trimmed 5 (String.length trimmed - 5))
        else if trimmed = "dependencies:" then 
          in_deps := true
        else if trimmed <> "" && indent = 0 then
          in_deps := false
        else if !in_deps && indent = 2 && not (starts_with trimmed "github:") 
             && not (starts_with trimmed "version:") && not (starts_with trimmed "branch:")
             && trimmed <> "" then
          (current_dep := trimmed; dep_indent := indent)
        else if !in_deps && !current_dep <> "" && indent > !dep_indent then
          if starts_with trimmed "github:" || starts_with trimmed "hex:" then
            let name = strip (if starts_with trimmed "github:" 
                              then String.sub trimmed 7 (String.length trimmed - 7)
                              else String.sub trimmed 4 (String.length trimmed - 4)) in
            if String.length name > 0 then
              let dep_name = match String.index_opt name '/' with
                | Some idx -> String.sub name (idx + 1) (String.length name - idx - 1)
                | None -> name
              in
              deps := dep_name :: !deps
      ) lines;
      
      (!project_name, !deps)
    with _ -> ("", [])
  end

let discover_sources ?(include_deps=false) ?(lang_filter=All) ?(extensions=[".cr"; ".gleam"; ".js"; ".jsx"; ".mjs"; ".cjs"; ".ts"; ".tsx"; ".svelte"; ".ml"; ".rs"]) (dir : string) (exclude : string list) : source_file list =
  (* Check if this is a Crystal project with shard.yml *)
  let has_shard = Sys.file_exists (Filename.concat dir "shard.yml") in
  let shard_deps = 
    if include_deps || not has_shard then []
    else begin
      match parse_shard_yml dir with
      | _, [] -> []
      | project_name, dep_names ->
        if project_name <> "" then project_name :: dep_names else dep_names
    end
  in
  
  let results = ref [] in
  let should_skip entry =
    List.mem entry exclude
    || (String.length entry > 0 && entry.[0] = '.')
  in
  
  let is_shard_dep path =
    List.exists (fun dep ->
      let lib_dep_path = Filename.concat "lib" dep in
      starts_with path (lib_dep_path ^ "/")
    ) shard_deps
  in
  
  let rec walk path =
    try
    if Sys.is_directory path then begin
      (* For Crystal projects with shard.yml, skip entire lib/ directory *)
      if has_shard && not include_deps then begin
        let last_char_pos = String.length path - 1 in
        if last_char_pos >= 3 && path.[last_char_pos-3] = '/'
                                && path.[last_char_pos-2] = 'l'
                                && path.[last_char_pos-1] = 'i'
                                && path.[last_char_pos] = 'b' then ()
        else begin
          let entries = try Sys.readdir path with Sys_error _ -> [||] in
          Array.iter (fun entry ->
            if not (should_skip entry) then begin
              let full = Filename.concat path entry in
              (* Skip .svelte.ts files - Svelte 5 runes confuse JS parser *)
              if Filename.check_suffix full ".svelte.ts" then ()
              else walk full
            end
          ) entries
        end
      end else begin
        let entries = try Sys.readdir path with Sys_error _ -> [||] in
        Array.iter (fun entry ->
          if not (should_skip entry) then begin
            let full = Filename.concat path entry in
            (* Skip .svelte.ts files - Svelte 5 runes confuse JS parser *)
            if Filename.check_suffix full ".svelte.ts" then ()
            else walk full
          end
        ) entries
      end
    end else begin
      if not include_deps && has_shard && is_shard_dep path then ()
      else begin
        let is_lib = has_shard && is_lib_path path in
        let dep_name = if is_lib then extract_dep_name path else "" in
        (* Match against configured extensions *)
        let matched_ext = List.find_opt (fun ext -> Filename.check_suffix path ext) extensions in
        match matched_ext with
        | None -> ()  (* Not a recognized source file *)
        | Some ext ->
          (* Determine language from extension *)
          let lang_name = match ext with
            | ".cr" -> "crystal"
            | ".gleam" -> "gleam"
            | ".ts" | ".tsx" -> "typescript"
            | ".js" | ".jsx" | ".mjs" | ".cjs" -> "javascript"
            | ".svelte" -> "svelte"
            | ".ml" | ".mli" -> "ocaml"
            | ".rs" -> "rust"
            | _ -> "unknown"
          in
          (* Apply lang_filter *)
          let include_file = match lang_filter with
            | All -> true
            | Only langs -> List.mem lang_name langs
          in
          if include_file then
            results := { path; lang = lang_name; is_dependency = is_lib && not (List.mem path shard_deps); dependency_name = dep_name } :: !results
      end
    end
    with Sys_error _ -> ()
  in
  walk dir;
  List.sort (fun a b -> String.compare a.path b.path) !results
