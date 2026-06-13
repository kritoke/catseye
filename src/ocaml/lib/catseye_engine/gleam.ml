(* lib/catseye_engine/gleam.ml
   Gleam extractor — tree-sitter CLI → XML → Security Nodes *)

open Base
open Catseye_types
open Security_node

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

(* Use shared XML parser — types and utilities from Xml_parse *)
type xml = Xml_parse.xml =
  { tag : string
  ; attrs : (string * string) list
  ; children : xml list
  ; text : string }

let attr = Xml_parse.attr
let line_of = Xml_parse.line_of
let find = Xml_parse.find
let children_where = Xml_parse.children_where
let contains = Xml_parse.contains

(* ── Constants ──────────────────────────────────────────────────────── *)

let taint_sources =
  [ "params"; "request"; "req"; "get_body"; "query"; "io.get_line"
  ; "dynamic.unsafe_coerce"; "request.get_body"; "user_url"; "user_input"
  ; "url"; "path"; "cmd"; "command"; "input"; "env"
  ; "ARGV"; "STDIN"; "gets" ]



let skip_calls =
  Set.Poly.of_list
  [ "list.map"; "list.filter"; "list.each"; "list.any"; "list.fold"
  ; "list.append"; "list.length"; "list.reverse"
  ; "result.try"; "result.map"; "result.then"; "result.is_ok"
  ; "result.is_err"; "result.unwrap"
  ; "option.map"; "option.unwrap"; "option.is_some"
  ; "io.println"; "io.print"; "io.debug"
  ; "string.concat"; "string.join"; "string.slice"; "string.split"
  ; "string.starts_with"; "string.ends_with"; "string.contains"
  ; "string.replace"; "string.lowercase"; "string.uppercase"
  ; "int.to_string"; "int.parse"; "float.to_string"
  ; "dict.new"; "dict.insert"; "dict.get"; "dict.values"
  ; "tuple.first"; "tuple.second"
  (* Safe crypto: Erlang crypto module uses strong_rand_bytes *)
  ; "crypto.strong_rand_bytes"
  ; "crypto.rand_bytes"
  (* External function patterns (BIFs that are safe) *)
  ; "random_suffix"; "secure_random"
  ; "facet_pi_server_util.random_suffix" ]

(* ── Substring helper (from Xml_parse) ────────────────────────────── *)

(* contains is now inherited from Xml_parse *)

(* ── Arg extraction ────────────────────────────────────────────────── *)

let classify_arg node =
  match node.tag with
  | "string" ->
    let qcs = find node ~tag:"quoted_content" in
    let value = match qcs with [] -> "" | qc :: _ -> qc.text in
    { arg_type = ArgLiteral; value; field = "" }
  | "integer" | "float" ->
    { arg_type = ArgLiteral; value = node.text; field = "" }
  | "identifier" ->
    { arg_type = ArgVar; value = node.text; field = "" }
  | "field_access" ->
    let value =
      (List.map ~f:(fun p -> p.text) (find node ~tag:"identifier")
      @ List.map ~f:(fun l -> l.text) (find node ~tag:"label"))
      |> Stdlib.String.concat "." in
    { arg_type = ArgCall; value; field = "" }
  | _ ->
    { arg_type = ArgUnknown; value = node.tag; field = "" }

let extract_args call =
  match find call ~tag:"arguments" with
  | [] -> []
  | args_node :: _ ->
    List.concat_map ~f:(fun child ->
      if child.tag <> "argument" then []
      else List.filter_map ~f:(fun vc ->
        match vc.tag with
        | "string" | "integer" | "float" | "identifier"
        | "field_access" | "tuple" | "record" -> Some (classify_arg vc)
        | _ -> None
      ) child.children
    ) args_node.children

(* ── Call name (from direct children only) ─────────────────────────── *)

let call_name call =
  children_where call ~f:(fun c -> attr c "field" = "function")
  |> List.find_map ~f:(fun child ->
    match child.tag with
    | "identifier" -> Some child.text
    | "field_access" ->
      Some (List.map ~f:(fun p -> p.text) (find child ~tag:"identifier")
          @ List.map ~f:(fun l -> l.text) (find child ~tag:"label")
          |> Stdlib.String.concat ".")
    | "label" -> Some child.text
    | _ -> None)

(* ── Node extraction ───────────────────────────────────────────────── *)

let extract_nodes root path =
  (* Pass 1: function defs (with params as args) *)
  let defs = List.filter_map ~f:(fun fn ->
    let name_opt =
      children_where fn ~f:(fun c ->
        c.tag = "identifier" && attr c "field" = "name")
      |> List.find_map ~f:(fun c -> if c.text <> "" then Some c.text else None) in
    match name_opt with
    | None -> None
    | Some name ->
      (* Extract params from function_parameter children *)
      let params =
        List.concat_map ~f:(fun p ->
          children_where p ~f:(fun c ->
            c.tag = "identifier" && attr c "field" = "name")
          |> List.filter_map ~f:(fun c ->
            if c.text <> "" then Some
              { arg_type = ArgVar; value = c.text; field = "" }
            else None)
        ) (find fn ~tag:"function_parameter") in
      Some { node_type = Def; name; args = params
           ; line = line_of fn; taint = false; file = path; language = "gleam"; metadata = [] }
  ) (find root ~tag:"function") in

  (* Pass 2: let bindings — build taint table *)
  let tainted = Stdlib.Hashtbl.create 32 in
  let assigns = List.concat_map ~f:(fun tag ->
    List.filter_map ~f:(fun (lt : xml) ->
      (* Find the pattern identifier *)
      let target = children_where lt ~f:(fun c ->
        c.tag = "identifier" && attr c "field" = "pattern") in
      match target with
      | [] -> None
      | tgt :: _ ->
        let name = tgt.text in
        (* Find the value child *)
        let rhs = children_where lt ~f:(fun c -> attr c "field" = "value") in
        let rhs_arg, rhs_kind = match rhs with
          | [] -> ("", ArgUnknown)
          | vc :: _ ->
            (match vc.children with
             | [] -> ("", ArgUnknown)
             | first :: _ ->
               let a = classify_arg first in
               (a.value, a.arg_type))
        in
        (* Taint: check if the full let text references a source *)
        let taint =
          List.exists ~f:(contains ~sub:lt.text) taint_sources
          || Stdlib.Hashtbl.fold (fun v _ acc ->
               acc || contains ~sub:v lt.text) tainted false in
        if taint then Stdlib.Hashtbl.replace tainted name true;
        let args = if rhs_arg <> "" then [{ arg_type = rhs_kind; value = rhs_arg; field = "" }] else [] in
        Some { node_type = Assign; name; args; line = line_of lt; taint; file = path; language = "gleam"; metadata = [] }
    ) (find root ~tag)
  ) ["let"; "let_assert"] in

  (* Pass 3: function calls *)
  let calls = List.filter_map ~f:(fun call ->
    match call_name call with
    | None | Some "fn" -> None
    | Some name when Set.Poly.mem skip_calls name -> None
    | Some name ->
      let args = extract_args call in
      let taint = List.exists ~f:(fun a ->
        (a.arg_type = ArgVar &&
         (List.mem taint_sources ~equal:Stdlib.String.equal a.value || Stdlib.Hashtbl.mem tainted a.value))
        || (a.arg_type = ArgCall && contains ~sub:"<interpolation>" a.value)
      ) args in
      Some { node_type = Call; name; args; line = line_of call; taint; file = path; language = "gleam"; metadata = [] }
  ) (find root ~tag:"function_call") in

  List.sort ~compare:(fun a b -> Int.compare a.line b.line) (defs @ assigns @ calls)

(* ── Public interface ──────────────────────────────────────────────── *)

let grammar_path () =
  (* Try env var first, then auto-discover *)
  let env_result = match Stdlib.Sys.getenv "TREE_SITTER_GLEAM_GRAMMAR" with
    | exception Stdlib.Not_found -> None
    | path -> Some path
  in
  match env_result with
  | Some path -> Ok path
  | None ->
    (* Auto-discover: check user tree-sitter directory first (has WASM/so parsers) *)
    let home = try Stdlib.Sys.getenv "HOME" with Stdlib.Not_found -> "" in
    let so_path = Stdlib.Filename.concat home ".tree-sitter/gleam.so" in
    if Stdlib.Sys.file_exists so_path then Ok so_path
    else begin
      (* Fall back to nix store - use maxdepth 3 to find parsers in subdirs *)
      (* SECURITY: Hardcode 'gleam' pattern in grep - no user input flows here *)
      let discovered = try
        let cmd = "find /nix/store -maxdepth 3 -name parser -type f -executable 2>/dev/null | grep -i 'tree-sitter-gleam' | head -1" in
        let ic = Unix.open_process_in cmd in
        let line = try Some (Stdlib.input_line ic) with Stdlib.End_of_file -> None in
        let _ = Unix.close_process_in ic in
        (match line with
         | Some p when Stdlib.Sys.file_exists p -> Some p
         | _ -> None)
      with _ -> None in
      (match discovered with
       | Some p -> Ok p
       | None ->
         let common = [
           "/usr/lib/tree-sitter-gleam/parser";
           "/usr/local/lib/tree-sitter-gleam/parser";
         ] in
         (match Stdlib.List.find_opt (fun p -> Stdlib.Sys.file_exists p) common with
          | Some p -> Ok p
          | None -> Error (`Msg "Gleam tree-sitter grammar not found. Set TREE_SITTER_GLEAM_GRAMMAR or install tree-sitter-gleam.")))
    end

let extract file_path =
  match grammar_path () with
  | Error e -> Error e
  | Ok grammar ->
  (* grammar is the path to the .so parser file, or the parser directory in nix *)
  (* Pass grammar directly for .so files, dirname for nix store parser dirs *)
  let lib_path = if Stdlib.Filename.check_suffix grammar ".so" then grammar
    else Stdlib.Filename.dirname grammar in
  (* SECURITY: Use quoted arguments with Sys.command to avoid shell injection *)
  let lib_path_escaped = Stdlib.Filename.quote lib_path in
  let file_path_escaped = Stdlib.Filename.quote file_path in
  (* Write tree-sitter XML output to a temp file to capture it *)
  let tmp_file, tmp_oc = Stdlib.Filename.open_temp_file ~perms:0o600 "catseye-gleam-" ".xml" in
  Stdlib.output_string tmp_oc "";  (* just create the file *)
  Stdlib.close_out tmp_oc;
  let cmd = Stdlib.Printf.sprintf "tree-sitter parse --lib-path %s --lang-name gleam -x %s > %s 2>/dev/null"
    lib_path_escaped file_path_escaped (Stdlib.Filename.quote tmp_file) in
  let exit_code = Stdlib.Sys.command cmd in
  let ok = match exit_code with
    | 0 -> true
    | 1 -> true  (* tree-sitter returns 1 for partial parse errors but still emits XML *)
    | _ -> false in
  if not ok then begin
    Stdlib.Sys.remove tmp_file;
    Error (`Msg (Stdlib.Printf.sprintf "tree-sitter failed for %s" file_path))
  end else begin
    let ic = Stdlib.open_in tmp_file in
    let len = Stdlib.in_channel_length ic in
    let content = Stdlib.Bytes.create len in
    Stdlib.really_input ic content 0 len;
    Stdlib.close_in ic;
    Stdlib.Sys.remove tmp_file;
    let doc = Xml_parse.parse_to_list (Stdlib.Bytes.to_string content) in
    (* Find source_file by recursive descent *)
    let rec find_sf = function
      | [] -> []
      | n :: rest ->
        (if n.tag = "source_file" then [n] else find_sf n.children)
        @ find_sf rest in
    match find_sf doc with
    | [] -> Ok []
    | root :: _ -> Ok (extract_nodes root file_path)
  end

let language = "gleam"
let extensions = [".gleam"]
