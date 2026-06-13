(* lib/catseye_engine/crystal_ts.ml
   Crystal extractor — tree-sitter CLI → XML → Security Nodes *)

open Base

open Catseye_types
open Security_node

(* Shadow string equality operators (Base makes these return bool, but OCaml comparisons return int) *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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
  [ "params"; "request"; "env"; "ARGV"; "STDIN"; "query"; "url"
  ; "user_input"; "user_url"; "path"; "cmd"; "command"; "input" ]

let sensitive_names =
  [ "secret"; "token"; "password"; "passwd"; "api_key"; "credential"
  ; "private_key"; "auth"; "session" ]

let chmod_calls = ["chmod"; "chown"; "chgrp"]

let non_atomic_calls = ["chmod"; "chown"; "chgrp"; "rename"; "unlink"; "close"]

let unbounded_reads = ["read"; "read?"; "read_byte"; "read_remaining"; "gets"]

let skip_calls_list =
  [ "puts"; "print"; "debug"; "to_s"; "to_i"; "to_f"; "to_i16"; "to_i32"
  ; "not_nil!"; "nil?"; "some?"; "is_a?"; "responds_to?"; "class"
  ; "each"; "map"; "filter"; "any?"; "all?"; "each_with_index"
  ; "keys"; "values"; "size"; "empty?"; "first"; "last"
  ; "join"; "split"; "strip"; "downcase"; "upcase"; "capitalize"
  ; "gsub"; "sub"; "reverse"; "length"; "includes?"; "starts_with?"; "ends_with?"
  ; "String.build"; "String.build {"
  ; "Array.new"; "Hash.new"; "Tuple.new"
  ; "raise"; "exit"; "abort"
  ; "File.open"; "File.join"; "File.dirname"; "File.basename"; "File.extname"
  ; "Path.new"; "Path.posix"; "Path.windows"
  ; "URI.parse"; "URI.encode"; "URI.decode"
  ; "JSON.parse"; "JSON.build"; "JSON.mapping"
  ; "Random::Secure.random_bytes"
  ; "Time.now"; "Time..utc"
  ; "Pointer.malloc"; "Pointer.new"
  ; "Slice.new"; "Bytes.new"
  ]



let skip_set = Set.Poly.of_list skip_calls_list

(* ── Crystal-specific XML helpers ───────────────────────────────────── *)

let is_method_call (n : xml) : bool =
  n.tag = "call" || n.tag = "index_call" || n.tag = "field_call"

let is_method_def (n : xml) : bool =
  n.tag = "method_def"

(* module_def and class_def are container definitions, not leaf definitions for security scanning *)

let is_macro (n : xml) : bool =
  n.tag = "macro_if" || n.tag = "macro_unless" || n.tag = "macro_for"

(** Deep collect all descendants matching [tag], skipping macros. *)
let rec find_skipping_macros (n : xml) ~tag : xml list =
  if is_macro n then []
  else if n.tag = tag then [n]
  else List.concat_map ~f:(find_skipping_macros ~tag) n.children

(** Find method calls *)
let rec find_calls (n : xml) : xml list =
  if is_macro n then []
  else if is_method_call n then
    n :: List.concat_map ~f:find_calls n.children
  else List.concat_map ~f:find_calls n.children

(** Find top-level definitions *)
let rec find_defs (n : xml) : xml list =
  if is_macro n then []
  else if is_method_def n then
    n :: List.concat_map ~f:find_defs n.children
  else List.concat_map ~f:find_defs n.children

(** Get named child tag *)
let get_child (n : xml) ~(tag : string) : xml option =
  List.find_map n.children ~f:(fun c -> if c.tag = tag then Some c else None)

(** Get direct text content of a node (not recursively) *)
let direct_text (n : xml) : string = n.text

(** Strip XML attributes from text - removes tags and attributes that may be included *)
let strip_xml_attrs (text : string) : string =
  let remove_attrs s =
    match Stdlib.String.index_opt s '>' with
    | Some idx -> Stdlib.String.sub s (idx + 1) (Stdlib.String.length s - idx - 1)
    | None -> s
  in
  let text = remove_attrs text in
  let text = Stdlib.String.trim text in
  let text = if String.length text > 0 && text.[0] = '<' then "" else text in
  text

(** Get direct text content of a node *)
let get_text (n : xml) : string =
  if n.text <> "" then
    strip_xml_attrs n.text
  else begin
    let acc = ref [] in
    let rec gather x =
      (if x.text <> "" then acc := x.text :: !acc);
      List.iter x.children ~f:gather
    in
    gather n;
    Stdlib.String.concat "" (List.rev !acc)
  end

(** Extract method name from call node *)
(* Look for <identifier field="method"> or <operator field="method"> inside call *)
let call_name (call : xml) : string option =
  let rec find_in_children children =
    match children with
    | [] -> None
    | c :: rest ->
      (match c.tag with
       | "identifier" | "operator" ->
         if attr c "field" = "method" then Some (get_text c) else find_in_children rest
       | _ -> find_in_children (c.children @ rest))
  in
  find_in_children call.children

let receiver_name (call : xml) : string option =
  (* Search recursively for <constant field="receiver"> or similar *)
  let rec find_in_children children =
    match children with
    | [] -> None
    | c :: rest ->
      (match c.tag with
       | "constant" | "identifier" ->
         if attr c "field" = "receiver" then Some (get_text c) else find_in_children rest
       | _ -> find_in_children (c.children @ rest))
  in
  find_in_children call.children

(** Full qualified call name for calls like File.read *)
let full_call_name (call : xml) : string =
  match (receiver_name call, call_name call) with
  | (Some obj, Some meth) -> obj ^ "." ^ meth
  | (None, Some meth) -> meth
  | _ -> ""

(* ── XML parsing (delegates to shared module) ─────────────────────── *)

let parse_xml = Xml_parse.parse_to_root

(* ── Argument extraction ────────────────────────────────────────────── *)

let extract_literal (n : xml) : string =
  match get_child n ~tag:"literal_content" with
  | Some lc -> lc.text
  | None ->
    match get_child n ~tag:"symbol" with
    | Some sym -> ":" ^ (get_text sym)
    | None -> get_text n

let extract_arg (a : xml) : arg =
  let field = attr a "field" in
  let value = extract_literal a in
  let arg_type : arg_type =
    if a.tag = "identifier" || a.tag = "constant" then ArgVar
    else if a.tag = "call" then ArgCall
    else if a.tag = "string" || a.tag = "symbol" || a.tag = "integer" || a.tag = "float" then ArgLiteral
    else ArgUnknown
  in
  { arg_type; value; field }

let extract_args (call : xml) : arg list =
  match get_child call ~tag:"argument_list" with
  | Some args ->
    let kids = children_where args ~f:(fun c ->
      c.tag <> "empty_list" && c.tag <> "(" && c.tag <> ")" && c.tag <> ",") in
    List.map kids ~f:extract_arg
  | None -> []

(* ── Security detection ──────────────────────────────────────────────── *)

let extract_calls_in_def (def : xml) : t list =
  let calls = find_calls def in
  List.filter_map calls ~f:(fun call ->
    let name = full_call_name call in
    let line = line_of call in
    if name = "" || Set.Poly.mem skip_set name then None
    else if List.exists chmod_calls ~f:(fun c -> name = c || name = "File." ^ c) then
      Some { node_type = IgnoredReturn; name; args = extract_args call;
             line; taint = false; file = ""; language = "crystal"; metadata = [] }
    else if List.exists non_atomic_calls ~f:(fun c -> name = c || name = "File." ^ c || name = "Dir." ^ c || name = "IO." ^ c) then
      Some { node_type = NonAtomicFileOp; name; args = extract_args call;
             line; taint = false; file = ""; language = "crystal"; metadata = [] }
    else if List.exists unbounded_reads ~f:(fun c -> name = c || name = "File." ^ c || name = "IO." ^ c) then
      Some { node_type = UnboundedRead; name; args = extract_args call;
             line; taint = false; file = ""; language = "crystal"; metadata = [] }
    else None
  )

let extract_defs (root : xml) : t list =
  let defs = find_defs root in
  List.concat_map defs ~f:extract_calls_in_def

(** TOCTOU: exists? -> read/write pattern *)
let detect_toctou (root : xml) : t list =
  let calls = find_skipping_macros root ~tag:"call" in
  let rec find_exists_path nodes : t list =
    match nodes with
    | [] -> []
    | call :: rest ->
      (match call_name call with
       | Some "exists?" | Some "exists" | Some "file?" | Some "directory?" ->
         let path_arg = 
    let args = extract_args call in
    if args = [] then {arg_type=ArgUnknown; value=""; field=""}
    else Stdlib.List.hd args
  in
let later_calls = List.filter calls ~f:(fun c ->
            let cl = line_of c in
            cl > (line_of call) && cl < (line_of call) + 10 &&
            List.exists ["read"; "open"; "write"; "delete"; "remove"] ~f:(fun m -> contains ~sub:m (full_call_name c))
          ) in
         if later_calls <> [] && path_arg.value <> "" then
           { node_type = TOCTOU;
name = "exists -> " ^ 
               (match later_calls with first :: _ -> full_call_name first | [] -> "");
              args = [{arg_type = ArgVar; value = path_arg.value; field = ""}];
              line = line_of call; taint = false; file = ""; language = "crystal"; metadata = [] }
            :: find_exists_path rest
         else find_exists_path rest
       | _ -> find_exists_path rest)
  in
  find_exists_path calls

(* ── Grammar discovery ──────────────────────────────────────────────── *)

let grammar_path () =
  let env_result = try Some (Stdlib.Sys.getenv "TREE_SITTER_CRYSTAL_GRAMMAR") with Stdlib.Not_found -> None in
  match env_result with
  | Some path -> Ok path
  | None ->
    (* Check user tree-sitter directory first *)
    let home = try Stdlib.Sys.getenv "HOME" with Stdlib.Not_found -> "" in
    let user_path = Stdlib.Filename.concat home ".tree-sitter/crystal/parser.so" in
    if Stdlib.Sys.file_exists user_path then Ok user_path
    else
      (* Check nix store *)
      let discovered = try
        let cmd = "find /nix/store -maxdepth 4 -name 'parser.so' 2>/dev/null | grep 'tree-sitter-crystal' | head -1" in
        let ic = Unix.open_process_in cmd in
        let line = try Some (Stdlib.input_line ic) with Stdlib.End_of_file -> None in
        (try ignore (Unix.close_process_in ic) with _ -> ());
        line
      with _ -> None
      in
      match discovered with
      | Some path when Stdlib.Sys.file_exists path -> Ok path
      | _ -> Error (`Msg "Crystal tree-sitter grammar not found. Set TREE_SITTER_CRYSTAL_GRAMMAR or install tree-sitter-crystal.")

let parse_xml_file (path : string) : xml =
  let lib_path = match grammar_path () with
    | Ok p -> p
    | Error (`Msg e) -> failwith ("Grammar error: " ^ e)
  in
  let cmd = Stdlib.Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name crystal -x '%s'" lib_path path in
  let ic = Unix.open_process_in cmd in
  let buf = Stdlib.Buffer.create 32768 in
  (try while true do Stdlib.Buffer.add_channel buf ic 4096 done with Stdlib.End_of_file -> ());
  let status = Unix.close_process_in ic in
  match status with
  | Unix.WEXITED 0 | Unix.WEXITED 1 ->
    let xml_str = Stdlib.Buffer.contents buf in
    if String.length xml_str = 0 then
      failwith ("Empty XML output from tree-sitter for " ^ path)
    else
      (try parse_xml xml_str with e ->
        failwith ("Failed to parse XML: " ^ Stdlib.Printexc.to_string e))
  | _ ->
    let err = Stdlib.Buffer.contents buf in
    failwith ("tree-sitter parse failed for " ^ path ^ ": " ^ err)

(* ── Public interface ──────────────────────────────────────────────── *)

let extract ~(path : string) : t list =
  let root = parse_xml_file path in
  let defs = extract_defs root in
  let toctou_finds = detect_toctou root in
  List.sort (defs @ toctou_finds) ~compare:(fun a b -> Int.compare a.line b.line)
