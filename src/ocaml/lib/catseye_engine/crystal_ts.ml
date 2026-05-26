(* lib/catseye_engine/crystal_ts.ml
   Crystal extractor — tree-sitter CLI → XML → Security Nodes *)

open Base

open Catseye_types
open Security_node

(* Shadow string equality operators (Base makes these return bool, but OCaml comparisons return int) *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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

module String_set = Stdlib.Set.Make(String)

let skip_set = String_set.of_list skip_calls_list

(* ── Substring helper ──────────────────────────────────────────────── *)

let contains ~sub s =
  let sublen = String.length sub in
  let slen = String.length s in
  sublen > 0 &&
  let rec loop i =
    i + sublen <= slen &&
    (Stdlib.String.sub s i sublen = sub || loop (i + 1))
  in
  loop 0

(* ── XML tree ──────────────────────────────────────────────────────── *)

type xml =
  { tag : string
  ; attrs : (string * string) list
  ; children : xml list
  ; text : string }

let assoc' k alist =
  match List.find alist ~f:(fun (k',_) -> k' = k) with
  | Some (_, v) -> v
  | None -> raise Stdlib.Not_found

let attr (n : xml) (k : string) : string =
  try assoc' k n.attrs with Stdlib.Not_found -> ""

let line_of (n : xml) : int =
  match attr n "srow" with
  | "" -> 0
  | s -> (try Int.of_string s + 1 with _ -> 0)

let is_method_call (n : xml) : bool =
  n.tag = "call" || n.tag = "index_call" || n.tag = "field_call"

let is_method_def (n : xml) : bool =
  n.tag = "method_def"

(* module_def and class_def are container definitions, not leaf definitions for security scanning *)

let is_macro (n : xml) : bool =
  n.tag = "macro_if" || n.tag = "macro_unless" || n.tag = "macro_for"

(** Deep collect all descendants matching [tag]. *)
let rec find (n : xml) ~tag : xml list =
  if is_macro n then []
  else if n.tag = tag then [n]
  else List.concat_map ~f:(find ~tag) n.children

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

(** Collect direct children *)
let children_where (n : xml) ~f : xml list =
  List.filter n.children ~f:f

(** Get named child tag *)
let get_child (n : xml) ~(tag : string) : xml option =
  List.find_map n.children ~f:(fun c -> if c.tag = tag then Some c else None)

(** Get direct text content of a node (not recursively) *)
let direct_text (n : xml) : string = n.text

(** Strip XML attributes from text - removes tags and attributes that may be included *)
let strip_xml_attrs (text : string) : string =
  (* Remove any content that looks like XML attributes at start of text *)
  let remove_attrs s =
    match Stdlib.String.index_opt s '>' with
    | Some idx -> Stdlib.String.sub s (idx + 1) (Stdlib.String.length s - idx - 1)
    | None -> s
  in
  let text = remove_attrs text in
  let text = Stdlib.String.trim text in
  (* Remove any leading XML-like content *)
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

(* ── Tokenizer ─────────────────────────────────────────────────────── *)

type tok = Open of string * (string * string) list | Close of string | Text of string

let is_ws c = c = ' ' || c = '\t' || c = '\n' || c = '\r'

let skip_until s pos pred =
  let len = String.length s in
  let rec go i = if i < len && not (pred s.[i]) then go (i + 1) else i in
  let stop = go pos in
  (Stdlib.String.sub s pos (stop - pos), stop)

let parse_attrs s =
  let rec go i acc =
    let len = String.length s in
    let i = let rec skip j =
      if j < len && is_ws s.[j] then skip (j + 1) else j in skip i in
    if i >= len || s.[i] = '/' || s.[i] = '>' then List.rev acc
    else
      let (name, i) = skip_until s i (fun c -> c = '=' || is_ws c || c = '>' || c = '/') in
      if name = "" then go i acc
      else
        let i = let rec find_eq j =
          if j < len && s.[j] <> '=' then find_eq (j + 1) else j in find_eq i in
        if i >= len || s.[i] <> '=' then go i acc
        else
          let i = let rec skip_ws j =
            if j < len && is_ws s.[j] then skip_ws (j + 1) else j in skip_ws (i + 1) in
          if i < len && s.[i] = '"' then
            let (value, i) = skip_until s (i + 1) (fun c -> c = '"') in
            go (i + 1) ((name, value) :: acc)
          else go i acc
  in
  go 0 []

let tokenize s =
  let len = String.length s in
  let rec go pos acc =
    if pos >= len then List.rev acc  (* Reverse to get document order *)
    else if s.[pos] <> '<' then begin
      let (txt, next) = skip_until s pos (fun c -> c = '<') in
      let trimmed = Stdlib.String.trim txt in
      if trimmed = "" then go next acc
      else go next (Text trimmed :: acc)
    end else if pos + 1 < len && s.[pos + 1] = '?' then begin
      let (_, next) = skip_until s pos (fun c -> c = '>') in
      go (next + 1) acc
    end else if pos + 1 < len && s.[pos + 1] = '/' then begin
      let (name, next) = skip_until s (pos + 2) (fun c -> c = '>') in
      go (next + 1) (Close (Stdlib.String.trim name) :: acc)
    end else if pos + 3 < len && s.[pos + 1] = '!' && s.[pos + 2] = '-' && s.[pos + 3] = '-' then begin
      let (_, next) = skip_until s (pos + 4) (fun c -> c = '>') in
      go (next + 1) acc
    end else begin
      let (name_rest, next) = skip_until s (pos + 1) (fun c -> c = '>' || is_ws c) in
      let rest = if next < len && s.[next] = '>' then "" else
        let (r, _) = skip_until s next (fun c -> c = '>') in r in
      let attrs = parse_attrs rest in
      (* Check for self-closing tag *)
      let tag_name = Stdlib.String.trim name_rest in
      let is_self_closing = tag_name <> "" && tag_name.[String.length tag_name - 1] = '/' in
      let tag_name = if is_self_closing then Stdlib.String.sub tag_name 0 (Stdlib.String.length tag_name - 1) else tag_name in
      go (next + 1) (Open (tag_name, attrs) :: acc)
    end
  in
  go 0 []

(** Build XML tree from tokens *)
let of_tokens (tokens : tok list) : xml =
  let rec build (stack : xml list) (toks : tok list) : xml =
    match toks with
    | [] ->
      (match stack with
       | [] -> { tag = ""; attrs = []; children = []; text = "" }
       | [x] -> x
       | _ -> failwith ("Unclosed tags: " ^ Stdlib.String.concat "," (List.map ~f:(fun n -> n.tag) stack)))
    | Text txt :: rest ->
      (match stack with
       | [] -> build [] rest  (* Text outside root - skip *)
       | parent :: par ->
         let updated = { parent with text = parent.text ^ txt } in
         build (updated :: par) rest)
    | Open (tag, attrs) :: rest ->
      let node = { tag; attrs; children = []; text = "" } in
      build (node :: stack) rest
    | Close tag :: rest ->
      (match stack with
       | [] -> failwith ("Unexpected close tag: " ^ tag)
       | node :: par ->
         if node.tag <> tag then
           (* Skip intermediate nodes to find the matching tag *)
           let rec pop_until found stack' =
             match stack' with
             | [] -> failwith ("Could not find matching open tag for " ^ tag)
             | n :: rest' when n.tag = tag ->
               (* Found it - build the rest of the tree *)
               let closed = { n with children = List.rev n.children } in
               (match rest' with
                | [] -> closed  (* This is the root *)
                | parent :: parpar ->
                  let updated = { parent with children = closed :: parent.children } in
                  build (updated :: parpar) rest)
             | n :: rest' ->
               (* This is an intermediate unclosed node - close it and continue *)
               let closed_intermediate = { n with children = List.rev n.children } in
               (match rest' with
                | [] -> failwith ("Unmatched intermediate tags")
                | parent :: parpar ->
                  let updated = { parent with children = closed_intermediate :: parent.children } in
                  pop_until found (updated :: parpar))
           in
           pop_until false stack
         else
           let closed = { node with children = List.rev node.children } in
           (match par with
            | [] -> closed  (* This is the root *)
            | parent :: parpar ->
              let updated = { parent with children = closed :: parent.children } in
              build (updated :: parpar) rest))
  in
  match tokens with
  | [] -> { tag = ""; attrs = []; children = []; text = "" }
  | _ ->
    let root = build [] tokens in
    (* Handle tree-sitter wrapper: if root is "sources", return its first child *)
    if root.tag = "sources" && root.children <> [] then
      Stdlib.List.hd root.children
    else if root.tag = "" then
      failwith "Empty XML"
    else
      root

let parse_xml (s : string) : xml =
  let tokens = tokenize s in
  of_tokens tokens

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
    if name = "" || String_set.mem name skip_set then None
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
  let calls = find root ~tag:"call" in
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
