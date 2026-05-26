(* lib/catseye_ast/tree_sitter_xml.ml
   Shared tree-sitter XML CST parser.

   Tree-sitter produces XML output via `tree-sitter parse --output xml`.
   This module provides a functional XML parser that converts the flat
   XML string into a tree of nodes with tags, attributes, children, and text.

   Used by all tree-sitter language mappers (Gleam, TypeScript, Svelte, JS).
*)

open Base

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* ── XML tree type ──────────────────────────────────────────────────── *)

type xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

(** Get an attribute value from an XML node. *)
let attr (n : xml) (k : string) : string =
  try Stdlib.List.assoc k n.attrs with Stdlib.Not_found -> ""

(** Get the text content of an XML node. *)
let text (n : xml) = n.text

(** Get the source line number from the srow attribute (1-indexed). *)
let line_of (n : xml) : int =
  match attr n "srow" with "" -> 0 | s -> (try Stdlib.int_of_string s + 1 with _ -> 0)

(** Deep collect all descendants matching [tag]. *)
let rec find (n : xml) ~tag : xml list =
  (if n.tag = tag then [n] else []) @ List.concat_map ~f:(find ~tag) n.children

(** Collect only *direct* children matching a predicate. *)
let children_where (n : xml) ~f : xml list =
  List.filter n.children ~f:f

(* ── Tokenizer ─────────────────────────────────────────────────────── *)

type tok = Open of string * (string * string) list | Close of string | Text of string

let is_ws c = c = ' ' || c = '\t' || c = '\n' || c = '\r'

(** Skip to the first char satisfying [pred], returning the skipped substring. *)
let skip_until s pos pred =
  let len = String.length s in
  let start = pos in
  let rec go i = if i < len && not (pred s.[i]) then go (i + 1) else i in
  let stop = go start in
  (Stdlib.String.sub s start (stop - start), stop)

(** Parse name=value pairs from inside a tag. Respects quoting. *)
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

(** Tokenize XML string into a flat token list. *)
let tokenize s =
  let len = String.length s in
  let rec go pos acc =
    if pos >= len then List.rev acc
    else if s.[pos] <> '<' then begin
      let (txt, next) = skip_until s pos (fun c -> c = '<') in
      let trimmed = String.strip txt in
      if trimmed = "" then go next acc
      else go next (Text trimmed :: acc)
    end else if pos + 1 < len && s.[pos + 1] = '?' then begin
      (* XML declaration *)
      let (_, next) = skip_until s pos (fun c -> c = '>') in
      go (next + 1) acc
    end else if pos + 1 < len && s.[pos + 1] = '/' then begin
      (* closing tag *)
      let (name, next) = skip_until s (pos + 2) (fun c -> c = '>') in
      go (next + 1) (Close (String.strip name) :: acc)
    end else if pos + 3 < len && s.[pos + 1] = '!' && s.[pos + 2] = '-' && s.[pos + 3] = '-' then begin
      (* comment *)
      let rec find_end i =
        if i + 2 >= len then len
        else if s.[i] = '-' && s.[i + 1] = '-' && s.[i + 2] = '>' then i + 3
        else find_end (i + 1) in
      go (find_end (pos + 4)) acc
    end else begin
      (* opening tag *)
      let (tag, i) = skip_until s (pos + 1) (fun c -> is_ws c || c = '>' || c = '/') in
      if tag = "" then go (pos + 1) acc
      else begin
        let (raw_attrs, i) = skip_until s i (fun c -> c = '>') in
        let self_close =
          let alen = String.length raw_attrs in
          alen > 0 && raw_attrs.[alen - 1] = '/' in
        let attrs = parse_attrs raw_attrs in
        let acc = Open (tag, attrs) :: acc in
        go (i + 1) (if self_close then Close tag :: acc else acc)
      end
    end
  in
  go 0 []

(* ── Parser: tokens → xml tree ─────────────────────────────────────── *)

(** Parse an XML string into an xml tree.
    Returns the root node, or an empty node if parsing fails. *)
let parse_xml s =
  let arr = Array.of_list (tokenize s) in
  let len = Array.length arr in
  let rec build pos =
    if pos >= len then ([], pos)
    else match arr.(pos) with
    | Text _ -> build (pos + 1)
    | Close _ -> ([], pos)  (* caller consumes *)
    | Open (tag, attrs) ->
      let (children, text, pos') = collect (pos + 1) tag in
      let (rest, pos'') = build pos' in
      ({ tag; attrs; children; text } :: rest, pos'')
  and collect pos close_tag =
    let rec go pos acc last_text =
      if pos >= len then (List.rev acc, last_text, pos)
      else match arr.(pos) with
      | Text t -> go (pos + 1) acc t
      | Close ct when ct = close_tag -> (List.rev acc, last_text, pos + 1)
      | Close _ -> (List.rev acc, last_text, pos)  (* mismatched — stop *)
      | Open _ ->
        let (nodes, pos') = build pos in
        go pos' (List.rev_append nodes acc) last_text
    in
    go pos [] ""
  in
  match build 0 with
  | ([], _) -> { tag = ""; attrs = []; children = []; text = "" }
  | (root :: _, _) -> root

(** Parse an XML string, returning all root-level nodes. *)
let parse_xml_all s =
  let arr = Array.of_list (tokenize s) in
  let len = Array.length arr in
  let rec build pos =
    if pos >= len then ([], pos)
    else match arr.(pos) with
    | Text _ -> build (pos + 1)
    | Close _ -> ([], pos)
    | Open (tag, attrs) ->
      let (children, text, pos') = collect (pos + 1) tag in
      let (rest, pos'') = build pos' in
      ({ tag; attrs; children; text } :: rest, pos'')
  and collect pos close_tag =
    let rec go pos acc last_text =
      if pos >= len then (List.rev acc, last_text, pos)
      else match arr.(pos) with
      | Text t -> go (pos + 1) acc t
      | Close ct when ct = close_tag -> (List.rev acc, last_text, pos + 1)
      | Close _ -> (List.rev acc, last_text, pos)
      | Open _ ->
        let (nodes, pos') = build pos in
        go pos' (List.rev_append nodes acc) last_text
    in
    go pos [] ""
  in
  fst (build 0)

(** Direct children with a specific tag. *)
let children_with_tag (n : xml) ~(tag : string) : xml list =
  List.filter ~f:(fun c -> c.tag = tag) n.children

(** Direct children with a specific attribute. *)
let children_with_field (n : xml) ~(field : string) : xml list =
  List.filter ~f:(fun c -> Stdlib.List.mem_assoc field c.attrs) n.children

(* ── Grammar resolution ─────────────────────────────────────────────── *)

(** Resolve a tree-sitter grammar path.
    Search order:
    1. <LANG>_GRAMMAR env var (e.g. TREE_SITTER_RUST_GRAMMAR)
    2. TREE_SITTER_GRAMMAR_DIR/<lang>.so or <lang>.wasm
    3. Bundled grammars next to executable: <exe_dir>/../lib/catseye/grammars/<lang>.so
    4. Nix store auto-discover via find (slow, fallback)
    5. CWD fallback

    Note: On linux-aarch64, tree-sitter-rust may only be available as WASM.
    The find command looks for 'parser' binary files in tree-sitter-* directories.
*)
let resolve_grammar ~(lang : string) ~(env_var : string) : string option =
  (* 1. User tree-sitter directory first (~/.tree-sitter/{lang}.so) *)
  (* Native parsers compiled from npm packages are more reliable than nix store *)
  let user_so = Stdlib.Filename.concat "/home/kritoke/.tree-sitter" (lang ^ ".so") in
  if Stdlib.Sys.file_exists user_so then Some user_so
  else
    (* 2. Explicit env var *)
    (match Stdlib.Sys.getenv env_var with
     | path -> Some path
     | exception Stdlib.Not_found ->
       (* 3. Grammar directory from env *)
       (match Stdlib.Sys.getenv "TREE_SITTER_GRAMMAR_DIR" with
        | dir ->
          (* Try .so first, then .wasm for WASM-based grammars *)
          let so_path = Stdlib.Filename.concat dir (lang ^ ".so") in
          let wasm_path = Stdlib.Filename.concat dir (lang ^ ".wasm") in
          if Stdlib.Sys.file_exists so_path then Some so_path
          else if Stdlib.Sys.file_exists wasm_path then Some wasm_path
          else None
        | exception Stdlib.Not_found ->
          (* 4. Bundled grammars next to executable *)
          let exe_dir = Stdlib.Filename.dirname (Stdlib.Sys.executable_name) in
          let bundled = exe_dir ^ "/../lib/catseye/grammars/" ^ lang ^ ".so" in
          if Stdlib.Sys.file_exists bundled then Some bundled
          else
            (* 5. Nix store discovery - look for 'parser' binary in tree-sitter-* dirs *)
            let discovered =
              try
                let ic = Unix.open_process_in
                  (Stdlib.Printf.sprintf "find /nix/store -maxdepth 3 -name parser -type f -executable 2>/dev/null | grep -i 'tree-sitter-%s' | head -1" lang)
                in
                let line = try Some (Stdlib.input_line ic) with Stdlib.End_of_file -> None in
                let _ = Unix.close_process_in ic in
                (match line with
                 | Some p when Stdlib.Sys.file_exists p -> Some p
                 | _ -> None)
              with _ -> None
            in
            (match discovered with
             | Some p -> Some p
             | None ->
               (* 6. CWD fallback *)
               let local = Stdlib.Filename.concat (Stdlib.Sys.getcwd ()) (lang ^ "_parser.so") in
               if Stdlib.Sys.file_exists local then Some local else None)))
