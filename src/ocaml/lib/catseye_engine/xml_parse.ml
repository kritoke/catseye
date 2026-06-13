(* lib/catseye_engine/xml_parse.ml
   Shared XML parser for tree-sitter output.

   Extracted from crystal_ts.ml and gleam.ml to eliminate ~300 lines of
   duplication and ensure both extractors benefit from correct comment
   handling and self-closing tag logic. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* ── Types ─────────────────────────────────────────────────────────── *)

type xml =
  { tag : string
  ; attrs : (string * string) list
  ; children : xml list
  ; text : string }

type tok = Open of string * (string * string) list | Close of string | Text of string

(* ── Utility functions ─────────────────────────────────────────────── *)

(** Substring search. *)
let contains ~sub s =
  let sublen = String.length sub in
  let slen = String.length s in
  sublen > 0 &&
  let rec loop i =
    i + sublen <= slen &&
    (Stdlib.String.sub s i sublen = sub || loop (i + 1))
  in
  loop 0

(** Look up an attribute by key. *)
let attr (n : xml) (k : string) : string =
  try Stdlib.List.assoc k n.attrs with Stdlib.Not_found -> ""

(** Extract source line from "srow" attribute (1-based). *)
let line_of (n : xml) : int =
  match attr n "srow" with "" -> 0 | s -> (try Int.of_string s + 1 with _ -> 0)

(** Deep collect all descendants matching [tag]. *)
let rec find (n : xml) ~tag : xml list =
  (if n.tag = tag then [n] else []) @ List.concat_map ~f:(find ~tag) n.children

(** Collect only direct children matching a predicate. *)
let children_where (n : xml) ~f : xml list =
  List.filter ~f n.children

(* ── Tokenizer ─────────────────────────────────────────────────────── *)

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

(** Tokenize XML string into a flat token list.
    Correctly handles comments (looks for "-->", not just ">")
    and self-closing tags with attributes (checks raw_attrs for trailing "/"). *)
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
      (* comment: find "-->" not just ">" *)
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
        (* Check for self-closing, respecting quotes *)
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

(* ── Parsers ───────────────────────────────────────────────────────── *)

(** Array-indexed recursive descent parser.
    Used by gleam.ml. Returns a list of top-level xml nodes. *)
let parse_to_list (s : string) : xml list =
  let arr = Stdlib.Array.of_list (tokenize s) in
  let len = Stdlib.Array.length arr in
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

(** Stack-based parser.
    Used by crystal_ts.ml. Returns a single root xml node.
    Handles tree-sitter "sources" wrapper and unmatched close tags. *)
let parse_to_root (s : string) : xml =
  let tokens = tokenize s in
  let rec build (stack : xml list) (toks : tok list) : xml =
    match toks with
    | [] ->
      (match stack with
       | [] -> { tag = ""; attrs = []; children = []; text = "" }
       | [x] -> x
       | _ -> failwith ("Unclosed tags: " ^ Stdlib.String.concat "," (List.map ~f:(fun n -> n.tag) stack)))
    | Text txt :: rest ->
      (match stack with
       | [] -> build [] rest
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
           let rec pop_until stack' =
             match stack' with
             | [] -> failwith ("Could not find matching open tag for " ^ tag)
             | n :: rest' when n.tag = tag ->
               let closed = { n with children = List.rev n.children } in
               (match rest' with
                | [] -> closed
                | parent :: parpar ->
                  let updated = { parent with children = closed :: parent.children } in
                  build (updated :: parpar) rest)
             | n :: rest' ->
               let closed_intermediate = { n with children = List.rev n.children } in
               (match rest' with
                | [] -> failwith "Unmatched intermediate tags"
                | parent :: parpar ->
                  let updated = { parent with children = closed_intermediate :: parent.children } in
                  pop_until (updated :: parpar))
           in
           pop_until stack
         else
           let closed = { node with children = List.rev node.children } in
           (match par with
            | [] -> closed
            | parent :: parpar ->
              let updated = { parent with children = closed :: parent.children } in
              build (updated :: parpar) rest))
  in
  match tokens with
  | [] -> { tag = ""; attrs = []; children = []; text = "" }
  | _ ->
    let root = build [] tokens in
    if root.tag = "sources" && root.children <> [] then
      Stdlib.List.hd root.children
    else if root.tag = "" then
      failwith "Empty XML"
    else
      root
