(* src/ocaml/lib/catseye_ast/gleam_mapper.ml
   Bridge from tree-sitter Gleam XML output to CatseyeAST.t
   
   Part of the JSON Bridge - tree-sitter XML → CatseyeAST.t
   Inline XML parsing to avoid circular dependencies.
*)

open Types
open Error

(* ── XML Parsing (from catseye_engine/gleam.ml) ─────────────────────── *)

type xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

let attr (n : xml) (k : string) : string =
  try List.assoc k n.attrs with Not_found -> ""

let text (n : xml) = n.text

let line_of (n : xml) : int =
  match attr n "srow" with "" -> 0 | s -> (try int_of_string s + 1 with _ -> 0)

let rec find (n : xml) ~tag : xml list =
  (if n.tag = tag then [n] else []) @ List.concat_map (find ~tag) n.children

let children_where (n : xml) ~f : xml list =
  List.filter f n.children

(* Tokenizer *)
type tok = Open of string * (string * string) list | Close of string | Text of string

let is_ws c = c = ' ' || c = '\t' || c = '\n' || c = '\r'

let skip_until s pos pred =
  let len = String.length s in
  let start = pos in
  let rec go i = if i < len && not (pred s.[i]) then go (i + 1) else i in
  let stop = go start in
  (String.sub s start (stop - start), stop)

let parse_attrs s =
  let rec go i acc =
    let len = String.length s in
    let i = let rec skip j = if j < len && is_ws s.[j] then skip (j + 1) else j in skip i in
    if i >= len || s.[i] = '/' || s.[i] = '>' then List.rev acc
    else
      let (name, i) = skip_until s i (fun c -> c = '=' || is_ws c || c = '>' || c = '/') in
      if name = "" then go i acc
      else
        let i = let rec find_eq j = if j < len && s.[j] <> '=' then find_eq (j + 1) else j in find_eq i in
        if i >= len || s.[i] <> '=' then go i acc
        else
          let i = let rec skip_ws j = if j < len && is_ws s.[j] then skip_ws (j + 1) else j in skip_ws (i + 1) in
          if i < len && s.[i] = '"' then
            let (value, i) = skip_until s (i + 1) (fun c -> c = '"') in
            go (i + 1) ((name, value) :: acc)
          else go i acc
  in
  go 0 []

let tokenize s =
  let len = String.length s in
  let rec go pos acc =
    if pos >= len then List.rev acc
    else if s.[pos] <> '<' then begin
      let (txt, next) = skip_until s pos (fun c -> c = '<') in
      let trimmed = String.trim txt in
      if trimmed = "" then go next acc
      else go next (Text trimmed :: acc)
    end else if pos + 1 < len && s.[pos + 1] = '?' then begin
      let (_, next) = skip_until s pos (fun c -> c = '>') in
      go (next + 1) acc
    end else if pos + 1 < len && s.[pos + 1] = '/' then begin
      let (name, next) = skip_until s (pos + 2) (fun c -> c = '>') in
      go (next + 1) (Close (String.trim name) :: acc)
    end else if pos + 3 < len && s.[pos + 1] = '!' && s.[pos + 2] = '-' && s.[pos + 3] = '-' then begin
      let rec find_end i = if i + 2 >= len then len else if s.[i] = '-' && s.[i + 1] = '-' && s.[i + 2] = '>' then i + 3 else find_end (i + 1) in
      go (find_end (pos + 4)) acc
    end else begin
      let (tag, i) = skip_until s (pos + 1) (fun c -> is_ws c || c = '>' || c = '/') in
      if tag = "" then go (pos + 1) acc
      else begin
        let (raw_attrs, i) = skip_until s i (fun c -> c = '>') in
        let self_close = let alen = String.length raw_attrs in alen > 0 && raw_attrs.[alen - 1] = '/' in
        let attrs = parse_attrs raw_attrs in
        go (i + 1) ((if self_close then Open (tag, attrs) :: Close tag :: acc else Open (tag, attrs) :: acc))
      end
    end
  in
  go 0 []

let parse_xml s =
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
        let (rest, pos') = build pos in
        go pos' (rest @ acc) last_text
    in
    go pos [] ""
  in
  match build 0 with
  | ([], _) -> { tag = ""; attrs = []; children = []; text = "" }
  | (root :: _, _) -> root

(* ── Position helpers ─────────────────────────────────────────────── *)

let position_of_xml (n : xml) ~field =
  let row = try int_of_string (attr n field) + 1 with _ -> 0 in
  Position.make ~line:row ~column:0 ~byte_offset:0

let range_of_xml (n : xml) =
  { start = position_of_xml n ~field:"srow";
    end_ = position_of_xml n ~field:"erow" }

(* ── XML → CatseyeAST conversion ────────────────────────────────────── *)

let rec literal_of_xml (n : xml) =
  match attr n "type" with
  | "string" -> LString (text n)
  | "integer" -> LInt (text n)
  | "float" -> LFloat (text n)
  | "char" when text n <> "" -> LChar (text n).[0]
  | _ -> LUnit

and pattern_of_xml (n : xml) =
  match attr n "type" with
  | "identifier" | "_" -> PVar (text n)
  | _ when text n <> "" -> PLiteral (literal_of_xml n)
  | _ -> PVar (attr n "type")

and expr_of_xml (n : xml) =
  let loc = range_of_xml n in
  let value = match attr n "type" with
    | "unit" -> EUnit
    | "string" | "integer" | "float" -> ELiteral (literal_of_xml n)
    | "identifier" -> EVar (text n)
    | "field_access" ->
        (match find n ~tag:"field" with [f] -> EFieldAccess (expr_of_xml n, text f) | _ -> EUnknown "field_access")
    | "tuple" -> ETuple (List.map expr_of_xml (children_where n ~f:(fun c -> c.tag <> "type")))
    | "list" -> EList (List.map expr_of_xml (children_where n ~f:(fun c -> c.tag <> "type")))
    | "record" -> ERecord (List.map (fun c -> (attr c "field", expr_of_xml c)) (find n ~tag:"field"))
    | "call" ->
        let fn = match find n ~tag:"function" with [f] -> expr_of_xml f | _ -> expr_of_xml n in
        EApp (fn, [])
    | "fn" ->
        let params = children_where n ~f:(fun c -> c.tag = "parameter") in
        let body = match find n ~tag:"body" with [b] -> expr_of_xml b | _ -> expr_of_xml n in
        EFn (List.map pattern_of_xml params, body)
    | "if" ->
        let cond = match find n ~tag:"condition" with [c] -> expr_of_xml c | _ -> expr_of_xml n in
        let then_ = match find n ~tag:"then" with [c] -> expr_of_xml c | _ -> expr_of_xml n in
        EIf (cond, then_, None)
    | "let" | "assignment" ->
        let body = match find n ~tag:"body" with [b] -> expr_of_xml b | _ -> expr_of_xml n in
        ELet (PVar "pat", expr_of_xml n, body)
    | _ when text n <> "" -> EVar (text n)
    | _ -> EUnknown (attr n "type")
  in
  { expr_value = value; expr_location = loc }

and item_of_xml (n : xml) =
  let loc = range_of_xml n in
  let value = match attr n "type" with
    | "function" ->
        let name = match find n ~tag:"name" with [nm] -> text nm | _ -> "unknown" in
        IFunction (name, [], None, expr_of_xml n)
    | "import" -> IImport (text n, None)
    | "type" -> ITypeDef (text n, [], [])
    | "module" -> IModule (text n, [])
    | _ -> IUnknown (attr n "type")
  in
  { item_value = value; item_location = loc }

(* ── Parse via tree-sitter CLI ─────────────────────────────────────── *)

let parse_file ~(path : string) : (t, parse_error) result =
  let grammar_path = try Some (Sys.getenv "TREE_SITTER_GLEAM_GRAMMAR") with Not_found -> None in
  match grammar_path with
  | None ->
      Error (make_error ~file:path ~message:"TREE_SITTER_GLEAM_GRAMMAR not set")
  | Some grammar ->
      let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>/dev/null" grammar path in
      let ic = Unix.open_process_in cmd in
      let xml_str = Buffer.create 4096 in
      (try while true do Buffer.add_channel xml_str ic 4096 done with End_of_file -> ());
      let status = Unix.close_process_in ic in
      match status with
      | Unix.WEXITED 0 ->
          let xml = parse_xml (Buffer.contents xml_str) in
          let items = List.filter (fun c -> List.mem c.tag ["function"; "import"; "type"]) xml.children in
          Ok { mod_lang = Gleam; mod_path = path; mod_items = List.map item_of_xml items; parse_errors = [] }
      | _ ->
          Error (make_error ~file:path ~message:"tree-sitter parse failed")