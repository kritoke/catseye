(* lib/catseye_engine/gleam.ml
   Gleam extractor — tree-sitter CLI → XML → Security Nodes *)

open Catseye_types
open Security_node

(* ── Constants ──────────────────────────────────────────────────────── *)

let taint_sources =
  [ "params"; "request"; "req"; "get_body"; "query"; "io.get_line"
  ; "dynamic.unsafe_coerce"; "request.get_body"; "user_url"; "user_input"
  ; "url"; "path"; "cmd"; "command"; "input"; "env"
  ; "ARGV"; "STDIN"; "gets" ]

module String_set = Set.Make(String)

let skip_calls =
  String_set.of_list
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

(* ── XML tree ──────────────────────────────────────────────────────── *)

type xml =
  { tag : string
  ; attrs : (string * string) list
  ; children : xml list
  ; text : string }

let attr (n : xml) (k : string) : string =
  try List.assoc k n.attrs with Not_found -> ""

let line_of (n : xml) : int =
  match attr n "srow" with "" -> 0 | s -> (try int_of_string s + 1 with _ -> 0)

(** Deep collect all descendants matching [tag]. *)
let rec find (n : xml) ~tag : xml list =
  (if n.tag = tag then [n] else []) @ List.concat_map (find ~tag) n.children

(** Collect only *direct* children matching a predicate. *)
let children_where (n : xml) ~f : xml list =
  List.filter f n.children

(* ── Tokenizer ─────────────────────────────────────────────────────── *)

type tok = Open of string * (string * string) list | Close of string | Text of string

let is_ws c = c = ' ' || c = '\t' || c = '\n' || c = '\r'

(** Skip to the first char satisfying [pred], returning the skipped substring. *)
let skip_until s pos pred =
  let len = String.length s in
  let start = pos in
  let rec go i = if i < len && not (pred s.[i]) then go (i + 1) else i in
  let stop = go start in
  (String.sub s start (stop - start), stop)

(** Parse name=value pairs from inside a tag. Respects quoting. *)
let parse_attrs s =
  let rec go i acc =
    let len = String.length s in
    (* skip whitespace *)
    let i = let rec skip j =
      if j < len && is_ws s.[j] then skip (j + 1) else j in skip i in
    if i >= len || s.[i] = '/' || s.[i] = '>' then List.rev acc
    else
      (* name *)
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
      let trimmed = String.trim txt in
      if trimmed = "" then go next acc
      else go next (Text trimmed :: acc)
    end else if pos + 1 < len && s.[pos + 1] = '?' then begin
      (* XML declaration *)
      let (_, next) = skip_until s pos (fun c -> c = '>') in
      go (next + 1) acc
    end else if pos + 1 < len && s.[pos + 1] = '/' then begin
      (* closing tag *)
      let (name, next) = skip_until s (pos + 2) (fun c -> c = '>') in
      go (next + 1) (Close (String.trim name) :: acc)
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

(* ── Parser: tokens → xml tree (functional recursive descent) ─────── *)

(** Build xml nodes from token array starting at [pos].
    Returns (nodes, next_pos). *)
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
  fst (build 0)

(* ── Substring helper ──────────────────────────────────────────────── *)

let contains ~sub s =
  let slen = String.length sub in
  let slen_s = String.length s in
  slen > 0 &&
  let rec loop i =
    i + slen <= slen_s && (String.sub s i slen = sub || loop (i + 1))
  in
  loop 0

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
      (List.map (fun p -> p.text) (find node ~tag:"identifier")
      @ List.map (fun l -> l.text) (find node ~tag:"label"))
      |> String.concat "." in
    { arg_type = ArgCall; value; field = "" }
  | _ ->
    { arg_type = ArgUnknown; value = node.tag; field = "" }

let extract_args call =
  match find call ~tag:"arguments" with
  | [] -> []
  | args_node :: _ ->
    List.concat_map (fun child ->
      if child.tag <> "argument" then []
      else List.filter_map (fun vc ->
        match vc.tag with
        | "string" | "integer" | "float" | "identifier"
        | "field_access" | "tuple" | "record" -> Some (classify_arg vc)
        | _ -> None
      ) child.children
    ) args_node.children

(* ── Call name (from direct children only) ─────────────────────────── *)

let call_name call =
  children_where call ~f:(fun c -> attr c "field" = "function")
  |> List.find_map (fun child ->
    match child.tag with
    | "identifier" -> Some child.text
    | "field_access" ->
      Some (List.map (fun p -> p.text) (find child ~tag:"identifier")
          @ List.map (fun l -> l.text) (find child ~tag:"label")
          |> String.concat ".")
    | "label" -> Some child.text
    | _ -> None)

(* ── Node extraction ───────────────────────────────────────────────── *)

let extract_nodes root path =
  (* Pass 1: function defs (with params as args) *)
  let defs = List.filter_map (fun fn ->
    let name_opt =
      children_where fn ~f:(fun c ->
        c.tag = "identifier" && attr c "field" = "name")
      |> List.find_map (fun c -> if c.text <> "" then Some c.text else None) in
    match name_opt with
    | None -> None
    | Some name ->
      (* Extract params from function_parameter children *)
      let params =
        List.concat_map (fun p ->
          children_where p ~f:(fun c ->
            c.tag = "identifier" && attr c "field" = "name")
          |> List.filter_map (fun c ->
            if c.text <> "" then Some
              { arg_type = ArgVar; value = c.text; field = "" }
            else None)
        ) (find fn ~tag:"function_parameter") in
      Some { node_type = Def; name; args = params
           ; line = line_of fn; taint = false; file = path; language = "gleam"; metadata = [] }
  ) (find root ~tag:"function") in

  (* Pass 2: let bindings — build taint table *)
  let tainted = Hashtbl.create 32 in
  let assigns = List.concat_map (fun tag ->
    List.filter_map (fun (lt : xml) ->
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
          List.exists (contains ~sub:lt.text) taint_sources
          || Hashtbl.fold (fun v _ acc ->
               acc || contains ~sub:v lt.text) tainted false in
        if taint then Hashtbl.replace tainted name true;
        let args = if rhs_arg <> "" then [{ arg_type = rhs_kind; value = rhs_arg; field = "" }] else [] in
        Some { node_type = Assign; name; args; line = line_of lt; taint; file = path; language = "gleam"; metadata = [] }
    ) (find root ~tag)
  ) ["let"; "let_assert"] in

  (* Pass 3: function calls *)
  let calls = List.filter_map (fun call ->
    match call_name call with
    | None | Some "fn" -> None
    | Some name when String_set.mem name skip_calls -> None
    | Some name ->
      let args = extract_args call in
      let taint = List.exists (fun a ->
        (a.arg_type = ArgVar &&
         (List.mem a.value taint_sources || Hashtbl.mem tainted a.value))
        || (a.arg_type = ArgCall && contains ~sub:"<interpolation>" a.value)
      ) args in
      Some { node_type = Call; name; args; line = line_of call; taint; file = path; language = "gleam"; metadata = [] }
  ) (find root ~tag:"function_call") in

  List.sort (fun a b -> compare a.line b.line) (defs @ assigns @ calls)

(* ── Public interface ──────────────────────────────────────────────── *)

let grammar_path () =
  (* Try env var first, then auto-discover *)
  let env_result = match Sys.getenv "TREE_SITTER_GLEAM_GRAMMAR" with
    | exception Not_found -> None
    | path -> Some path
  in
  match env_result with
  | Some path -> Ok path
  | None ->
    (* Auto-discover: check user tree-sitter directory first (has WASM/so parsers) *)
    let so_path = "/home/kritoke/.tree-sitter/gleam.so" in
    if Sys.file_exists so_path then Ok so_path
    else begin
      (* Fall back to nix store - use maxdepth 3 to find parsers in subdirs *)
      let discovered = try
        let cmd = Printf.sprintf "find /nix/store -maxdepth 3 -name parser -type f -executable 2>/dev/null | grep -i 'tree-sitter-%s' | head -1" "gleam" in
        let ic = Unix.open_process_in cmd in
        let line = try Some (input_line ic) with End_of_file -> None in
        let _ = Unix.close_process_in ic in
        (match line with
         | Some p when Sys.file_exists p -> Some p
         | _ -> None)
      with _ -> None in
      (match discovered with
       | Some p -> Ok p
       | None ->
         let common = [
           "/usr/lib/tree-sitter-gleam/parser";
           "/usr/local/lib/tree-sitter-gleam/parser";
         ] in
         (match List.find_opt Sys.file_exists common with
          | Some p -> Ok p
          | None -> Error (`Msg "Gleam tree-sitter grammar not found. Set TREE_SITTER_GLEAM_GRAMMAR or install tree-sitter-gleam.")))
    end

let extract file_path =
  match grammar_path () with
  | Error e -> Error e
  | Ok grammar ->
  (* grammar is the path to the .so parser file, or the parser directory in nix *)
  (* Pass grammar directly for .so files, dirname for nix store parser dirs *)
  let lib_path = if Filename.check_suffix grammar ".so" then grammar
    else Filename.dirname grammar in
  let cmd = Printf.sprintf
    "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>/dev/null"
    lib_path file_path in
  let (out, inp, err) = Unix.open_process_full cmd (Unix.environment ()) in
  let buf = Buffer.create 8192 in
  (try while true do Buffer.add_channel buf out 4096 done
   with End_of_file -> ());
  let ok = match Unix.close_process_full (out, inp, err) with
    | Unix.WEXITED 0 -> true
    | Unix.WEXITED 1 -> Buffer.length buf > 0  (* tree-sitter returns 1 for partial parse errors but still emits XML *)
    | _ -> false in
  if not ok then Error (`Msg (Printf.sprintf "tree-sitter failed for %s" file_path))
  else begin
    let doc = parse_xml (Buffer.contents buf) in
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
