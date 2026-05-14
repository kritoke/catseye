(* src/ocaml/lib/catseye_ast/crystal_mapper.ml
   Bridge from Crystal extractor JSON to CatseyeAST.t
   
   Part of the JSON Bridge - Crystal extractor JSON → CatseyeAST.t
   The Crystal extractor emits Security_node JSON which we convert
   to the unified CatseyeAST schema.
*)

open Types
open Error

(** JSON types for Security_node from extractor *)
type security_node = {
  node_type : string;
  name : string;
  args : arg_node list;
  line : int;
  column : int;
  call : string option;
  field : string option;
  taint : string option;
  sinks : string list;
}

and arg_node = {
  arg_type : string;
  value : string;
  field : string;
}

(* ── JSON parsing (minimal, no external deps) ──────────────────────── *)

let string_of_json = function
  | `String s -> s
  | _ -> ""

let int_of_json = function
  | `Int i -> i
  | _ -> 0

let list_of_json = function
  | `List l -> l
  | _ -> []

let assoc_of_json = function
  | `Assoc l -> l
  | _ -> []

let rec find_field (fields : (string * Yojson.Safe.t) list) key =
  match fields with
  | [] -> `Null
  | (k, v) :: _ when k = key -> v
  | _ :: rest -> find_field rest key

let parse_arg (json : Yojson.Safe.t) : arg_node =
  let fields = assoc_of_json json in
  {
    arg_type = string_of_json (find_field fields "arg_type");
    value = string_of_json (find_field fields "value");
    field = string_of_json (find_field fields "field");
  }

let parse_security_node (json : Yojson.Safe.t) : security_node =
  let fields = assoc_of_json json in
  {
    node_type = string_of_json (find_field fields "type");
    name = string_of_json (find_field fields "name");
    args = List.map parse_arg (list_of_json (find_field fields "args"));
    line = int_of_json (find_field fields "line");
    column = int_of_json (find_field fields "column");
    call = (match find_field fields "call" with `String s when s <> "" -> Some s | _ -> None);
    field = (match find_field fields "field" with `String s when s <> "" -> Some s | _ -> None);
    taint = (match find_field fields "taint" with `String s when s <> "" -> Some s | _ -> None);
    sinks = List.map string_of_json (list_of_json (find_field fields "sinks"));
  }

(* ── Security_node → CatseyeAST conversion ────────────────────────── *)

let position_of line col = {
  start = { line; column = col; byte_offset = 0 };
  end_ = { line; column = col; byte_offset = 0 };
}

let range_of line col len = {
  start = { line; column = col; byte_offset = 0 };
  end_ = { line; column = col + len; byte_offset = 0 };
}

let arg_to_expr (arg : arg_node) : expr =
  let loc = position_of 0 0 in
  match arg.arg_type with
  | "literal" ->
      { expr_value = ELiteral (LString arg.value); expr_location = loc }
  | "var" ->
      { expr_value = EVar arg.value; expr_location = loc }
  | "call" ->
      { expr_value = EApp ({ expr_value = EVar arg.value; expr_location = loc }, []); expr_location = loc }
  | _ ->
      { expr_value = EVar arg.value; expr_location = loc }

let node_to_expr (node : security_node) : expr =
  let loc = range_of node.line node.column (String.length node.name) in
  let value = match node.node_type with
    | "call" ->
        (match node.call with
         | Some call_name -> 
             let fn = { expr_value = EVar call_name; expr_location = loc } in
             let args = List.map arg_to_expr node.args in
             EApp (fn, args)
         | None -> EVar node.name)
    | "assign" ->
        (match node.args with
         | [val_arg] ->
             let var = { expr_value = EVar node.name; expr_location = loc } in
             let val_expr = arg_to_expr val_arg in
             EAssignment (var, val_expr)
         | _ -> EVar node.name)
    | "string" -> ELiteral (LString node.name)
    | "number" -> ELiteral (LInt node.name)
    | "var" -> EVar node.name
    | _ -> EVar node.name
  in
  { expr_value = value; expr_location = loc }

let node_to_item (node : security_node) : item list =
  let loc = range_of node.line node.column (String.length node.name) in
  match node.node_type with
  | "def" ->
      let params = List.map (fun a -> PVar a.value) node.args in
      let body = match node.args with
        | [] -> { expr_value = EUnit; expr_location = loc }
        | args -> { expr_value = EBlock (List.map arg_to_expr args); expr_location = loc }
      in
      [{ item_value = IFunction (node.name, params, None, body); item_location = loc }]
  | "class" ->
      [{ item_value = IClass (node.name, []); item_location = loc }]
  | "module" ->
      [{ item_value = IModule (node.name, []); item_location = loc }]
  | "import" ->
      [{ item_value = IImport (node.name, None); item_location = loc }]
  | _ ->
      (* For calls and assignments, add as item with expression *)
      if node.name <> "" then
        [{ item_value = IUnknown node.node_type; item_location = loc }]
      else
        []

(* ── Parse via Crystal extractor ──────────────────────────────────── *)

let parse_file ~(path : string) : (t, parse_error) result =
  let extractor_cmd = 
    try Sys.getenv "CATSEYE_CRYSTAL_EXTRACTOR"
    with Not_found -> "crystal run src/extractor/extractor.cr --"
  in
  let cmd = Printf.sprintf "%s '%s' 2>/dev/null" extractor_cmd path in
  let ic = Unix.open_process_in cmd in
  let json_str = Buffer.create 8192 in
  (try while true do Buffer.add_channel json_str ic 4096 done
   with End_of_file -> ());
  let status = Unix.close_process_in ic in
  match status with
  | Unix.WEXITED 0 ->
      let json = Yojson.Safe.from_string (Buffer.contents json_str) in
      let nodes = match json with
        | `List items -> List.map parse_security_node items
        | _ -> []
      in
      (* Convert security nodes to items *)
      let items = List.concat_map node_to_item nodes in
      Ok { mod_lang = Crystal; mod_path = path; mod_items = items; parse_errors = [] }
  | _ ->
      Error (make_error ~file:path ~message:"Crystal extractor failed")