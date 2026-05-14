(* src/ocaml/lib/catseye_ast/crystal_mapper.ml
   Bridge from Crystal extractor JSON to CatseyeAST.t
   
   Part of the JSON Bridge - Crystal extractor JSON → CatseyeAST.t
*)

open Types
open Error

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

(* JSON helpers *)
let string_of_json = function `String s -> s | _ -> ""
let int_of_json = function `Int i -> i | _ -> 0
let list_of_json = function `List l -> l | _ -> []
let assoc_of_json = function `Assoc l -> l | _ -> []

let rec find_field fields key =
  match fields with [] -> `Null | (k, v) :: _ when k = key -> v | _ :: r -> find_field r key

let parse_arg json = match assoc_of_json json with fields ->
  { arg_type = string_of_json (find_field fields "arg_type");
    value = string_of_json (find_field fields "value");
    field = string_of_json (find_field fields "field"); }

let parse_security_node json = match assoc_of_json json with fields ->
  { node_type = string_of_json (find_field fields "type");
    name = string_of_json (find_field fields "name");
    args = List.map parse_arg (list_of_json (find_field fields "args"));
    line = int_of_json (find_field fields "line");
    column = int_of_json (find_field fields "column");
    call = (match find_field fields "call" with `String s when s <> "" -> Some s | _ -> None);
    field = (match find_field fields "field" with `String s when s <> "" -> Some s | _ -> None);
    taint = (match find_field fields "taint" with `String s when s <> "" -> Some s | _ -> None);
    sinks = List.map string_of_json (list_of_json (find_field fields "sinks")); }

(* Helpers *)
let make_range line col len = {
  start = { line; column = col; byte_offset = 0 };
  end_ = { line; column = col + len; byte_offset = 0 };
}

let make_loc line col = make_range line col 0

(* Convert arg to expression *)
let arg_to_expr (arg : arg_node) =
  let loc = make_loc 0 0 in
  match arg.arg_type with
  | "literal" -> { expr_value = ELiteral (LString arg.value); expr_location = loc }
  | "call" -> { expr_value = EApp ({ expr_value = EVar arg.value; expr_location = loc }, []); expr_location = loc }
  | _ -> { expr_value = EVar arg.value; expr_location = loc }

(* Get call name from node *)
let get_call_name node = match node.call with
  | Some c -> c
  | None when node.name <> "" -> node.name
  | None -> ""

(* Convert node to item *)
let node_to_item node =
  let loc = make_range node.line node.column (String.length node.name) in
  match node.node_type with
  | "def" ->
      let params = List.map (fun a -> PVar a.value) node.args in
      let body = { expr_value = EUnit; expr_location = loc } in
      [{ item_value = IFunction (node.name, params, None, body); item_location = loc }]
  | "class" -> [{ item_value = IClass (node.name, []); item_location = loc }]
  | "module" -> [{ item_value = IModule (node.name, []); item_location = loc }]
  | "import" -> [{ item_value = IImport (node.name, None); item_location = loc }]
  | _ -> []

(* Convert call node to IUnknown item (for ai_linter to analyze) *)
let call_to_item node =
  let call_name = get_call_name node in
  if call_name = "" then [] else
    let loc = make_range node.line node.column (String.length node.name) in
    [{ item_value = IUnknown ("call:" ^ call_name); item_location = loc }]

(* Parse via Crystal extractor *)
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
      let nodes = match json with `List items -> List.map parse_security_node items | _ -> [] in
      (* Items: def, class, module, import *)
      let items = List.concat_map node_to_item nodes in
      (* Calls as items for ai_linter to analyze *)
      let call_items = List.concat_map call_to_item nodes in
      Ok { mod_lang = Crystal; mod_path = path; mod_items = items @ call_items; parse_errors = [] }
  | _ ->
      Error (make_error ~file:path ~message:"Crystal extractor failed")