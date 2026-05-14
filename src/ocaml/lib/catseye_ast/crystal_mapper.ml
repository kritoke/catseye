(* src/ocaml/lib/catseye_ast/crystal_mapper.ml
   Bridge from Crystal extractor JSON to CatseyeAST.t
   
   Part of the JSON Bridge - Crystal extractor JSON → CatseyeAST.t
   The Crystal extractor emits Security_node JSON which we convert
   to the unified CatseyeAST schema.
*)

open Types
open Error

(** JSON types for Security_node *)
type security_node = {
  node_type : string;
  name : string;
  line : int;
  column : int;
  call : string option;
  field : string option;
  taint : string option;
  sinks : string list;
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

let parse_security_node (json : Yojson.Safe.t) : security_node =
  let fields = assoc_of_json json in
  {
    node_type = string_of_json (find_field fields "type");
    name = string_of_json (find_field fields "name");
    line = int_of_json (find_field fields "line");
    column = int_of_json (find_field fields "column");
    call = (match find_field fields "call" with `String s when s <> "" -> Some s | _ -> None);
    field = (match find_field fields "field" with `String s when s <> "" -> Some s | _ -> None);
    taint = (match find_field fields "taint" with `String s when s <> "" -> Some s | _ -> None);
    sinks = List.map string_of_json (list_of_json (find_field fields "sinks"));
  }

(* ── Security_node → CatseyeAST conversion ────────────────────────── *)

let security_node_to_expr (node : security_node) : expr =
  let loc = {
    start = Position.make ~line:node.line ~column:node.column ~byte_offset:0;
    end_ = Position.make ~line:node.line ~column:(node.column + String.length node.name) ~byte_offset:0;
  } in
  let value = match node.node_type with
    | "var" -> EVar node.name
    | "call" ->
        (match node.call with
         | Some call_name -> 
             let fn = { expr_value = EVar call_name; expr_location = loc } in
             EApp (fn, [])
         | None -> EVar node.name)
    | "string" -> ELiteral (LString node.name)
    | "number" -> ELiteral (LInt node.name)
    | _ -> EVar node.name
  in
  { expr_value = value; expr_location = loc }

let security_node_to_item (node : security_node) : item =
  let loc = {
    start = Position.make ~line:node.line ~column:node.column ~byte_offset:0;
    end_ = Position.make ~line:node.line ~column:0 ~byte_offset:0;
  } in
  let value = match node.node_type with
    | "function" | "def" -> IFunction (node.name, [], None, { expr_value = EUnit; expr_location = loc })
    | "class" -> IClass (node.name, [])
    | "module" -> IModule (node.name, [])
    | _ -> IUnknown node.node_type
  in
  { item_value = value; item_location = loc }

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
      let items = List.map (fun node ->
        if node.node_type = "function" || node.node_type = "def" then
          security_node_to_item node
        else
          security_node_to_item { node with node_type = "var" }
      ) nodes in
      Ok { mod_lang = Crystal; mod_path = path; mod_items = items; parse_errors = [] }
  | _ ->
      Error (make_error ~file:path ~message:"Crystal extractor failed")