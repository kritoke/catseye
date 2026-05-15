(* src/ocaml/lib/catseye_ast/crystal_mapper.ml
   Crystal extractor JSON → CatseyeAST.t

   Reconstructs expression trees from the flat node list produced by
   the Crystal extractor. Function bodies are populated with EBlock
   containing EApp nodes for calls, ELet for assignments, etc.
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

(* ── Location helpers ──────────────────────────────────────────────── *)

let make_range line col len = {
  start = { line; column = col; byte_offset = 0 };
  end_ = { line; column = col + len; byte_offset = 0 };
}

let make_loc line = make_range line 0 0

(* ── Dotted name → expression tree ─────────────────────────────────── *)

(** "context.request.headers.[]" becomes
    EFieldAccess(EFieldAccess(EFieldAccess(EVar "context", "request"), "headers"), "[]") *)
let rec dotted_to_expr ?(loc={ start = { line = 0; column = 0; byte_offset = 0 }; end_ = { line = 0; column = 0; byte_offset = 0 }}) (name : string) : expr =
  match String.index_opt name '.' with
  | None -> { expr_value = EVar name; expr_location = loc }
  | Some idx ->
      let prefix = String.sub name 0 idx in
      let suffix = String.sub name (idx + 1) (String.length name - idx - 1) in
      let receiver = dotted_to_expr ~loc prefix in
      { expr_value = EFieldAccess (receiver, suffix); expr_location = loc }

(* ── Node → expression ─────────────────────────────────────────────── *)

(** Convert an arg to an expression *)
let arg_to_expr (arg : arg_node) (loc : range) =
  match arg.arg_type with
  | "literal" ->
      (* Try to parse as int/float, fallback to string *)
      (try
        let _ = int_of_string arg.value in
        { expr_value = ELiteral (LInt arg.value); expr_location = loc }
      with _ ->
      try
        let _ = float_of_string arg.value in
        { expr_value = ELiteral (LFloat arg.value); expr_location = loc }
      with _ ->
        { expr_value = ELiteral (LString arg.value); expr_location = loc })
  | "call" ->
      let fn_expr = dotted_to_expr ~loc arg.value in
      let args = match arg.field with
        | "" | "?" -> []
        | f -> [{ expr_value = ELiteral (LString f); expr_location = loc }]
      in
      { expr_value = EApp (fn_expr, args); expr_location = loc }
  | "var" ->
      dotted_to_expr ~loc arg.value
  | _ ->
      { expr_value = EVar arg.value; expr_location = loc }

(** Convert a call node to an EApp expression *)
let call_to_expr (node : security_node) : expr =
  let loc = make_range node.line node.column (String.length node.name) in
  let fn_expr = dotted_to_expr ~loc node.name in
  let args = List.map (fun a -> arg_to_expr a loc) node.args in
  { expr_value = EApp (fn_expr, args); expr_location = loc }

(** Convert an assign node to an ELet expression *)
let assign_to_expr (node : security_node) : expr =
  let loc = make_range node.line node.column (String.length node.name) in
  let target = PVar node.name in
  let value_expr = match node.args with
    | [a] -> arg_to_expr a loc
    | _ -> { expr_value = EBlock (List.map (fun a -> arg_to_expr a loc) node.args); expr_location = loc }
  in
  { expr_value = ELet (target, value_expr, { expr_value = EUnit; expr_location = loc }); expr_location = loc }

(** Convert a control node to an expression *)
let control_to_expr (node : security_node) : expr =
  let loc = make_range node.line node.column (String.length node.name) in
  { expr_value = EUnknown ("control:" ^ node.name); expr_location = loc }

(** Convert a terminator node (return, next, break) *)
let terminator_to_expr (node : security_node) : expr =
  let loc = make_range node.line node.column (String.length node.name) in
  { expr_value = EUnknown ("terminator:" ^ node.name); expr_location = loc }

(** Convert any statement node to an expression *)
let stmt_to_expr (node : security_node) : expr option =
  match node.node_type with
  | "call" -> Some (call_to_expr node)
  | "assign" -> Some (assign_to_expr node)
  | "control" -> Some (control_to_expr node)
  | "terminator" -> Some (terminator_to_expr node)
  | _ -> None

(* ── Function body reconstruction ──────────────────────────────────── *)

(** Find the line where a function/class/module scope ends.
    This is the line of the next def/class/module/import at the same or lesser indentation,
    or the end of the file. *)
let find_scope_end (nodes : security_node list) (def_idx : int) : int =
  let def_node = List.nth nodes def_idx in
  let def_line = def_node.line in
  let rec scan idx =
    if idx >= List.length nodes then max_int
    else
      let node = List.nth nodes idx in
      if idx > def_idx && node.line > def_line then
        match node.node_type with
        | "def" | "class" | "module" -> node.line
        | _ -> scan (idx + 1)
      else scan (idx + 1)
  in
  scan (def_idx + 1)

(** Collect body expressions for a function, given its line range *)
let collect_body (nodes : security_node list) (start_line : int) (end_line : int) : expr list =
  List.filter_map (fun node ->
    if node.line > start_line && node.line < end_line then
      stmt_to_expr node
    else None
  ) nodes

(* ── Build items ───────────────────────────────────────────────────── *)

(** Build top-level items from the flat node list *)
let build_items (nodes : security_node list) : item list =
  let items = ref [] in
  let nodes_array = Array.of_list nodes in
  let node_count = Array.length nodes_array in
  
  (* For each def, find its body *)
  Array.iteri (fun idx node ->
    let loc = make_range node.line node.column (String.length node.name) in
    match node.node_type with
    | "def" ->
        (* Find the end of this function scope *)
        let end_line = ref max_int in
        for j = idx + 1 to node_count - 1 do
          let n = nodes_array.(j) in
          if n.node_type = "def" && !end_line = max_int then
            end_line := n.line
        done;
        
        let body_exprs = collect_body nodes node.line !end_line in
        let body = match body_exprs with
          | [] -> { expr_value = EUnit; expr_location = loc }
          | [e] -> e
          | es -> { expr_value = EBlock es; expr_location = loc }
        in
        let params = List.map (fun a -> PVar a.value) node.args in
        items := { item_value = IFunction (node.name, params, None, body); item_location = loc } :: !items

    | "class" ->
        items := { item_value = IClass (node.name, []); item_location = loc } :: !items
    | "module" ->
        items := { item_value = IModule (node.name, []); item_location = loc } :: !items
    | "import" ->
        let module_path = match node.args with
          | [{ value; _ }] -> value
          | _ -> node.name
        in
        items := { item_value = IImport (module_path, None); item_location = loc } :: !items
    | _ -> ()
  ) nodes_array;
  
  List.rev !items

(* ── Parse via Crystal extractor ───────────────────────────────────── *)

let parse_file ~(path : string) : (t, parse_error) result =
  let extractor_cmd =
    try Sys.getenv "CATSEYE_CRYSTAL_EXTRACTOR"
    with Not_found ->
      (* Try the pre-built binary first, fall back to crystal run *)
      let bin_path = Filename.concat (Sys.getcwd ()) "bin/catseye-crystal-extractor" in
      if Sys.file_exists bin_path then bin_path
      else "crystal run src/extractor/extractor.cr --"
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
      let items = build_items nodes in
      Ok { mod_lang = Crystal; mod_path = path; mod_items = items; parse_errors = [] }
  | _ ->
      Error (make_error ~file:path ~message:"Crystal extractor failed")
