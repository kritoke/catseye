(* lib/catseye_types/security_node.ml *)

type node_type =
  | Call
  | Assign
  | Def
  | Var
  | Literal

type arg_type =
  | ArgVar
  | ArgLiteral
  | ArgCall
  | ArgUnknown

type arg = {
  arg_type : arg_type;
  value : string;
  field : string;
}

type t = {
  node_type : node_type;
  name : string;
  args : arg list;
  line : int;
  taint : bool;
  file : string;
}

let arg_type_of_string = function
  | "var" -> ArgVar
  | "literal" -> ArgLiteral
  | "call" -> ArgCall
  | _ -> ArgUnknown

let string_of_arg_type = function
  | ArgVar -> "var"
  | ArgLiteral -> "literal"
  | ArgCall -> "call"
  | ArgUnknown -> "unknown"

let node_type_of_string = function
  | "call" -> Call
  | "assign" -> Assign
  | "def" -> Def
  | "var" -> Var
  | "literal" -> Literal
  | _ -> Call

let string_of_node_type = function
  | Call -> "call"
  | Assign -> "assign"
  | Def -> "def"
  | Var -> "var"
  | Literal -> "literal"

(* JSON decoding *)
let decode_arg (json : Yojson.Safe.t) : arg =
  let get = Yojson.Safe.Util.to_string in
  let field_opt key dict =
    match List.assoc_opt key dict with
    | Some v -> get v
    | None -> ""
  in
  match json with
  | `Assoc dict ->
    { arg_type = arg_type_of_string (get (List.assoc "arg_type" dict))
    ; value = get (List.assoc "value" dict)
    ; field = field_opt "field" dict
    }
  | _ ->
    { arg_type = ArgUnknown; value = ""; field = "" }

let decode (json : Yojson.Safe.t) : t =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  let bool_val = Yojson.Safe.Util.to_bool in
  let to_list = Yojson.Safe.Util.to_list in
  match json with
  | `Assoc dict ->
    let args_json = List.assoc "args" dict in
    { node_type = node_type_of_string (get (List.assoc "type" dict))
    ; name = get (List.assoc "name" dict)
    ; args = List.map decode_arg (to_list args_json)
    ; line = int_val (List.assoc "line" dict)
    ; taint = bool_val (List.assoc "taint" dict)
    ; file = get (List.assoc "file" dict)
    }
  | _ ->
    { node_type = Call; name = ""; args = []; line = 0; taint = false; file = "" }

let decode_many (json : Yojson.Safe.t) : t list =
  Yojson.Safe.Util.to_list json |> List.map decode

(* JSON encoding *)
let encode_arg (a : arg) : Yojson.Safe.t =
  `Assoc
    [ ("arg_type", `String (string_of_arg_type a.arg_type))
    ; ("value", `String a.value)
    ; ("field", `String a.field)
    ]

let encode (n : t) : Yojson.Safe.t =
  `Assoc
    [ ("type", `String (string_of_node_type n.node_type))
    ; ("name", `String n.name)
    ; ("args", `List (List.map encode_arg n.args))
    ; ("line", `Int n.line)
    ; ("taint", `Bool n.taint)
    ; ("file", `String n.file)
    ]

let encode_many (nodes : t list) : Yojson.Safe.t =
  `List (List.map encode nodes)
