(* lib/catseye_types/security_node.ml *)

type node_type =
  | Call
  | Assign
  | Def
  | Var
  | Literal
  | Import
  | Guard
  | Class
  | Module
  | Enum
  | Control
  | Terminator
  (* Security-specific node types *)
  | IgnoredReturn
  | NonAtomicFileOp
  | UnboundedRead
  | TOCTOU

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
  language : string;  (* "gleam", "crystal", etc. *)
  metadata : (string * string) list;  (* extensible key-value pairs *)
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
  | "import" -> Import
  | "guard" -> Guard
  | "class" -> Class
  | "module" -> Module
  | "enum" -> Enum
  | "control" -> Control
  | "terminator" -> Terminator
  | "ignored_return" -> IgnoredReturn
  | "non_atomic_file_op" -> NonAtomicFileOp
  | "unbounded_read" -> UnboundedRead
  | "toctou" -> TOCTOU
  | _ -> Call

let string_of_node_type = function
  | Call -> "call"
  | Assign -> "assign"
  | Def -> "def"
  | Var -> "var"
  | Literal -> "literal"
  | Import -> "import"
  | Guard -> "guard"
  | Class -> "class"
  | Module -> "module"
  | Enum -> "enum"
  | Control -> "control"
  | Terminator -> "terminator"
  | IgnoredReturn -> "ignored_return"
  | NonAtomicFileOp -> "non_atomic_file_op"
  | UnboundedRead -> "unbounded_read"
  | TOCTOU -> "toctou"

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

let decode_metadata (json : Yojson.Safe.t) : (string * string) list =
  match json with
  | `Assoc pairs ->
    List.filter_map (fun (k, v) ->
      match v with
      | `String s -> Some (k, s)
      | `Bool b -> Some (k, string_of_bool b)
      | `Int i -> Some (k, string_of_int i)
      | _ -> None
    ) pairs
  | _ -> []

let decode (json : Yojson.Safe.t) : t =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  let bool_val = Yojson.Safe.Util.to_bool in
  let to_list = Yojson.Safe.Util.to_list in
  let get_opt key dict default = 
    match List.assoc_opt key dict with
    | Some v -> get v
    | None -> default
  in
  match json with
  | `Assoc dict ->
    let args_json = List.assoc "args" dict in
    let metadata = match List.assoc_opt "metadata" dict with
      | Some m -> decode_metadata m
      | None -> []
    in
    (* Support both "node_type" (from Crystal extractor) and "type" (from other sources) *)
    let node_type_str = get_opt "node_type" dict (get_opt "type" dict "call") in
    { node_type = node_type_of_string node_type_str
    ; name = get (List.assoc "name" dict)
    ; args = List.map decode_arg (to_list args_json)
    ; line = int_val (List.assoc "line" dict)
    ; taint = bool_val (List.assoc "taint" dict)
    ; file = get (List.assoc "file" dict)
    ; language = (match List.assoc_opt "language" dict with
                  | Some v -> get v | None -> "")
    ; metadata
    }
  | _ ->
    { node_type = Call; name = ""; args = []; line = 0; taint = false; file = ""; language = ""; metadata = [] }

let decode_many (json : Yojson.Safe.t) : t list =
  Yojson.Safe.Util.to_list json |> List.map decode

(* JSON encoding *)
let encode_arg (a : arg) : Yojson.Safe.t =
  `Assoc
    [ ("arg_type", `String (string_of_arg_type a.arg_type))
    ; ("value", `String a.value)
    ; ("field", `String a.field)
    ]

let encode_metadata (md : (string * string) list) : Yojson.Safe.t =
  `Assoc (List.map (fun (k, v) -> (k, `String v)) md)

let encode (n : t) : Yojson.Safe.t =
  let base =
    [ ("type", `String (string_of_node_type n.node_type))
    ; ("name", `String n.name)
    ; ("args", `List (List.map encode_arg n.args))
    ; ("line", `Int n.line)
    ; ("taint", `Bool n.taint)
    ; ("file", `String n.file)
    ; ("language", `String n.language)
    ]
  in
  if n.metadata = [] then `Assoc base
  else `Assoc (base @ [("metadata", encode_metadata n.metadata)])

let encode_many (nodes : t list) : Yojson.Safe.t =
  `List (List.map encode nodes)

(** Get a metadata value from a node *)
let get_metadata (node : t) (key : string) : string option =
  List.find_opt (fun (k, _) -> k = key) node.metadata
  |> Option.map snd

(** Check if a node has a metadata key set to "true" *)
let has_metadata_flag (node : t) (key : string) : bool =
  match get_metadata node key with
  | Some "true" -> true
  | _ -> false
