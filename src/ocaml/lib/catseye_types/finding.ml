(* lib/catseye_types/finding.ml *)

type flow_step = {
  file : string;
  line : int;
  message : string;
}

type t = {
  rule : string;
  severity : string;
  file : string;
  line : int;
  message : string;
  flow : flow_step list;
  language : string;
  dependency : string option;
}

(* JSON encoding *)
let encode_flow_step (s : flow_step) : Yojson.Safe.t =
  `Assoc
    [ ("file", `String s.file)
    ; ("line", `Int s.line)
    ; ("message", `String s.message)
    ]

let encode (f : t) : Yojson.Safe.t =
  let base =
    [ ("rule", `String f.rule)
    ; ("severity", `String f.severity)
    ; ("file", `String f.file)
    ; ("line", `Int f.line)
    ; ("message", `String f.message)
    ; ("flow", `List (List.map encode_flow_step f.flow))
    ]
  in
  match f.dependency with
  | Some dep -> `Assoc (("dependency", `String dep) :: base)
  | None -> `Assoc base

let encode_many (findings : t list) : Yojson.Safe.t =
  `List (List.map encode findings)

(* JSON decoding *)
let decode_flow_step (json : Yojson.Safe.t) : flow_step =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  match json with
  | `Assoc dict ->
    { file = get (List.assoc "file" dict)
    ; line = int_val (List.assoc "line" dict)
    ; message = get (List.assoc "message" dict)
    }
  | _ ->
    { file = ""; line = 0; message = "" }

let decode (json : Yojson.Safe.t) : t =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  match json with
  | `Assoc dict ->
    let flow_json = List.assoc "flow" dict in
    let dep = match List.assoc_opt "dependency" dict with
      | Some (`String s) -> Some s
      | _ -> None
    in
    { rule = get (List.assoc "rule" dict)
    ; severity = get (List.assoc "severity" dict)
    ; file = get (List.assoc "file" dict)
    ; line = int_val (List.assoc "line" dict)
    ; message = get (List.assoc "message" dict)
    ; flow = List.map decode_flow_step (Yojson.Safe.Util.to_list flow_json)
    ; language = ""
    ; dependency = dep
    }
  | _ ->
    { rule = ""; severity = ""; file = ""; line = 0
    ; message = ""; flow = []; language = ""; dependency = None }

let decode_many (json : Yojson.Safe.t) : t list =
  Yojson.Safe.Util.to_list json |> List.map decode
