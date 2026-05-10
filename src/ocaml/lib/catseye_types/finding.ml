(* lib/catseye_types/finding.ml *)

type flow_step = {
  file : string;
  line : int;
  message : string;
}

type reachability_status =
  | Live
  | Dormant
  | Safe

type reachability = {
  status : reachability_status;
  entry_point : string option;
  entry_function : string option;
  path_length : int;
  path : (string * int) list;
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
  reachability : reachability option;
}

(* JSON encoding *)
let encode_flow_step (s : flow_step) : Yojson.Safe.t =
  `Assoc
    [ ("file", `String s.file)
    ; ("line", `Int s.line)
    ; ("message", `String s.message)
    ]

let encode_reachability_status = function
  | Live -> `String "live"
  | Dormant -> `String "dormant"
  | Safe -> `String "safe"

let encode_reachability (r : reachability) : Yojson.Safe.t =
  let base = [
    ("status", encode_reachability_status r.status);
    ("path_length", `Int r.path_length);
  ] in
  let with_entry = match r.entry_point with
    | Some ep -> ("entry_point", `String ep) :: base
    | None -> base
  in
  let with_func = match r.entry_function with
    | Some ef -> ("entry_function", `String ef) :: with_entry
    | None -> with_entry
  in
  let with_path = if r.path <> [] then
    ("path", `List (List.map (fun (f, l) ->
      `Assoc [("file", `String f); ("line", `Int l)]
    ) r.path)) :: with_func
  else with_func
  in
  `Assoc with_path

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
  let with_dep = match f.dependency with
    | Some dep -> ("dependency", `String dep) :: base
    | None -> base
  in
  let with_reach = match f.reachability with
    | Some r -> ("reachability", encode_reachability r) :: with_dep
    | None -> with_dep
  in
  `Assoc with_reach

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

let decode_reachability_status = function
  | "live" -> Live
  | "dormant" -> Dormant
  | "safe" -> Safe
  | _ -> Dormant

let decode_reachability (json : Yojson.Safe.t) : reachability =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  match json with
  | `Assoc dict ->
    let status = decode_reachability_status (get (List.assoc "status" dict)) in
    let entry_point = match List.assoc_opt "entry_point" dict with
      | Some v -> Some (get v)
      | None -> None
    in
    let entry_function = match List.assoc_opt "entry_function" dict with
      | Some v -> Some (get v)
      | None -> None
    in
    let path_length = match List.assoc_opt "path_length" dict with
      | Some v -> int_val v
      | None -> 0
    in
    let path = match List.assoc_opt "path" dict with
      | Some (`List items) ->
        List.filter_map (function
          | `Assoc d ->
            Some (get (List.assoc "file" d), int_val (List.assoc "line" d))
          | _ -> None
        ) items
      | _ -> []
    in
    { status; entry_point; entry_function; path_length; path }
  | _ ->
    { status = Dormant; entry_point = None; entry_function = None;
      path_length = 0; path = [] }

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
    let reach = match List.assoc_opt "reachability" dict with
      | Some r -> Some (decode_reachability r)
      | None -> None
    in
    { rule = get (List.assoc "rule" dict)
    ; severity = get (List.assoc "severity" dict)
    ; file = get (List.assoc "file" dict)
    ; line = int_val (List.assoc "line" dict)
    ; message = get (List.assoc "message" dict)
    ; flow = List.map decode_flow_step (Yojson.Safe.Util.to_list flow_json)
    ; language = ""
    ; dependency = dep
    ; reachability = reach
    }
  | _ ->
    { rule = ""; severity = ""; file = ""; line = 0
    ; message = ""; flow = []; language = ""; dependency = None
    ; reachability = None }

let decode_many (json : Yojson.Safe.t) : t list =
  Yojson.Safe.Util.to_list json |> List.map decode
