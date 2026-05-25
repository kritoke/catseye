(* lib/catseye_types/finding.ml *)

(** All decode functions use assoc_opt for safety - missing keys get defaults *)

open Base

(* Expose stdlib functions that Base shadows *)
let ( = ) = Stdlib.( = )
let std_list_map = Stdlib.List.map
let std_list_filter_map = Stdlib.List.filter_map
let std_list_assoc_opt = Stdlib.List.assoc_opt

type flow_step = {
  file : string;
  line : int;
  message : string;
} [@@deriving sexp]

type reachability_status =
  | Live
  | Dormant
  | Safe
[@@deriving sexp]

type reachability = {
  status : reachability_status;
  entry_point : string option;
  entry_function : string option;
  path_length : int;
  path : (string * int) list;
} [@@deriving sexp]

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
  suggestion : string option;
} [@@deriving sexp]

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
  let with_path = if r.path = [] then with_func else
    ("path", `List (std_list_map (fun (f, l) ->
      `Assoc [("file", `String f); ("line", `Int l)]
    ) r.path)) :: with_func
  in
  `Assoc with_path

let encode (f : t) : Yojson.Safe.t =
  let base =
    [ ("rule", `String f.rule)
    ; ("severity", `String f.severity)
    ; ("file", `String f.file)
    ; ("line", `Int f.line)
    ; ("message", `String f.message)
    ; ("flow", `List (std_list_map encode_flow_step f.flow))
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
  let with_suggestion = match f.suggestion with
    | Some s -> ("suggestion", `String s) :: with_reach
    | None -> with_reach
  in
  `Assoc with_suggestion

let encode_many (findings : t list) : Yojson.Safe.t =
  `List (std_list_map encode findings)

(* JSON decoding *)
let decode_flow_step (json : Yojson.Safe.t) : flow_step =
  let get = Yojson.Safe.Util.to_string in
  let int_val = Yojson.Safe.Util.to_int in
  match json with
  | `Assoc dict ->
    { file = (match std_list_assoc_opt "file" dict with Some v -> get v | _ -> "");
      line = (match std_list_assoc_opt "line" dict with Some v -> int_val v | _ -> 0);
      message = (match std_list_assoc_opt "message" dict with Some v -> get v | _ -> "") }
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
    let status = (match std_list_assoc_opt "status" dict with
      | Some v -> decode_reachability_status (get v)
      | None -> Dormant) in
    let entry_point = (match std_list_assoc_opt "entry_point" dict with
      | Some v -> Some (get v) | None -> None) in
    let entry_function = (match std_list_assoc_opt "entry_function" dict with
      | Some v -> Some (get v) | None -> None) in
    let path_length = (match std_list_assoc_opt "path_length" dict with
      | Some v -> int_val v | None -> 0) in
    let path = (match std_list_assoc_opt "path" dict with
      | Some (`List items) ->
        std_list_filter_map (function
          | `Assoc d ->
            (match std_list_assoc_opt "file" d with
             | Some f ->
               let line = (match std_list_assoc_opt "line" d with
                 | Some l -> int_val l | _ -> 0) in
               Some (get f, line)
             | _ -> None)
          | _ -> None)
        items
      | _ -> [])
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
    let flow_json = (match std_list_assoc_opt "flow" dict with
      | Some v -> v | None -> `List []) in
    let dep = (match std_list_assoc_opt "dependency" dict with
      | Some (`String s) -> Some s | _ -> None) in
    let reach = (match std_list_assoc_opt "reachability" dict with
      | Some r -> Some (decode_reachability r) | None -> None) in
    { rule = (match std_list_assoc_opt "rule" dict with Some v -> get v | _ -> "");
      severity = (match std_list_assoc_opt "severity" dict with Some v -> get v | _ -> "");
      file = (match std_list_assoc_opt "file" dict with Some v -> get v | _ -> "");
      line = (match std_list_assoc_opt "line" dict with Some v -> int_val v | _ -> 0);
      message = (match std_list_assoc_opt "message" dict with Some v -> get v | _ -> "");
      flow = std_list_map decode_flow_step (Yojson.Safe.Util.to_list flow_json);
      language = "";
      dependency = dep;
      reachability = reach;
      suggestion = (match std_list_assoc_opt "suggestion" dict with
        | Some (`String s) -> Some s | _ -> None) }
  | _ ->
    { rule = ""; severity = ""; file = ""; line = 0
    ; message = ""; flow = []; language = ""; dependency = None
    ; reachability = None; suggestion = None }

let decode_many (json : Yojson.Safe.t) : t list =
  std_list_map decode (Yojson.Safe.Util.to_list json)