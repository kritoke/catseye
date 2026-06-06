(* lib/catseye_rules/loader.ml *)

open Base
let ( = ) = Stdlib.( = )
open Types

(* Helper: get string value from a property list *)
let get_prop (props : Kdl.prop list) (key : string) : string option =
  List.find_map ~f:(fun (k, (_, v)) ->
    if k = key then
      match v with
      | `String s -> Some s
      | #Kdl.Num.t as n -> Some (Kdl.Num.to_string n)
      | _ -> None
    else None
  ) props

(* Helper: get string value from first positional argument *)
let get_first_arg (args : Kdl.annot_value list) : string option =
  match args with
  | [(_, `String s)] -> Some s
  | _ -> None

let parse_sinks_node (node : Kdl.node) : sink_def list =
  let pattern = match get_first_arg node.args with
    | Some s -> s
    | None -> node.name
  in
  let sanitizers =
    node.children
    |> List.filter_map ~f:(fun (child : Kdl.node) ->
      if child.name = "sanitizer" then
        get_first_arg child.args
      else None
    )
  in
  let requires_field = get_prop node.props "requires_field" in
  let arg_pos = match get_prop node.props "arg" with
    | Some s -> (try Some (Int.of_string s) with _ -> None)
    | None -> None
  in
  let match_mode = match get_prop node.props "match" with
    | Some "exact" -> Exact
    | _ -> Substring
  in
  let fix_template = match get_prop node.props "fix" with
    | Some f -> Some f
    | None ->
      node.children
      |> List.find_map ~f:(fun (child : Kdl.node) ->
        if child.name = "fix" then get_first_arg child.args else None)
  in
  [{ pattern; match_mode; sanitizers; requires_field; arg_pos; fix_template }]

let parse_sources_node (node : Kdl.node) : source_def list =
  let name = match get_first_arg node.args with
    | Some s -> s
    | None -> node.name
  in
  let field = get_prop node.props "field" in
  [{ name; field }]

let parse_languages (children : Kdl.node list) : string list * string list =
  let excludes, includes =
    List.fold_left ~init:([], []) ~f:(fun (excl, incl) (child : Kdl.node) ->
      let val_of = get_first_arg child.args in
      match child.name with
      | "exclude" -> (match val_of with Some s -> (s :: excl, incl) | None -> (excl, incl))
      | "include" -> (match val_of with Some s -> (excl, s :: incl) | None -> (excl, incl))
      | _ -> (excl, incl)
    ) children
  in
  (excludes, includes)

let parse_conditions (children : Kdl.node list) : conditions =
  let known = ["skip_taint_check"; "skip_all_literals"; "check_args_contain"; "check_args_missing"] in
  List.fold_left ~init:(default_conditions ()) ~f:(fun acc (child : Kdl.node) ->
    match child.name with
    | "skip_taint_check" ->
      { acc with requires_tainted_args = false }
    | "skip_all_literals" ->
      { acc with skip_all_literals = true }
    | "check_args_contain" ->
      let pattern = match get_first_arg child.args with
        | Some s -> s
        | None -> ""
      in
      { acc with check_args_contain = pattern :: acc.check_args_contain }
    | "check_args_missing" ->
      let pattern = match get_first_arg child.args with
        | Some s -> s
        | None -> ""
      in
      { acc with check_args_missing = pattern :: acc.check_args_missing }
    | k when List.mem known ~equal:String.equal k ->
      { acc with extensions = (k, "true") :: acc.extensions }
    | k ->
      let v = match get_first_arg child.args with
        | Some s -> s
        | None -> match get_prop child.props "value" with
          | Some s -> s
          | None -> "true"
      in
      Logs.warn (fun m -> m "Unknown rule condition '%s' (value='%s'); ignoring" k v);
      { acc with extensions = (k, v) :: acc.extensions }
  ) children

let parse_rule_node (node : Kdl.node) : rule_def option =
  let id = match get_first_arg node.args with
    | Some s -> s
    | None -> node.name
  in
  let severity = match get_prop node.props "severity" with
    | Some s -> s
    | None -> "Medium"
  in
  let sinks, sources, conds, message =
    List.fold_left ~init:([], [], default_conditions (), "") ~f:(fun (sinks, sources, conds, msg) (child : Kdl.node) ->
      match child.name with
      | "sinks" ->
        let new_sinks = List.concat_map ~f:parse_sinks_node child.children in
        (new_sinks @ sinks, sources, conds, msg)
      | "sources" ->
        let new_sources = List.concat_map ~f:parse_sources_node child.children in
        (sinks, new_sources @ sources, conds, msg)
      | "conditions" ->
        let c = parse_conditions child.children in
        (sinks, sources, c, msg)
      | "languages" ->
        let excl, incl = parse_languages child.children in
        let c = { conds with exclude_languages = excl; include_languages = incl } in
        (sinks, sources, c, msg)
      | "message" ->
        let msg_text = match get_first_arg child.args with
          | Some s -> s
          | None -> Kdl.to_string [node]
        in
        (sinks, sources, conds, msg_text)
      | _ -> (sinks, sources, conds, msg)
    ) node.children
  in
  if id = "" then None
  else Some { id; severity; sinks; sources; conditions = conds; message_template = message }

let parse_string (content : string) : (rule_def list, [> `Msg of string ]) Result.t =
  match Kdl.of_string content with
  | Ok doc ->
    let rules = List.filter_map ~f:parse_rule_node doc in
    Ok rules
  | Error (msg, _) ->
    Error (`Msg (Printf.sprintf "KDL parse error: %s" msg))

let load_default_rules () : (rule_def list, [> `Msg of string ]) Result.t =
  let content = Default_rules.get_all_kdl () in
  match Kdl.of_string content with
  | Ok doc ->
    let rules = List.filter_map ~f:parse_rule_node doc in
    Ok rules
  | Error (msg, _) ->
    Error (`Msg (Printf.sprintf "Default rules parse error: %s" msg))

let load_rules (path : string) : (rule_def list, [> `Msg of string ]) Result.t =
  if not (Stdlib.Sys.file_exists path) then begin
    Logs.info (fun m -> m "Rules not found at '%s', using embedded defaults" path);
    load_default_rules ()
  end else if Stdlib.Sys.is_directory path then begin
    let files =
      Stdlib.Sys.readdir path
      |> Array.to_list
      |> List.filter ~f:(fun f -> Stdlib.Filename.check_suffix f ".kdl")
      |> List.sort ~compare:String.compare
    in
    let rules = List.concat_map ~f:(fun f ->
      let full_path = Stdlib.Filename.concat path f in
      let ic = Stdlib.open_in full_path in
      let len = Stdlib.in_channel_length ic in
      let buf = Bytes.create len in
      Stdlib.really_input ic buf 0 len;
      Stdlib.close_in ic;
      let content = Bytes.to_string buf in
      match parse_string content with
      | Ok r -> r
      | Error (`Msg msg) ->
        Logs.warn (fun m -> m "Warning: skipping %s: %s" full_path msg);
        []
    ) files in
    Ok rules
  end else begin
    let ic = Stdlib.open_in path in
    let len = Stdlib.in_channel_length ic in
    let buf = Bytes.create len in
    Stdlib.really_input ic buf 0 len;
    Stdlib.close_in ic;
    parse_string (Bytes.to_string buf)
  end
