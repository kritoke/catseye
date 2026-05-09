(* lib/catseye_rules/loader.ml *)

open Types

(* Helper: get string value from a property list *)
let get_prop (props : Kdl.prop list) (key : string) : string option =
  List.find_map (fun (k, (_, v)) ->
    if k = key then
      match v with
      | `String s -> Some s
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
    |> List.filter_map (fun (child : Kdl.node) ->
      if child.name = "sanitizer" then
        get_first_arg child.args
      else None
    )
  in
  let requires_field = get_prop node.props "requires_field" in
  [{ pattern; sanitizers; requires_field }]

let parse_sources_node (node : Kdl.node) : source_def list =
  let name = match get_first_arg node.args with
    | Some s -> s
    | None -> node.name
  in
  let field = get_prop node.props "field" in
  [{ name; field }]

let parse_conditions (children : Kdl.node list) : conditions =
  List.fold_left (fun acc (child : Kdl.node) ->
    match child.name with
    | "requires_tainted_args" ->
      { acc with requires_tainted_args = true }
    | "skip_all_literals" ->
      { acc with skip_all_literals = true }
    | k ->
      let v = match get_first_arg child.args with
        | Some s -> s
        | None -> match get_prop child.props "value" with
          | Some s -> s
          | None -> "true"
      in
      { acc with extensions = (k, v) :: acc.extensions }
  ) (default_conditions ()) children

let parse_rule_node (node : Kdl.node) : rule_def option =
  (* Node name is "rule", actual id is first positional arg *)
  let id = match get_first_arg node.args with
    | Some s -> s
    | None -> node.name
  in
  let severity = match get_prop node.props "severity" with
    | Some s -> s
    | None -> "Medium"
  in
  let sinks, sources, conds, message =
    List.fold_left (fun (sinks, sources, conds, msg) (child : Kdl.node) ->
      match child.name with
      | "sinks" ->
        let new_sinks = List.concat_map parse_sinks_node child.children in
        (new_sinks @ sinks, sources, conds, msg)
      | "sources" ->
        let new_sources = List.concat_map parse_sources_node child.children in
        (sinks, new_sources @ sources, conds, msg)
      | "conditions" ->
        let c = parse_conditions child.children in
        (sinks, sources, c, msg)
      | "message" ->
        let msg_text = match get_first_arg child.args with
          | Some s -> s
          | None -> Kdl.to_string [node]
        in
        (sinks, sources, conds, msg_text)
      | _ -> (sinks, sources, conds, msg)
    ) ([], [], default_conditions (), "") node.children
  in
  if id = "" then None
  else Some { id; severity; sinks; sources; conditions = conds; message_template = message }

let parse_string (content : string) : (rule_def list, [> `Msg of string ]) result =
  match Kdl.of_string content with
  | Ok doc ->
    let rules = List.filter_map parse_rule_node doc in
    Ok rules
  | Error (msg, _) ->
    Error (`Msg (Printf.sprintf "KDL parse error: %s" msg))

let load_rules (path : string) : (rule_def list, [> `Msg of string ]) result =
  if not (Sys.file_exists path) then
    Error (`Msg (Printf.sprintf "Rules directory not found: %s" path))
  else if Sys.is_directory path then begin
    let files =
      Sys.readdir path
      |> Array.to_list
      |> List.filter (fun f -> Filename.check_suffix f ".kdl")
      |> List.sort String.compare
    in
    let rules = List.concat_map (fun f ->
      let full_path = Filename.concat path f in
      let ic = open_in full_path in
      let len = in_channel_length ic in
      let buf = Bytes.create len in
      really_input ic buf 0 len;
      close_in ic;
      let content = Bytes.to_string buf in
      match parse_string content with
      | Ok r -> r
      | Error (`Msg msg) ->
        Logs.warn (fun m -> m "Warning: skipping %s: %s" full_path msg);
        []
    ) files in
    Ok rules
  end else
    let ic = open_in path in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    parse_string (Bytes.to_string buf)
