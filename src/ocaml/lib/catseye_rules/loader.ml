(* lib/catseye_rules/loader.ml *)

open Types

let load_file path =
  let ic = open_in path in
  let content = really_input ic (in_channel_length ic) in
  close_in ic;
  content

let parse_sinks_node (node : Kdl.document_node) : sink_def list =
  let pattern = node.name in
  let sanitizers =
    node.children
    |> List.filter_map (fun (child : Kdl.document_node) ->
      if child.name = "sanitizer" then
        match child.properties with
        | [] -> Some child.name
        | _ -> Some child.name
      else None
    )
  in
  let requires_field =
    node.properties
    |> List.find_opt (fun (k, _) -> k = "requires_field")
    |> Option.map snd
  in
  [{ pattern; sanitizers; requires_field }]

let parse_sources_node (node : Kdl.document_node) : source_def list =
  let name = node.name in
  let field =
    node.properties
    |> List.find_opt (fun (k, _) -> k = "field")
    |> Option.map snd
  in
  [{ name; field }]

let parse_conditions (children : Kdl.document_node list) : conditions =
  List.fold_left (fun acc (child : Kdl.document_node) ->
    match child.name with
    | "requires_tainted_args" ->
      { acc with requires_tainted_args = true }
    | "skip_all_literals" ->
      { acc with skip_all_literals = true }
    | k ->
      let v = match child.properties with
        | [(_, val_str)] -> val_str
        | _ -> child.name
      in
      { acc with extensions = (k, v) :: acc.extensions }
  ) (default_conditions ()) children

let parse_rule_node (node : Kdl.document_node) : rule_def option =
  let id = node.name in
  let severity =
    node.properties
    |> List.find_opt (fun (k, _) -> k = "severity")
    |> Option.map snd
    |> Option.value ~default:"Medium"
  in
  let sinks, sources, conds, message =
    List.fold_left (fun (sinks, sources, conds, msg) (child : Kdl.document_node) ->
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
        let msg_text =
          node.properties
          |> List.find_opt (fun (k, _) -> k = "text")
          |> Option.map snd
          |> Option.value ~default:(String.concat " " (List.map fst node.properties))
        in
        (sinks, sources, conds, msg_text)
      | _ -> (sinks, sources, conds, msg)
    ) ([], [], default_conditions (), "") node.children
  in
  if id = "" then None
  else Some { id; severity; sinks; sources; conditions = conds; message_template = message }

let parse_string (content : string) : (rule_def list, [> `Msg of string ]) result =
  try
    let doc = Kdl.parse_string content in
    let rules = List.filter_map parse_rule_node doc.nodes in
    Ok rules
  with exn ->
    Error (`Msg (Printf.sprintf "KDL parse error: %s" (Printexc.to_string exn)))

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
      let content = load_file full_path in
      match parse_string content with
      | Ok r -> r
      | Error (`Msg msg) ->
        Logs.warn (fun m -> m "Warning: skipping %s: %s" full_path msg);
        []
    ) files in
    Ok rules
  end else
    let content = load_file path in
    parse_string content
