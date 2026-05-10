(* lib/catseye_engine/returns.ml *)

open Catseye_types
open Db

(* Find the next def line in the same file after a given line *)
let next_def_line (nodes : Security_node.t list) (file : string) (line : int) : int option =
  nodes
  |> List.filter (fun n ->
    n.Security_node.node_type = Security_node.Def
    && n.Security_node.file = file
    && n.Security_node.line > line
  )
  |> List.map (fun n -> n.Security_node.line)
  |> List.sort compare
  |> function [] -> None | hd :: _ -> Some hd

(* Track functions whose body produces tainted data *)
let track_return_taint (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let defs =
    nodes
    |> List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  in
  List.fold_left (fun acc def ->
    let ndl = next_def_line nodes def.Security_node.file def.Security_node.line in
    let fn_assigns =
      nodes
      |> List.filter (fun n ->
        n.Security_node.node_type = Security_node.Assign
        && n.Security_node.file = def.Security_node.file
        && n.Security_node.line > def.Security_node.line
        && match ndl with
           | Some next_line -> n.Security_node.line < next_line
           | None -> true
      )
    in
    let fn_tainted =
      List.exists (fun n ->
        Db.has_record acc n.Security_node.name || n.Security_node.taint
      ) fn_assigns
    in
    if fn_tainted && not (Db.has_record acc def.Security_node.name) then
      Db.add_record acc {
        var_name = def.Security_node.name
      ; file = def.Security_node.file
      ; line = def.Security_node.line
      ; description = def.Security_node.name ^ " returns tainted data"
      ; source_var = ""
      ; field = None
      ; status = Tainted { source = def.Security_node.name
                          ; field = None
                          ; origin = From_var def.Security_node.name }
      }
    else acc
  ) db defs
