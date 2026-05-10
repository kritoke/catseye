(* lib/catseye_engine/dag.ml
   Build vulnerability DAGs from taint analysis results.
   Replaces linear flow traces with directed acyclic graphs. *)

open Catseye_types
open Catseye_types.Dag_types
open Db

(** Build a vulnerability DAG from a sink call and the taint DB.
    Walks backwards from the sink through the taint chain to find sources. *)
let build_dag (sink : Security_node.t) (db : Db.t)
    (all : Security_node.t list) : vulnerability_dag option =
  let tainted_vars = get_tainted_vars_in_file db sink.file in
  let relevant =
    List.filter (fun v ->
      List.exists (fun a ->
        a.Security_node.arg_type = Security_node.ArgVar && a.Security_node.value = v
      ) sink.args
    ) tainted_vars in
  match relevant with [] -> None | _ ->

  let sink_id = "sink" in
  let sink_node : dag_node = {
    id = sink_id; label = sink.name; node_type = `Sink;
    file = sink.file; line = sink.line
  } in

  (* Find assignment that defines a variable *)
  let find_assign var =
    List.find_opt (fun n ->
      n.Security_node.node_type = Security_node.Assign
      && n.Security_node.name = var
      && n.Security_node.file = sink.file
    ) all
  in

  (* Check if var is a function parameter *)
  let is_param var =
    List.exists (fun n ->
      n.Security_node.node_type = Security_node.Def
      && List.exists (fun a -> a.Security_node.value = var) n.Security_node.args
    ) all
  in

  (* Trace a single var backwards; returns (nodes, edges, entry_point_ids) *)
  let counter = ref 0 in
  let fresh () = incr counter; Printf.sprintf "n%d" !counter in

  let rec trace var =
    match find_assign var with
    | None when is_param var ->
      let id = fresh () in
      ([ { id; label = var; node_type = `Source; file = sink.file; line = 0 } ],
       [],
       [id])
    | None ->
      ([], [], [])
    | Some assign ->
      let id = fresh () in
      let propagator : dag_node = {
        id; label = Printf.sprintf "%s = ..." var; node_type = `Propagator;
        file = assign.file; line = assign.line
      } in
      let source_var =
        List.find_opt (fun a -> a.Security_node.arg_type = Security_node.ArgVar) assign.args
        |> Option.map (fun a -> a.Security_node.value) in
      match source_var with
      | None ->
        let src_id = fresh () in
        let src : dag_node = {
          id = src_id; label = var ^ " (source)"; node_type = `Source;
          file = assign.file; line = assign.line
        } in
        ([src; propagator],
         [{ src = src_id; dst = id; label = "defines" }],
         [src_id])
      | Some sv ->
        let (up_nodes, up_edges, entries) = trace sv in
        (propagator :: up_nodes,
         { src = id; dst = sink_id; label = "flows to" } :: up_edges,
         entries)
  in

  let (nodes, edges, entries) =
    List.fold_left (fun (acc_n, acc_e, acc_ent) var ->
      let (ns, es, ents) = trace var in
      (ns @ acc_n, es @ acc_e, ents @ acc_ent)
    ) ([sink_node], [], []) relevant
  in

  Some {
    nodes = List.sort_uniq (fun a b -> String.compare a.id b.id) nodes;
    edges;
    entry_points = List.sort_uniq String.compare entries;
    exit_point = sink_id;
  }
