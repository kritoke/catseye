(* lib/catseye_engine/engine.ml *)

open Catseye_types
open Db
open Seed
open Propagate
open Returns
open Interproc
open Dag

let version = "0.3.0"

(** Build the full taint database: seed → propagate → returns → interproc → propagate again *)
let build_taint_db ?(extra_sources = []) (nodes : Security_node.t list) : Db.t =
  let seeded = seed_sources ~extra_sources nodes Db.empty in
  let propagated = propagate nodes seeded in
  let with_returns = track_return_taint nodes propagated in
  let with_interproc = propagate_interprocedural nodes with_returns in
  (* Second pass propagation after inter-procedural *)
  propagate nodes with_interproc

(** Convert a vulnerability DAG to flow steps for a finding.
    Traces paths from entry points toward the sink node using DFS with
    post-order append (via fold_right). After all branches are collected,
    one List.rev puts steps in source → ... → sink order. *)
let dag_to_flow_steps (dag : Catseye_types.Dag_types.vulnerability_dag)
    (_all : Security_node.t list) : Finding.flow_step list =
  let open Catseye_types.Dag_types in
  let node_of_id id = List.find_opt (fun n -> n.id = id) dag.nodes in
  let succs src =
    List.filter_map (fun e ->
      if e.src = src then Some e.dst else None
    ) dag.edges
    |> List.sort String.compare
  in
  let visited = Hashtbl.create 16 in
  let rec dfs acc node_id =
    if Hashtbl.mem visited node_id then acc
    else begin
      Hashtbl.replace visited node_id true;
      match node_of_id node_id with
      | None -> acc
      | Some n ->
        if node_id = dag.exit_point then
          { Finding.file = n.file; line = n.line; message = n.label } :: acc
        else
          let acc' = { Finding.file = n.file; line = n.line; message = n.label } :: acc in
          List.fold_right (fun dst a -> dfs a dst) (succs node_id) acc'
    end
  in
  let steps = List.fold_right (fun entry acc -> dfs acc entry) dag.entry_points [] in
  List.rev steps

(** Run the full analysis pipeline and return findings with populated flow.
    The DAG is built for each finding to trace the taint path. *)
let analyze ?(extra_sources = []) (rules : Catseye_rules.Types.rule_def list)
    (nodes : Security_node.t list) : Finding.t list =
  let db = build_taint_db ~extra_sources nodes in
  let tainted = get_tainted_vars db in
  let raw_findings = Catseye_rules.Interpreter.run_all rules nodes tainted in
  (* Populate flow steps by building a DAG for each finding *)
  List.map (fun f ->
    let sink_node = List.find_opt (fun n ->
      n.Security_node.node_type = Security_node.Call
      && n.Security_node.file = f.Finding.file
      && n.Security_node.line = f.Finding.line
    ) nodes in
    match sink_node with
    | None -> f
    | Some sink ->
      match build_dag sink db nodes with
      | None -> f
      | Some dag -> { f with Finding.flow = dag_to_flow_steps dag nodes }
  ) raw_findings