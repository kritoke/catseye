(* lib/catseye_engine/engine.ml *)

open Catseye_types
open Db
open Seed
open Propagate
open Returns
open Interproc
open Dag

let version = "0.3.0"

(** Named constants *)
let dag_visited_size = 16

(** Build the full taint database: seed → propagate → returns → interproc → propagate again *)
let build_taint_db ?(extra_sources = []) (nodes : Security_node.t list) : Db.t =
  let seeded = seed_sources ~extra_sources nodes Db.empty in
  let propagated = propagate nodes seeded in
  let with_returns = track_return_taint nodes propagated in
  let with_interproc = propagate_interprocedural nodes with_returns in
  (* Second pass propagation after inter-procedural *)
  propagate nodes with_interproc

(** Build a lookup map from (file, line) to Call node for O(1) sink lookup *)
let build_sink_lookup_map (nodes : Security_node.t list) 
    : Security_node.t StringMap.t =
  List.fold_left (fun m n ->
    if n.Security_node.node_type = Security_node.Call then
      StringMap.add (n.Security_node.file ^ ":" ^ string_of_int n.Security_node.line) n m
    else m
  ) StringMap.empty nodes

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
  let visited = Hashtbl.create dag_visited_size in
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
  (* Precompute sink lookup map for O(1) access per finding *)
  let sink_map = build_sink_lookup_map nodes in
  let results = ref [] in
  List.iter (fun f ->
    let key = f.Finding.file ^ ":" ^ string_of_int f.Finding.line in
    match StringMap.find_opt key sink_map with
    | None -> results := f :: !results
    | Some sink ->
      (match build_dag sink db nodes with
       | None -> results := f :: !results
       | Some dag ->
         let flow = dag_to_flow_steps dag nodes in
         results := { f with Finding.flow = flow } :: !results)
  ) raw_findings;
  List.rev !results