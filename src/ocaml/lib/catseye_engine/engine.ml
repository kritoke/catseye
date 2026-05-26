(* lib/catseye_engine/engine.ml *)

open Base

open Catseye_types
open Db
open Seed
open Propagate
open Returns
open Interproc
open Dag

(* Shadow string equality operators for strings *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let version = Catseye_types.Version.version

(** Named constants *)
let dag_visited_size = 16

(** Cross-file taint propagation.
    After per-file analysis, check if any call targets a function defined
    in an imported file that returns tainted data. If so, propagate taint
    to the calling file.
    
    Algorithm:
    1. Build symbol table (fn_name -> defining locations)
    2. Build import map (file -> imported file paths)
    3. For each Assign where RHS is a call to an imported function:
       - If that function returns tainted data in its defining file,
         propagate the taint to the calling file.
*)
let propagate_cross_file (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let sym_tbl = Symbol_table.build nodes in
  let import_map = Symbol_table.build_import_map nodes in
  (* Now propagate: for each assign where RHS is a call,
     check if the called function is defined in an imported file
     and returns tainted data there. *)
  Stdlib.List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else begin
      let file = node.Security_node.file in
      (* Get files imported by this file *)
      let imported_files = try Stdlib.Hashtbl.find import_map file with Stdlib.Not_found -> [] in
      (* Check each call arg *)
      let tainted_call =
        Stdlib.List.find_opt (fun a ->
          if a.Security_node.arg_type <> Security_node.ArgCall then false
          else begin
            let fn_name = a.Security_node.value in
            (* Look up where this function is defined *)
            let defs = Symbol_table.lookup sym_tbl fn_name in
            Stdlib.List.exists (fun sym ->
              (* Is this function defined in an imported file? *)
              Stdlib.List.mem sym.Symbol_table.file imported_files &&
              (* Does it return tainted data in its defining file? *)
              Db.has_record_in_file acc fn_name sym.Symbol_table.file
            ) defs
          end
        ) node.Security_node.args
      in
      match tainted_call with
      | Some a ->
          Db.add_record acc {
            var_name = node.Security_node.name;
            file = node.Security_node.file;
            line = node.Security_node.line;
            description = node.Security_node.name ^
              " assigned from cross-file tainted call: " ^ a.Security_node.value;
            source_var = a.Security_node.value;
            field = None;
            status = Tainted { source = a.Security_node.value;
                              field = None;
                              origin = From_var a.Security_node.value }
          }
      | None -> acc
    end
  ) db nodes

(** Build the full taint database: seed -> propagate -> returns -> interproc -> propagate -> guards *)
let build_taint_db ?(extra_sources = []) (nodes : Security_node.t list) : Db.t =
  let seeded = seed_sources ~extra_sources nodes Db.empty in
  let propagated = propagate nodes seeded in
  let with_returns = track_return_taint nodes propagated in
  let with_interproc = propagate_interprocedural nodes with_returns in
  (* Second pass propagation after inter-procedural *)
  let with_prop2 = propagate nodes with_interproc in
  (* Cross-file propagation: taint from imported functions *)
  let with_cross_file = propagate_cross_file nodes with_prop2 in
  (* Third pass propagation after cross-file *)
  let with_prop3 = propagate nodes with_cross_file in
  (* Apply guards: remove taint from vars validated by guard nodes *)
  let guards = Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Guard) nodes in
  Stdlib.List.fold_left (fun db guard ->
    Db.apply_guard db guard.Security_node.name guard.Security_node.file guard.Security_node.line
  ) with_prop3 guards

(** Build a lookup map from (file, line) to Call node for O(1) sink lookup *)
let build_sink_lookup_map (nodes : Security_node.t list) 
    : (string, Security_node.t) Map.Poly.t =
  Stdlib.List.fold_left (fun m n ->
    if n.Security_node.node_type = Security_node.Call then
      Map.Poly.set m ~key:(n.Security_node.file ^ ":" ^ Int.to_string n.Security_node.line) ~data:n
    else m
  ) Map.Poly.empty nodes

(** Convert a vulnerability DAG to flow steps for a finding.
    Traces paths from entry points toward the sink node using DFS with
    post-order append (via fold_right). After all branches are collected,
    one List.rev puts steps in source → ... → sink order. *)
let dag_to_flow_steps (dag : Catseye_types.Dag_types.vulnerability_dag)
    (_all : Security_node.t list) : Finding.flow_step list =
  let open Catseye_types.Dag_types in
  let node_of_id id = Stdlib.List.find_opt (fun n -> n.id = id) dag.nodes in
  let succs src =
    Stdlib.List.filter_map (fun e ->
      if e.src = src then Some e.dst else None
    ) dag.edges
    |> Stdlib.List.sort Stdlib.String.compare
  in
  let visited = Stdlib.Hashtbl.create dag_visited_size in
  let rec dfs acc node_id =
    if Stdlib.Hashtbl.mem visited node_id then acc
    else begin
      Stdlib.Hashtbl.replace visited node_id true;
      match node_of_id node_id with
      | None -> acc
      | Some n ->
        if node_id = dag.exit_point then
          { Finding.file = n.file; line = n.line; message = n.label } :: acc
        else
          let acc' = { Finding.file = n.file; line = n.line; message = n.label } :: acc in
          let succs_list = succs node_id in
          Stdlib.List.fold_right (fun dst a -> dfs a dst) succs_list acc'
    end
  in
  let steps = Stdlib.List.fold_right (fun entry acc -> dfs acc entry) dag.entry_points [] in
  List.rev steps

(** Run the full analysis pipeline and return findings with populated flow.
    The DAG is built for each finding to trace the taint path.
    Path sensitivity is applied to suppress findings where validation
    scopes cover the sink use. *)
let analyze ?(extra_sources = []) (rules : Catseye_rules.Types.rule_def list)
    (nodes : Security_node.t list) : Finding.t list =
  let db = build_taint_db ~extra_sources nodes in
  let tainted = get_tainted_vars db in
  (* Build file-scoped taint map to prevent cross-file taint bleed *)
  let files =
    Stdlib.List.fold_left (fun acc n ->
      let f = n.Security_node.file in
      if Stdlib.List.mem f acc then acc else f :: acc
    ) [] nodes in
  let by_file = Stdlib.List.map (fun f -> (f, get_tainted_vars_in_file db f)) files in
  let ctx = Catseye_rules.Interpreter.make_taint_context
    ~global:tainted ~by_file
    ~import_map:(Symbol_table.build_import_map nodes)
    () in
  let raw_findings = Catseye_rules.Interpreter.run_all rules nodes ctx in
  (* Build validation scopes for path sensitivity *)
  let validation_scopes = Path_sensitivity.build_validation_scopes nodes in
  (* Precompute sink lookup map for O(1) access per finding *)
  let sink_map = build_sink_lookup_map nodes in
  let results = ref [] in
  Stdlib.List.iter (fun f ->
    (* Check if this finding should be suppressed due to path sensitivity *)
    let suppressed = Path_sensitivity.should_suppress f validation_scopes in
    if suppressed then () (* Skip this finding *)
    else begin
      let key = f.Finding.file ^ ":" ^ Int.to_string f.Finding.line in
      match Map.Poly.find sink_map key with
      | None -> results := f :: !results
      | Some sink ->
        (match build_dag sink db nodes with
         | None -> results := f :: !results
         | Some dag ->
           let flow = dag_to_flow_steps dag nodes in
           results := { f with Finding.flow = flow } :: !results)
    end
  ) raw_findings;
  Stdlib.List.rev !results