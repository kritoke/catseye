(* lib/catseye_engine/engine.ml *)

open Catseye_types
open Db
open Seed
open Propagate
open Returns
open Interproc

let version = "0.3.0"

(** Build the full taint database: seed → propagate → returns → interproc → propagate again *)
let build_taint_db ?(extra_sources = []) (nodes : Security_node.t list) : Db.t =
  let seeded = seed_sources ~extra_sources nodes Db.empty in
  let propagated = propagate nodes seeded in
  let with_returns = track_return_taint nodes propagated in
  let with_interproc = propagate_interprocedural nodes with_returns in
  (* Second pass propagation after inter-procedural *)
  propagate nodes with_interproc

(** Run the full analysis pipeline and return findings *)
let analyze ?(extra_sources = []) (rules : Catseye_rules.Types.rule_def list)
    (nodes : Security_node.t list) : Finding.t list =
  let db = build_taint_db ~extra_sources nodes in
  let tainted = get_tainted_vars db in
  Catseye_rules.Interpreter.run_all rules nodes tainted
