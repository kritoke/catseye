# CFG Graph Adapter — Spec

## OCamlgraph functor instances for Catseye

### Digraph for CFG

```ocaml
(* cfg_graph.ml *)

(** Vertex type: a basic block, identified by int ID *)
module V = struct
  type t = int
  let compare = compare
  let hash = Hashtbl.hash
  let equal = (==)
end

(** Edge label: transition type between blocks *)
type edge_label =
  | FallThrough          (* sequential flow *)
  | TrueBranch           (* if condition = true *)
  | FalseBranch          (* if condition = false *)
  | Merge                (* join point after branch *)

(** Block content stored externally in a Hashtbl *)
(** We use Abstract imperitive digraph so vertices are just ints,
   and we keep a separate Hashtbl for block content. *)

module CfgGraph = Graph.Imperative.Digraph.Abstract(struct
  type t = int
  let compare = compare
end)

(** Augmented CFG with block content *)
type t = {
  graph : CfgGraph.t;
  entry : CfgGraph.V.t;
  blocks : (CfgGraph.V.t * il_node list) Hashtbl.t;
  fn_name : string;
  fn_params : string list;
  pos : pos;
}
```

### Fixpoint for taint analysis

```ocaml
(** Analysis direction: forward (source → sink) *)
module TaintAnalysis = Graph.Fixpoint.Make(CfgGraph)(struct
  type v = CfgGraph.V.t
  type g = CfgGraph.t

  (** Taint state: set of tainted lvalues *)
  type data = LvalSet.t

  let direction = `Forward

  let equal = LvalSet.equal

  (** Transfer: apply taint rules to block nodes *)
  let transfer graph v state =
    let block_nodes = Hashtbl.find blocks v in
    List.fold_left (apply_taint_rule graph) state block_nodes

  (** Join: union of taint states at merge points *)
  let join = LvalSet.union
end)
```

### Graphviz for DOT output

```ocaml
module CfgDot = Graph.Graphviz.Make(CfgGraph)(struct
  let graph_attributes _ = [`Rankdir `LR; `Fontname "Helvetica"]
  let default_vertex_attributes _ = [`Shape `Box; `Style `Filled]
  let vertex_name v = string_of_int v
  let vertex_attributes v =
    match classify v with
    | Entry -> [`Color "#4CAF50"; `Shape `Diamond]
    | Sink rule -> [`Color "#F44336"; `Label (v_name ^ "\\n[" ^ rule ^ "]")]
    | Reachable -> [`Color "#2196F3"]
    | Dormant -> [`Color "#9E9E9E"; `Style `Dashed]
  let default_edge_attributes _ = []
  let edge_attributes e = []
end)
```

## Migration strategy

1. Phase 1-2: Add ocamlgraph, create adapter, replace DOT output (no analysis changes)
2. Phase 3: Refactor cfg_builder to produce `CfgGraph.t` instead of hand-rolled `cfg`
3. Phase 4: Refactor cfg_taint to use `Fixpoint.Make` instead of custom worklist
4. Phase 5 (future): Add dominator-based FP pruning

Each phase is independently testable — the CFG taint engine's results should be identical before and after each refactor.
