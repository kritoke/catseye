# Integrate OCamlgraph for CFG & Dataflow

**Change:** `ocamlgraph-integration`
**Priority:** P2
**Size:** M (2–3 days)
**Status:** Proposal

## Motivation

Catseye has three hand-rolled graph components that ocamlgraph would replace with battle-tested, standard implementations:

1. **CFG data structure** — `il_types.ml` defines `basic_block` with `successors : int list` and `cfg_block_map : basic_block IntMap.t`. This is a minimal directed graph, but we get no graph operations for free (iteration, edge queries, reverse edges, etc.).

2. **Taint fixpoint loop** — `cfg_taint.ml` has a custom worklist (`Queue.t`), `visit_count` with `max_visits=3` for convergence, and mutable `findings` accumulation. OCamlgraph's `Fixpoint.Make` is exactly this pattern — a work-list algorithm for forward/backward dataflow analysis with proper widening support.

3. **DOT output** — `dot.ml` is 200 lines of hand-written DOT string building for call graph visualization. OCamlgraph's `Graphviz.Make` is a functor that renders any graph to DOT with styling callbacks.

### What we gain

| Feature | Current | With ocamlgraph |
|---------|---------|-----------------|
| **Graph data structure** | Hand-rolled `basic_block` + `IntMap` | `Imperative.Digraph` — O(1) edge ops, vertex/edge iteration, reverse edges |
| **Taint fixpoint** | Custom worklist, `max_visits=3` hack | `Fixpoint.Make` — proper work-list algorithm with widening |
| **DOT output** | 200 lines hand-written strings | ~20-line functor instance |
| **Dominator analysis** | Not available | `Dominator.compute` — "does guard X always execute before sink Y?" |
| **SCC decomposition** | Not available | `Components.scc` — group mutual-recursive functions |
| **Reachability queries** | Not available | `Path.check` — fast pre-filter: is there any path source→sink? |

### What we won't use

`Coloring`, `Clique`, `Eulerian`, `Planar`, `Delaunay`, `Kruskal`, `Mincut`, `dgraph/` (GTK viewer), `GML` parser — these are for combinatorial optimization or interactive visualization, not static analysis.

## Changes

### Phase 1: Add dependency + graph adapter (S)

Add `ocamlgraph` to the project, create a thin adapter that wraps our `il_node`-labeled blocks into an ocamlgraph-compatible directed graph.

### Phase 2: Replace DOT output with Graphviz functor (S)

Replace `dot.ml`'s hand-written DOT generation with `Graphviz.Make`. This is the lowest-risk change — pure output, no analysis logic affected.

### Phase 3: Replace CFG data structure with ocamlgraph digraph (M)

Refactor `il_types.ml` and `cfg_builder.ml` to use `Imperative.Digraph.Abstract` with our `il_node list` as vertex labels. Update `cfg_taint.ml` to iterate over the graph using ocamlgraph's traversal API instead of manual `IntMap` lookups.

### Phase 4: Replace fixpoint loop with Fixpoint.Make (M)

Refactor `cfg_taint.ml`'s worklist into a `Fixpoint.Make` functor instance. Define the transfer function, join operation, and direction (forward). This gives us proper widening support for loops instead of the `max_visits=3` hack.

### Phase 5 (Future): Dominator analysis for FP pruning (M)

Use `Dominator.compute` to identify guards that dominate sinks. If a sanitizer check always executes before a sink, suppress the finding. This would fix entire classes of FPs (e.g., guarded path traversal, validated SSRF).

## Files

### New
- `src/ocaml/lib/catseye_il/cfg_graph.ml` — ocamlgraph functor instances (Digraph for CFG, Graphviz for DOT)

### Modified
- `src/ocaml/lib/catseye_il/dune` — add `ocamlgraph` dependency
- `src/ocaml/lib/catseye_il/il_types.ml` — replace `basic_block`/`cfg` with ocamlgraph types
- `src/ocaml/lib/catseye_il/cfg_builder.ml` — build ocamlgraph digraph instead of hand-rolled CFG
- `src/ocaml/lib/catseye_il/cfg_taint.ml` — use `Fixpoint.Make` for taint analysis
- `src/ocaml/lib/catseye_cli/dot.ml` — replace with `Graphviz.Make` functor call
- `dune-project` or `src/ocaml/dune-project` — add `ocamlgraph` dependency

## Specs

- `specs/cfg-graph/spec.md`
