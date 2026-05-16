# OCamlgraph Integration — Tasks

**Change:** `ocamlgraph-integration`
**Status:** Open

## Phase 1: Add dependency + graph adapter

- [x] 1.1 Add `ocamlgraph` to `src/ocaml/dune-project` (already present)
- [x] 1.2 Create `src/ocaml/lib/catseye_il/cfg_graph.ml` with `CfgGraph` module (Concrete Imperative Digraph)
- [x] 1.3 Define vertex type (`int` block IDs), augmented CFG type with `Hashtbl` for block content
- [x] 1.4 Add `Graphviz.Dot` functor instance for DOT output
- [x] 1.5 Add `cfg_graph` to `catseye_il/dune` modules + `ocamlgraph` dependency
- [x] 1.6 Verify `dune build` + all tests pass

## Phase 2: Replace DOT output with Graphviz functor

- [x] 2.1 Created `CallGraph` module (string-keyed Concrete Digraph) in `dot.ml`
- [x] 2.2 Created `Graphviz.Dot` functor instance for call graph with classification-based styling
- [x] 2.3 Kept classification logic (Entry/Sink/Reachable/Dormant), replaced hand-written DOT with functor
- [x] 2.4 Added `ocamlgraph` to `catseye_cli/dune` dependencies
- [x] 2.5 Test: `--format dot` produces valid DOT output with correct styling
- [x] 2.6 Verify `dune build` + existing tests pass

## Phase 3: Replace CFG data structure with ocamlgraph digraph

- [x] 3.1 Refactored `cfg_builder.ml` — builds `Cfg_graph.t` using `add_block`/`add_edge` instead of hand-rolled `cfg`
- [x] 3.2 Refactored `cfg_taint.ml` `analyze_cfg` — uses `Cfg_graph.iter_succ`, `Cfg_graph.block_nodes`, `Cfg_graph.iter_vertices` instead of `IntMap` + `cfg_block_map`
- [x] 3.3 Removed dead code from `il_types.ml`: `basic_block`, `cfg`, `IntMap` types
- [x] 3.4 Removed dead code from `cfg_builder.ml`: `block_acc`, `make_acc`, `emit_block`
- [x] 3.5 Updated test files: `Cfg_graph.v_count` instead of `List.length cfg.cfg_blocks`
- [x] 3.6 Verified `dune build` + all tests pass
- [x] 3.7 Verified CFG taint findings identical (7 errors, 3 warnings = 10 findings)

## Phase 4: Improve worklist with ocamlgraph graph APIs

- [x] 4.1 Replaced hand-built predecessor Hashtbl with `Cfg_graph.G.pred` (ocamlgraph native)
- [x] 4.2 Documented why Fixpoint.Make doesn't fit: per-edge API vs our per-block transfer + findings side effects
- [x] 4.3 Cleaned up broken Fixpoint.Make attempt, removed dead code (~45 lines)
- [x] 4.4 Verified CFG taint findings identical to Phase 3 baselines
- [x] 4.5 All tests pass

## Phase 5 (Future): Dominator analysis for FP pruning

- [ ] 5.1 Use `Dominator.compute` on CFG to build dominator tree
- [ ] 5.2 Identify guards (sanitizer checks) that dominate sinks
- [ ] 5.3 Suppress findings where a sanitizer dominates the sink
- [ ] 5.4 Test: verify FPs reduced on guarded_test samples
- [ ] 5.5 Test: verify no true positives suppressed

## Verification Commands

```bash
# Build
just build

# Run tests
just test

# CFG-specific tests
cd src/ocaml && dune exec test/ast/il_cfg_test.exe
cd src/ocaml && dune exec test/ast/cfg_perf_test.exe
cd src/ocaml && dune exec test/ast/taint_perf_test.exe

# DOT output test
./bin/catseye-ocaml --rules src/ocaml/rules --format dot test/samples/ > /tmp/test.dot
dot -Tpng /tmp/test.dot -o /tmp/test.png

# Full scan comparison (before/after findings should be identical)
./bin/catseye-ocaml --rules src/ocaml/rules --cfg --format json test/samples/ | jq '.findings_count'
```
