## Why

The taint engine operates on a flat `Security_node.t list` — a linear sequence of nodes with no branch structure. This causes entire classes of false positives (dead code on early-return guards, branch-insensitive taint, no field sensitivity) that require growing piles of heuristics to patch. An Intermediate Language + Control Flow Graph derived from `CatseyeAST.t` would let the engine reason about program structure the same way the AI linter already does.

## What Changes

- **New IL module** (`catseye_il`) — simplified representation with assign/call/branch/return nodes and field-sensitive lvalues (`x.a.b`)
- **CFG builder** — converts IL into basic blocks with edges, preserving branch/merge structure
- **Rewritten taint engine** — forward dataflow analysis on CFG instead of flat list propagation
- **KDL precision upgrades** — optional `arg=N` for sink argument position, `$var` metavariables for receiver matching
- **Migration** — CatseyeAST → IL → CFG → engine runs alongside existing flat path until verified

## Capabilities

### New Capabilities
- `il-cfg`: Intermediate Language and Control Flow Graph derived from CatseyeAST.t, powering branch-aware dataflow analysis
- `kdl-precision`: Enhanced KDL rule format with argument position and metavariable matching

### Modified Capabilities
- `taint-engine`: Taint tracking uses CFG dataflow instead of flat Security_node.t propagation

## Impact

- New OCaml library: `src/ocaml/lib/catseye_il/` (types, of_catseye_ast, cfg_builder)
- Engine rewrite: `src/ocaml/lib/catseye_engine/engine.ml`, `propagate.ml`, `db.ml`
- KDL parser: `src/ocaml/lib/catseye_rules/loader.ml`
- Existing test corpus must produce identical results before switching default
- Claws and AI linter unaffected (they don't use the taint engine)
