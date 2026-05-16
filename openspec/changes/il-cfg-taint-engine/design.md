## Context

Catseye's taint engine was built on a flat `Security_node.t list` extracted from Crystal/Gleam source files. The AI linter already uses a proper tree (`CatseyeAST.t`) with `EIf`, `ECase`, `ELet`, `EApp` nodes. The bridge (`to_security_node.ml`) converts the tree back to a flat list — losing all structural information in the process.

This refactor adds an IL layer between CatseyeAST and the engine, similar to how production static analyzers work. The IL is purpose-built for dataflow: just assigns, calls, branches, returns, and field-sensitive lvalues.

## Goals / Non-Goals

**Goals:**
- Eliminate dead-code false positives without heuristics
- Enable branch-sensitive taint (guards actually block propagation)
- Enable field-sensitive taint (`params.url` ≠ `params.body`)
- Enable arg-position sink matching (first arg only for HTTP calls)
- Keep all existing KDL rules working unchanged
- Keep existing test corpus findings identical

**Non-Goals:**
- Inter-procedural analysis across files (cross-file already works via symbol table)
- Type inference integration (separate concern)
- Migrating Claws to CatseyeAST (A4, separate task)
- Supporting languages beyond Crystal/Gleam/Svelte

## Decisions

### IL as separate library, not extension of CatseyeAST
**Decision:** Create `catseye_il` as a new OCaml library.
**Rationale:** CatseyeAST serves the AI linter and parsing. IL serves dataflow. Different consumers, different representations. Keeps both clean.
**Alternative:** Add IL types directly to CatseyeAST — rejected because it bloats the AST with analysis-specific concerns.

### CFG as basic blocks, not SSA
**Decision:** Basic blocks with successor edges. No SSA form.
**Rationale:** SSA is overkill for taint tracking. Basic blocks give us branch boundaries and merge points — that's enough. Simpler to build and debug.
**Alternative:** SSA with phi nodes — rejected as unnecessary complexity for a may-analysis.

### KDL extensions as optional attributes
**Decision:** `arg=N` and `$var` are optional. Existing rules work without changes.
**Rationale:** 12 KDL files in production. Breaking them blocks migration. Optional attributes let us enhance rules incrementally.

### Parallel engine paths during migration
**Decision:** Keep both flat Security_node.t path and CFG path. Orchestrator selects via flag.
**Rationale:** Need to verify identical results before switching. Parallel paths let us compare in CI.
**Alternative:** Big-bang switch — rejected as too risky for a working system.

## Risks / Trade-offs

- **[IL conversion completeness]** → Some CatseyeAST constructs may not map cleanly to IL. Mitigation: `ILResume` node for rescue/ensure, `IEUnknown` for unhandled expressions.
- **[CFG construction complexity]** → Nested branches create many blocks. Mitigation: Start with single-level branches, verify, then handle nesting.
- **[Performance]** → CFG analysis may be slower than flat propagation. Mitigation: CFG is built once per function, dataflow is O(blocks × vars). Should be negligible vs extraction time.
- **[Gleam tree-sitter gaps]** → Gleam tree-sitter produces partial ASTs. Mitigation: `IEUnknown` fallback preserves taint through unknown code.

## Migration Plan

1. Build IL + CFG behind `--cfg` flag
2. Run both engines on test corpus, diff results
3. Run both engines on all 5 Crystal projects + facet_pi, diff results
4. Fix any discrepancies
5. Switch default to CFG, keep flat as `--flat-engine` fallback
6. Remove flat engine after one release cycle

## Open Questions

- Should the IL also feed Claws, or keep Claws on Security_node.t via bridge?
- How to represent Crystal's `case ... when` in IL? As nested `ILBranch` or dedicated `ILCase`?
- Should `$var` metavariables apply to sources and sanitizers too, or just sinks?
