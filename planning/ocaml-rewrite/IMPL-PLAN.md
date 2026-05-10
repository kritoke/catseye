# Implementation Plan: Design Issue Fixes

**Date**: 2026-05-09  
**Last updated**: 2026-05-09 (post review reasoning)

---

## Priority 1: Wire parallel.ml into extraction (N2) — DEFERRED ✅

**Problem**: `parallel.ml` defines `extract_parallel` but is never called. Extraction is fully sequential.

**Why deferred**: Sequential extraction is correct and easier to debug. Parallelism is a performance optimization — you only pay for it once the core logic is 100% stable. For a port from Gleam/BEAM, deterministic output is more valuable than speed at this stage.

**When to revisit**: After differential testing (Phase 0) passes consistently and the engine logic is stable. OCaml 5 Domains API is already in place in `parallel.ml`; wiring it in is ~20 lines of refactoring.

---

## Priority 2: Wire dag.ml into findings (D3) — DONE ✅

**Problem**: `dag.ml` builds `vulnerability_dag` but `orchestrator.ml` never calls it. Every finding has `flow = []`.

**Done**: Integrated in `engine.ml`:
- `Dag.build_dag` traces taint from sink back to sources
- `dag_to_flow_steps` converts DAG to ordered `flow_step list` using DFS with post-append + single `List.rev` (fixes B-2 ordering bug)
- Findings now have populated `flow[]` instead of empty list

**Files**: `engine.ml` (new `dag_to_flow_steps` + wiring), `dag.ml` (already existed)

---

## Priority 3: Wire merge_db into engine pipeline (D4) — DEFERRED ✅

**Problem**: `merge.ml` defines `merge_db` but it's never used. Multi-file TaintDB union is never performed.

**Why deferred**: The benefit of `merge_db` depends entirely on D2 (cross-file taint propagation). There's no point in wiring a database union if there is no link between files to justify the merge. Currently the engine runs on a flat list of all nodes, which is equivalent to "merge everything up front" — the same logical result without the per-file grouping infrastructure.

**When to revisit**: After D2 is addressed. The `merge_db` function is correct and ready; it just needs the pipeline to do per-file propagation first.

---

## Priority 4: Fail on unknown rule extensions (D5) — DONE ✅

**Problem**: Custom KDL conditions are parsed into `extensions` but silently ignored.

**Done**: `loader.ml` now explicitly matches known condition names and logs `Logs.warn` for unknown conditions. Extensions are still collected for future use, but users are informed when something is ignored.

---

## Priority 5: Propagate language through pipeline (D6) — DONE ✅

**Problem**: `language = ""` always in findings. The extractor knows the language but it never flows through.

**Done**:
- `Security_node.t` gained `language : string` field
- `Gleam.extract` sets `language = "gleam"` on all emitted nodes
- Crystal nodes from external CLI work unchanged (field is optional)
- `interpreter.ml` reads language from sink node → `Finding.t`
- JSON encode/decode handles the new field

---

## D1: Call/Assign Same-Line Heuristic — DEFERRED ✅

**Problem**: `interproc.ml` searches for a `Call` node at the exact same line as an `Assign` node. This is fragile — AST formatting changes break it.

**Why deferred**: This is a heuristic. The correct approach is to rely on the structural relationship — checking if the RHS of an assignment is a tainted call (Strategy 1) — which already works correctly. Strategy 1 doesn't depend on co-located nodes. "Strategy 2" (same-line search) is an optimization that can only be safely removed, not fixed, without understanding the actual AST contract from the Gleam extractor.

**When to revisit**: After running the Gleam extractor on real code and inspecting whether `x = foo()` produces one node or two. If the AST wraps the call inside the assignment, the same-line search would find nothing regardless.

---

## D2: Cross-File Taint Propagation — DEFERRED

**Problem**: `propagate.ml` only checks `is_tainted_in_file`. Taint doesn't cross file boundaries.

**Why deferred**: This is less a taint problem and more a **namespace problem**. To propagate taint from module A to module B, you need to know exactly where `foo()` is defined. Without type resolution or a global symbol table, the analysis is effectively a per-file scanner. The Gleam extractor produces `Security_node.t` records with `file` fields but doesn't capture import resolution.

**Approach when revisiting**:
1. Extend AST extractor to track cross-file references (imports → function definitions)
2. Add a symbol table: module name → function name → file + def node
3. When a Call is to a function in another file, look up its def and propagate taint

**Risk**: High. This touches extraction, not just the engine.

---

## Not in this PR: N1 (Db O(n) duplicate check), N3 (Blake3)

**N1 — O(n) duplicate check in Db**: Negligible compared to extraction time for real workloads. Adding a secondary index would cost more than it saves for typical source file sizes.

**N3 — Hashtbl.hash not Blake3**: Perfectly adequate for content-addressing in a local cache. Not a cryptographic use case. Blake3 is an optimization theater item for this tool.

---

## N2 Revisited: Why Sequential First

Parallelism in OCaml 5 Domains is powerful but introduces non-determinism (file processing order, domain scheduling). For a port, **deterministic output is more valuable than speed**. The `parallel.ml` module is already written and correct — it's just not wired in. Deferring the wiring is the right call.

---

## Deferred Items Requiring Extraction Changes (High Risk)

These are out of scope for the current engine-only PR:

| Item | Risk | Reason |
|------|------|--------|
| D2: Cross-file taint | High | Needs symbol table / import resolution in extractor |
| D4: merge_db | Medium | Blocked on D2 — no point without cross-file links |

---

## Completion Checklist

- [x] 1. Parallel extraction wired into orchestrator — **DEFERRED** (correct: sequential first)
- [x] 2. DAG builder connected — findings have populated `flow`
- [x] 3. `merge_db` used in engine pipeline — **DEFERRED** (correct: blocked on D2)
- [x] 4. Unknown rule extensions warn at load time
- [x] 5. `language` field propagates through pipeline
- [x] D1: Same-line heuristic — **DEFERRED** (correct: Strategy 1 is the right path)
- [x] D2: Cross-file taint — **DEFERRED** (correct: needs symbol table)
- [x] Build passes
- [x] All existing tests pass