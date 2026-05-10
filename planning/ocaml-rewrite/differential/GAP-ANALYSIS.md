# Plan vs Reality — Gap Analysis

Cross-reference of `planning/ocaml-rewrite/PLAN.md` (rev 3) against what's actually implemented on the `ocaml-rewrite` branch.

## Phase 0: Differential Testing Infrastructure

| Task | Status | Notes |
|------|--------|-------|
| Build vulnerability corpus | ✅ Done | `test/samples/` with 8 files covering all 11 rule types |
| Create diff harness | ✅ Done | Manual diff in `differential/RESULTS.md`, shell one-liners |
| CI workflow | ❌ Deferred | No GitHub Actions. Diff is run manually. |

## Phase 1: OCaml CLI + TOML Config + State Persistence

| Task | Status | Notes |
|------|--------|-------|
| Dune workspace structure | ✅ Done | 5 libraries, clean module layout |
| Cmdliner argument parsing | ✅ Done | Idiomatic recursive descent parser in `args.ml` |
| TOML config loading | ✅ Done | `config.ml` with `.catseye.toml` auto-discovery, walks up to root |
| File discovery with exclusion | ✅ Done | `discovery.ml` with configurable exclude dirs |
| Pre-built Crystal binary | ✅ Done | `bin/catseye-crystal-extractor` — 54x faster per file |
| SQLite state persistence | ❌ Deferred | In-memory cache only (`cache.ml`). SQLite schema designed but not wired. |
| Wire up CLI → extraction → output | ✅ Done | Full pipeline: extract → cache → seed → propagate → returns → interproc → rules → output |
| Legacy Gleam bridge | ✅ Skipped | Replaced entirely by native OCaml engine |

**Key deviation**: Plan called for SQLite + Blake3 in Phase 1. Delivered in-memory cache with `Hashtbl.hash` fingerprinting. Blake3 not in nixpkgs; SQLite deferred. The cache API is ready for SQLite backing.

## Phase 2: KDL Rule DSL + OCaml Extractors

| Task | Status | Notes |
|------|--------|-------|
| KDL parser for rule definitions | ✅ Done | `loader.ml` parses KDL → `rule_def` records |
| Rule interpreter (KDL → matching) | ✅ Done | `interpreter.ml` with substring matching, sanitizer checks, non-taint conditions |
| OCaml tree-sitter Gleam extractor | ✅ Done | `gleam.ml` — idiomatic functional recursive descent XML parser, no refs/while for control flow |
| Abstract Protocol module | ❌ Dropped | JSON kept directly. Not the bottleneck. Abstract module designed but not needed yet. |
| Register Gleam extractor in CLI | ✅ Done | Orchestrator dispatches by file extension |
| Wire KDL rules into engine | ✅ Done | 11 KDL rule files, all load and match |
| Verify identical results | ✅ Done | 19/19 on test/samples, 7/7 on facet_pi |

## Phase 3: OCaml Taint Analysis Engine (Multicore)

| Task | Status | Notes |
|------|--------|-------|
| Port taint.gleam → OCaml | ✅ Done | `db.ml`, `seed.ml`, `propagate.ml`, `returns.ml`, `interproc.ml`, `merge.ml` |
| Map.Make(String) TaintDB | ✅ Done | `StringMap` in `db.ml` |
| Fixed-point propagation | ✅ Done | `propagate.ml` loops until no new tainted vars |
| Domain.parallel_map | ✅ Done | `parallel.ml` with Domain.spawn/join, graceful fallback |
| DAG builder | ✅ Done | `dag.ml` — backward trace from sink through taint chain |
| KDL-loaded rule matching | ✅ Done | All 11 rules via KDL + interpreter |
| SQLite analysis cache | ❌ Deferred | In-memory cache only. Schema designed in plan §4.3. |
| Differential tests | ✅ Done | 4 projects, 37/37 legacy parity |

**Key addition not in plan**: `interproc.ml` strategy 2 — call-arg taint propagation. If a call receives tainted args, its return is tainted. This covers external functions and was the key to matching the last missing findings.

## Phase 4: Crystal Worker Pool + Full Integration

| Task | Status | Notes |
|------|--------|-------|
| `--serve` mode for Crystal extractor | ❌ Deferred | Pre-built binary is 54x faster. Worker pool is incremental gain on top. |
| Eio-based worker pool | ❌ Deferred | Domain parallelism covers extraction. Eio adds persistent Crystal processes. |
| Wire pool into pipeline | ❌ Deferred | Single-process extraction works well (0.12s on PrismatIQ 393 files) |
| Graceful fallback | ✅ Done | `parallel.ml` falls back to sequential on Domain errors |
| Output formatters | ✅ Partial | Terminal ✅, JSON ✅, SARIF ✅, Markdown ✅, **DOT ❌** |
| Remove Nim+Gleam from flake.nix | ❌ Deferred | Still need Nim to build legacy binary for comparison |
| Performance benchmarking | ✅ Done | 535x on quickheadlines, 393x on PrismatIQ |

## Phase 5: Polish & Release

| Task | Status | Notes |
|------|--------|-------|
| Error handling | ✅ Mostly | Sys_error guards in discovery and extraction. Could be more thorough. |
| Documentation | ❌ Not done | No user guide, no rule authoring guide |
| Performance benchmarks published | ❌ Not done | Results in RESULTS.md but not published externally |
| Windows/macOS testing | ❌ Not done | Only tested on Linux ARM64 |
| Release binary (musl static) | ❌ Not done | Dynamic binary only |

---

## Plan Sections — What Was Built Differently

### §4.2 Eio for Crystal Worker Pool I/O
**Planned**: Eio-based persistent worker pool with Unix domain socket protocol.
**Reality**: Pre-built Crystal binary is fast enough that the worker pool is diminishing returns. 0.12s for 393 files. Deferred.

### §4.3 State Persistence Layer (Incremental Analysis)
**Planned**: SQLite + Blake3 for persistent extraction cache across runs.
**Reality**: In-memory cache with `Hashtbl.hash`. Cache survives within a run (parallel extraction) but not across runs. SQLite schema designed, API ready.

### §5.3 Worker Pool Protocol
**Planned**: `--serve` mode with JSON-over-socket protocol for persistent Crystal processes.
**Reality**: Not needed at current performance levels.

### §6.4 DAG → SARIF codeFlows
**Planned**: Full DAG → SARIF codeFlows conversion.
**Reality**: SARIF output exists but codeFlows use flat finding flow steps, not full DAG traversal. Works but doesn't exercise the DAG builder.

### §6.5 DAG → DOT (GraphViz)
**Planned**: DOT output for visual DAG rendering.
**Reality**: Not implemented. DAG types exist but no DOT formatter.

### §8 Dune Workspace Structure
**Planned**: 7 libraries with `catseye_extractors` as a separate library.
**Reality**: 5 libraries. Gleam extractor lives inside `catseye_engine` (module wrapping issue). Extractors library was attempted but dune couldn't resolve the `Security_node` module across library boundaries with the single-package setup.

---

## Summary

| Category | Planned | Done | Deferred | Dropped |
|----------|---------|------|----------|---------|
| Phase 0 tasks | 3 | 2 | 1 | 0 |
| Phase 1 tasks | 8 | 6 | 1 | 1 |
| Phase 2 tasks | 7 | 6 | 0 | 1 |
| Phase 3 tasks | 8 | 7 | 1 | 0 |
| Phase 4 tasks | 7 | 2 | 4 | 0 |
| Phase 5 tasks | 5 | 1 | 0 | 4 |
| **Total** | **38** | **24** | **7** | **6** |

### Deferred (worth doing later)
1. **SQLite persistent cache** — API ready, just needs SQLite backing
2. **Eio worker pool** — for projects with 1000+ files
3. **CI differential testing** — GitHub Actions workflow
4. **DOT output** — GraphViz visualization of vulnerability DAGs
5. **Documentation** — user guide, rule authoring guide
6. **Remove Nim+Gleam from flake.nix** — when we stop comparing
7. **`--serve` mode** — Crystal extractor persistent process

### Dropped (deliberately)
1. **Protocol abstraction module** — JSON is fine, not the bottleneck
2. **Legacy Gleam bridge** — native engine replaces it entirely
3. **Blake3** — not in nixpkgs, `Hashtbl.hash` sufficient for cache invalidation
4. **Windows/macOS testing** — Linux-only for now
5. **musl static binary** — not needed for dev tooling
6. **External benchmarks** — internal RESULTS.md sufficient
