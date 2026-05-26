# Catseye Jane Street Ecosystem Migration Spec

**Version:** 0.2  
**Created:** 2026-05-26  
**Status:** Draft → In Progress

## 1. Problem Statement

Catseye currently operates as a file-by-file scanner. Moving to Jane Street Base and Core enables:

1. **Incremental diff scanning** via Incremental library (self-updating DAG)
2. **Streaming multi-worker pipelines** via Core_unix + OCaml 5 **Domains** (not Moonpool)
3. **Type-safe CLI orchestration** via Core.Command
4. **Production-grade monadic pipelines** for complex semantic rules

> **Decision:** Using OCaml 5 native `Domain` parallelism instead of Moonpool — no extra dependency required.

## 2. Current State Assessment

| Capability | Status | Location |
|------------|--------|----------|
| Base/Stdlib | ✅ Migrated | All files use `open Base` |
| Domain parallelism | ✅ Partial | `lib/catseye_engine/parallel.ml` |
| Core.Command | ❌ Not used | `cmdliner` in deps |
| Incremental | ❌ Not used | Config field only |
| Core_unix streaming | ❌ Not used | Basic `Unix.pipe` in orchestrator |
| Result monad pipelines | ❌ Not used | Deep nested matches in rules |

## 3. Migration Phases

### Phase 1: Core CLI (Core.Command) [FIRST]

**Goal:** Replace custom arg parser with type-safe `Core.Command`

**Changes:**
- Add `core` dependency to `dune-project`
- Replace `lib/catseye_cli/args.ml` with `Core.Command` declarative API
- Generate `--help` with auto-color support
- Handle SIGPIPE natively
- Add `incremental` dependency for Phase 2 prep

**Work unit:** `feat(cli): migrate to Core.Command`

### Phase 2: Incremental Analysis DAG

**Goal:** Build self-updating graph for diff scanning

**Changes:**
- Add `incremental` dependency
- Create `lib/catseye_incremental/` module
- Build DAG with nodes for: files, ASTs, findings, smells
- Implement `stabilize()` cycle for minimal recomputation

**Work unit:** `feat(incremental): add Incremental DAG for diff scanning`

### Phase 3: Streaming Pipeline (Core_unix + Domains)

**Goal:** Non-blocking Crystal process pool with on-the-fly CFG

**Changes:**
- Create `lib/catseye_pipeline/` module
- Use `Core_unix` for async process management
- Wire into existing `parallel.ml` Domain pool
- Stream JSON bytes as Crystal emits them

**Work unit:** `feat(pipeline): streaming Crystal extractor via Core_unix`

### Phase 4: Monadic Rule Pipelines

**Goal:** Railway-oriented security rules using Result monad

**Changes:**
- Create `lib/catseye_rules/pipeline.ml`
- Migrate checker functions to `>>=` / `>>|` style
- Implement "Hiss" exploit simulation module
- Refactor `hierarchy_smells.ml` as demonstration

**Work unit:** `feat(rules): monadic Result pipelines for semantic analysis`

## 4. Dependencies to Add

```scheme
;; dune-project additions (core is already partially used via base/stdio)
(package (name catseye) (depends ... core incremental))
```

> Note: `base` and `stdio` already provide some Core functionality.
> `core` adds: `Core.Command`, `Core_unix`, `Core.Array`, etc.

## 5. File Structure Changes

```
lib/
├── catseye_incremental/      # NEW: Incremental DAG
│   ├── dune
│   ├── analysis_graph.ml     # Core Incremental.t graph
│   └── diff_engine.ml        # Minimal recomputation
├── catseye_pipeline/         # NEW: Streaming pipeline
│   ├── dune
│   ├── process_pool.ml       # Core_unix process management
│   └── stream_reader.ml      # Async byte streams
├── catseye_rules/
│   ├── pipeline.ml           # NEW: Monadic rule combinators
│   └── hiss.ml              # NEW: Exploit simulation
├── catseye_cli/
│   ├── args.ml              # REPLACE with Core.Command
│   └── command.ml           # NEW: Command module
└── catseye_engine/
    └── parallel.ml          # ENHANCE with streaming
```

## 6. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | `--help` shows color-formatted output | Manual test |
| 2 | Single file change triggers minimal recompute | `just test` |
| 3 | Crystal extractor streams JSON incrementally | Binary output before complete |
| 4 | Complex rules use `>>=` pipeline style | Code review |
| 5 | All existing tests pass | `just test` |
| 6 | No new dependencies break existing CI | `dune build` |

## 7. Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Core API differences | Medium | Write adapter layer for Domain usage; existing parallel.ml already uses Domains |
| Incremental learning curve | Low | Start with simple file-watching pattern; existing `incremental` config field shows intent |
| Breaking existing CLI | Medium | Keep `--output` format during transition; test with existing workflows |
| nix build updates | Low | Update flake.nix deps alongside dune-project changes |

## 8. Delivery Strategy

**Option B (Chained PRs) — RECOMMENDED:** 
- PR1: Phase 1 (Core.Command + incremental dep)
- PR2: Phase 2 (Incremental DAG)
- PR3: Phase 3 (Pipeline + streaming)
- PR4: Phase 4 (Monadic rules)

Each PR builds on the previous, with work-unit commits per phase.