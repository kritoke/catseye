# Catseye — Roadmap & Phase Plan

**Last Updated:** 2026-05-11  
**Source of Truth:** This document supersedes all prior task lists.  
**Parent:** `planning/TDD.md`

---

## Current State: v0.3.0

The OCaml rewrite is complete. All Gleam/BEAM and Nim code has been removed. The engine matches legacy parity on 4 real-world codebases.

### What's Done

| Capability | Module | Status |
|-----------|--------|--------|
| Crystal AST extraction | Extractor | ✅ Production |
| Gleam AST extraction (tree-sitter) | Extractor | ✅ Production |
| Fixed-point taint propagation | Catseye Engine | ✅ Production |
| Inter-procedural taint | Catseye Engine | ✅ Production |
| 11 vulnerability rules (KDL) | Catseye Rules | ✅ Production |
| Hunter Persona (Hiss/Meow/Purr) | CLI | ✅ Production |
| Predator Vision (reachability) | Engine + CLI | ✅ Production |
| Crow's Nest (supply chain) | Crowsnest | ✅ Production |
| Incremental cache (in-memory) | Engine | ✅ Working |
| Terminal / JSON / SARIF / Markdown / DOT output | CLI | ✅ Production |
| Nix Flake dev environment | Infra | ✅ Production |
| Zero false positives on real scans | Engine | ✅ Verified |

### What's NOT Done

| Capability | Module | Gap |
|-----------|--------|-----|
| Code smell detection | **Claws** | Not started — new module |
| DRY structural hashing | **Claws** | Not started — new module |
| Persistent cache (SQLite) | Engine | API exists, no backing store |
| Crystal Worker Pool | Extractor | Protocol designed, not implemented |
| Cross-file taint (D2) | Engine | Needs symbol table in extractor |
| File-level scope isolation | Engine | Variables bleed across files |
| Field-level taint tracking | Engine | API exists, extractors don't emit fields |
| Parallel extraction wiring | Engine | `parallel.ml` exists, not wired |
| Static binary release | Infra | Dynamic binary only |

---

## Phase Plan

### Phase 6: Engine Hardening (Next)

**Goal:** Fix known engine limitations that cause false positives/missed findings.

**Priority:** High — these are correctness issues, not features.

| Task | File(s) | Size | Description |
|------|---------|------|-------------|
| F1: File-level scope isolation | `db.ml`, `propagate.ml` | Medium | Namespace variables per file so `x` in `a.cr` doesn't share taint with `x` in `b.cr`. Current work-around in `engine.ml` creates `by_file` context, but the DB itself is still global. |
| F2: Fix B2 message template truncation | `interpreter.ml` | Small | `substitute_template` produces `"rs}"` instead of full message. Debug the Buffer-based rewrite. |
| F3: Conditional taint refinement | New `conditional.ml` | Medium | `if validator.is_valid(x)` on true branch → clear taint. Requires scope-aware branch tracking. |
| F4: Wire parallel.ml | `orchestrator.ml`, `parallel.ml` | Small | ~20 lines. Group sources by language, run `extract_parallel` per group. Gate behind `--parallelism N` flag. |

**Exit criteria:**
- Zero cross-file variable bleed on test corpus
- All finding messages render correctly
- `--parallelism 4` works without regression

**Planning doc:** `planning/phase6-engine-hardening.md`

---

### Phase 7: Claws Module — Code Smells & DRY

**Goal:** Implement the Claws module as defined in TDD §7.

**Priority:** High — this is a major new capability.

| Task | File(s) | Size | Description |
|------|---------|------|-------------|
| C1: Dune library scaffold | `lib/catseye_claws/dune` | Small | New library `catseye.claws` with types + pipeline |
| C2: Complexity walker | `lib/catseye_claws/complexity.ml` | Medium | Approximate cyclomatic complexity from Security Nodes |
| C3: Anatomy walker | `lib/catseye_claws/anatomy.ml` | Medium | Parameter count, nesting depth, god object detection |
| C4: DRY structural hashing | `lib/catseye_claws/dry.ml` | Large | Windowed AST normalization + hash bucketing |
| C5: Smell pipeline | `lib/catseye_claws/smells.ml` | Small | Unified pipeline: complexity → anatomy → DRY → findings |
| C6: CLI integration | `args.ml`, `orchestrator.ml`, `config.ml` | Small | `--claws` flag, TOML `[claws]` section, finding output |
| C7: Ameba hook (optional) | `lib/catseye_claws/ameba_hook.ml` | Medium | Shell out to `ameba --format json`, convert to findings |
| C8: Claws KDL rules | `rules/` | Small | Smell severity thresholds in KDL or TOML config |

**Exit criteria:**
- `--claws` flag activates smell detection
- Complexity + anatomy + DRY findings appear in all output formats
- DRY detects exact-copy blocks across files in test corpus
- Performance budget: < 200ms added per 1K nodes

**Planning doc:** `planning/phase7-claws.md`

---

### Phase 8: Persistent Cache & Worker Pool

**Goal:** SQLite-backed cache for incremental cross-run scanning, plus Crystal worker pool.

**Priority:** Medium — performance, not correctness.

| Task | File(s) | Size | Description |
|------|---------|------|-------------|
| P1: SQLite cache backing | `cache.ml` | Medium | Replace `Hashtbl` with SQLite. Schema: `(path, hash, nodes_json, analyzed_at)`. |
| P2: Cache CLI flags | `args.ml`, `config.ml` | Small | `--cache-dir`, `--clear-cache` |
| P3: Crystal worker protocol | `extractor.cr` | Medium | Persistent loop: read JSON request → extract → write JSON response |
| P4: OCaml worker pool | New `worker_pool.ml` | Large | Manage N Crystal workers, distribute files, collect results |
| P5: Pool integration | `orchestrator.ml` | Medium | Use pool when `--crystal-workers N > 0` |

**Exit criteria:**
- `catseye dir` → second run uses cache, 10x faster
- Worker pool handles 100+ Crystal files without hanging
- Graceful fallback to sequential on worker crash

**Planning doc:** `planning/phase8-cache-workers.md`

---

### Phase 9: Cross-File Taint & Symbol Resolution

**Goal:** D2 — taint propagates across file boundaries via import resolution.

**Priority:** Medium-High — significant analysis capability improvement.

| Task | File(s) | Size | Description |
|------|---------|------|-------------|
| X1: Import extraction | `extractor.cr`, `gleam.ml` | Large | Parse `require`/`import` statements, emit import metadata nodes |
| X2: Symbol table | New `symbol_table.ml` | Large | `module.function → (file, def_node)` map |
| X3: Cross-file propagation | `propagate.ml`, `interproc.ml` | Medium | Use symbol table to resolve cross-file calls |
| X4: Wire merge_db | `merge.ml`, `engine.ml` | Small | Per-file propagate → merge → interproc on merged result |
| X5: Cross-file test corpus | `test/samples/` | Small | Multi-file Crystal/Gleam projects with cross-file taint |

**Exit criteria:**
- Taint flows from `a.cr` → `b.cr` via function call
- No regression on existing single-file tests
- `merge_db` correctly unions per-file databases

**Planning doc:** `planning/phase9-cross-file.md`

---

### Phase 10: Release & Distribution

**Goal:** Ship Catseye as a polished, distributable tool.

**Priority:** Low until Phases 6–9 complete.

| Task | Size | Description |
|------|------|-------------|
| R1: Static binary (musl) | Medium | OCaml + Crystal static linking |
| R2: CI pipeline | Medium | Build + test + lint + self-scan on every PR |
| R3: Multi-arch builds | Large | aarch64-linux + x86_64-linux (stretch: macOS) |
| R4: opam package | Medium | Publish to opam registry |
| R5: Version stamping | Small | Single source of truth from dune-project |
| R6: Integration test suite | Medium | Formalize unit + E2E + differential + perf |
| R7: Release automation | Medium | Tag → GitHub Release with static binaries |
| R8: User documentation | Large | README rewrite, rule guide, config guide, CI integration |
| R9: Nix Flake package | Medium | `nix run github:kritoke/catseye` works |

**Implementation order:** R5 → R6 → R2 → R1 → R7 → R8 → R9 → R3 → R4

**Planning doc:** `planning/phase10-release.md`

---

## Phase Dependencies

```
Phase 6: Engine Hardening
    │
    ├──▶ Phase 7: Claws Module (independent, can parallel)
    │
    ├──▶ Phase 8: Cache & Workers (independent, can parallel)
    │
    └──▶ Phase 9: Cross-File Taint (depends on Phase 6 F1)
              │
              └──▶ Phase 10: Release (depends on all above)
```

Phases 7 and 8 are independent of each other and can be worked on in parallel after Phase 6.

---

## DNF Cross-Reference

Items from `planning/DNF.md` mapped to phases:

| DNF Item | Phase | Action |
|----------|-------|--------|
| parallel.ml wiring | Phase 6 (F4) | Wire after stability |
| merge_db wiring | Phase 9 (X4) | Wire with cross-file |
| Db O(n) check | DNF | Keep deferred — not a bottleneck |
| D1 same-line heuristic | Phase 9 (X1) | Revisit with extractor changes |
| D2 cross-file taint | Phase 9 | Full plan |
| N3 Blake3 | DNF | Keep deferred — not needed |
| A3 interproc nesting | Phase 6 (F2 area) | Clean up when touching interpreter |
| A7 tokenizer helpers | DNF | Keep deferred |
| B2 message truncation | Phase 6 (F2) | Fix directly |
| B3 taint source matching | Phase 6 | Add generic names to known_sources |

---

*This document is the single source of truth for what's next. Update it when phases complete.*
