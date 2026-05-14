# OCaml Rewrite Tracking

## Status: Rev 3 — Comprehensive Architecture

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-09 | OCaml as target language | Single language, native perf, tree-sitter bindings |
| 2026-05-09 | Keep Crystal in Crystal | No equivalent to Crystal::Parser in OCaml |
| 2026-05-09 | Graph-based output (DAGs) | More expressive than linear flows |
| 2026-05-09 | OCaml 5 Domains for parallelism | Per-file taint analysis is embarrassingly parallel |
| 2026-05-09 | Extraction cache | Skip unchanged files |
| 2026-05-09 | Differential testing | Catch silent false negatives |
| 2026-05-09 | Rule interface DSL-ready | Design for future DSL |
| 2026-05-09 | Keep JSON, abstract protocol | JSON not the bottleneck |
| 2026-05-09 (rev 3) | **KDL for rule DSL** | Hierarchical structure maps to AST nodes; YAML/TOML too flat |
| 2026-05-09 (rev 3) | **TOML via otaml for config** | Orchestration config is flat key-value; TOML is standard |
| 2026-05-09 (rev 3) | **Blake3 + SQLite for state** | Fast hashing + indexed queries for dependency tracking |
| 2026-05-09 (rev 3) | **Eio for Crystal worker pool** | Effects-based I/O, OCaml 5 native, pairs with Domain |
| 2026-05-09 (rev 3) | **Phase 0 for diff testing** | Validation before any migration code |
| 2026-05-09 (rev 3) | **Vulnerability DAGs** | Replace linear flows with directed acyclic graphs |

## Phase Progress

| Phase | Description | Status | Depends On |
|-------|-------------|--------|------------|
| **0** | Differential testing infrastructure | Not started | — |
| **1** | CLI + TOML config + SQLite state + Crystal binary | Not started | Phase 0 |
| **2** | KDL rule DSL + OCaml tree-sitter extractors | Not started | Phase 1 |
| **3** | Taint engine (multicore Domains) + DAG builder | Not started | Phase 2 |
| **4** | Crystal worker pool (Eio) + output formatters | Not started | Phase 3 |
| **5** | Polish, docs, release | Not started | Phase 4 |

## Timeline

| Phase | Estimated Duration | Cumulative |
|-------|--------------------|------------|
| Phase 0 | 1-2 days | 1-2 days |
| Phase 1 | 3-5 days | 4-7 days |
| Phase 2 | 4-6 days | 8-13 days |
| Phase 3 | 7-10 days | 15-23 days |
| Phase 4 | 3-5 days | 18-28 days |
| Phase 5 | 3-5 days | 21-33 days |

## Key Dependencies to Investigate

| Package | Status | Action Needed |
|---------|--------|---------------|
| `otaml` | Needs evaluation | Verify TOML support (arrays, nested tables) |
| `kdl` (OCaml) | Needs evaluation | Verify KDL v2 spec support |
| `blake3` | Needs evaluation | Verify OCaml 5 compatibility |
| `sqlite3` (ocaml-sqlite3) | Mature | Standard, low risk |
| `eio` | Stable | OCaml 5 standard |
| `tree-sitter` (OCaml) | Needs evaluation | Test with gleam grammar |
| `ocamlgraph` | Mature | Standard, low risk |

## Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| KDL parser insufficient | Write minimal parser; schema is simple | Monitor |
| Taint translation bugs | Phase 0 diff testing | Planned |
| Crystal pool crashes | Graceful fallback to single-process | Planned |
| SQLite concurrent access | WAL mode, single writer | Planned |
| Domain merge semantics | File-scoped DBs, associative merge | To validate |

---

*Last updated: 2026-05-09 (rev 3)*