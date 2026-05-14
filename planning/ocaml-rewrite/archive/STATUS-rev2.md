# OCaml Rewrite Tracking

## Status: Draft — Updated After Critique Review (rev 2)

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-09 | OCaml as target language | Single language, native perf, tree-sitter bindings |
| 2026-05-09 | Keep Crystal in Crystal | No equivalent to Crystal::Parser in OCaml |
| 2026-05-09 | Graph-based output | More expressive than linear flows |
| 2026-05-09 | OCaml 5 Domains for parallelism | Per-file taint analysis is embarrassingly parallel |
| 2026-05-09 | Extraction cache (Tier 1) | Skip unchanged files, biggest bang for buck |
| 2026-05-09 | Differential testing in CI | Only way to catch silent false negatives |
| 2026-05-09 | Rule interface DSL-ready, no DSL now | 10 rules don't justify DSL complexity |
| 2026-05-09 | Keep JSON, abstract protocol | JSON not the bottleneck, debuggable |
| 2026-09-09 | (Pending) | Engine review feedback |

## Pending Validations

- [ ] Benchmark current architecture on large Crystal codebase
- [ ] Compare with Semgrep taint analysis approach
- [ ] Compare with CodeQL taint tracking approach
- [ ] Prototype OCaml taint engine subset
- [ ] Evaluate OCaml tree-sitter bindings maturity
- [ ] Evaluate Domain parallelism overhead threshold
- [ ] Evaluate extraction cache hit rate on typical codebases

## Open Questions

| Question | Owner | Status |
|----------|-------|--------|
| Map vs List for TaintDB semantics | (pending engine review) | Open |
| Single-pass vs fixed-point correctness | (pending engine review) | Open |
| Graph vs linear flow value | (pending engine review) | Open |
| Incremental vs batch analysis | (pending engine review) | Open |
| Optimal Domain count for parallel phases | (needs benchmarking) | Open |
| Extraction cache threshold | (needs benchmarking) | Open |
| Tier 2 analysis cache value | (deferred) | Deferred |

## Phase Progress

| Phase | Description | Status | Notes |
|-------|-------------|--------|-------|
| 1 | CLI skeleton + Crystal binary + extraction cache | Not started | |
| 2 | OCaml Gleam extractor + abstract protocol | Not started | |
| 3 | OCaml taint engine + Domains + diff testing | Not started | Core phase |
| 4 | Graph output + SARIF | Not started | |
| 5 | Crystal worker pool | Not started | |
| 6 | Full integration, retire Nim + Gleam | Not started | |

## Deferred Items

| Item | Revisit When |
|------|-------------|
| Rule DSL (YAML/JSON) | 50+ rules or community contributors |
| Binary serialization | Profiling proves JSON is slow |
| Analysis cache (Tier 2) | Inter-procedural analysis is slow |

## Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| Taint logic translation bugs | Differential testing in CI | Planned |
| Crystal worker pool instability | Graceful fallback | Planned |
| Long rewrite period | Parallel validation | Planned |
| Domain merge semantics | File-scoped DBs, associative merge | To validate |
| Extraction cache bugs | Content-hash + --clear-cache flag | Planned |

---

*Last updated: 2026-05-09 (rev 2)*