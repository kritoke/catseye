# Catseye — Project Status

**Last updated:** 2026-05-11  
**Repo:** github.com/kritoke/catseye  
**Commits:** 23 on main  
**Version:** 0.3.0

## Architecture

```
Crystal (.cr) ──→ Crystal AST Extractor ──→ Security Node JSON
                                                  ↓
Gleam (.gleam) ─→ OCaml + tree-sitter ──→ Security Node JSON ──→ OCaml Engine ──→ Findings
                                                                                       ↓
                                                                    Terminal / JSON / SARIF / Markdown / DOT
```

| Component | Language | Purpose |
|-----------|----------|---------|
| CLI + Orchestrator | OCaml 5.4 | File discovery, orchestration, output formatting |
| Crystal Extractor | Crystal 1.18 | AST parsing via Crystal::Parser, taint seeding |
| Gleam Extractor | OCaml + tree-sitter | XML CST parsing of .gleam files |
| Taint Engine | OCaml | Taint propagation, reachability, vulnerability rules |
| Supply Chain Audit | OCaml | OSV.dev CVE lookup, staleness scoring, caching |
| **Claws** | OCaml | Code smells, complexity, DRY detection |
| **Persistent Cache** | OCaml + SQLite | Extraction results cached across runs |
| **Worker Pool** | OCaml + Crystal | Persistent Crystal workers for parallel extraction |

## Completed Features (archived)

These features are fully implemented and their planning docs are archived in `planning/archive/`.

| Feature | Archive | Summary |
|---------|---------|---------|
| **Hunter Persona** | `009-hunter-persona.md` | Hiss/Meow/Purr terminal persona, `--no-persona` opt-out |
| **Predator Vision** | `010-predator-vision.md` | Reachability heatmap, Live/Dormant/Safe, `--format dot` |
| **Crow's Nest** | `011-crows-nest.md` | Supply chain audit: OSV CVE + staleness + caching |
| **Crystal FP Reduction** | `013-crystal-false-positive-reduction.md` | 33 FP → 0 on real codebases |
| **Implementation Status** | `012-implementation-status.md` | Detailed per-phase status of all features |

### Core Engine
- [x] Crystal extractor — `Crystal::Parser` + `Crystal::Visitor`, full taint seeding
- [x] Gleam extractor — tree-sitter XML CST, accurate node extraction
- [x] Multi-hop assignment propagation with fixed-point iteration
- [x] Sanitizer recognition, return value tracking, inter-procedural propagation
- [x] Field-sensitive tracking API, scope-aware analysis
- [x] Config-driven sources/sanitizers via `.catseye.toml`
- [x] 11 vulnerability rules: SSRF, CmdInjection, PathTraversal, SQLInjection, OpenRedirect, HardcodedSecrets, LDAP/XMLInjection, MissingTimeout, ReDoS, WeakCrypto, Deserialization
- [x] Output formats: Terminal, JSON, SARIF v2.1.0, Markdown, DOT
- [x] Hunter Persona — Hiss/Meow/Purr severity, cat banner, scent lines
- [x] Predator Vision — entry point detection, call adjacency, BFS reachability
- [x] Crow's Nest — manifest parsing, OSV.dev API, staleness engine, SQLite cache
- [x] Vulnerability DAG — backward taint tracing, multi-path flow visualization
- [x] Crystal false positive reduction — zero FP across all real scan targets
- [x] Claws module — complexity, anatomy (god/params/nesting), DRY, ameba hook
- [x] Persistent SQLite cache — extraction results persist across runs
- [x] Crystal worker pool — persistent NDJSON workers for parallel extraction
- [x] Cache CLI — `--clear-cache`, `--cache-dir`, `--no-cache`

## Real-World Scan Results

| Target | Language | Files | Nodes | Findings | Notes |
|--------|----------|-------|-------|----------|-------|
| facet_pi | Gleam | 36 | 3,001 | 0 | Client-side app, no vuln sinks |
| quickheadlines/src | Crystal | 66 | 5,337 | 1 | PathTraversal in favicon_cache.cr (real) |
| test/samples | Both | 10 | 100+ | 12+ | All rule types covered |
| test/samples/safe* | Both | 3 | ~30 | 0 | Zero false positives |

## Known Limitations

| Limitation | Description | Phase to Fix |
|------------|-------------|-------------|
| No file-level scope isolation | Variables with same name in different files share taint namespace | Phase 6 (F1) | ~~DONE~~ |
| Message template truncation | Some finding messages show `"rs}"` instead of full text | Phase 6 (F2) | ~~DONE~~ |
| No conditional taint | `if x != "" then use x` doesn't reduce taint | Phase 6 (F3) | Blocked — extractor change |
| Sanitizer only suppresses direct args | `f(URI.parse(x))` suppressed, but `y = URI.parse(x); f(y)` still flagged | Extractor change |
| Field-sensitive is read-only API | `is_tainted_field` exists but extractors don't emit field-level taint yet | Phase 9 |
| No call graph | Inter-procedural is limited to direct function name matching | Phase 9 |
| ~~No code smell detection~~ | ~~Claws module not yet implemented~~ | ~~Phase 7~~ | ~~DONE~~ |
| ~~No persistent cache~~ | ~~Cache is in-memory only, lost between runs~~ | ~~Phase 8~~ | ~~DONE~~ |

## Planning Documents

| Document | Lines | Purpose |
|----------|------:|----------|
| `TDD.md` | 1,360 | Technical Design Document — comprehensive architecture spec |
| `roadmap.md` | 197 | Phase plan — what's next, dependencies, DNF cross-reference |
| `phase6-engine-hardening.md` | 322 | Engine correctness fixes (scope isolation, template fix) |
| `phase7-claws.md` | 530 | Code smell & DRY module design |
| `phase8-cache-workers.md` | 609 | SQLite cache + Crystal worker pool |
| `phase9-cross-file.md` | 491 | Import resolution + cross-file taint propagation |
| `phase10-release.md` | 657 | Static binary, CI, opam, docs, release automation |
| `DNF.md` | 202 | Deferred items with rationale and revisit triggers |
| `tasks.md` | 105 | Active task list with status |
| `status.md` | — | This document |
| `svelte-support.md` | 99 | Future Svelte extractor design |
| `archive/` | — | Completed feature planning docs (001–013) |

**Total: ~4,900 lines across 12 documents. All 5 phases (6–10) have dedicated plan files.**

*Last updated: 2026-05-11*
