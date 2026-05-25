# Catseye Planning Documents

Architectural planning, design decisions, and gap analysis for the Catseye static analysis scanner.

## Quick Start

| Document | Purpose |
|----------|---------|
| `PROJECT_STATUS.md` | Current status, known issues, architecture overview |
| `security-analysis-gaps.md` | Security detector gaps and implementation status |

## Active Documents

| File | Purpose |
|------|---------|
| `PROJECT_STATUS.md` | Overall project health, known issues, next steps |
| `security-analysis-gaps.md` | Security gap analysis and implementation tracker |
| `catseye_false_positives.md` | Known false positive patterns (don't fix) |
| `ARCHITECTURE.md` | OCaml/Base environment rules for developers |

## Archived

Historical planning documents moved to `archive/`:

| Document | Status |
|----------|--------|
| Phase implementation docs (6-10) | ✅ Complete |
| Architecture snapshots | ✅ Complete |
| Exploration notes | ✅ Complete |

See `archive/` for implementation history and reference materials.

## OpenSpec Tracks

Formal change tracking in `openspec/config.yaml`:

| Track | Status |
|-------|--------|
| `security-rules-review-2025-05` | Phase 1 done |
| `jane-street-base-migration` | Not started |
| `claws-anti-patterns` | Phase 1 open |
| `interprocedural-dominance` | Not started |

## Source Code

- `src/ocaml/lib/catseye_ast/` — Unified AST schema + language mappers
- `src/ocaml/lib/ai_linter/` — Per-language AST rules
- `src/ocaml/lib/catseye_claws/` — Code smell detection
- `src/ocaml/lib/catseye_cli/` — CLI orchestrator
- `src/ocaml/lib/catseye_engine/` — Taint engine + security node extraction
- `src/ocaml/lib/catseye_il/` — IL/CFG-based taint analysis
- `src/ocaml/rules/` — KDL taint rule definitions