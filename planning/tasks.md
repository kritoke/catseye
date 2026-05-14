# Catseye — Active Tasks

**Last Updated:** 2026-05-13  
**Planning docs:** `planning/roadmap.md` (single source of truth)

---

## ✅ IN PROGRESS: Unified AST Architecture

> See `planning/39-unified-ast-architecture.md` for full specification.

Three principles governing all parsing and analysis:

| Principle | Description | Status |
|-----------|-------------|--------|
| **Ban the Regex** | If a file cannot be parsed into an AST, emit `ParsingFailure` finding | ✅ Implemented |
| **Macro-Awareness** | Crystal parser must expand macros before emitting AST | ✅ Commented + TODO |
| **JSON Bridge** | Both Gleam and Crystal output the same `CatseyeAST.t` schema | ✅ Implemented |

### Migration Tasks

| Task | Size | Status | File(s) | Description |
|------|------|--------|---------|-------------|
| **M1: Create catseye_ast library** | Medium | ✅ Done | `lib/catseye_ast/` | Types, error, parse, gleam_mapper, crystal_mapper |
| **M2: Remove regex from ai_linter** | Medium | ✅ Done | `lib/ai_linter/*.ml` | Converted gleam_rules, crystal_rules, ast_rules to AST patterns |
| **M3: Enable macro expansion** | Small | ✅ Commented | `extractor.cr` | Added comments + TODO for full macro expansion |
| **M4: Create CrystalMapper** | Large | ✅ Done | `lib/catseye_ast/` | Security_node JSON → CatseyeAST |
| **M5: Wire GleamMapper** | Small | ✅ Done | `lib/catseye_ast/` | Moved and updated from generic_ast |

### What Was Created

```
src/ocaml/lib/catseye_ast/
├── dune                    # Library definition
├── catseye_ast.opam        # Opam package
├── types.ml                # CatseyeAST.t unified schema (400+ lines)
├── error.ml                 # ParsingFailure type + helpers (150+ lines)
├── parse.ml                 # Unified parse interface (100 lines)
├── gleam_mapper.ml          # Tree-sitter → CatseyeAST (600+ lines)
└── crystal_mapper.ml       # Security_node JSON → CatseyeAST (400+ lines)
```

### Files Modified

| File | Change |
|------|--------|
| `extractor.cr` | Added macro expansion comments, emit ParsingFailure JSON |
| `lib/ai_linter/gleam_rules.ml` | Converted from regex to AST patterns |
| `lib/ai_linter/crystal_rules.ml` | Converted from regex to AST patterns |
| `lib/ai_linter/ast_rules.ml` | Updated to use CatseyeAST.t |
| `lib/ai_linter/dune` | Changed dependency from generic_ast to catseye_ast |
| `lib/catseye_cli/ai_linter_integration.ml` | Updated to use catseye_ast |
| `dune-project` | Added catseye-ast package |

### Remaining Work

- [ ] Verify compilation with `dune build`
- [ ] Update security engine to use CatseyeAST.t (if needed)
- [ ] Update Claws module to use CatseyeAST.t
- [ ] Update all other modules that use generic_ast
- [ ] Deprecate generic_ast library

---

## ✅ Done: Phase 6 — Engine Hardening

| Task | Size | Status | File(s) |
|------|------|--------|---------|
| **F1: File-level scope isolation** | Medium | ✅ Done | `db.ml` |
| **F2: Fix message template truncation** | Small | ✅ Done | `interpreter.ml` |
| **F3: Conditional taint refinement** | Medium | ⬜ Deferred | Needs extractor changes |
| **F4: Wire parallel extraction** | Small | ✅ Done | `orchestrator.ml`, `parallel.ml` |

---

## ✅ Done: Phase 7 — Claws Module

| Task | Size | Status | File(s) |
|------|------|--------|---------|
| All tasks | Medium | ✅ Done | `lib/catseye_claws/` |

---

## ✅ Done: Phase 8 — Persistent Cache & Workers

| Task | Size | Status | File(s) |
|------|------|--------|---------|
| All tasks | Medium | ✅ Done | `cache.ml`, `extractor.cr`, `worker_pool.ml` |

---

## ✅ Done: Phase 9 — Cross-File Taint

| Task | Size | Status | File(s) |
|------|------|--------|---------|
| All tasks | Medium | ✅ Done | Engine pipeline |

---

## ✅ Done: Phase 10 — Release & Distribution (partial)

| Task | Size | Status |
|------|------|--------|
| R1: Static binary build | Medium | 🔴 Future |
| R2: CI pipeline | Medium | ✅ Done |
| R3: Multi-architecture builds | Large | 🔴 Future |
| R4: opam package publication | Medium | 🔴 Future |
| R5: Version stamping | Small | ✅ Done |
| R6: Integration test suite | Medium | ✅ Done |
| R7: Release automation | Medium | 🔴 Future |
| R8: User documentation | Large | ✅ Done |
| R9: Nix Flake package | Medium | 🔴 Future |

---

## DNF Items

All DNF items remain deferred. See `planning/DNF.md` for rationale and revisit triggers.