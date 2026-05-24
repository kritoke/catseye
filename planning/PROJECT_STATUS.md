# Catseye Project Status — May 2026

**Last Updated:** 2026-05-24

## Quick Summary

| Area | Status |
|------|--------|
| OCaml Rewrite | ✅ Complete |
| Crystal Extraction | ✅ Working (native + tree-sitter) |
| Gleam Extraction | ✅ Working (tree-sitter) |
| JavaScript/TypeScript | ✅ Working (tree-sitter) |
| Security Rules | ✅ Phase 1 Complete |
| Code Smells (Claws) | ✅ Working |
| CLI SIGPIPE Bug | ⚠️ Known Issue |

---

## Recent Commits

```
159a225 Update openspec/config.yaml: add security-rules-review and jane-street-base-migration tracks
e8acc49 Add vulnerable.gleam test sample for Gleam extraction testing
a11647f Improve test_gleam.ml: accept path arg, show grammar path
7714bfc Phase 1: Security rules review fixes
0097cb2 Add security analysis rules across languages
```

---

## Active OpenSpec Tracks

See `openspec/config.yaml` for full track list. Key active tracks:

| Track | Status | Phase |
|-------|--------|-------|
| `security-rules-review-2025-05` | In Progress | Phase 1 done |
| `jane-street-base-migration` | Open | Not started |
| `code-review-2025-05` | In Progress | - |
| `readability-refactor` | In Progress | - |
| `claws-anti-patterns` | Open | Phase 1 |
| `interprocedural-dominance` | Open | Not started |

---

## Known Issues

### CLI SIGPIPE (exit 141)
The compiled `main.exe` exits with code 141 (SIGPIPE) when run directly, but works via `dune exec`. Root cause not yet determined.

**Workaround:** Use `dune exec ./bin/main.exe -- [args]` instead of running the binary directly.

**Known working:**
- `dune exec ./test/debug_run_steps.exe` 
- Direct extraction via `Crystal_ts.extract` library function

---

## Architecture Overview

```
Source Files (Crystal, Gleam, JS, TS, Rust, Svelte)
         │
         ▼
┌─────────────────────────────────────┐
│         Extraction Layer             │
│  - Crystal: native extractor + TS   │
│  - Gleam: tree-sitter              │
│  - JS/TS/Svelte: tree-sitter       │
│  - Rust: tree-sitter               │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│          CatseyeAST.t                │
│   Unified AST schema (ocaml type)    │
└─────────────────────────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────┐
│ai_linter│ │ catseye_ │
│        │ │  claws   │
│Gleam   │ │Complexity│
│Rust    │ │ DRY      │
│JS/TS   │ │Anatomy   │
│Crystal │ │Extras    │
└────────┘ └──────────┘
    │         │
    ▼         ▼
┌─────────────────────────────────────┐
│      Finding.t (unified result)     │
└─────────────────────────────────────┘
```

---

## Source Structure

```
src/ocaml/
├── bin/main.ml              # CLI entry point
├── lib/
│   ├── catseye_cli/         # CLI, config, discovery, orchestration
│   ├── catseye_engine/      # Taint engine, security nodes, cache
│   ├── catseye_types/       # Types (Security_node, Finding)
│   ├── catseye_ast/         # Unified AST + language mappers
│   ├── catseye_rules/       # KDL rule loader, interpreter
│   ├── catseye_claws/       # Code smell detection (AST-native)
│   ├── catseye_ai_linter/   # Per-language AST rules
│   └── catseye_il/          # IL/CFG-based taint analysis
└── rules/*.kdl              # Security rules
```

---

## Testing

```bash
# Build
cd src/ocaml && dune build

# Run tests
dune test

# Test specific extractor
dune exec ./test/crystal_ts_test.exe
dune exec ./test/test_gleam.exe
```

---

## Next Steps (Priority Order)

1. **Fix CLI SIGPIPE** — Debug binary exit 141
2. **Phase 2 Security Rules** — Dedup, expand coverage
3. **Jane Street Base Migration** — Performance improvements
4. **Interprocedural Analysis** — Better cross-function guard suppression