# Catseye Planning Documents

This folder contains architectural planning, design decisions, and task tracking for the Catseye project.

## Current Status (May 2026)

### ✅ Unified AST Architecture — Complete

Catseye implements a unified AST-based analysis pipeline following these principles:

1. **Ban the Regex** — If a file cannot be parsed into an AST, emit a `ParsingFailure` finding
2. **Macro-Awareness** — Crystal parser must expand macros so OCaml sees "final scent"
3. **JSON Bridge** — Both tree-sitter (Gleam) and native parser (Crystal) output to `CatseyeAST.t`

```
Gleam ──▶ tree-sitter ──▶ gleam_mapper ──▶ CatseyeAST.t
Crystal ──▶ extractor ──▶ crystal_mapper ──▶ CatseyeAST.t
                                              │
                          ┌───────────────────┴───────┐
                          │         ai_linter          │
                          ├───────────────────────────┤
                          │ AST_rules (structural)    │
                          │ Gleam_rules              │
                          │ Crystal_rules            │
                          └───────────────────────────┘
```

### Working Rules

**Crystal:** `hallucinated-stdlib`, `deprecated-syntax`, `redundant-conversion`, `primitive-obsession`

**Gleam:** `list-wrap-unnecessary`, `deprecated-result-check`, `panic-call`, `hallucinated-or-default`, `hallucinated-to-list`, `typescript-interface`

---

## Active Documents

| File | Purpose |
|------|---------|
| `README.md` | This file — overview and current status |
| `tasks.md` | Active task tracking |
| `39-unified-ast-architecture.md` | Three pillars specification |
| `40-ai-patterns-hunting-plan.md` | 4 categories of AI anti-patterns |
| `37-ai-linter-architecture.md` | AI linter design |
| `38-ai-linter-ocaml-plan.md` | OCaml implementation |
| `35-gleam-crystal-linter.md` | Initial linter exploration |
| `36-ai-linter-impl.md` | Implementation details |
| `claws-improvements.md` | Claws code smell module |
| `status.md` | Status snapshots |

---

## Libraries

- `src/ocaml/lib/catseye_ast/` — Unified AST schema
- `src/ocaml/lib/ai_linter/` — AST-based rules
- `src/ocaml/lib/catseye_cli/` — CLI with `--ai-lint` flag

---

## Running Tests

```bash
# Build
cd src/ocaml && dune build

# Test Gleam
TREE_SITTER_GLEAM_GRAMMAR=third_party/tree-sitter dune exec test/ast/catseye_ast_test.exe

# CLI with AI linter
./catseye --ai-lint target_dir/
```

---

## Guidelines for AI Assistants

- Use ripgrep (`rg`) for text searches and edits when possible
- See `~/.pi/agent/skills/cli-text-tools/SKILL.md` for ripgrep patterns
- Use aider-style diff format (`<<<<<<< SEARCH` / `=======` / `>>>>>> REPLACE`)
- Test changes with `dune build` before committing

---

## Archive (`planning/archive/`)

Superseded or exploration-phase documents:
- `DNF.md` — Deferred Nice-to-Haves (original)
- `TDD.md` — Test-driven development notes
- `architecture.md` — Original architecture
- `roadmap.md` — Historical roadmap
- `oxcaml-exploration.md` — OCaml rewrite exploration
- `001-*.md` through `013-*.md` — Implementation snapshots
- `ocaml-rewrite/` — OCaml rewrite exploration notes

## DNF (`planning/dnf/`)

**Deferred Nice-to-Haves** — intentional deferrals with rationale and revisit triggers:
- `41-riot-supervisor-exploration.md` — Riot/Supervisor exploration
- `42-miou-vs-moonpool.md` — Miou vs Moonpool comparison
- `43-moonpool-integration-plan.md` — Moonpool integration plan

See `planning/archive/DNF.md` for the main DNF tracking document.