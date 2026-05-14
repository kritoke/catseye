# Catseye Planning Documents

This folder contains architectural planning, design decisions, and task tracking for the Catseye project.

## Three Pillars Architecture

Catseye implements a unified AST-based analysis pipeline following these principles:

1. **Ban the Regex** — If a file cannot be parsed into an AST, emit a `ParsingFailure` finding (never use regex for analysis)

2. **Macro-Awareness** — Crystal parser must expand macros so the OCaml engine sees the "final scent" of code

3. **JSON Bridge** — Both tree-sitter (Gleam) and native parser (Crystal) output to the same `CatseyeAST.t` schema

```
┌─────────────────────────────────────────────────────────────┐
│                    Catseye Architecture                      │
├─────────────────────────────────────────────────────────────┤
│  Gleam ──▶ tree-sitter ──▶ gleam_mapper ──▶ CatseyeAST.t    │
│  Crystal ──▶ extractor ──▶ crystal_mapper ──▶ CatseyeAST.t │
│                                              │              │
│                          ┌───────────────────┴───────┐     │
│                          │         ai_linter          │     │
│                          ├───────────────────────────┤     │
│                          │ AST_rules (structural)    │     │
│                          │ Gleam_rules              │     │
│                          │ Crystal_rules            │     │
│                          └───────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Key Documents

| File | Purpose |
|------|---------|
| `39-unified-ast-architecture.md` | Formalizes the three pillars and migration plan |
| `40-ai-patterns-hunting-plan.md` | Documents 4 categories of AI anti-patterns |
| `37-ai-linter-architecture.md` | AI linter design and rule structure |
| `38-ai-linter-ocaml-plan.md` | OCaml implementation details |
| `tasks.md` | Current task tracking |

## Libraries

- `src/ocaml/lib/catseye_ast/` — Unified AST schema (CatseyeAST.t)
- `src/ocaml/lib/ai_linter/` — AST-based rules (ast_rules, gleam_rules, crystal_rules)
- `src/ocaml/lib/catseye_engine/` — Main analysis engine
- `src/ocaml/lib/tree_sitter/` — Tree-sitter integration

## Test Samples

- `test/samples/ai_antipatterns.gleam` — Gleam AI anti-patterns test
- `test/samples/ai_antipatterns.cr` — Crystal AI anti-patterns test

## Guidelines for AI Assistants

- Use ripgrep (`rg`) for text searches and edits when possible
- See `~/.pi/agent/skills/cli-text-tools/SKILL.md` for ripgrep patterns
- Use aider-style diff format (`<<<<<<< SEARCH` / `=======` / `>>>>>> REPLACE`) for clarity
- Prefer AST-based analysis over regex where possible
- Test changes with `dune build` before committing

## Running Tests

```bash
# Gleam parsing (requires tree-sitter grammar)
TREE_SITTER_GLEAM_GRAMMAR=third_party/tree-sitter dune exec test/ast/catseye_ast_test.exe

# Crystal parsing (requires Crystal extractor)
CATSEYE_CRYSTAL_EXTRACTOR='crystal run src/extractor/extractor.cr --' dune exec test/ast/catseye_ast_test.exe
```