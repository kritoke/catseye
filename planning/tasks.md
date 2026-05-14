# Catseye — Active Tasks

**Last Updated:** 2026-05-14  
**Replaced by:** `planning/README.md` (more current status)

---

## ✅ COMPLETED: Unified AST Architecture

See `planning/39-unified-ast-architecture.md` for full specification.

### Three Principles

| Principle | Description | Status |
|-----------|-------------|--------|
| **Ban the Regex** | If a file cannot be parsed into an AST, emit `ParsingFailure` finding | ✅ Implemented |
| **Macro-Awareness** | Crystal parser must expand macros before emitting AST | ✅ Commented + TODO |
| **JSON Bridge** | Both Gleam and Crystal output the same `CatseyeAST.t` schema | ✅ Implemented |

### Migration Tasks (All ✅ Done)

| Task | Size | Status |
|------|------|--------|
| M1: Create catseye_ast library | Medium | ✅ Done |
| M2: Remove regex from ai_linter | Medium | ✅ Done |
| M3: Enable macro expansion | Small | ✅ Commented |
| M4: Create CrystalMapper | Large | ✅ Done |
| M5: Wire GleamMapper | Small | ✅ Done |

### Created Files

```
src/ocaml/lib/catseye_ast/
├── types.ml            # CatseyeAST.t unified schema
├── error.ml           # ParsingFailure type
├── parse.ml           # Unified parse interface
├── gleam_mapper.ml    # Tree-sitter → CatseyeAST
└── crystal_mapper.ml  # Security_node JSON → CatseyeAST

src/ocaml/lib/ai_linter/
├── types.ml           # Severity levels
├── ast_rules.ml       # Structural rules (todo-in-code)
├── gleam_rules.ml     # Gleam-specific rules
└── crystal_rules.ml   # Crystal-specific rules

third_party/tree-sitter/gleam/
├── native_gleam.so    # Native-compiled tree-sitter grammar
└── *.so              # Grammar shared libraries
```

---

## Working AI Linter Rules

### Crystal Rules
- `hallucinated-stdlib` — detects `to_map`, `String.join`
- `deprecated-syntax` — detects `puts`, `p`, `String.new`
- `redundant-conversion` — detects `String.new`
- `primitive-obsession` — detects 5+ param functions

### Gleam Rules
- `list-wrap-unnecessary` — detects `List.wrap` calls
- `deprecated-result-check` — detects `Result.is_ok/is_err`
- `panic-call` — detects `panic` keyword
- `hallucinated-or-default` — detects `_or_default` methods
- `hallucinated-to-list` — detects `_to_list` methods
- `typescript-interface` — detects `interface` keyword

---

## Test Commands

```bash
# Build
cd src/ocaml && nix develop --command bash -c "dune build"

# Test Gleam
TREE_SITTER_GLEAM_GRAMMAR=/workspaces/catseye/third_party/tree-sitter dune exec test/ast/catseye_ast_test.exe

# Test Crystal
CATSEYE_CRYSTAL_EXTRACTOR='crystal run /workspaces/catseye/src/extractor/extractor.cr --' dune exec test/ast/catseye_ast_test.exe

# CLI with AI linter
./catseye --ai-lint target_dir/
```

---

## Remaining Work

- [x] Verify compilation with `dune build`
- [ ] Update security engine to use CatseyeAST.t (if needed)
- [ ] Update Claws module to use CatseyeAST.t
- [ ] Update all other modules that use generic_ast
- [ ] Deprecate generic_ast library
- [ ] Moonpool integration (deferred, see `planning/43-moonpool-integration-plan.md`)