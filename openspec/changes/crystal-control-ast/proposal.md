# Crystal Control Flow AST Reconstruction

**Change:** `crystal-control-ast`
**Priority:** P1
**Size:** M (2-3 days)
**Status:** ✅ Complete
**Commit:** `5bb117f`

## Summary

Created a hierarchical Crystal AST extractor that emits nested JSON directly from the Crystal compiler's visitor pattern, eliminating the need to reconstruct control flow from flat sequential nodes.

## What Changed

### New Files
- **`src/extractor/hierarchical_extractor.cr`** — New `CatseyeHierarchicalVisitor` that overrides `visit(Crystal::If)`, `visit(Crystal::Case)`, `visit(Crystal::Def)`, etc. and emits nested JSON with `condition`, `then`, `else`, `whens`, `body` child objects. Also preserves taint/scent/sanitizer metadata.

- **`src/ocaml/lib/catseye_ast/crystal_hierarchical_mapper.ml`** — OCaml mapper that parses the hierarchical JSON directly into `CatseyeAST.t` expressions (`EIf`, `ECase`, `EBlock`, `EApp`, etc.). Auto-discovers the hierarchical extractor.

### Modified Files
- **`src/ocaml/lib/catseye_ast/parse.ml`** — `parse_crystal` now uses hierarchical mapper by default, falls back to flat mapper on failure.
- **`src/ocaml/lib/catseye_ast/dune`** — Added `crystal_hierarchical_mapper` to modules list.

## Key Design Decisions

1. **Visitor pattern with `false` returns**: By returning `false` from each `visit` override, we take manual control of child traversal. This produces proper nesting in the JSON output instead of flattening.

2. **`node.accept(self)` dispatch**: Uses Crystal's native double-dispatch for type safety. Unknown AST node types fall back to the catch-all `visit(node : Crystal::ASTNode)`.

3. **Auto-discovery resolution order**:
   - `CATSEYE_CRYSTAL_EXTRACTOR` env var (explicit override)
   - `src/extractor/hierarchical_extractor.cr` (project relative)
   - `bin/catseye-crystal-hierarchical-extractor` (installed binary)
   - Fallback to old flat extractor

4. **Unless → negated if**: `Crystal::Unless` maps to `EIf(EUnOp("!", cond), then, else)` in OCaml.

5. **Case branches**: `Crystal::When` patterns parsed into `PLiteral`/`PVar`/`PDiscard`. Else branch appended as `PDiscard` pattern.

## Results

| File | Before (flat) | After (hierarchical) |
|------|---------------|---------------------|
| `complex.cr` | EUnknown("control:if") | EIf(EIf(EIf(...), EIf(...)), ECase(...)) |
| Complexity M | 0 (AST path) → 13 (flat fallback) | 13 (AST path directly) |
| GodObject | 25 defs via flat | 25 defs via AST |
| LongParams | 7 params via flat | 7 params via AST |

## Acceptance Criteria — All Met

- [x] `complex_function` in `complex.cr` produces `HighComplexity` via AST path (M=13)
- [x] Crystal `case` with `when` branches produces `ECase` with correct branch count
- [x] Crystal `if`/`unless` produces `EIf` with correct then/else structure
- [x] All 9 Claws findings on test corpus preserved via AST path
- [x] Flat engine findings identical (no regressions)
- [x] `dune build` succeeds, all tests pass

## Future Work

- Port remaining extractor features: `Crystal::MacroIf`, `Crystal::MacroFor`, `Crystal::EnumDef`
- Add `metadata` field to extractor output for taint flow (condition-line tracking)
- Consider making `--bridge` the default for Crystal
- Pre-compile `hierarchical_extractor.cr` to a binary for performance
