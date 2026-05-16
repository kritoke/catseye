# Claws → CatseyeAST Migration — Tasks

**Change:** `claws-ast-migration`
**Status:** Open

## Phase 1: Infrastructure

- [x] 1.1 Add `catseye.ast` dependency to `src/ocaml/lib/catseye_claws/dune`
- [x] 1.2 Create `src/ocaml/lib/catseye_claws/ast_scope.ml` — shared `ast_scope` type and `build_ast_scopes` that walks `CatseyeAST.t list` producing `ast_scope list`
- [x] 1.3 Add `analyze_ast : Catseye_ast.Types.t list -> Types.claws_config -> Finding.t list` to `smells.ml` alongside existing `analyze`
- [x] 1.4 Wire `smells.ml` `analyze_ast` into `orchestrator.ml` — pass parsed ASTs to Claws when available
- [x] 1.5 Verify `dune build` succeeds, existing tests pass
- [x] 1.6 Fix gleam_mapper.ml ECase branches (was always empty)
- [x] 1.7 Bundle gleam_parser.so as grammar fallback (works without nix)

## Phase 2: Complexity (155 lines, 25 refs)

- [x] 2.1 Create `complexity_ast.ml` — `count_decisions : Catseye_ast.Types.expr -> int` walks EIf (+1/+2), ECase (+branches), EBinOp with &&/|| (+1), EBlock (recurse), ELet (recurse body)
- [x] 2.2 Add `analyze_ast : Catseye_ast.Types.t list -> Types.claws_config -> Finding.t list` using `ast_scope` + `count_decisions`
- [x] 2.3 Wire into `smells.ml` AST path
- [x] 2.4 Test: scan `test/samples/smell_samples/` — all existing tests pass
- [x] 2.5 Test: scan facet_pi — 41 HighComplexity findings (was 0 with flat engine)

## Phase 3: Anatomy (325 lines, 63 refs)

- [x] 3.1 Create `anatomy_ast.ml` — `check_params_ast` reads `IFunction` pattern lists directly for exact param count
- [x] 3.2 `check_nesting_ast` — walk `EIf`/`ECase` nesting depth from expression tree (exact, not heuristic)
- [x] 3.3 `check_god_objects_ast` — track `IClass`/`IModule` boundaries, count `IFunction` items per class/module (not per file)
- [x] 3.4 Wire into `smells.ml` AST path
- [x] 3.5 Test: scan `test/samples/smell_samples/params.cr`, `god.cr` — compare with flat engine
- [x] 3.6 Test: scan quickheadlines — verify no regression

## Phase 4: DRY (248 lines, 38 refs)

- [ ] 4.1 Create `dry_ast.ml` — `hash_expr : Catseye_ast.Types.expr -> string` canonicalizes expression subtrees
- [ ] 4.2 `detect_ast` — hash subtrees across files, group by hash, report duplicates above threshold
- [ ] 4.3 Wire into `smells.ml` AST path
- [ ] 4.4 Test: scan `test/samples/smell_samples/dry_a.cr` + `dry_b.cr` — verify duplication detected
- [ ] 4.5 Verify reduced noise vs flat engine (skip boilerplate like import sequences)

## Phase 5: Extra Smells (849 lines, 176 refs — largest)

- [ ] 5.1 Create `extra_smells_ast.ml` with `build_ast_scopes` (reuse from ast_scope.ml)
- [ ] 5.2 `check_long_method_ast` — count nodes in expression tree (exact vs heuristic line-range)
- [ ] 5.3 `check_complex_conditionals_ast` — walk `EBinOp` with &&/|| chains
- [ ] 5.4 `check_message_chains_ast` — walk `EFieldAccess` nesting depth
- [ ] 5.5 `check_data_clumps_ast` — track function parameter sets across `ast_scope` list
- [ ] 5.6 `check_flag_arguments_ast` — analyze `EIf` conditions referencing specific params
- [ ] 5.7 `check_complex_match_ast` — count `ECase` branches
- [ ] 5.8 `check_dead_code_ast` — detect unreachable `EBlock` after `EIf` with always-true conditions
- [ ] 5.9 `check_data_classes_ast` — analyze `ITypeDef` for data-only types
- [ ] 5.10 `check_feature_envy_ast` — count external var accesses in function bodies
- [ ] 5.11 Wire all into `smells.ml` AST path
- [ ] 5.12 Test: scan full test corpus, compare with flat engine results

## Phase 6: Concurrency (250 lines, 55 refs)

- [ ] 6.1 Create `concurrency_ast.ml` — walk `EApp` calls for spawn/send/receive patterns
- [ ] 6.2 `check_orphaned_spawn_ast` — find `EApp("spawn", ...)` without surrounding rescue/ensure
- [ ] 6.3 `check_muted_channel_ast` — find channel send without receive
- [ ] 6.4 Wire into `smells.ml` AST path
- [ ] 6.5 Test: scan `test/samples/concurrency/traps.cr` — verify findings

## Phase 7: Integration & Validation

- [ ] 7.1 Make AST path the default in `smells.ml` (keep flat as fallback behind flag)
- [ ] 7.2 Full scan comparison on test corpus: AST findings == flat findings (or better)
- [ ] 7.3 Full scan on quickheadlines (67 files) — no crashes, no regressions
- [ ] 7.4 Full scan on facet_pi (272 files) — no crashes, no regressions
- [ ] 7.5 Scan all 10 Crystal projects — no crashes, reasonable findings
- [ ] 7.6 Update `openspec/config.yaml` status to complete
- [ ] 7.7 Update `planning/OPENSPEC.md` — mark A4 as done

## Verification Commands

```bash
# Build
cd src/ocaml && dune build

# Test corpus
just test

# Quickheadlines
./bin/catseye-ocaml --rules src/ocaml/rules --ai-lint --claws /workspaces/quickheadlines/src/

# facet_pi
./bin/catseye-ocaml --rules src/ocaml/rules --ai-lint --claws /workspaces/facet_pi/

# Compare flat vs AST
./bin/catseye-ocaml --rules src/ocaml/rules --claws --format json test/samples/ > /tmp/flat.json
./bin/catseye-ocaml --rules src/ocaml/rules --claws --format json --ast-bridge test/samples/ > /tmp/ast.json
diff <(jq '.findings_count' /tmp/flat.json) <(jq '.findings_count' /tmp/ast.json)
```
