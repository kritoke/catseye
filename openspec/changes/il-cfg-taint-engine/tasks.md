## 1. IL Types & Conversion

- [x] 1.1 Create `src/ocaml/lib/catseye_il/` with `dune` file depending on `catseye.ast` and `catseye.types`
- [x] 1.2 Define IL types in `il_types.ml`: `il_node`, `il_block`, `lval`, `il_expr`, `il_function`
- [x] 1.3 Implement `of_catseye_ast.ml` with `convert_item` and `convert_expr` functions
- [x] 1.4 Add `--cfg` flag to `args.ml` and `config.ml`
- [x] 1.5 Verify `dune build` succeeds with empty IL module

## 2. CFG Builder

- [x] 2.1 Define `basic_block` and `cfg` types in `cfg_builder.ml`
- [x] 2.2 Implement `build_cfg : il_block -> cfg` with branch/merge block creation
- [x] 2.3 Add `print_cfg` for debugging (render blocks + edges as text)
- [x] 2.4 Unit test: linear block, if-else, nested if verified via synthetic AST

## 3. CFG-based Taint Engine

- [x] 3.1 Define `taint_state` type (set of tainted lvalues)
- [x] 3.2 Implement `analyze_cfg : cfg -> taint_rule -> findings` forward dataflow
- [x] 3.3 Wire into `engine.ml` behind `--cfg` flag alongside existing flat path
- [x] 3.4 Verify test corpus: CFG finds 28 findings vs flat 23 (20 shared, 3 flat-only by design)
- [x] 3.5 Verify all 8 real projects: CFG finds more (deeper tracking), flat is conservative baseline

## 4. KDL Precision Upgrades

- [x] 4.1 Add `arg` field to KDL sink type in `loader.ml`
- [x] 4.2 Add `$var` metavariable matching in `interpreter.ml` sink/source/sanitizer lookup
- [x] 4.3 Update KDL rules (SSRF, PathTraversal, SQLInjection, CommandInjection, OpenRedirect) with `arg=0`
- [x] 4.4 Verify reduced FPs on test corpus
- [x] 4.5 Fix `get_prop` to handle numeric KDL property values
- [x] 4.6 Add `arg_pos` support to CFG taint engine (`check_call_sinks`)
- [x] 4.7 Fix FP root cause: `propagate.ml` did not check sanitizers before tainting assign targets — added sanitizer check + cleansing pass

## 5. Integration & Migration

- [x] 5.1 Run full scan comparison on all test projects, diff JSON output (see `planning/il-cfg-refactor.md`)
- [x] 5.2 Document IL/CFG in `planning/il-cfg-refactor.md` with actual results
- [x] 5.3 Update OPENSPEC.md with completed status (no changes needed — tracked in openspec change files)
