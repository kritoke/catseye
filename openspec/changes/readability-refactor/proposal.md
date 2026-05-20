# Readability Refactor — Safe Changes

**Change:** `readability-refactor`  
**Priority:** P2  
**Size:** S (4-6 hours)

## Motivation

Manual code review identified 15 safe refactoring opportunities across the
Crystal extractors and OCaml engine. These are pure structure changes that
preserve all detection logic: variable renames, helper extraction, magic
number constants, duplicated constant consolidation, and guard-clause
flattening.

All items classified as 🟢 Safe in `planning/code-readability-review-2025-05.md`.

## Scope

### In Scope (🟢 Safe — no logic change)

1. Variable renames (8 items across 6 files)
2. `Finding.t` builder helper in `extra_smells.ml`
3. Guard-clause flattening in `cfg_taint.ml` `check_call_sinks`
4. Magic number → named constants (5 items)
5. Extract shared constants to `common.cr` between Crystal extractors
6. Replace hand-rolled `find_substring` with stdlib
7. JSON emit helper for `hierarchical_extractor.cr`
8. Stringly-typed node type constants in `extractor.cr`

### Out of Scope

| Item                                  | Risk | Reason                         | Where Tracked                                      |
| ------------------------------------- | ---- | ------------------------------ | -------------------------------------------------- |
| Generic `fold_expr` for AST walkers   | 🔴   | Could silently break detection | `planning/code-readability-review-2025-05.md` §3.1 |
| `crystal_rules.ml` god module split   | 🔴   | Hidden rule dependencies       | `planning/code-readability-review-2025-05.md` §5.4 |
| `propagate.ml` ref → fold conversion  | 🟡   | Fixed-point sequencing         | `planning/code-readability-review-2025-05.md` §5.1 |
| `is_idiomatic_chain` cleanup          | 🟡   | FP suppression filter          | `planning/code-readability-review-2025-05.md` §4.1 |
| `annotate_timeouts` decomposition     | 🟡   | Phase ordering                 | `planning/code-readability-review-2025-05.md` §4.2 |
| `orchestrator.ml` `run` decomposition | 🟡   | Mutable state, side effects    | `planning/code-readability-review-2025-05.md` §4.3 |

## Verification

After each task:

1. `just build` — must compile cleanly
2. `just test` — all existing tests pass
3. Self-scan diff — no new or missing findings on `test/samples/`

```bash
# Capture baseline before starting
catseye scan test/samples/ --format json > /tmp/baseline.json

# After each task
catseye scan test/samples/ --format json > /tmp/after.json
diff <(jq -S '.findings[] | {rule,file,line,message}' /tmp/baseline.json) \
     <(jq -S '.findings[] | {rule,file,line,message}' /tmp/after.json)
# Must be empty
```
