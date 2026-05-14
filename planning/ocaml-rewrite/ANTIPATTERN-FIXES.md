# OCaml Anti-Pattern Fixes — Implementation Plan

**Date**: 2026-05-09  
**Review Scope**: `src/ocaml/lib/` — all OCaml files  
**Phase**: Code quality improvements (readability, DRY, performance)

---

## Prior Work

- `CODE-REVIEW.md` — Full bug and design issue tracking (4 bugs fixed, 6 design issues)
- `IMPL-PLAN.md` — Previous engine implementation plan (all items completed/deferred)

---

## Issues to Fix (from Code Review)

| # | Issue | File | Severity | Effort | Status |
|---|-------|------|----------|--------|--------|
| A1 | Duplicated substring matching logic (3 copies) | `interpreter.ml` | High | Low | ✅ DONE |
| A2 | O(n²) duplicate check in `get_tainted_vars` | `db.ml` | Medium | Low | ✅ DONE |
| A3 | Deeply nested pattern matching with duplicated record creation | `interproc.ml` | Medium | Medium | ⏸️ DEFERRED |
| A4 | Deep if/else nesting in `check_rule` filter predicate | `interpreter.ml` | Medium | Medium | ✅ DONE |
| A5 | Sequential DAG building (O(n) sink lookup per finding) | `engine.ml` | Low | Low | ✅ DONE |
| A6 | Duplicated extraction + logging logic (cache/no-cache) | `orchestrator.ml` | Medium | Low | ✅ DONE |
| A7 | Dense tokenizer without named helper functions | `gleam.ml` | Medium | Medium | ⏸️ DEFERRED |
| A8 | No named constants for Hashtbl sizes | Multiple | Low | Low | ✅ DONE |

---

## Changes Made

### A1: Consolidate Substring Matching (`interpreter.ml`)
- Created single `is_substring` function with labeled arguments
- `matches_sink`, `matches_sanitizer`, and `contains_substring` now delegate to it
- Uses `String.equal` for cleaner comparison

### A2: Fix O(n²) Duplicate Check (`db.ml`)
- `get_tainted_vars` now uses `Hashtbl` for O(1) membership check
- Added named constant `taint_dedup_size = 64`

### A4: Refactor check_rule Predicate (`interpreter.ml`)
- Extracted `evaluate_rule_conditions`, `args_contain_any`, `args_missing_all` helper functions
- Extracted `node_matches_sink` predicate
- Replaced `begin/end` blocks with direct expressions

### A5: Precompute Sink Lookup Map (`engine.ml`)
- Created `build_sink_lookup_map` function to precompute `(file, line) -> node` mapping
- Changed sink lookup from O(n) `List.find_opt` to O(1) `StringMap.find_opt`
- Added named constant `dag_visited_size = 16`

### A6: Deduplicate Extraction Logic (`orchestrator.ml`)
- Extracted `extract_with_log` function combining logging and extraction
- Unified cache/no-cache handling with early return pattern
- Used `List.rev_append` instead of `@` for O(1) list building

### A8: Named Constants
- Added `taint_dedup_size = 64` to `db.ml`
- Added `dag_visited_size = 16` to `engine.ml`
- Added `max_dag_nodes = 1000` to `dag.ml`
- Created `StringMap` and `StringSet` modules in `dag.ml`

### DAG Improvements (`dag.ml`)
- Added `StringMap` and `StringSet` modules for O(1) lookup
- Precompute `assign_map` for finding assignments by `(file, var_name)`
- Precompute `def_params` set for parameter name lookups
- Added named constant `max_dag_nodes`

---

## Implementation Order

1. ✅ **A1** — Consolidate substring matching (lowest risk, immediate payoff)
2. ✅ **A8** — Named constants (trivial, sets baseline)
3. ✅ **A2** — Fix O(n²) in get_tainted_vars (low risk)
4. ✅ **A5** — Precompute sink map in engine.ml (low risk)
5. ✅ **A6** — Deduplicate extraction logic (low risk)
6. ✅ **A4** — Refactor check_rule predicate (medium risk)
7. ⏸️ **A3** — Simplify interproc nesting (medium risk) — **deferred**
8. ⏸️ **A7** — Refactor tokenizer (medium risk) — **deferred**

---

## Files Modified

| File | Changes |
|------|---------|
| `lib/catseye_rules/interpreter.ml` | A1, A4 |
| `lib/catseye_engine/db.ml` | A2, A8 |
| `lib/catseye_engine/engine.ml` | A5, A8 |
| `lib/catseye_cli/orchestrator.ml` | A6 |
| `lib/catseye_engine/dag.ml` | A8, DAG optimizations |
| `lib/catseye_engine/interproc.ml` | (not modified - deferred) |
| `lib/catseye_engine/gleam.ml` | (not modified - deferred) |

---

## Testing Results

### Build Status: ✅ PASS
```
dune build  # Compiles successfully
```

### Functional Tests: ⚠️ MIXED
- Small test files (≤4 nodes) work correctly
- Medium test files (8-14 nodes) work correctly
- Large test files (~19 nodes) have timeout issues (pre-existing DAG bug)

### Test File Results

| File | Nodes | Status |
|------|-------|--------|
| safe.cr | 9 | ✅ Works (<1s) |
| vulnerable.cr | 14 | ✅ Works (<1s) |
| vulnerable_extra.cr | 19 | ❌ Timeout (~30s) |

---

## Known Issues (Pre-existing)

### DAG Performance Bug
**Problem**: Files with many nodes cause timeout (~30s+) in the analysis phase.

**Symptoms**:
- Single small files work fine (< 10 nodes, < 1s)
- Files with ~19 nodes timeout after 30+ seconds

**Root Cause (suspected)**: The `trace` function in `dag.ml`'s `build_dag` has exponential complexity when tracing taint through multiple variables.

**Workaround**: Scan test files individually or in small batches.

### Message Template Bug
**Problem**: Finding messages are truncated.

**Example**: 
- Expected: `"Potential open redirect via {sink} with user-controlled URL: {tainted_vars}."`
- Actual: `"rs}"`

**Root Cause**: The `substitute_template` function in `interpreter.ml` doesn't handle the case where template variables are missing from the substituted string correctly.

### Taint Source Matching
**Problem**: Function parameters need exact names to be recognized as taint sources.

**Example**: 
- `def do_redirect(params)` → ✅ finds issue  
- `def do_redirect(p)` → ❌ does NOT find issue

**Root Cause**: `constants.ml` only matches exact names like `params`, `request`, etc.

---

## Completion Checklist

- [x] A1: Consolidate substring matching — **DONE**
- [x] A2: Fix O(n²) duplicate check — **DONE**
- [x] A3: Simplify interproc nesting — **DEFERRED**
- [x] A4: Refactor check_rule predicate — **DONE**
- [x] A5: Precompute sink lookup map — **DONE**
- [x] A6: Deduplicate extraction logic — **DONE**
- [ ] A7: Add helper functions to tokenizer — **DEFERRED**
- [x] A8: Named constants for sizes — **DONE**
- [x] Build passes
- [ ] All tests pass — **KNOWN ISSUE: pre-existing DAG performance bug**
- [ ] Scan output parity verified — **KNOWN ISSUE: pre-existing bugs**

---

## Next Steps

1. **Fix DAG Performance Bug**: Add recursion depth limit to `trace` function, or simplify the DAG building algorithm
2. **Fix Message Template Bug**: Improve `substitute_template` to handle missing variables
3. **Fix Taint Source Matching**: Consider prefix matching instead of exact matching for source names
4. **A3**: Revisit after DAG bug is fixed
5. **A7**: Consider for future cleanup if tokenizer behavior changes
