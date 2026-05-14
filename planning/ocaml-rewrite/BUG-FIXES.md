# OCaml Bug Fixes — Implementation Plan

**Date**: 2026-05-10  
**Issue**: Pre-existing bugs discovered during anti-pattern refactoring  
**Priority**: High — These bugs prevent the tool from working correctly on real code

---

## Bugs to Fix

| # | Bug | Severity | Impact | Root Cause | Status |
|---|-----|----------|--------|------------|--------|
| B1 | DAG Performance: Exponential complexity in `build_dag` | High | Files with many nodes timeout | `trace` function could have exponential behavior | ✅ FIXED |
| B2 | Message Template: Finding messages truncated | Medium | Unreadable findings | `substitute_template` bug | ⏸️ DEFERRED |
| B3 | Taint Source Matching: Only exact names work | Medium | Generic param names not recognized | `constants.ml` exact matching | ⏸️ DEFERRED |

---

## B1: DAG Performance Fix — COMPLETED ✅

### Changes Made

Added depth limit and cycle detection to `dag.ml`:

```ocaml
(** Maximum recursion depth for trace to prevent infinite loops *)
let max_trace_depth = 50

(* In trace function: *)
let rec trace var =
  trace_with_depth var 0 StringSet.empty

and trace_with_depth var depth seen =
  (* Check depth limit and cycle detection *)
  if depth > max_trace_depth || StringSet.mem var seen then
    ([], [], [])
  else
    let seen' = StringSet.add var seen in
    ...
```

### Test Results

| File | Nodes | Before | After |
|------|-------|--------|-------|
| test/samples (8 files) | 127+ | Timeout | **15ms** |
| vulnerable.gleam | 18 | 15ms | 15ms |

The fix enables the analysis to complete in ~15ms for all test files.

### Root Cause Analysis

The original `trace` function in `build_dag` had no depth limit or cycle detection. While the algorithm is theoretically O(n) for tracing through assignments, practical issues like:
- Circular variable references (a = b, b = a)
- Deep chains (>50 assignments)
- Missing assignments (could cause infinite loops)

could cause exponential behavior or infinite recursion.

The depth limit of 50 is sufficient for practical code while preventing runaway recursion.

---

## B2: Message Template Fix — DEFERRED

### Problem

Finding messages are truncated. For example:
- Template: `"Potential open redirect via {sink} with user-controlled URL: {tainted_vars}."`
- Output: `"rs}"`

### Next Steps

1. Add debug output to trace the substitution
2. Fix the `substitute_template` function
3. Test with known templates

---

## B3: Taint Source Matching — DEFERRED

### Problem

Function parameters need exact names like `params` to be recognized as taint sources. Generic names like `p` are not recognized.

### Next Steps

1. Add `p` to `known_sources` in `constants.ml`
2. Test with both `params` and `p` parameter names

---

## Files Modified

| File | Changes |
|------|---------|
| `lib/catseye_engine/dag.ml` | Added `max_trace_depth = 50`, depth tracking, cycle detection |
| `lib/catseye_engine/engine.ml` | Minor cleanup, refactored analyze function |

---

## Success Criteria

- [x] Files with many nodes complete in <1 second
- [x] Build passes
- [ ] Finding messages show full template text — **DEFERRED**
- [ ] Both `params` and `p` as param names work as sources — **DEFERRED**
