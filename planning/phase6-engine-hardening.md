# Phase 6: Engine Hardening — Implementation Plan

**Phase:** 6  
**Priority:** High (correctness)  
**Depends on:** None (can start immediately)  
**Parent:** `planning/roadmap.md`  
**Status:** Ready to implement

---

## Overview

Fix known engine limitations that cause false positives or incorrect output. These are correctness issues, not features. Each task is scoped to be independently testable.

---

## F1: File-Level Scope Isolation

### Problem

Variables with the same name in different files share a taint namespace. If `x` is tainted in `a.cr`, `x` in `b.cr` is also considered tainted.

**Current mitigation:** `engine.ml` builds a `by_file` context for rule evaluation, but the underlying `Db.t` is global. The `is_tainted_in_file` function exists but propagation (`propagate.ml`) still uses the global DB for assignment taint checks via `Db.check_assignment_taint`.

**Root cause:** `check_assignment_taint` in `db.ml` calls `is_tainted acc a.Security_node.value` (global fallback) when `is_tainted_in_file` returns false:

```ocaml
(* db.ml line ~95 *)
let check_assignment_taint node acc =
  ...
  List.find_opt (fun a ->
    a.Security_node.arg_type = Security_node.ArgVar
    && (is_tainted_in_file acc a.Security_node.value node.Security_node.file
        || is_tainted acc a.Security_node.value)  (* ← THIS IS THE LEAK *)
  ) node.Security_node.args
```

### Fix

Remove the global fallback from `check_assignment_taint`. All taint checks during propagation should be file-scoped:

```ocaml
let check_assignment_taint node acc =
  let is_sanitized = ... in  (* unchanged *)
  if is_sanitized then None
  else
    List.find_opt (fun a ->
      a.Security_node.arg_type = Security_node.ArgVar
      && is_tainted_in_file acc a.Security_node.value node.Security_node.file
      (* REMOVED: || is_tainted acc a.Security_node.value *)
    ) node.Security_node.args
    |> Option.map (fun a -> a.Security_node.value)
```

**Risk:** This may break inter-procedural propagation. When `returns.ml` marks a function as tainted, the record is in the file where the function is *defined*. When `interproc.ml` checks `Db.has_record acc a.Security_node.value`, it uses the global lookup — which is correct for function names (they're unique across the codebase, usually).

**Mitigation:** Keep `has_record` and `is_tainted` as global lookups. Only remove the global fallback from `check_assignment_taint` (assignment propagation). Inter-procedural should remain global — that's its entire purpose.

### Files to Change

| File | Change |
|------|--------|
| `db.ml` | Remove `|| is_tainted acc a.Security_node.value` from `check_assignment_taint` |
| `interproc.ml` | Verify `call_has_tainted_args` uses file-scoped check (it already does for ArgVar) |
| `engine.ml` | Verify the `by_file` context in `analyze` is still correct |

### Testing

1. Create test: `test/samples/cross_file_bleed/` with two files:
   - `a.cr`: `def foo(params); url = params["url"]; end`
   - `b.cr`: `def bar(x); system(x); end` — `x` is NOT tainted
2. Run analysis, verify `bar` in `b.cr` does NOT produce a finding for `system(x)`
3. Verify existing single-file tests still pass (regression)

---

## F2: Fix Message Template Truncation

### Problem

Finding messages are truncated to `"rs}"` instead of the full template. For example:

Template: `"Potential open redirect via {sink} with user-controlled URL: {tainted_vars}."`  
Actual output: `"rs}"`

**Root cause:** The `substitute_template` function in `interpreter.ml` was rewritten (commit `079f1e8`) to fix an OOM bug, but the Buffer-based implementation may still have an off-by-one in the empty-pattern guard or the scanning logic.

### Investigation Steps

1. Add a unit test for `substitute_template`:
   ```ocaml
   let () =
     let result = substitute_template
       "Potential open redirect via {sink} with user-controlled URL: {tainted_vars}."
       ~sink:"redirect" ~vars:"url" in
     assert (result = "Potential open redirect via redirect with user-controlled URL: url.")
   ```

2. Run with debug logging to see intermediate states

3. Check if the issue is in the template itself (KDL parsing may truncate the string) vs. the substitution

### Likely Fix

The KDL parser may be splitting the message at the `{` character since `{` has special meaning in KDL. Check if the `message` node content is already truncated before substitution.

**Test:** Print the raw `rule.message_template` after KDL loading to see if it's complete.

### Files to Change

| File | Change |
|------|--------|
| `interpreter.ml` | Debug + fix `substitute_template` |
| `loader.ml` | Debug raw template from KDL parse |
| `test/` | Add unit test for template substitution |

### Testing

1. Add unit test with multi-placeholder template
2. Verify all 11 rule message templates render correctly
3. Run full scan, check output messages

---

## F3: Conditional Taint Refinement

### Problem

Variables validated by guard patterns are still considered tainted:

```crystal
if path.starts_with?("/allowed/")
  File.read(path)  # path is validated, but still flagged as tainted
end
```

The Crystal extractor already handles this partially — `matches?` and `starts_with?` remove the variable from `@tainted_vars` in `extractor.cr`. But the OCaml engine doesn't know about conditional branches.

### Approach

This is complex. Full branch-sensitive analysis requires:
1. Tracking if/else scope boundaries
2. Merging taint states at branch confluence
3. Distinguishing "cleared on true branch" from "still tainted on false branch"

**Pragmatic approach:** Instead of full branch analysis, add a **guard pattern recognizer** at the rule evaluation level:

```ocaml
(* In interpreter.ml — extend is_suspect *)
let has_recent_guard (node : Security_node.t) (all_nodes : Security_node.t list)
    (tainted_var : string) : bool =
  (* Look for a guard call on the same tainted var within 5 lines before this node *)
  List.exists (fun n ->
    n.Security_node.node_type = Security_node.Call
    && n.Security_node.file = node.Security_node.file
    && n.Security_node.line < node.Security_node.line
    && n.Security_node.line >= node.Security_node.line - 5
    && List.exists (fun a ->
      a.Security_node.arg_type = Security_node.ArgVar
      && a.Security_node.value = tainted_var
    ) n.Security_node.args
    && List.exists (fun prefix ->
      String.length n.Security_node.name >= String.length prefix
      && String.sub n.Security_node.name 0 (String.length prefix) = prefix
    ) ["starts_with?"; "matches?"; "includes?"; "in?"; "validate_"]
  ) all_nodes
```

**Trade-off:** This is a heuristic (line proximity) rather than true branch analysis. It may suppress some false negatives. But the alternative (branch-sensitive analysis) is a much larger scope change.

### Alternative: Trust the Extractor

The Crystal extractor already removes guarded variables from `@tainted_vars`. If the extractor is doing its job, the OCaml engine shouldn't see them as tainted. **Check if the extractor is already handling this correctly** before adding engine-level logic.

**Decision:** Verify extractor behavior first. If `path.starts_with?("/allowed/")` causes the extractor to set `taint=false` on subsequent uses of `path`, no engine change is needed.

### Files to Change

| File | Change |
|------|--------|
| `interpreter.ml` | Possibly add guard pattern check |
| Or `extractor.cr` | Strengthen guard detection if needed |

### Testing

1. Add test: `test/samples/guarded_access.cr`
   ```crystal
   def safe_handler(params)
     path = params["path"]
     if path.starts_with?("/public/")
       File.read(path)  # Should NOT flag
     end
   end
   ```
2. Verify no finding for `File.read(path)` after guard

---

## F4: Wire Parallel Extraction

### Problem

`parallel.ml` exists and is tested but never called. Extraction is sequential.

### Implementation

This is straightforward — wire `Parallel.extract_parallel` into the orchestrator:

```ocaml
(* In orchestrator.ml — modify extraction loop *)

(* Current: sequential *)
List.iter (fun src ->
  let nodes = extract_with_log config src in
  ...
) sources;

(* New: conditional parallel *)
let extract_one src =
  match extract_file config src with
  | Some ns -> Some (src, ns)
  | None -> None
in

let extracted =
  if config.parallelism > 1 then begin
    (* Group by language for batch extraction *)
    let crystal_files = List.filter (fun s -> s.lang = "crystal") sources in
    let gleam_files = List.filter (fun s -> s.lang = "gleam") sources in
    let crystal_nodes = Parallel.extract_parallel extract_one crystal_files in
    let gleam_nodes = Parallel.extract_parallel extract_one gleam_files in
    crystal_nodes @ gleam_nodes
  end else
    List.filter_map extract_one sources
in
```

**Caveat:** `extract_file` for Crystal spawns a subprocess. OCaml 5 Domains + `Unix.open_process_full` should work but needs testing on Linux. The `parallel.ml` fallback handles Domain errors gracefully.

### Files to Change

| File | Change |
|------|--------|
| `orchestrator.ml` | Wire parallel extraction, gated on `config.parallelism` |
| `config.ml` | Ensure `parallelism` reads from TOML |
| `args.ml` | Ensure `--parallelism` works |

### Testing

1. Run with `--parallelism 1` — should be identical to current behavior
2. Run with `--parallelism 4` — verify findings match sequential
3. Run with `--parallelism 4` on 50+ files — verify no crashes or hangs
4. Run with `--parallelism 4` + `--format json` — verify JSON output is deterministic

---

## B3: Expand Taint Source Matching

### Problem

Function parameters need exact names (`params`) to be recognized as taint sources. Generic names like `p`, `req`, `ctx` may be missed.

### Fix

Add common abbreviations to `known_sources` in `constants.ml`:

```ocaml
let known_sources = [
  (* existing *)
  "params"; "request"; "req"; "get_body"; "query"; ...
  (* add *)
  "p";           (* common abbreviation for params *)
  "r";           (* common for request/response *)
  "ctx";         (* context — already covered by prefix match *)
  "conn";        (* connection — already covered *)
  "event";       (* event handler parameter *)
  "payload";     (* API payload *)
  "body";        (* request body *)
  "data";        (* generic user data *)
]
```

**Risk:** Too-broad matching causes false positives. `"p"` and `"r"` are very short variable names that could match legitimate non-tainted variables.

**Mitigation:** Only add abbreviations that are *commonly used* in web frameworks for request parameters. Don't add single-letter names. Keep the list curated.

### Decision

Add only low-risk names: `"event"`, `"payload"`, `"body"`. Skip `"p"` and `"r"` — too ambiguous. The `.catseye.toml` `extra_sources` mechanism handles project-specific source names.

### Files to Change

| File | Change |
|------|--------|
| `constants.ml` | Add `"event"`, `"payload"`, `"body"` to `known_sources` |
| `test/` | Add test with these parameter names |

---

## Implementation Order

```
F2 (message template)  ←── quickest fix, unblocks readable output
  │
F1 (scope isolation)   ←── highest correctness impact
  │
B3 (source matching)   ←── small change, improves coverage
  │
F3 (conditional taint) ←── verify extractor first, may be no-op
  │
F4 (parallel wiring)   ←── performance, lowest risk
```

## Exit Criteria

- [ ] F1: Zero cross-file variable bleed on test corpus
- [ ] F2: All 11 rule messages render correctly in terminal + JSON output
- [ ] F3: Guard patterns suppress false positives (or verified extractor handles it)
- [ ] F4: `--parallelism 4` produces identical findings to sequential
- [ ] B3: New source names detected in test cases
- [ ] All existing tests pass
- [ ] Zero regressions on real-world scan targets (quickheadlines, facet_pi)
