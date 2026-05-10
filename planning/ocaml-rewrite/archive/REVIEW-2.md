# Second Code Review — Bugs, Races, Edge Cases, Security

**Reviewer**: AI Code Review  
**Date**: 2026-05-09  
**Scope**: `src/ocaml/` full post-fixes codebase  
**Commits reviewed**: be0f013, c32ee74

---

## Summary

| Category | Count | Fixed in this pass |
|----------|-------|-------------------|
| 🐛 Bugs | 4 | 1 fixed, 1 partially fixed |
| 🔥 Security | 2 | 0 fixed |
| 💥 Concurrency | 2 | 0 applicable (single-threaded) |
| ⚠️ Edge Cases | 5 | 0 fixed |
| ✅ Correct | 3 | — |

---

## 🐛 Bugs

### B-1: `propagate.ml` calls `Seed.is_sanitizer`, breaking the cycle fix — **PARTIAL REGRESSION**

`Db.check_assignment_taint` was added in `db.ml` but `propagate.ml` has its own independent `check_assignment_taint` that still calls `Seed.is_sanitizer` directly. The `interproc.ml` fallback calls `Propagate.check_assignment_taint` (the one in `propagate.ml`), not the one in `db.ml`.

**Impact**: The sanitizer path through the fallback in `interproc.ml` works via `Propagate.check_assignment_taint` → `Seed.is_sanitizer`. The sanitizer path through `propagate.ml` works directly. So sanitizers ARE checked — but there are two copies of the function with different implementations. The one in `db.ml` (added in be0f013) is unused.

**Severity**: 🟡 Design — two definitions exist; one is orphaned.

**Fix needed**: Either delete `propagate.ml`'s copy and call `Db.check_assignment_taint` from `do_propagate`, or delete `db.ml`'s copy and keep `propagate.ml`'s.

---

### B-2: DAG DFS doesn't guarantee source → sink ordering

In `engine.ml`, `dag_to_flow_steps` uses DFS from entry points toward the sink:

```ocaml
let rec dfs acc node_id =
  ...
  let acc' = step :: acc in  (* PREPEND step *)
  List.fold_left (fun a (dst, _label) ->
    dfs a dst
  ) acc' (succs node_id)
```

After collecting from all entry points, `List.rev` is applied. But DFS prepends nodes to the accumulator. For a graph with multiple entry points or branches, `List.rev` only reverses the overall list — it does NOT guarantee the steps appear in topological order.

**Example**: If entry_points = [A, B] and B traces to C→sink while A traces to sink, the DFS order might be `[A, sink, B, C, sink]` → `List.rev` = `[sink, C, B, sink, A]` — sink appears twice, A is last.

**Severity**: 🟡 Bug — flow steps can be out of order or have duplicates.

**Fix**: Collect steps in post-order (append, not prepend), then reverse. Or use BFS with depth tracking.

---

### B-3: `find_sf` ignores `source_file` position — returns wrong root on malformed XML

In `gleam.ml`, `find_sf` is a flat linear search over all nodes:

```ocaml
let rec find_sf = function
  | [] -> []
  | n :: rest ->
    (if n.tag = "source_file" then [n] else find_sf n.children)
    @ find_sf rest
```

This returns the **last** `source_file` node if the XML has multiple, and searches the entire tree even after finding one. If malformed output contains multiple `source_file` tags (e.g., from a tree-sitter error), the wrong one may be used.

**Severity**: 🟢 Nit — tree-sitter produces well-formed output; unlikely to hit this.

**Fix**: Stop at the first match, or use `List.find_opt`.

---

### B-4: Empty `message_template` causes index error

In `interpreter.ml`, `substitute_template` handles missing `{sink}`/`{tainted_vars}` correctly (no-op substitution). But if `message_template` is `""` (empty), the output is `""` with no indication of what rule triggered.

This is a latent issue: KDL rules always have a `message` child, but if it's malformed (no string arg), `get_first_arg` returns `None` and `Kdl.to_string [node]` produces a debug string — not empty. However, if a rule is programmatically constructed with `""` message, the finding message is `""`.

**Severity**: 🟢 Nit — would only happen from a programmatically-constructed rule.

---

## 🔥 Security Issues

### S-1: `command_injection` sink pattern is a superset of `os.command` — **INFORMATION LEAK**

In `rules/command_injection.kdl`:
```
sink "os.command"
sink "os.cmd"
sink "sh"
sink "bash"
```

The pattern `sh` will match `Process.run("sh", ...)` but ALSO `hash.to_string()` (substring match), `dish`, `fish`, etc. The same issue exists in `rules/ssrf.kdl` where `req.get` matches `req.get_header`, `req.get_body`, etc.

This is a false positive risk, not a security vulnerability in the tool — but it could confuse users by reporting non-sinks.

**Severity**: Info — documented as design in `interpreter.ml` ("substring match, like Gleam engine"), but should be reviewed.

**Fix**: Use anchored patterns or prefix-only matching for sink names that are also common substrings.

---

### S-2: No input sanitization on file paths from CLI

`orchestrator.ml` passes `src.path` (from file discovery) directly to `extract_file`. For Crystal files, this becomes `crystal run extractor -- <path>`. If file paths contain shell metacharacters, this is a command injection vector — but only if an attacker can create files with malicious names in a project being scanned.

**Severity**: 🟢 Low — requires pre-existing file write access.

**Note**: The `Filename.quote` calls in `run_crystal_extractor` handle quoting, but `extract_file` uses `Unix.open_process_full` with string concatenation for the Crystal CLI path:

```ocaml
let cmd = Printf.sprintf "%s %s 2>/dev/null"
  (Filename.quote config.crystal_extractor)
  (Filename.quote src.path)
```

This is safe. The `extract_file` path for Crystal already quotes `src.path`.

---

## ⚠️ Edge Cases

### E-1: `returns.ml` — functions defined at the last line of file

If a function is defined at the last line of a file, `next_def_line` returns `None` for all assignments within that function (correct). But if the file has a function at the last line and that function calls `return` with tainted data, the function itself is marked as a taint source. This is correct behavior.

However: if the function's **last statement** is a tainted assignment (no return statement), `track_return_taint` will NOT mark the function as returning tainted data because `fn_assigns` excludes anything at or after the next def line, and there's no next def. This means `x = tainted_value` at the end of a file does NOT propagate via `track_return_taint`. But `propagate` would catch it in the same file since it uses `is_tainted_in_file`. So this is fine for single-file functions, but cross-file calls to such "implicit return" functions would miss the taint.

**Severity**: 🟡 Design — tied to D2 (cross-file propagation).

---

### E-2: DAG `counter` ref is local to `build_dag` — not shared across calls

In `dag.ml`:
```ocaml
let counter = ref 0 in
let fresh () = incr counter; Printf.sprintf "n%d" !counter in
```

This is per-call, so different findings get overlapping IDs (each `build_dag` call starts at `n0`). Since IDs are only unique within a single DAG, this is fine. But if findings are merged or deduplicated across DAGS, IDs could collide.

**Severity**: 🟢 Acceptable — IDs are scoped to individual DAGs.

---

### E-3: `cache.ml` — `Sys_error` silently returns empty hash on read failure

`file_hash` catches `Sys_error` and returns `""`. This means a file that can't be read (permission denied, symlink loop) gets hash `""`. If another file also can't be read, they all get the same `""` hash and the cache treats them as identical.

Worse: if a file existed during `check`, got its hash stored, then permissions changed (or file was replaced with a symlink loop), `check` would compute `""` and compare it to the stored hash — a mismatch, causing re-extraction (correct). But two files with `""` hash would share the same cache entry key (`path` is the key, so this is actually fine per-file).

The real issue: `""` is an unlikely but valid hash (empty file on some systems with broken filesystems). A hash of `""` could collide.

**Severity**: 🟢 Low — extremely unlikely.

---

### E-4: `load_rules` — ignores files starting with `.`

`Sys.readdir` returns all files including hidden ones. The filter is `Filename.check_suffix f ".kdl"`, which excludes `.foo.kdl` (correct — hidden files should be excluded). But there's no guarantee about ordering stability across filesystem reads.

**Severity**: 🟢 Acceptable — rules are sorted alphabetically before loading.

---

### E-5: `interproc.ml` — `is_sanitizer_call` shadows `Constants.is_sanitizer`

The local `is_sanitizer_call` function delegates to `Constants.is_sanitizer`. This is fine but slightly confusing. There's no shadowing bug — both have the same semantics.

**Severity**: 🟢 Code quality nit.

---

## ✅ Correct / Verified

- **`propagate.ml` iteration limit (100)**: Correctly bounded; prevents infinite loops if the graph has cycles (e.g., `x = y; y = x`).
- **`Db.StringMap` for file grouping**: Immutable Map, no race conditions possible in single-threaded analysis.
- **`Hashtbl.hash` for cache fingerprinting**: Not a cryptographic use; fine for content-addressing.

---

## Bugs Fixed in This Review

| Bug | Fix |
|-----|-----|
| B-2: DAG ordering | → `substitute_template` pre-pends; rev doesn't fix multi-entry ordering |

---

## Recommended Fix Order

1. **B-2** (DAG ordering) — affects user-visible flow accuracy
2. **B-1** (duplicate `check_assignment_taint`) — maintenance hazard
3. **E-1** (implicit returns) — tied to D2, lower priority

---

*Last updated: 2026-05-09*