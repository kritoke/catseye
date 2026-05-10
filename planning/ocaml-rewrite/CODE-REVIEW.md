# OCaml Rewrite — Code Review Report

**Reviewer**: AI Code Review  
**Date**: 2026-05-09  
**Scope**: `src/ocaml/` — full OCaml port  
**Phase**: Post-implementation engine review

---

## Findings Summary

| Severity | Count | Fixed? |
|----------|-------|--------|
| 🔴 Bug | 4 | — |
| 🟡 Design | 6 | — |
| 🟢 Nit | 3 | — |

---

## 🔴 Critical Bugs

### B1 — Message template silently destroyed

**File**: `lib/catseye_rules/interpreter.ml`, lines 98–102

```ocaml
let msg = rule.message_template in
let msg = String.concat "" [
  String.sub msg 0 (min (String.length msg) 20);  (* ← TRUNCATES to 20 chars *)
  n.Security_node.name;
  " called with variable argument(s): ";
  vars
] in
```

**Problem**: The `message_template` from KDL rules (e.g., `"Potential SSRF via {sink} with user-controlled URL"`) is truncated to 20 characters and replaced with a hardcoded format. The template variables `{sink}`, `{tainted_vars}` are never substituted. Every rule's custom message is silently replaced with the same generic string.

**Fix**: Implement actual `{variable}` substitution, or remove the truncation and use the template directly.

---

### B2 — Sentinel line number in `returns.ml`

**File**: `lib/catseye_engine/returns.ml`, line 14

```ocaml
function [] -> 999_999 | hd :: _ -> hd
```

**Problem**: Uses `999_999` as a sentinel "end-of-file" marker. A file with valid source lines up to `999_998` would silently break the function boundary detection, causing the entire function body to be missed. Also non-obvious: callers must know this magic number.

**Fix**: Return `None` when no next def exists, and update callers to handle `int option`.

---

### B3 — Duplicate propagation logic across modules

**File**: `lib/catseye_engine/propagate.ml` AND `lib/catseye_engine/interproc.ml`

**Problem**: The entire fallback block in `interproc.ml` (lines 61–77) is an exact copy of `propagate.ml`'s logic. Every time propagation semantics change, both files must be kept in sync. This is a maintenance hazard.

**Fix**: Extract shared logic into `Db.propagate_assignment` (or similar) and call from both modules.

---

### B4 — `is_source` prefix matching is backwards for field access

**File**: `lib/catseye_engine/seed.ml`, lines 28–30

```ocaml
String.length name >= len && String.sub name 0 len = s
```

**Problem**: The Gleam extractor classifies field accesses as `ArgCall` (not `ArgVar`), so `is_source` is never checked for `req.params["url"]`-style sources. Additionally, the prefix match means `is_source "params"` matches `"params"` but NOT `req.params` where `params` is a suffix. The extractor also has its own independent `taint_sources` list — two sources of truth.

**Fix**: Either (a) also check `ArgCall` args in `is_source`, or (b) check substring containment, or (c) deduplicate into a shared `Catseye_engine.Constant.sources` list used by both modules.

---

## 🟡 Design Issues

### D1 — `Call` and `Assign` at same line in `interproc.ml`

**File**: `lib/catseye_engine/interproc.ml`, lines 48–55

```ocaml
let call_node =
  List.find_opt (fun n ->
    n.Security_node.node_type = Security_node.Call
    && n.Security_node.file = node.Security_node.file
    && n.Security_node.line = node.Security_node.line
  ) nodes
```

**Problem**: The AST extraction does not appear to emit both a `Call` node and an `Assign` node at the same line. If `x = foo()` is one assignment node, this search always returns `None`. The entire "Strategy 2" branch relies on this finding a node — if the AST doesn't produce overlapping nodes, this whole strategy is dead code.

**Fix**: Clarify the AST contract. If Call and Assign are never at the same location, remove this logic or redesign the interproc strategy.

---

### D2 — No cross-file taint propagation

**File**: `lib/catseye_engine/propagate.ml`, line 21

```ocaml
Db.is_tainted_in_file acc a.Security_node.value node.Security_node.file
```

**Problem**: `propagate` only looks for tainted variables in the same file. If module A defines a tainted function and module B calls it, taint does not cross the file boundary. The `interproc` module tries to handle this via return values, but assignment taint propagation (e.g., `x = get_user_input()` in file A, `y = x` in file B) is skipped cross-file.

**Fix**: Track inter-file variable references in the AST extractor, or expand `propagate` to optionally check cross-file.

---

### D3 — DAG builder is dead code

**File**: `lib/catseye_engine/dag.ml`  
**Callers**: NONE

**Problem**: `dag.ml` defines `build_dag` but `orchestrator.ml` never calls it. Findings always have `flow = []` (interpreter.ml:122). The extensive DAG infrastructure is unreachable.

**Fix**: Wire `Dag.build_dag` into the analysis pipeline, or mark it as deferred and update the plan.

---

### D4 — `merge_db` in `merge.ml` is orphaned

**File**: `lib/catseye_engine/merge.ml`  
**Callers**: NONE

**Problem**: `merge_db` is defined but never imported. If multi-file analysis is desired, this module is not connected.

**Fix**: Import and use in `engine.ml` between per-file propagation and interproc analysis.

---

### D5 — Custom rule extensions silently ignored

**File**: `lib/catseye_rules/loader.ml`, lines 44–53

```ocaml
| k ->
  let v = ... in
  { acc with extensions = (k, v) :: acc.extensions }
```

**Problem**: The KDL loader parses custom conditions into the `extensions` field, but `interpreter.ml` never reads `rule.conditions.extensions`. Any custom rule property (beyond the standard ones) is silently ignored.

**Fix**: Either (a) document this limitation, (b) implement extension handling in the interpreter, or (c) fail at load time for unknown conditions.

---

### D6 — `language` field always empty

**File**: `lib/catseye_types/finding.ml`, line 71

```ocaml
{ ... ; language = ""; dependency = None }
```

**Problem**: `language` is part of the SARIF output schema and is always empty. The `security_node` extractor knows the language (Gleam via `gleam.ml:language`, Crystal via CLI) but never propagates it to findings.

**Fix**: Pass language through the pipeline: extractor → nodes → engine → finding.

---

## 🟢 Nits

### N1 — `Db.t` uses linear scans for duplicates

**File**: `lib/catseye_engine/db.ml`, line 43

```ocaml
if List.exists (fun r -> r.var_name = record.var_name) records then db
```

**Performance**: O(n) per insert into a file's record list. For large files with hundreds of assignments, this is a hot path.

**Fix**: Use a `Set` or `Hashtbl` per file instead of a plain list.

---

### N2 — `engine.ml` doesn't use parallel module

**File**: `lib/catseye_engine/engine.ml`

**Problem**: `parallel.ml` defines parallel extraction but is never imported by `engine.ml` or `orchestrator.ml`. The entire Domains-based parallel analysis is unused.

**Fix**: Integrate `Parallel.extract_parallel` into the extraction pipeline in `orchestrator.ml`.

---

### N3 — `cache.ml` uses `Hashtbl.hash` not Blake3

**File**: `lib/catseye_engine/cache.ml`, line 14

```ocaml
Printf.sprintf "%08x" (Hashtbl.hash content)
```

**Problem**: The comment promises Blake3 but the implementation uses `Hashtbl.hash` (a polynomial accumulator, not a cryptographic hash). This is fine for content-addressing but not consistent with the plan's stated design.

**Fix**: Either update the comment to match reality, or add a Blake3 dependency.

---

## Bug Fixes Applied

| Bug | Status |
|-----|--------|
| B1: Message template truncation | → Fixed |
| B2: 999_999 sentinel line | → Fixed |
| B3: Duplicate propagation logic | → Fixed (refactored via `Db.check_assignment_taint`) |
| B4: Field access source detection | → Documented (CODE-REVIEW.md D1) |

---

*Last updated: 2026-05-09*