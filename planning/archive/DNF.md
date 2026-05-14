# DNF — Did Not Fix

Items that were intentionally deferred, with rationale and revisit triggers. These are **not failures** — each was a deliberate trade-off.

---

## Deferred: Engine Only

These live in `src/ocaml/lib/catseye_engine/` and require no extraction-layer changes. All are correct to defer.

### parallel.ml — unused parallel extraction

**File**: `src/ocaml/lib/catseye_engine/parallel.ml`  
**Status**: Written, tested, not wired in

The `extract_parallel` function using OCaml 5 Domains is correct. The orchestrator iterates sequentially instead.

**Why deferred**: Parallelism introduces non-determinism (file ordering, domain scheduling). For a port from Gleam/BEAM, **deterministic output is more valuable than speed**. Sequential extraction is easier to debug and reproduce.

**Revisit trigger**: After differential testing (Phase 0) passes consistently and the engine logic is stable for 30+ consecutive runs. Wiring `parallel.ml` is ~20 lines of refactoring.

**How**: Group sources by language, run `Parallel.extract_parallel` per group. Keep Crystal extraction (external process) and Gleam extraction (in-process) separate with a shared `extract_fn` type.

---

### merge_db — orphaned TaintDB union

**File**: `src/ocaml/lib/catseye_engine/merge.ml`  
**Status**: Written, correct, not used

`merge_db` correctly computes the union of two `Db.t` records per file. The engine pipeline never calls it.

**Why deferred**: The benefit depends entirely on D2 (cross-file taint propagation). There's no point in wiring a database union if there are no cross-file links to justify the merge. Currently the engine runs on a flat list of all nodes, which is logically equivalent to "merge everything up front."

**Revisit trigger**: After D2 is resolved (see below).

**How**: Once D2 adds cross-file symbol tracking, group nodes by file → per-file propagate → `merge_db` union → interproc on merged result.

---

### Db O(n) duplicate check

**File**: `src/ocaml/lib/catseye_engine/db.ml`, line 43  
**Code**: `List.exists (fun r -> r.var_name = record.var_name) records`

**Why deferred**: The O(n) scan is per-insert into a single file's record list. For typical source files with dozens to hundreds of assignments, this is fast enough. The actual bottleneck is AST extraction, not in-memory DB operations. Adding a `Set` or `Hashtbl` index adds complexity for no measurable gain in the target workload.

**Revisit trigger**: Profiling shows DB insertion is >10% of total analysis time on real codebases.

**How**: Add `module VarSet = Set.Make(String)` inside the file-keyed map, or a `Hashtbl` mapping file → `var_name set`. Track dedup state in the fold rather than scanning on every insert.

---

## Deferred: Requires Extraction Changes

These require modifications to the AST extraction layer, not just the engine. Higher risk.

### D1 — Call/Assign same-line heuristic

**File**: `src/ocaml/lib/catseye_engine/interproc.ml`, lines 48–55  
**Code**: Searches for a `Call` node at the exact same `(file, line)` as an `Assign` node

```ocaml
let call_node =
  List.find_opt (fun n ->
    n.Security_node.node_type = Security_node.Call
    && n.Security_node.file = node.Security_node.file
    && n.Security_node.line = node.Security_node.line
  ) nodes
```

**Why deferred**: This is a fragile heuristic — AST formatting changes break it. The correct approach is the structural check (Strategy 1: does the RHS of the assignment resolve to a tainted call?). Strategy 1 already works correctly and doesn't depend on co-located nodes. The same-line search is an optimization that can only be safely removed without understanding the actual AST contract.

**Revisit trigger**: Run the Gleam extractor on real code (`test/samples/`, `test/e2e/`) and inspect the raw JSON output for `x = foo()` patterns. Confirm whether tree-sitter emits one node or two at the same location.

**How**: If AST emits one `Assign` node with `ArgCall` on the RHS → remove the same-line search entirely, Strategy 1 is sufficient. If AST emits two nodes → keep the search but add a test case.

---

### D2 — Cross-file taint propagation

**File**: `src/ocaml/lib/catseye_engine/propagate.ml`, line 21  
**Code**: `is_tainted_in_file acc a.Security_node.value node.Security_node.file` (same-file only)

**Why deferred**: This is less a taint problem and more a **namespace problem**. To propagate taint from module A to module B, you need to know exactly where `foo()` is defined. Without type resolution or a global symbol table, the analysis is effectively a per-file scanner. The Gleam extractor doesn't capture import resolution.

**What breaks without this**:
- Functions defined in file A that return tainted data, called from file B — taint missed
- Cross-module data flows

**Revisit trigger**: After Phase 0 differential testing shows cross-file taint flows are missing in real codebases.

**How**: Three-step approach:
1. **Extend extractor** to track cross-file references: parse `import` statements and map imported names to their defining module/file
2. **Build symbol table**: `module_name.function_name → (file, def_node)` map
3. **Wire into engine**: when a `Call` resolves to a function in another file, look up its def and propagate taint through the return value

**Risk**: High. This touches extraction (parser changes), not just the engine.

---

## Deferred: Nice to Have

### N3 — Hashtbl.hash not Blake3

**File**: `src/ocaml/lib/catseye_engine/cache.ml`, line 14  
**Code**: `Printf.sprintf "%08x" (Hashtbl.hash content)`

**Why deferred**: Not a cryptographic use case. `Hashtbl.hash` is a polynomial accumulator — fast, deterministic, adequate for content-addressing in a local cache. Blake3 would be ~14x faster but adds a dependency for a non-bottleneck operation.

**Revisit trigger**: Profiling shows cache fingerprint computation is >10% of total time on large codebases.

**How**: `opam install blake3`, swap the hash function, update the comment.

---

## Summary Table

| Item | File | Risk | Revisit trigger |
|------|------|------|-----------------|
| parallel.ml | `parallel.ml` | Low | 30+ stable differential runs |
| merge_db | `merge.ml` | Low | D2 resolved |
| Db O(n) check | `db.ml` | Low | Profiling shows >10% DB time |
| D1: same-line search | `interproc.ml` | Medium | Inspect raw tree-sitter JSON |
| D2: cross-file taint | `propagate.ml` | High | Phase 0 finds missing cross-file flows |
| N3: Blake3 | `cache.ml` | Low | Profiling shows >10% hash time |

---

## Deferred: Anti-Pattern Refactoring (2026-05-10)

Code quality improvements identified during OCaml code review.

### A3 — Simplify interproc nesting

**File**: `src/ocaml/lib/catseye_engine/interproc.ml`

**Issue**: 4-level nesting with duplicated record creation (same `{var_name; file; line; ...}` appears 3x).

**Why deferred**: Complexity, medium risk of breaking control flow. The `trace` function in DAG was the actual bottleneck.

**Revisit trigger**: When DAG tracing is stable, revisit interproc for cleaner code.

**How**: Extract `make_taint_record` helper, precompute call lookup map, use strategy pattern.

### A7 — Tokenizer helper functions

**File**: `src/ocaml/lib/catseye_engine/gleam.ml`

**Issue**: 50-line `tokenize` function with dense nested conditionals.

**Why deferred**: Lower priority. Tokenizer behavior is correct and well-tested. Refactoring is cosmetic.

**Revisit trigger**: When Gleam extractor behavior needs to change.

**How**: Extract named helpers with `rec` and `and` for `handle_text`, `handle_open_tag`, etc.

---

## Deferred: Pre-Existing Bugs

### B2 — Message template truncation

**File**: `src/ocaml/lib/catseye_rules/interpreter.ml`

**Issue**: Finding messages truncated to `"rs}"` instead of full template.

**Example**: Template `"Potential open redirect via {sink} with user-controlled URL: {tainted_vars}."` produces `"rs}"`.

**Revisit trigger**: When message readability is needed for user-facing output.

**How**: Add debug tracing to `substitute_template`, fix string handling.

### B3 — Taint source matching

**File**: `src/ocaml/lib/catseye_engine/constants.ml`

**Issue**: Function parameters need exact names (`params`) to be recognized. Generic names (`p`) not matched.

**Revisit trigger**: When testing shows Crystal code with generic param names is missed.

**How**: Add `"p"` to `known_sources` list.

---

## Summary Table (Updated)

| Item | File | Risk | Revisit trigger |
|------|------|------|----------------|
| parallel.ml | `parallel.ml` | Low | 30+ stable differential runs |
| merge_db | `merge.ml` | Low | D2 resolved |
| Db O(n) check | `db.ml` | Low | Profiling shows >10% DB time |
| D1: same-line search | `interproc.ml` | Medium | Inspect raw tree-sitter JSON |
| D2: cross-file taint | `propagate.ml` | High | Phase 0 finds missing cross-file flows |
| N3: Blake3 | `cache.ml` | Low | Profiling shows >10% hash time |
| A3: interproc nesting | `interproc.ml` | Medium | After DAG stability |
| A7: tokenizer helpers | `gleam.ml` | Low | Gleam extractor changes |
| B2: message template | `interpreter.ml` | Low | User-facing output needed |
| B3: taint source matching | `constants.ml` | Low | Testing shows missed cases |

---

*Last updated: 2026-05-10*