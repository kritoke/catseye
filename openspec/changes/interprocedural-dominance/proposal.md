# Interprocedural Dominance Analysis for FP Suppression

**Change:** `interprocedural-dominance`
**Priority:** P2
**Size:** L (4–5 days)
**Status:** Proposal
**Depends on:** `ocamlgraph-integration` (complete)

## Motivation

Catseye's intra-procedural dominator analysis (Phase 5 of ocamlgraph-integration) correctly identifies sanitizer-guarded paths within a single function. However, the most common false positive pattern — validated SSRF, guarded path traversal, etc. — has the sanitizer in a **different function** than the sink.

### Example: fetcher.cr SSRF

```
function fetch_youtube(url):
  http_client.get(url)           ← SINK (in fetch_youtube's CFG)

class CrestHttpClient:
  function perform_request(url):
    check_ssrf(url)              ← SANITIZER (in perform_request's CFG)
    ... actual HTTP call ...
```

`fetch_youtube` calls `http_client.get`, which internally calls `perform_request`, which calls `check_ssrf`. The sanitizer dominates the actual HTTP call within `perform_request`, but our per-function CFG analysis can't see across this boundary.

### Current workaround

Per-project `.catseye.toml` `[taint.suppress]` manually suppresses these. This works but requires every user to identify and document the same pattern.

### Goal

Automatically suppress findings where every interprocedural call chain from source to sink passes through a sanitizer.

## Design

### Core idea: interprocedural call graph + per-function dominance

Build a **call graph** from the IL (which functions call which), then for each sink finding:

1. Identify the sink function `F_sink` and the tainted parameter
2. Walk the call graph backward to find all possible callers
3. For each caller chain, check if a sanitizer function dominates the call to `F_sink`'s caller within that caller's CFG
4. If **every** chain passes through a sanitizer, suppress the finding

### Concrete example walkthrough

```
Call graph:
  fetch_youtube → CrestHttpClient.get → perform_request

Finding: SSRF in fetch_youtube (http_client.get with tainted url)

Step 1: sink is in fetch_youtube's CFG, calling CrestHttpClient.get
Step 2: walk backward: CrestHttpClient.get → perform_request
Step 3: in perform_request's CFG, check_ssrf dominates the actual HTTP call
Step 4: therefore the finding in fetch_youtube is guarded → suppress
```

### Architecture

```
IL functions (il_unit.il_functions)
    │
    ├─ Build per-function CFGs (existing: cfg_builder.ml)
    │
    ├─ Build IL-level call graph (NEW: il_call_graph.ml)
    │   - vertex: function name (string)
    │   - edge: caller → callee (from ILCall nodes)
    │   - uses ocamlgraph Imperative.Digraph.Concrete
    │
    ├─ Compute per-function dominators (existing: cfg_dominator.ml)
    │   - one dominator tree per function's CFG
    │   - cached in a (fn_name, Cfg_dominator.t) Hashtbl
    │
    └─ Interprocedential guard check (NEW: cfg_dominator.ml extended)
        - Given: sink function, sink block, sink sanitizers
        - Walk call graph from sink function upward
        - At each caller, check if the call to callee is dominated
          by a sanitizer block in the caller's CFG
        - If all paths are guarded → suppress
```

## Phases

### Phase 1: IL Call Graph Builder (S, ~2h)

Build a call graph from `il_unit.il_functions` by scanning ILCall nodes.

- New module: `il_call_graph.ml`
- Vertex type: `string` (function name, qualified by class/module if available)
- Edge: caller → callee
- Also track which IL nodes are the call sites (for dominance checking)
- Use ocamlgraph `Imperative.Digraph.Concrete`

### Phase 2: Dominator Cache (S, ~2h)

Cache per-function dominator analysis results so we don't recompute.

- Extend `cfg_dominator.ml` or create `dominator_cache.ml`
- `compute_all : il_unit -> (string, Cfg_dominator.t) Hashtbl.t`
- Compute CFG + dominators for every function in the unit, cache by fn_name
- Thread through `analyze_unit` in `cfg_taint.ml`

### Phase 3: Interprocedural Guard Check (M, ~4h)

The core algorithm: given a sink finding, check if it's interprocedurally guarded.

- Extend `cfg_dominator.ml` with `is_interprocedurally_guarded`
- Input: call graph, dominator cache, sink function name, sink block, sanitizers
- Algorithm:
  1. Find all functions that call the sink function (call graph predecessors)
  2. For each caller: find the call site to the sink function
  3. In the caller's CFG: check if a sanitizer block dominates the call site
  4. If ALL callers are guarded → return true (suppress finding)
  5. If ANY caller is unguarded → return false (keep finding)
- Handle recursion: limit depth to 5 call graph steps
- Handle indirect calls: if we can't resolve the callee, assume unguarded (conservative)

### Phase 4: Integration into Taint Analysis (M, ~3h)

Wire the interprocedural check into `cfg_taint.ml`.

- `analyze_cfg` receives dominator cache + call graph
- `check_call_sinks` calls `is_interprocedurally_guarded` when a sink matches
- Only trigger for sinks that are function calls to known internal functions
  (not external/library calls where we don't have IL)
- Findings suppressed get `flow` annotation explaining the guard chain

### Phase 5: Testing & Tuning (S, ~2h)

- Test on fetcher.cr: SSRF findings should be auto-suppressed
- Test on quickheadlines: verify no true positives suppressed
- Test on synthetic samples: guarded/unguarded variants
- Tune sanitizer matching: ensure `check_ssrf`, `validate_*`, etc. match
- Benchmark: dominator computation per function should be <1ms

## Specs

- `specs/interprocedural-guard/spec.md`

## Files

### New
- `src/ocaml/lib/catseye_il/il_call_graph.ml` — IL-level call graph builder

### Modified
- `src/ocaml/lib/catseye_il/cfg_dominator.ml` — add interprocedural guard check
- `src/ocaml/lib/catseye_il/cfg_taint.ml` — integrate interprocedural suppression
- `src/ocaml/lib/catseye_il/il_types.ml` — possibly add call site tracking types
- `src/ocaml/lib/catseye_il/dune` — add new modules

## Risks

| Risk | Mitigation |
|------|------------|
| **Performance** — computing dominators for every function | Cache results; skip functions with <3 blocks; lazy computation |
| **Indirect calls** — Crystal's dynamic dispatch | Conservative: assume unguarded; only track direct calls |
| **Recursion** — mutual recursion in call graph | Depth limit (5 hops); visited set |
| **Over-suppression** — suppressing real findings | Conservative: only suppress when ALL paths guarded; per-rule opt-in |
| **Naming** — Crystal class methods vs module functions | Use qualified names (Class.method) from IL translator |

## Future Extensions

- **Call graph from flat engine** — already exists in `dot.ml`/`reachability.ml`; could merge IL-level and flat-level call graphs
- **Context-sensitive analysis** — track which sanitizer was applied to which data, not just control flow
- **Summary-based approach** — compute function summaries ("this function sanitizes its first arg") and propagate interprocedurally
- **Performance profiles** — BAP (Binary Analysis Platform) uses this same approach for binary taint analysis
