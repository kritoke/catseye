# Performance & Safety Fix — Design

**Change:** `openspec/changes/performance-safety`  

---

## Context

During a production scan of a large codebase, Catseye hung for over 3000 seconds. The hang occurred during the taint analysis phase (not extraction), specifically in the CFG-based engine path. Investigation revealed the root cause in `cfg_builder.ml`.

## Root Cause

### The Recursive Prepending Problem

The original `cfg_builder.ml` uses a recursive `build_block` function that:
1. Splits nodes at branch boundaries with `take_linear`
2. Recurses into then/else blocks
3. Prepends linear nodes to the result list with `emit_block acc linear [...]`

The problem: `linear` is reconstructed by reversing an accumulator in `take_linear`:
```ocaml
let rec go acc = function
  | [] -> (List.rev acc, [])
  | hd :: tl -> go (hd :: acc) tl
```

And each recursive call prepends to block lists:
```ocaml
emit_block acc linear [then_id; else_id]
```

For deeply nested code, this creates O(n²) behavior in node list operations. Combined with CFG taint analysis running on each function, the total time becomes unacceptable.

### Secondary Factor: No Bounds

The CFG builder has no limits on:
- Number of blocks per function
- Depth of recursion
- Time spent on any single function

For pathological input (deeply nested branches, generated code), the analysis never terminates.

## Goals

1. **Eliminate exponential behavior** — all operations must be O(n) or better
2. **Add hard limits** — configurable max blocks, timeout per function
3. **Fail gracefully** — timeout/failure returns to flat engine, doesn't hang
4. **Preserve correctness** — all existing test corpus findings must remain

## Non-Goals

- Migrating away from CFG — the CFG approach is correct, just needs fixing
- Changing taint propagation semantics — only the construction algorithm changes
- Supporting new languages — Crystal and Gleam only

## Design Decisions

### Queue-Based Builder (instead of recursive)

**Decision:** Replace `build_block` recursion with an iterative queue-based algorithm.

**Rationale:** Eliminates stack growth and repeated list operations. Each block is processed exactly once.

```ocaml
let build_cfg (fn : il_function) : (cfg, cfg_error) result =
  let state = {
    blocks = [];
    next_id = 0;
    pending = Queue.create ();
  } in
  Queue.add fn.fn_body state.pending;
  
  while not (Queue.is_empty state.pending) do
    let nodes = Queue.take state.pending in
    let linear, rest = take_linear nodes in
    (* Emit block from linear nodes *)
    let block_id = emit_block state linear [] in
    (* Queue remaining work *)
    match rest with
    | [ILBranch (_, then_b, else_b, _)] ->
      let merge_id = emit_block state [] [] in
      Queue.add then_b state.pending;
      Option.iter (fun eb -> Queue.add eb state.pending) else_b;
      (* Update edges *)
      add_edge state block_id then_id;
      add_edge state block_id else_id;
      add_edge state then_id merge_id;
      add_edge state else_id merge_id
    | _ -> ()
  done;
  finalize_cfg state
```

### Error Result Instead of Exception

**Decision:** `build_cfg` returns `Result.t cfg cfg_error` instead of raising.

**Rationale:** Allows callers to handle bounds violations gracefully and fall back to flat engine.

```ocaml
type cfg_error =
  | TooManyBlocks of { actual : int; limit : int }
  | Timeout of { elapsed_ms : int; partial_blocks : int }
```

### Configurable Limits (not hardcoded)

**Decision:** Add CLI flags `--cfg-max-blocks` and `--cfg-timeout-ms` with reasonable defaults.

**Defaults:** 500 blocks per function, 5000ms timeout.

**Rationale:** Different codebases have different characteristics. Allows tuning without code changes.

## Risk Analysis

| Risk | Mitigation |
|------|------------|
| Queue algorithm produces different blocks than recursive | Build correctness test: parse known function, verify block IDs and edges |
| Timeout causes false negatives | Log warning when timeout fires; provide `--no-cfg` for full analysis |
| Backward compat: existing tests break | Run full test corpus before/after, diff findings |

## Performance Targets

| Target | Metric |
|--------|--------|
| Large codebase scan | < 60s total (extraction + analysis) |
| Per-function CFG build | < 500ms (or timeout/fallback) |
| Memory | < 500MB for codebase with 10,000 functions |

## Alternatives Considered

### Alternative 1: Keep recursive builder, add depth limit

**Rejected:** Still has list concatenation problem. Would need to also fix take_linear.

### Alternative 2: Use mutation instead of functional updates

**Rejected:** OCaml's immutable approach is correct for correctness. The problem is algorithmic, not functional/imperative choice.

### Alternative 3: Skip CFG entirely, use flat engine

**Rejected:** CFG is the right architecture. Branch-aware analysis eliminates entire classes of false positives that can't be fixed heuristically.

### Alternative 4: Parallel CFG analysis

**Rejected:** Adding parallelism without fixing the algorithmic issue would make the hang worse (parallel tasks all stuck).

---

## Implementation Order

1. **Add `cfg_error` type** to `il_types.ml`
2. **Write `cfg_builder_v2.ml`** — queue-based builder, timeout, block limits
3. **Add CLI flags** — `--cfg-max-blocks`, `--cfg-timeout-ms`
4. **Wire into `cfg_taint.ml`** — use `cfg.cfg_block_map` for O(1) lookup
5. **Add fallback in orchestrator** — if CFG fails, use flat engine
6. **Test** — verify no hang, verify same findings as before

---

## Open Questions

1. Should we add a `--no-cfg` flag for users who want to disable CFG entirely?
2. What's the right default for `--cfg-timeout-ms`? Too short = false negatives, too long = still hangs.
3. Should we cache CFG results per file to avoid rebuilding on repeated scans?