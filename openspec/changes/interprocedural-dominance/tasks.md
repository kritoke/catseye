# Interprocedural Dominance Analysis — Tasks

**Change:** `interprocedural-dominance`
**Status:** Open

## Phase 1: IL Call Graph Builder

- [ ] 1.1 Create `src/ocaml/lib/catseye_il/il_call_graph.ml`
- [ ] 1.2 Define `call_graph` type (ocamlgraph string digraph + call site Hashtbl)
- [ ] 1.3 Implement `build : il_unit -> call_graph` — scan all ILCall nodes
- [ ] 1.4 Implement `callers : call_graph -> string -> string list`
- [ ] 1.5 Implement `callees : call_graph -> string -> string list`
- [ ] 1.6 Add `il_call_graph` to `catseye_il/dune` modules
- [ ] 1.7 Verify `dune build` passes

## Phase 2: Dominator Cache

- [ ] 2.1 Add `compute_all : il_unit -> (string, Cfg_dominator.t) Hashtbl.t` to `cfg_dominator.ml`
- [ ] 2.2 Compute CFG + dominators for every function, cache by fn_name
- [ ] 2.3 Skip functions with <3 blocks (no meaningful dominance)
- [ ] 2.4 Verify `dune build` passes

## Phase 3: Interprocedural Guard Check

- [ ] 3.1 Implement `is_interprocedurally_guarded` in `cfg_dominator.ml`
- [ ] 3.2 Algorithm: walk call graph predecessors, check dominance at each caller
- [ ] 3.3 Add depth limit (5 hops) and visited set for recursion safety
- [ ] 3.4 Conservative: if callee has no IL (external call), assume unguarded
- [ ] 3.5 Conservative: if ANY caller path is unguarded, return false
- [ ] 3.6 Unit tests: guarded, unguarded, recursive, partially guarded cases

## Phase 4: Integration into Taint Analysis

- [ ] 4.1 Build call graph + dominator cache in `analyze_unit` (once per IL unit)
- [ ] 4.2 Thread cache + call graph to `analyze_cfg` via refs (like `current_dom_data`)
- [ ] 4.3 Call `is_interprocedurally_guarded` from `check_call_sinks`
- [ ] 4.4 Only trigger for internal function calls (not external/library)
- [ ] 4.5 Add flow annotation to suppressed findings explaining the guard chain

## Phase 5: Testing & Tuning

- [ ] 5.1 Test on fetcher.cr: SSRF findings should be auto-suppressed
- [ ] 5.2 Test on quickheadlines: verify no true positives suppressed
- [ ] 5.3 Test on vug.cr: verify findings unchanged
- [ ] 5.4 Create synthetic test samples: guarded/unguarded variants
- [ ] 5.5 Benchmark: dominator cache computation <10ms per file
- [ ] 5.6 Remove `[taint.suppress]` entries from fetcher.cr `.catseye.toml` (no longer needed)

## Verification Commands

```bash
# Build
just build

# Run tests
just test

# Verify fetcher.cr SSRF auto-suppressed (should be 0 SSRF without .catseye.toml)
mv /workspaces/fetcher.cr/.catseye.toml /tmp/
./bin/catseye-ocaml --rules src/ocaml/rules --cfg /workspaces/fetcher.cr/src/ 2>&1 | grep "SSRF"
mv /tmp/.catseye.toml /workspaces/fetcher.cr/

# Verify quickheadlines unchanged
./bin/catseye-ocaml --rules src/ocaml/rules --cfg --claws /workspaces/quickheadlines/src/ 2>&1 | grep "Found"
```
