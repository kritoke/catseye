# Catseye OpenSpec — Performance & Safety Fixes

**Created:** 2026-05-15  
**Status:** Implemented  
**Changes:** `--no-cfg`, `--analysis-timeout`, progress logging, flat engine fallback  

---

## Context

During a production scan on a real codebase, Catseye hung for over 3000 seconds (50+ minutes). The hang occurred during the analysis phase. While the CFG builder itself scales linearly (verified with synthetic tests), the root cause remains unknown — could be XML parsing, circular imports, worker pool, or external tool hang.

## Implemented Changes

### ✅ `--no-cfg` flag

Forces use of the flat taint engine (`Catseye_engine.Engine.analyze`) instead of the CFG-based engine. The flat engine has more predictable O(n) performance characteristics and is less likely to hang on pathological input.

**Files changed:**
- `src/ocaml/lib/catseye_cli/config.ml` — added `no_cfg_use` field
- `src/ocaml/lib/catseye_cli/args.ml` — added `--no-cfg` flag parsing
- `src/ocaml/lib/catseye_cli/orchestrator.ml` — applied override before analysis

### ✅ `--analysis-timeout` flag

Sets a timeout (in ms) for the analysis phase. If the timeout is exceeded, falls back to the flat engine.

**Files changed:**
- `src/ocaml/lib/catseye_cli/config.ml` — added `analysis_timeout_ms` field
- `src/ocaml/lib/catseye_cli/args.ml` — added `--analysis-timeout` flag parsing
- `src/ocaml/lib/catseye_cli/orchestrator.ml` — added `with_timeout` helper and fallback logic

### ✅ Progress logging

Logs every 10 files during CFG analysis to help diagnose hangs:

```
  [progress] Analyzed 10/50 files...
  [progress] Analyzed 20/50 files...
```

**Files changed:**
- `src/ocaml/lib/catseye_cli/orchestrator.ml` — added `analyzed` counter and progress output

### ✅ Engine indicator in output

Shows which engine is in use:

```
  [cfg] Using IL/CFG-based taint engine
  [engine] Using flat taint engine
```

**Files changed:**
- `src/ocaml/lib/catseye_cli/orchestrator.ml` — added engine indicator

---

## Usage

```bash
# Use flat engine (more predictable performance)
catseye --no-cfg /path/to/codebase

# Use CFG engine with 60s timeout
catseye --cfg --analysis-timeout 60000 /path/to/codebase

# CFG engine with fallback on timeout
catseye --cfg --analysis-timeout 30000 /path/to/codebase
# Output if timeout: "[timeout] Analysis exceeded limit. Falling back to flat engine..."
```

---

## Investigation Status

The CFG builder performance tests show linear scaling:

| Input | Time |
|-------|------|
| 500 sequential ILBranch nodes | 0.073ms |
| 100 nested ILBranch nodes | 0.013ms |
| 10,000 linear ILAssign nodes | 2.733ms |

The 3000s hang is **not** reproduced with synthetic CFG inputs. Possible causes remaining:

1. **Infinite loop in Gleam XML parsing** — `parse_xml` in `gleam_mapper.ml` builds nested AST
2. **Circular file dependencies** — cross-file symbol resolution
3. **Worker pool deadlock** — parallel extraction
4. **External tool hang** — tree-sitter or Crystal extractor

---

## Tasks (Completed)

- [x] 1.1 Add `--no-cfg` flag to args.ml
- [x] 1.2 Wire `--no-cfg` into orchestrator (use flat engine when set)
- [x] 2.1 Add `--analysis-timeout` flag (default: 0 = disabled)
- [x] 2.2 Wrap analysis phase in timeout handler
- [x] 3.1 Add progress logging every 10 files
- [x] 3.2 Log which engine is being used

---

## Open Questions

1. What codebase caused the 3000s hang? Can we test it?
2. Should we make `--no-cfg` the default until CFG path is proven reliable?
3. Should the timeout check be more granular (e.g., every 100 nodes instead of once)?

---

## Backward Compatibility

- `--no-cfg` is purely additive — no existing behavior changes
- `--analysis-timeout` defaults to 0 (no timeout) — safe for small codebases
- CFG path is still default (use `--cfg` to enable it)
