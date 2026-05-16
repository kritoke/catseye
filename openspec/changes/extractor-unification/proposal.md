# Unify Extractor Resolution & Pipeline

**Change:** `extractor-unification`
**Priority:** P1
**Size:** M (1–2 days)
**Status:** Proposal

## Motivation

The Crystal extractor resolution is duplicated across 4 separate locations with inconsistent logic:

| Location | What it resolves | Resolution order |
|----------|-----------------|------------------|
| `args.ml` `resolve_extractor` | `config.crystal_extractor` | CWD → exe_dir → global install → CWD fallback |
| `crystal_mapper.ml` `parse_file` | Flat AST extractor | env var → exe_dir → upward search → `crystal run` |
| `crystal_hierarchical_mapper.ml` `resolve_hierarchical_extractor` | Hierarchical AST extractor | env var → exe_dir → upward search → `crystal run` |
| `worker_pool.ml` | `--serve` mode pool | Receives path from `config.crystal_extractor` |

**Problems:**

1. **3 independent resolvers, 3 different strategies** — `args.ml` doesn't search upward, mappers don't use config, worker pool just takes whatever config gives it.
2. **Slow by default** — When running from the repo root, `crystal_hierarchical_mapper` found `src/extractor/hierarchical_extractor.cr` before `bin/catseye-hierarchical-extractor`, forcing `crystal run` (recompile per invocation, ~1.3s/file). A 53-file scan took 72s when it should take <5s.
3. **Two extractors, one env var** — `CATSEYE_CRYSTAL_EXTRACTOR` overrides both flat and hierarchical, but they're different binaries. Setting it for one breaks the other.
4. **Config has one extractor path** — `config.crystal_extractor` points to the flat extractor. The hierarchical mapper ignores it entirely and has its own resolution. The Claws/AI-lint AST path bypasses config.
5. **No caching across calls** — The Claws path calls `parse_file` 48 times, each spawning a subprocess. No reuse of the `--serve` worker pool.

**Before the hotfix (pre-compiled binary priority):** fetcher.cr 53 files with `--claws` = **72s** (every file spawned `crystal run`).
**After hotfix:** ~75s still because the upward search didn't fully resolve correctly from all CWDs.
**Expected after refactor:** <5s using pre-compiled binaries + worker pool.

## What Changes

### Core idea: Single `Extractor_registry` module

Replace all 3 resolver functions with one module that:
- Finds both extractors (flat + hierarchical) at startup
- Prefers pre-compiled binaries over `crystal run` source
- Exposes a `--serve` mode pool for batch extraction
- Is passed through config, not called ad-hoc

### Resolution order (unified)

```
1. CATSEYE_CRYSTAL_EXTRACTOR env var        → flat extractor override
2. CATSEYE_CRYSTAL_HIERARCHICAL env var     → hierarchical extractor override
3. Pre-compiled binary next to exe          → bin/catseye-crystal-extractor, bin/catseye-crystal-hierarchical-extractor
4. Search upward from CWD for bin/          → works from any subdirectory
5. Global install layout                    → $exe_dir/../lib/catseye/extractor/
6. crystal run on source                    → last resort (slow)
```

### Architecture

```
                    ┌─────────────────────┐
                    │ Extractor_registry   │
                    │  (new module)        │
                    ├─────────────────────┤
                    │ flat_cmd : string    │
                    │ hier_cmd : string    │
                    │ pool : Worker_pool.t │
                    │  option              │
                    └────────┬────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                  │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌───────▼──────┐
    │ Flat taint  │  │ Claws AST   │  │ AI-lint AST  │
    │ engine      │  │ path        │  │ path         │
    │ (nodes)     │  │ (modules)   │  │ (modules)    │
    └─────────────┘  └─────────────┘  └──────────────┘
```

## Files

### New
- `src/ocaml/lib/catseye_core/extractor_registry.ml` — unified resolver + pool manager
- `src/ocaml/lib/catseye_core/extractor_registry.mli` — interface

### Modified
- `src/ocaml/lib/catseye_cli/config.ml` — replace `crystal_extractor : string` with `extractor_registry : Extractor_registry.t`
- `src/ocaml/lib/catseye_cli/args.ml` — remove `resolve_extractor`, use registry at startup
- `src/ocaml/lib/catseye_cli/orchestrator.ml` — pass registry through, use for all extraction
- `src/ocaml/lib/catseye_ast/crystal_mapper.ml` — accept registry instead of self-resolving
- `src/ocaml/lib/catseye_ast/crystal_hierarchical_mapper.ml` — accept registry instead of self-resolving
- `src/ocaml/lib/catseye_engine/worker_pool.ml` — accept pre-resolved cmd, no path logic
- `justfile` — ensure extractors are always compiled in `build` step

### Removed (logic moved to registry)
- `args.ml` `resolve_extractor`
- `crystal_mapper.ml` inline resolution
- `crystal_hierarchical_mapper.ml` `resolve_hierarchical_extractor` + `find_project_bin`

## Specs

- `specs/extractor-registry/spec.md`
