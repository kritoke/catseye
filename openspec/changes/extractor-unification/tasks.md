# Extractor Unification — Tasks

**Change:** `extractor-unification`
**Status:** Complete

## Phase 1: Extractor Registry Module

- [x] 1.1 Create `src/ocaml/lib/catseye_engine/extractor_registry.ml` with unified `resolve` function
- [x] 1.2 Implement resolution order: env var → exe_dir → upward CWD search → global install → `crystal run` fallback
- [x] 1.3 Add `extract_flat` and `extract_hier` that spawn a single subprocess and return JSON
- [x] 1.4 Add `create_pool` / `shutdown_pool` wrapping `Worker_pool` for batch extraction
- [x] 1.5 Add to `catseye_engine/dune`
- [x] 1.6 Verify `dune build` succeeds

## Phase 2: Wire Registry Through Config

- [x] 2.1 Add `extractor_registry : Extractor_registry.t` to `config.ml` type (replacing `crystal_extractor : string`)
- [x] 2.2 Create registry at startup in `args.ml`, removing old `resolve_extractor`
- [x] 2.3 Remove `crystal_extractor : string` from config
- [x] 2.4 Update `worker_pool.ml` callers to use registry's `flat_cmd`
- [x] 2.5 Verify `dune build` + existing tests pass

## Phase 3: Refactor AST Mappers

- [x] 3.1 `crystal_mapper.ml` — removed inline resolution, accepts `~extractor_cmd` parameter
- [x] 3.2 `crystal_hierarchical_mapper.ml` — removed `resolve_hierarchical_extractor` and `find_project_bin`, accepts `~extractor_cmd`
- [x] 3.3 Updated `Catseye_ast.Parse.parse_file` to accept `~extractor_registry` parameter
- [x] 3.4 Updated all call sites in orchestrator (4), ai_linter_integration, tests (3)
- [x] 3.5 Verify `dune build` + existing tests pass

## Phase 4: Validation

- [x] 4.1 Benchmark: fetcher.cr 53 files with `--claws` — **2.9s** (was 72s+)
- [x] 4.2 Benchmark: quickheadlines 67 files — **6.0s** (was 120s+)
- [x] 4.3 Benchmark: vug.cr 26 files — **0.45s** (was 74s)
- [x] 4.4 All tests pass (23 findings, 0 safe, 6 smells)
- [x] 4.5 Justfile updated — extractors compiled in `build` step, `build-extractors` target added

## Remaining (optional follow-ups)

- [ ] 5.1 Batch extraction via `--serve` pool for Claws/AI-lint paths (would cut another ~2x)
- [ ] 5.2 Add `parse_json` functions to mappers (parse from string, no subprocess)
- [ ] 5.3 Remove `run_crystal_extractor` dead code in orchestrator
- [ ] 5.4 Update justfile `install` target to install both extractor binaries
