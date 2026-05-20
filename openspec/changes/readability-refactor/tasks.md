# Readability Refactor — Tasks

All tasks are 🟢 Safe — no logic change, pure structure refactors.

## Phase 1: Crystal Extractors

- [ ] 1.1 **Extract shared constants to `common.cr`**
  - Files: `src/extractor/extractor.cr`, `src/extractor/hierarchical_extractor.cr`
  - Extract `TAINT_SOURCES`, `SCENT_SOURCES`, `SANITIZERS`, `format_call_name` into `src/extractor/common.cr`
  - Add `require "./common"` to both extractors
  - Verify: `crystal build src/extractor/extractor.cr` and `crystal build src/extractor/hierarchical_extractor.cr`

- [ ] 1.2 **Rename unclear variables in `extractor.cr`**
  - File: `src/extractor/extractor.cr`
  - `n` → `node` in `annotate_timeouts` and loops
  - `a` → `arg` in arg iteration loops
  - `ca` → `call_arg` in nested call arg checks
  - Verify: build + self-scan diff

- [ ] 1.3 **Stringly-typed node type constants in `extractor.cr`**
  - File: `src/extractor/extractor.cr`
  - Add constants at top: `NODE_CALL = "call"`, `NODE_ASSIGN = "assign"`, etc.
  - Replace string literals in comparisons
  - Verify: build + self-scan diff

- [ ] 1.4 **JSON emit helper for `hierarchical_extractor.cr`**
  - File: `src/extractor/hierarchical_extractor.cr`
  - Add private `emit(hash : Hash(String, _))` helper that writes object + fields
  - Refactor 2-3 simple `visit` methods as proof of concept (e.g., `Var`, `StringLiteral`)
  - Do NOT refactor all 20+ visit methods in this pass
  - Verify: build, compare JSON output on a test file before/after

## Phase 2: OCaml Engine

- [x] 2.1 **Guard-clause flattening in `cfg_taint.ml`**
  - File: `src/ocaml/lib/catseye_il/cfg_taint.ml`
  - Flattened 5-level nested `if/else begin/end` in `check_call_sinks` to guard-clause style
  - Verified: build + test + self-scan diff (84 findings identical)

- [x] 2.2 **Rename unclear variables**
  - ✅ `propagate.ml`: `db_ref` → `taint_db_ref` (4 functions)
  - ✅ `reachability.ml`: `adj` → `call_graph`
  - ✅ `cfg_taint.ml`: `state` → `taint_state` in transfer functions, `max_visits` → `max_visits_per_block`
  - Deferred: `gleam_rules.ml` `m`→`mod_` (low impact, follows existing convention)
  - Verified: build + test + self-scan diff (84 findings identical)

- [x] 2.3 **Magic number → named constants**
  - ✅ `propagate.ml`: `let max_propagation_iterations = 100` (replaces 4 occurrences)
  - ✅ `cfg_taint.ml`: `let max_visits_per_block = 3`
  - Deferred: orchestrator buffer size, extra_smells envy ratio (low impact, spread across many locations)
  - Verified: build + test + self-scan diff (84 findings identical)

- [x] 2.4 **`Finding.t` builder helper**
  - ✅ Added `make_finding` helper at top of `extra_smells.ml`
  - ✅ Converted all 8 Finding constructions to use `make_finding`
  - Verified: build + test + self-scan diff (84 findings identical)

- [ ] 2.5 **Replace hand-rolled `find_substring`**
  - File: `src/ocaml/lib/catseye_claws/extra_smells.ml`
  - Function `is_idiomatic_chain` contains a manual `find_substring` recursive loop
  - Replace with `Str.first_match` or inline `String.sub` comparison
  - Verify: build + test + self-scan diff (especially MessageChain findings)

- [ ] 2.6 **Language counts Hashtbl in orchestrator**
  - File: `src/ocaml/lib/catseye_cli/orchestrator.ml`
  - Replace 6 separate `let X_count = List.length (List.filter ...)` with single fold
  - Update `print_banner` to read from `lang_counts`
  - Verify: build + test + manual terminal output check

## Verification Checklist

After all tasks:

- [x] `just build` — clean compile, no warnings
- [x] `just test` — all tests pass
- [x] Self-scan diff — no new or missing findings on `test/samples/` (84 findings baseline preserved)
- [ ] Manual spot-check — terminal output looks correct for a sample project
