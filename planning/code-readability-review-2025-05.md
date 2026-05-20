# Code Readability Review — May 2025

Full findings from a manual code review focusing on anti-patterns, unclear
variable names, nested logic, and over-complicated conditionals across the
entire codebase.

## Scope

Files reviewed:

- `src/extractor/extractor.cr` (928 lines)
- `src/extractor/hierarchical_extractor.cr` (717 lines)
- `src/ocaml/lib/ai_linter/crystal_rules.ml` (1704 lines)
- `src/ocaml/lib/ai_linter/gleam_rules.ml` (1431 lines)
- `src/ocaml/lib/catseye_claws/extra_smells.ml` (871 lines)
- `src/ocaml/lib/catseye_cli/orchestrator.ml` (752 lines)
- `src/ocaml/lib/catseye_engine/propagate.ml` (462 lines)
- `src/ocaml/lib/catseye_il/cfg_taint.ml` (423 lines)
- `src/ocaml/lib/catseye_engine/reachability.ml` (339 lines)

## Risk Classification

| Risk Level  | Description                                                             |
| ----------- | ----------------------------------------------------------------------- |
| 🟢 Safe     | Pure refactor, no logic change. Renames, extraction helpers, constants. |
| 🟡 Moderate | Semantics preserved but subtle (fold vs ref, evaluation order).         |
| 🔴 High     | Could change detection accuracy (generic fold, module splits).          |

## Category 1: Deeply Nested Conditionals

### 1.1 Crystal extractor scent propagation — 🟢 Safe

**File:** `src/extractor/extractor.cr` ~lines 290-310
**Issue:** Triple-nested `if` with repeated `@scented_vars` mutations.
**Fix:** Extract `scent_propagated?` helper with early returns.

### 1.2 CFG taint sink checking — 🟢 Safe

**File:** `src/ocaml/lib/catseye_il/cfg_taint.ml` ~lines 180-230
**Issue:** 5 levels of `if/else begin/end` nesting in `check_call_sinks`.
**Fix:** Guard-clause flattening — each condition returns `[]` early.

## Category 2: Unclear Variable Names

| #   | File              | Variable                      | Problem                            | Suggestion            | Risk |
| --- | ----------------- | ----------------------------- | ---------------------------------- | --------------------- | ---- |
| 2.1 | `extractor.cr`    | `n`                           | SecNode or count?                  | `node` or `sec_node`  | 🟢   |
| 2.2 | `extractor.cr`    | `a` / `ca`                    | Double-meaning arg vars            | `arg` / `call_arg`    | 🟢   |
| 2.3 | `propagate.ml`    | `db_ref`                      | Sounds like DB handle              | `taint_db_ref`        | 🟢   |
| 2.4 | `orchestrator.ml` | `cr_count`, `gleam_count`, ×4 | 6 separate counters                | `lang_counts` Hashtbl | 🟢   |
| 2.5 | `extra_smells.ml` | `s`                           | Loop variable for substring checks | `suffix` or `pat`     | 🟢   |
| 2.6 | `reachability.ml` | `adj`                         | Non-obvious abbreviation           | `call_graph`          | 🟢   |
| 2.7 | `cfg_taint.ml`    | `st`                          | State accumulator in fold          | `taint_state`         | 🟢   |
| 2.8 | `gleam_rules.ml`  | `m`                           | Module param, looks mutable        | `mod_` or `module_`   | 🟢   |

## Category 3: Duplicated / Copy-Pasted Code

### 3.1 Duplicated AST walkers — 🔴 High Risk

**Files:** `gleam_rules.ml`, `crystal_rules.ml` (20+ near-identical recursive walkers)
**Issue:** Each rule has its own 15-line recursive `collect_*` or `find_*` function.
**Potential fix:** Generic `fold_expr` catamorphism.
**Risk:** Walkers have different stop conditions, merge strategies, and mutual
recursion. A single generic fold needs to handle all variants correctly.
Wrong implementation = silent detection misses.
**Status:** Tracked separately — requires golden-output test baseline first.

### 3.2 Duplicated constant sets between extractors — 🟢 Safe

**Files:** `src/extractor/extractor.cr`, `src/extractor/hierarchical_extractor.cr`
**Issue:** `TAINT_SOURCES`, `SCENT_SOURCES`, `SANITIZERS`, `format_call_name`
fully duplicated. Must be kept in sync manually.
**Fix:** Extract to `src/extractor/common.cr`, require from both.

### 3.3 Repeated Finding.t construction — 🟢 Safe

**File:** `src/ocaml/lib/catseye_claws/extra_smells.ml` (8+ occurrences)
**Issue:** Same 10-field record literal with `dependency=None; reachability=None; suggestion=None` tail.
**Fix:** `make_finding` builder helper.

### 3.4 Duplicated `find_substring` implementation — 🟢 Safe

**File:** `src/ocaml/lib/catseye_claws/extra_smells.ml`
**Issue:** Manually reimplements `Str.first_match` or substring search.
**Fix:** Replace with OCaml stdlib.

## Category 4: Over-Complicated Conditionals

### 4.1 `is_idiomatic_chain` — 🟡 Moderate Risk

**File:** `src/ocaml/lib/catseye_claws/extra_smells.ml` ~line 118
**Issue:** 40-line boolean expression with 7 `||` branches.
**Risk:** This is a FP suppression filter. Changing it may unsuppress
legitimate chains, causing noisy false positives.
**Fix:** Declarative suffix/prefix lists + membership check.
**Status:** Only refactor with golden-output diff validation.

### 4.2 `annotate_timeouts` — 🟡 Moderate Risk

**File:** `src/extractor/extractor.cr` ~lines 395-475
**Issue:** 80-line method tracking 5 sets + 2 hashtables in nested case/if/each.
**Risk:** Ordering between phases is load-bearing.
**Fix:** Break into named phases with explicit state threading.

### 4.3 `orchestrator.ml` `run` monolith — 🟡 Moderate Risk

**File:** `src/ocaml/lib/catseye_cli/orchestrator.ml` (752 lines)
**Issue:** Single function containing extraction, caching, analysis, AI linting,
claws, crow's nest, reachability, 4 output formats, exit code logic.
**Risk:** Mutable refs, side-effect ordering, config mutation mid-function.
**Fix:** Decompose into named phase functions.

## Category 5: Anti-Patterns

### 5.1 Mutable refs for foldable data — 🟡 Moderate Risk

**File:** `src/ocaml/lib/catseye_engine/propagate.ml` (4 functions)
**Issue:** `db_ref = ref db` + `db_ref :=` pattern in `propagate_cross_file`,
`propagate_uri_properties`, `propagate_aliases`, `propagate_string_ops`.
`do_propagate` already uses `List.fold_left` correctly.
**Risk:** `propagate_cross_file` reads earlier writes within the same pass —
`List.fold_left` does the same, so conversion is safe. But the 4 functions
are called from separate fixed-point loops; sequencing matters.
**Fix:** Convert one at a time with test verification.

### 5.2 Magic numbers — 🟢 Safe

| File              | Value  | Context                  | Fix                            |
| ----------------- | ------ | ------------------------ | ------------------------------ |
| `propagate.ml`    | `100`  | Max loop iterations (×4) | `let max_iterations = 100`     |
| `cfg_taint.ml`    | `3`    | `max_visits` per block   | `let max_visits_per_block = 3` |
| `cfg_taint.ml`    | `32`   | Hashtbl.create size      | Consistent named constant      |
| `orchestrator.ml` | `4096` | Buffer size              | `let buffer_size = 4096`       |
| `extra_smells.ml` | `0.7`  | Feature envy ratio       | `let envy_threshold = 0.7`     |

### 5.3 Stringly-typed node types in Crystal — 🟢 Safe

**File:** `src/extractor/extractor.cr`
**Issue:** Node types are strings (`"call"`, `"assign"`) leading to fragile comparisons.
**Fix:** Constants or enum.

### 5.4 God module: `crystal_rules.ml` — 🔴 High Risk

**File:** `src/ocaml/lib/ai_linter/crystal_rules.ml` (1704 lines)
**Issue:** 34 rule functions + database + helpers in a single file.
**Risk:** Hidden dependencies between rules (shared hashtables for data clumps,
repeated regex/string detection). `method_db` is built at module load time.
**Fix:** Split into category modules with shared state in a common module.
**Status:** Requires careful dependency audit.

## Category 6: Structural Issues

### 6.1 `hierarchical_extractor.cr` JSON boilerplate — 🟢 Safe

**File:** `src/extractor/hierarchical_extractor.cr`
**Issue:** Every `visit` method is 90% `@json.object do ... @json.field ... end`.
**Fix:** Hash/NamedTuple helper with `emit()` method.

### 6.2 `orchestrator.ml` 752-line `run` — See 4.3

## Triage Summary

| Risk        | Count    | Action                                  |
| ----------- | -------- | --------------------------------------- |
| 🟢 Safe     | 15 items | OpenSpec change — safe to implement now |
| 🟡 Moderate | 4 items  | Requires per-item test verification     |
| 🔴 High     | 2 items  | Requires golden-output baseline first   |

## See Also

- `openspec/changes/readability-refactor/` — OpenSpec for safe changes
- `planning/dnf/` — Items previously deferred
- `planning/catseye_false_positives.md` — Known FP patterns
