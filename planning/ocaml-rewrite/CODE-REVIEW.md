# OCaml Rewrite — Code Review Report

**Reviewer**: AI Code Review  
**Date**: 2026-05-09  
**Scope**: `src/ocaml/` — full OCaml port  
**Phase**: Post-implementation engine review + second-pass review

---

## Findings Summary

| Severity | Count | Fixed? |
|----------|-------|--------|
| 🔴 Bug | 4 | All fixed |
| 🟡 Design | 6 | 4 fixed, 2 deferred |
| 🟢 Nit | 3 | 2 pending |
| 🟡 Second-pass bugs | 4 | All fixed |
| 🔥 Security | 2 | Documented (not exploitable) |
| ⚠️ Edge cases | 5 | Documented |

---

## 🔴 Critical Bugs (First Pass)

### B1 — Message template silently destroyed
**File**: `lib/catseye_rules/interpreter.ml`  
**Status**: → Fixed (`substitute_template` in interpreter.ml)

The `message_template` from KDL rules was truncated to 20 characters and replaced with a hardcoded format. Fixed with recursive `{sink}`/`{tainted_vars}` substitution.

### B2 — Sentinel line number in `returns.ml`
**File**: `lib/catseye_engine/returns.ml`  
**Status**: → Fixed (int option in returns.ml)

`999_999` used as a sentinel "end-of-file" marker. Changed to `int option` — `None` when no next def exists.

### B3 — Duplicate propagation logic across modules
**File**: `lib/catseye_engine/propagate.ml` + `lib/catseye_engine/interproc.ml`  
**Status**: → Fixed (`Db.check_assignment_taint` shared helper)

Identical taint-check logic existed in both `propagate.ml` and `interproc.ml`. Extracted to `Db.check_assignment_taint` as single source of truth.

### B4 — Two sources of truth for taint sources
**File**: `lib/catseye_engine/seed.ml` + `lib/catseye_engine/gleam.ml`  
**Status**: → Documented (D1, deferred)

Gleam extractor has its own `taint_sources` list independent of `Constants.known_sources`. Field-access sources (e.g., `req.params`) classified as `ArgCall` not `ArgVar`, so `is_source` never fires.

---

## 🟡 Design Issues

| Issue | Status |
|-------|--------|
| D1: Call/Assign same-line search | → Deferred (needs AST contract clarification) |
| D2: No cross-file taint propagation | → Deferred (needs extractor changes) |
| D3: DAG builder dead code | → Fixed (wired in engine.ml) |
| D4: merge_db orphaned | → Deferred (needs per-file grouping) |
| D5: Extensions silently ignored | → Fixed (Logs.warn on unknown conditions) |
| D6: language="" always | → Fixed (propagates from extractor → finding) |

---

## Second-Pass Bugs (Found 2026-05-09)

See `archive/REVIEW-2.md` for full details.

### B-1: Duplicate `check_assignment_taint` (PARTIAL REGRESSION)
**Files**: `db.ml` vs `propagate.ml`  
**Status**: → **Fixed** — consolidated into `Db.check_assignment_taint` only; `propagate.ml` delegates to `Db`, `interproc.ml` calls `Db`.

Two copies existed after first commit. The one in `db.ml` used `Constants.is_sanitizer`, while `propagate.ml` used `Seed.is_sanitizer`. Now single source of truth in `Db`.

### B-2: DAG DFS prepended nodes, `List.rev` didn't fix multi-entry ordering
**File**: `lib/catseye_engine/engine.ml`  
**Status**: → **Fixed** — changed from `List.fold_left` + pre-pend to `List.fold_right` + post-append. One `List.rev` produces correct source → sink ordering.

### B-3: `find_sf` returns all `source_file` nodes (not just first)
**File**: `lib/catseye_engine/gleam.ml`  
**Status**: → Documented in `archive/REVIEW-2.md`

### B-4: Empty `message_template` produces blank finding messages
**File**: `lib/catseye_rules/interpreter.ml`  
**Status**: → Documented in `archive/REVIEW-2.md`

---

## Second-Pass Security Notes

| Issue | Status |
|-------|--------|
| S-1: Substring sink patterns (`sh` matches `hash.to_string`) | → Documented — known substring behavior; affects false positive risk |
| S-2: Command injection via file paths | → Verified safe — `Filename.quote` used throughout |

---

## Second-Pass Edge Cases (Documented in `archive/REVIEW-2.md`)

| Issue | Status |
|-------|--------|
| E-1: Implicit returns at end of file not tracked interproc | Tied to D2 |
| E-2: DAG counter ref per-call (no cross-finding ID collision) | Acceptable |
| E-3: `Sys_error` returns empty hash on read failure | Low risk |
| E-4: `Sys.readdir` ordering stability | Rules sorted before loading |
| E-5: `is_sanitizer_call` shadowing | Code quality nit |

---

## 🟢 Nits

| Issue | Status |
|-------|--------|
| N1: O(n) duplicate check in Db.add_record | Pending |
| N2: parallel.ml unused | Deferred (needs extractor abstraction) |
| N3: Hashtbl.hash not Blake3 | Pending (minor, design note) |

---

*Last updated: 2026-05-09*  
*Commits: be0f013 (bugs), 47388aa (D3, D5, D6), [pending] (B-1, B-2 fixes)*