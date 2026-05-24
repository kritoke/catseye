# Security Analysis Gaps & Enhancement Plan

**Created:** 2026-05-21
**Status:** Mostly Implemented
**Updated:** 2026-05-24
**Related:** `openspec/changes/security-rules-review-2025-05/`

## Executive Summary

Most Phase 1 security gaps have been addressed. Remaining work tracked in
`openspec/config.yaml` under `security-rules-review` track.

---

## Status Summary

| Issue | Languages | Status |
|-------|-----------|--------|
| chmod ignored | Crystal | ✅ Done |
| chmod ignored | Rust | ✅ Done |
| chmod ignored | Elixir | ✅ Done |
| Non-atomic file ops | Crystal | ✅ Done |
| Non-atomic file ops | Rust | ✅ Done |
| Non-atomic file ops | Elixir | ✅ Done |
| Unbounded read | Crystal | ✅ Done |
| Unbounded read | Rust | ✅ Done |
| Unbounded read | Elixir | ✅ Done |
| Unbounded read | JS/TS | ✅ Done |
| TOCTOU basic | JS/TS | ✅ Done |
| Magic strings | Rust | ✅ Done |
| Hardcoded URLs | Rust | ✅ Done |
| File.stream false positive | Elixir | ✅ Fixed |

---

## Languages Covered

| Language | Status | Rules Module |
|----------|--------|--------------|
| Crystal | Full | `crystal_rules.ml`, `crystal_ts.ml` |
| Gleam | Full | `gleam_rules.ml` |
| Elixir | Full | (via Sobelow, Credo, Claws) |
| Rust | Partial | `rust_rules.ml` |
| JavaScript/TypeScript | Partial | `javascript_rules.ml` |
| Svelte | Partial | `svelte_rules.ml` |
| OCaml | Partial | `ocaml_rules.ml` |

---

## Implemented Detectors

### 1. TOCTOU (Time-of-Check-Time-of-Use) — JS/TS ✅

Basic check-then-act pattern detection implemented:
- `exists` → `readFile/open/writeFile`
- `access` → `readFile/open/writeFile`  
- `stat/lstat` → `readFile/open`
- Qualified names: `fs.exists`, `fs.access`, `fs.stat`

See: `src/ocaml/lib/ai_linter/javascript_rules.ml`

### 2. Silent Permission Failure — Multi-Language ✅

**Crystal:**
- `chmod`, `chown`, `chgrp` in ignored-return patterns
- `detect_non_atomic_file_op` for write+perm combinations

**Rust:**
- `set_permissions`, `chmod` in ignored-permission patterns
- `detect_non_atomic_file_ops` (gated on write+perm)

**Elixir (via Claws):**
- `File.chmod`, `File.chown`, `File.chgrp`

See: `src/ocaml/lib/ai_linter/crystal_rules.ml`, `rust_rules.ml`, `elixir_claws.ml`

### 3. Unbounded File Read — Multi-Language ✅

**Crystal:**
- `File.read`, `File.read?`, `IO.copy`, `read`, `read?`

**Rust:**
- `std::fs::read`, `read_to_string`, `read_to_end`

**Elixir:**
- `File.read`, `File.read!` (NOT `File.stream` — lazy and recommended)

**JavaScript/TypeScript:**
- `fs.readFileSync`, `fs.readFile`, `readFileSync`, `readFile`

### 4. Magic String Heuristic — Rust ✅

Fixed to avoid false positives:
- Threshold raised to 40 chars (was 20)
- Safe patterns excluded: UUIDs, base64, hex, paths, emails
- Excludes test files

### 5. Hardcoded URLs — Rust ✅

Fixed to require `://` scheme separator:
- `http://`, `https://`, `ftp://`, `sftp://`
- Also detects `localhost`, `127.0.0.1`, `0.0.0.0`

---

## Gaps Requiring External Tools

| Issue | Languages | Recommendation |
|-------|-----------|----------------|
| Concurrent close | All | ThreadSanitizer, Infer |
| Use-after-free | Crystal, Rust | Valgrind, Miri |
| Complex race conditions | All | Infer, CodeQL |
| Memory safety | Crystal, Rust | Valgrind, Memory Sanitizer |

---

## Next Steps

See `openspec/changes/security-rules-review-2025-05/tasks.md`:

### Phase 2 (Design Improvements)
- [ ] Extract shared AST walker to `common.ml`
- [ ] Fix empty `file` field in legacy Rust rules
- [ ] Rename `UnsafeInLib` → `UnsafeUnwrap`
- [ ] Deduplicate overlapping permission rules
- [ ] Expand TOCTOU patterns

### Phase 3 (Style Cleanup)
- [ ] Add trailing newlines
- [ ] Convert ref accumulators to functional style
- [ ] Remove dead branch in `is_test_or_bench`
- [ ] Document severity mapping

---

## References

- [CWE-362: Race Condition (TOCTOU)](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-378: Creation of Temporary File With Insecure Permissions](https://cwe.mitre.org/data/definitions/378.html)
- [Infer Static Analyzer](https://fbinfer.com/)
- [Semgrep](https://semgrep.dev/)
- [ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html)