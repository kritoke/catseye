# Catseye Scan Report — QuickHeadlines

**Date:** 2026-05-11  
**Engine:** Catseye v0.3.0 (OCaml taint + Claws)  
**Target:** `/workspaces/quickheadlines/src`  
**Commit:** `8c72e98` on main  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Files scanned | 66 Crystal |
| AST nodes extracted | 5,507 |
| **Total findings** | **104** |
| Security (taint) | 2 |
| Code smells (Claws) | 102 |
| Extraction time | 0.6s |
| Analysis time | 0.05s |

**Severity breakdown:** 7 High (Hiss 🐱⚡), 97 Medium (Meow 🐾)

---

## Security Findings

### 1. 🐱⚡ HISS — PathTraversal (High)

**File:** `favicon_storage.cr:63`  
**Sink:** `File.write(filepath, image_data)`  
**Message:** Potential path traversal via File.write with variable argument(s): filepath, image_data. Validate and sanitize path components.

**Taint flow:**
```
favicon_storage.cr:140  ← filepath (source)
favicon_storage.cr:140  ← filepath = ...
favicon_storage.cr:63   → File.write(filepath, image_data)
```

**Assessment:** **Real finding.** The `filepath` variable is constructed from user-controlled input and passed directly to `File.write` without path sanitization. An attacker could potentially write files to arbitrary locations via path traversal (e.g., `../../etc/cron.d/malicious`).

**Remediation:** Use `Path.expand` + verify the result is within the intended directory:
```crystal
filepath = Path.expand(filepath)
unless filepath.starts_with?(FAVICON_DIR)
  raise "Invalid path"
end
```

---

### 2. 🐾 MEOW — PathTraversal (Medium)

**File:** `services/favicon_sync_service.cr:100`  
**Sink:** `File.join`  
**Message:** Potential path traversal via File.join (path join) with variable argument(s): filename. Validate path components.

**Assessment:** **Likely false positive.** `File.join` alone doesn't write files — it constructs a path string. The actual risk depends on how the joined path is subsequently used. If it's later passed to `File.write` or similar, the combined flow should be reviewed.

**Remediation:** Verify that downstream usage validates the path. If the result is only used for reads or is sanitized elsewhere, this can be marked as a known safe pattern.

---

## Code Smell Findings (Claws)

### By Category

| Category | High (Hiss) | Medium (Meow) | Total |
|----------|:-----------:|:-------------:|:-----:|
| DRYViolation | 0 | 78 | 78 |
| LongParameterList | 6 | 13 | 19 |
| GodObject | 0 | 3 | 3 |
| DeepNesting | 1 | 1 | 2 |
| **Total** | **7** | **95** | **102** |

### Top Files by Smell Count

| File | Findings | Primary issue |
|------|:--------:|---------------|
| `dtos/api_responses.cr` | 17 | DRY (repeated DTO constructor patterns) |
| `services/clustering_service.cr` | 11 | DRY (repeated DB query patterns) |
| `services/feed_service.cr` | 10 | DRY + LongParameterList |
| `fetcher/feed_fetcher.cr` | 10 | DRY (error handling duplication) + GodObject |
| `storage/database.cr` | 7 | DRY (repeated migration/schema patterns) |
| `services/favicon_sync_service.cr` | 5 | LongParameterList + DRY |
| `models.cr` | 4 | DRY + GodObject |
| `repositories/cluster_repository.cr` | 4 | DRY (query boilerplate) |

### Largest DRY Violations

| Locations | File:Line | Description |
|:---------:|-----------|-------------|
| 67 | `constants.cr:65` | Repeated constant definition blocks across multiple files |
| 48 | `dtos/api_responses.cr:211` | DTO response mapping patterns duplicated across 4 response types |
| 45 | `services/clustering_service.cr:154` | DB query + mapping patterns duplicated across services |
| 40 | `services/clustering_service.cr:153` | Near-identical query construction in clustering pipeline |
| 7 | `storage/database.cr:106` | Migration helper patterns |
| 7 | `repositories/cluster_repository.cr:108` | Repository query boilerplate |
| 5 | `web/static_controller.cr:109` | Route handler patterns |

### LongParameterList (6 Hiss + 13 Meow)

| Severity | File:Line | Notes |
|----------|-----------|-------|
| **High** | `dtos/api_responses.cr:78` | DTO constructor — 8+ params |
| **High** | `dtos/api_responses.cr:135` | DTO constructor — 8+ params |
| **High** | `dtos/api_responses.cr:228` | DTO constructor — 8+ params |
| **High** | `dtos/story_dto.cr:27` | Story DTO — 8+ params |
| **High** | `services/favicon_sync_service.cr:130` | Service method — 8+ params |
| **High** | `controllers/admin_controller.cr:8` | Deep nesting + params |
| Medium | `dtos/api_responses.cr:39` | DTO constructor — 6-7 params |
| Medium | `dtos/api_responses.cr:167` | DTO constructor — 6-7 params |
| Medium | `services/feed_service.cr:19,82,122` | Service methods |
| Medium | `services/clustering_service.cr:22,54,68` | Clustering methods |
| Medium | `fetcher/feed_fetcher.cr:59,316` | Fetcher methods |
| Medium | `services/app_bootstrap.cr:22` | Bootstrap init |
| Medium | `services/story_service.cr:6` | Story service |
| Medium | `services/favicon_sync_service.cr:58,108` | Sync service |

### DeepNesting

| Severity | File:Line | Notes |
|----------|-----------|-------|
| **High** | `controllers/admin_controller.cr:8` | Admin action with deeply nested conditionals |
| Medium | `storage/clustering_store.cr:105` | Clustering logic with nested loops/conditions |

### GodObject

| Severity | File:Line | Notes |
|----------|-----------|-------|
| Medium | `storage/feed_cache.cr:20` | FeedCache handles too many responsibilities |
| Medium | `fetcher/feed_fetcher.cr:22` | FeedFetcher is large and multi-purpose |
| Medium | `models.cr:26` | Models module has many definitions |

---

## Recommended Actions

### Priority 1 — Security Fix

- [ ] **Fix PathTraversal in `favicon_storage.cr`** — Add `Path.expand` + prefix check before `File.write`

### Priority 2 — High-Value Refactoring

- [ ] **Extract DTO base module** in `dtos/api_responses.cr` — 3 constructors with 8+ params and repeated mapping logic can use a shared `serializable` macro
- [ ] **Extract query builder** for repositories — `cluster_repository.cr`, `feed_repository.cr`, `story_repository.cr` share identical DB query patterns (DRY root cause)
- [ ] **Extract constant mapping macro** in `constants.cr` — 67-location duplication can be collapsed into a macro that generates the mappings

### Priority 3 — Code Quality

- [ ] **Reduce `favicon_sync_service.cr:130` parameters** — Use a config struct or named tuples
- [ ] **Simplify `admin_controller.cr:8` nesting** — Extract guard clauses into private methods
- [ ] **Split `feed_fetcher.cr`** — GodObject with 10 findings; separate fetch logic from parsing and error handling

---

## Comparison with Previous Scan

| Metric | v3 Engine (old) | v0.3.0 (current) |
|--------|:---------------:|:-----------------:|
| Security findings | 33 | 2 |
| False positives | High (many were sanitized) | Low (1 likely FP) |
| Code smell detection | None | 102 |
| Extraction time | ~2s | 0.6s |
| Analysis time | ~0.3s | 0.05s |

The v3 engine produced 33 security findings, most of which were false positives from overly aggressive taint propagation. The current engine's scope isolation fix (Phase 6 F1) and sanitizer recognition reduce this to 2 high-confidence findings. The Claws module adds 102 code smell detections, with DRY violations being the dominant category.

---

*Generated by Catseye v0.3.0 — `catseye-ocaml --claws --rules src/ocaml/rules /workspaces/quickheadlines/src`*
