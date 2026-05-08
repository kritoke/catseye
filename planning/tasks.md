# Catseye — Active Tasks

## In Progress

(None — ready for next task)

## Up Next

### Task: Extractor field-level taint
**Goal:** Crystal `params["url"]` → emit node with field="url" so `is_tainted_field` works end-to-end
**Files:** `src/extractor/extractor.cr`, `src/engine/src/catseye/node.gleam`, Erlang FFI

### Task: Conditional taint refinement
**Goal:** `if validator.is_valid(x)` on true branch → clear taint
**Approach:** Detect `if` nodes with validator calls, mark subsequent code as sanitized

### Task: Test coverage for real-world Crystal frameworks
**Goal:** Test against Lucky/Amber/Kemal patterns
**Approach:** Add framework-specific test samples, verify known-safe patterns aren't flagged

---

## Future / Planned

### Task: Software Composition Analysis (SCA) module
**Status:** Planned
**Language:** Nim (in CLI)
**Goal:** Scan dependency manifests for known vulnerabilities via OSV.dev API

**Spec:**
1. Detect `shard.yml` and `gleam.toml` in the project root
2. Parse the dependency list and pinned versions from each
3. Use Nim's `httpclient` to query the [OSV.dev API](https://osv.dev/docs/#api-) for known vulnerabilities in those specific versions
4. If a `high` or `critical` vulnerability is found, print a warning with a 🐈‍⬛ (Stray Cat) icon and the suggested upgrade version

**OSV API example:**
```
POST https://api.osv.dev/v1/query
{
  "package": {"name": "my-dep", "ecosystem": "crystal-shards"},
  "version": "1.2.3"
}
```

**Output example:**
```
🐈‍⬛ [SCA] High  my-dep 1.2.3 → upgrade to 1.2.5
    CVE-2024-12345: Remote code execution via deserialization
```

**Files to create/modify:**
- `src/cli/sca.nim` — SCA module (manifest detection, parsing, OSV query, reporting)
- `src/cli/catseye.nim` — integrate SCA scan into main pipeline

**Notes:**
- OSV supports `crystal-shards` and `hex` (Erlang/Gleam) ecosystems
- Should be opt-in via `--sca` flag or config `[sca] enabled = true`
- Cache OSV results locally for offline/repeat scans
- Rate-limit queries (batch multiple deps per request)
