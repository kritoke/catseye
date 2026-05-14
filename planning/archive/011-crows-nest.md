# The Crow's Nest — Deep Supply Chain Tracking

**Status:** Phase 0 ✅ Phase 1 ✅ Phase 2 ✅ Phase 3 ✅ Phase 4 ✅ Phase 5 ✅
**Target:** OCaml rewrite (`src/ocaml/`)
**Depends on:** Hunter persona terminal output (planning/hunter-persona.md)

---

## The Problem

Most SCA (Software Composition Analysis) tools do one thing: check your dependencies against a CVE database. That's useful but shallow. They don't tell you:

- **Is this dependency actually end-of-life?** A package with no maintainer is a vulnerability even without a CVE.
- **When was the last patch?** A dependency that hasn't been updated in 2 years is a ticking bomb.
- **Is the dependency reachable?** A vulnerable package in `lib/` that nothing imports is noise.
- **What's the transitive chain?** Your direct deps are fine, but their deps might be abandoned.

The Crow's Nest does all of this. It audits Crystal Shards and Gleam hex packages for:
1. Known CVEs (via OSV.dev API)
2. End-of-life / abandoned maintenance detection
3. Last-patch staleness
4. Reachability from your code (reuses Predator Vision's adjacency map)

---

## Why "Crow's Nest"

The crow's nest is the highest lookout point on a ship — the first to see what's coming. For Catseye, it's the module that watches your supply chain from above, spotting dangerous dependencies before they become incidents.

---

## Terminal Output

### Scan with Crow's Nest enabled (`--crows-nest`)

```
  🏴‍☠️ CROW'S NEST — Supply Chain Audit

  ┌─ Crystal Shards (shard.yml) ──────────────────────────────┐
  │                                                           │
  │  ameba        1.6.1     ✅ Purr   Active, no known CVEs   │
  │  kemal        1.1.2     🐱⚡ Hiss  CVE-2025-0471 RCE      │
  │  lucky        1.3.0     🐾 Meow   Last patch: 14 months   │
  │  crest        0.3.0     🐾 Meow   No release in 18 months │
  │  db           0.13.1    ✅ Purr   Active, no known CVEs   │
  │                                                           │
  └───────────────────────────────────────────────────────────┘

  ┌─ Gleam Hex Packages (gleam.toml) ────────────────────────┐
  │                                                           │
  │  gleam_http   3.7.1     ✅ Purr   Active, no known CVEs   │
  │  mist         4.0.0     ✅ Purr   Active, no known CVEs   │
  │  wisp         1.3.0     🐾 Meow   Last patch: 8 months    │
  │                                                           │
  └───────────────────────────────────────────────────────────┘

  ────────────────────────────────────────
  1 Hiss  •  3 Meow  •  4 Purr

  🐱⚡ kemal 1.1.2 — CVE-2025-0471
     Remote code execution via crafted Content-Type header
     Upgrade to kemal 1.1.5 or later
     https://osv.dev/vulnerability/CVE-2025-0471

  🐾 lucky 1.3.0 — Last patched 14 months ago
     No maintainer activity detected. Consider alternatives.
  🐾 crest 0.3.0 — No release in 18 months
     Potentially abandoned. Audit for alternatives.
  🐾 wisp  1.3.0 — Last patched 8 months ago
     Monitor for updates. Not critical yet.
```

### Reachability-Enhanced Output (with `--predator-vision` + `--crows-nest`)

```
  🐱⚡ kemal 1.1.2 — CVE-2025-0471
     Remote code execution via crafted Content-Type header
     Upgrade to kemal 1.1.5 or later
     📍 Reachable from: handle_request → Kemal::RouteHandler
        This is a LIVE dependency — the vulnerability is exploitable.
```

vs.

```
  🐾 crest 0.3.0 — No release in 18 months
     Potentially abandoned. Audit for alternatives.
     📍 Not reachable from any entry point
        Safe to defer, but plan removal.
```

---

## Data Sources

### 1. OSV.dev API — Known CVEs

Free, open, no API key required. Supports both Crystal Shards and Hex ecosystems.

```
POST https://api.osv.dev/v1/query
{
  "package": {"name": "kemal", "ecosystem": "crystal-shards"},
  "version": "1.1.2"
}
```

Response includes: CVE ID, severity (CVSS), summary, patched versions, references.

OCaml implementation using `curl` subprocess (no HTTP client dependency needed):

```ocaml
let query_osv (package : string) (ecosystem : string) (version : string)
    : osv_vulnerability list option =
  let json = Printf.sprintf
    {|{"package":{"name":"%s","ecosystem":"%s"},"version":"%s"}|}
    package ecosystem version
  in
  let cmd = Printf.sprintf
    "curl -s -X POST https://api.osv.dev/v1/query -d '%s'" json
  in
  (* parse response, extract vulnerabilities *)
```

**Alternative**: Use `cohttp` or `eio` for in-process HTTP. The subprocess approach is simpler and has zero new dependencies, which aligns with the "local hardware, minimal deps" philosophy.

### 2. Shard Registry — Crystal Shards

Crystal's shard registry (https://crystal-shards.org) and GitHub repos provide:
- Release dates (tags on GitHub)
- Commit activity (last commit date)
- Maintainer count
- Open issue/PR counts (staleness signal)

Detection: Parse `shard.yml` for dependency names and versions.

```yaml
# shard.yml
dependencies:
  kemal:
    github: kemalcr/kemal
    version: 1.1.2
```

### 3. Hex API — Gleam Packages

Gleam uses the Hex package manager (https://hex.pm/api).

```
GET https://hex.pm/api/packages/gleam_http
```

Response includes: release dates, retirement status, maintainers.

Detection: Parse `gleam.toml` for dependency names and versions.

```toml
# gleam.toml
[dependencies]
gleam_http = { version = "~> 3.7" }
mist = { version = "~> 4.0" }
```

### 4. Staleness Heuristics — End-of-Life Detection

No single signal means "abandoned." The Crow's Nest uses a composite score:

| Signal                    | Weight | Source                    |
|---------------------------|--------|---------------------------|
| No release in 12+ months  | +3     | GitHub tags / Hex releases |
| No commits in 6+ months   | +2     | GitHub API                |
| Open issues > 50          | +1     | GitHub API                |
| Open PRs > 10             | +1     | GitHub API                |
| README says "deprecated"  | +5     | README scan               |
| Hex "retired" status      | +5     | Hex API                   |

Scoring:
- 0-2: `Purr` (healthy)
- 3-5: `Meow` (watch)
- 6+: `Hiss` (likely abandoned)

---

## Implementation Plan

### Phase 0: Manifest Parsing

**Files:** New module `src/ocaml/lib/catseye_crowsnest/manifest.ml`

- [x] Parse `shard.yml` — `Manifest.Shard_dep` type + `parse_shard_yml` in `manifest.ml`
- [x] Parse `gleam.toml` — `Manifest.Hex_dep` type + `parse_gleam_toml` using existing `Toml` parser
- [x] Auto-detect manifests recursively — `find_manifests_recursive` (Shard_yml / Gleam_toml variants)

### Phase 1: OSV.dev Query Engine

**Files:** New module `src/ocaml/lib/catseye_crowsnest/osv.ml`

- [x] Query OSV.dev API for a single package — `Osv.query` with `osv_vulnerability` type in `osv.ml`
- [x] Batch queries — `query_batch` support
- [x] Local cache in `.catseye/crowsnest.db` (SQLite) — `Cache.open_db` / `Cache.close` in `cache.ml`, 24h TTL
- [x] Graceful offline fallback — cached results used when OSV unreachable, warning printed

### Phase 2: Staleness Engine

**Files:** New module `src/ocaml/lib/catseye_crowsnest/staleness.ml`

- [x] GitHub API query for repository activity — `Staleness.query_github` with `repo_activity` type
- [x] Hex API query for Gleam package retirement — `Staleness.query_hex` with `hex_package_info` type
- [x] Compute staleness score — `compute_staleness` with composite scoring + `Purr`/`Meow`/`Hiss` levels
- [x] Cache staleness results (24h TTL, same SQLite DB via `cache.ml`)

### Phase 3: Reachability Integration

**Files:** `src/ocaml/lib/catseye_crowsnest/dep_reachability.ml`, `orchestrator.ml`

- [x] Map dependency names to import sites — Crystal `require` + Gleam `import` parsing
- [x] Stdlib filtering — Crystal and Gleam standard library modules excluded
- [x] Cross-reference with Predator Vision call adjacency map for dep reachability
- [x] `enrich_with_reachability` — attaches reachability verdict to each dep result
- [x] Only runs when both `--crows-nest` and `--predator-vision` are enabled
- [x] Uses `StringSet` of reachable files from Predator Vision analysis

### Phase 4: CLI Integration

**Files:** `src/ocaml/lib/catseye_cli/orchestrator.ml`, `args.ml`, `config.ml`

- [x] `--crows-nest` / `-cn` flag in `args.ml`
- [x] `[crows_nest]` section support in `config.ml` via `load_toml`
- [x] Crow's Nest section in `orchestrator.ml` `run` — parses manifests, queries OSV + staleness, formats output
- [x] `crowsnest_format.ml` — terminal formatter with boxed sections per manifest
- [x] Exit code: 1 if any `Hiss` (CVE found), 0 otherwise

### Phase 5: Structured Output

- [x] JSON: `supply_chain` top-level field with dependencies + OSV + staleness + summary — `orchestrator.ml`
- [x] SARIF: Dependency vulnerabilities as additional results with `ruleId = "SCA/<CVE-ID>"` + `properties.supplyChain` — `sarif.ml`
- [x] Markdown: Supply chain section with dependency audit table — `markdown.ml`

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Crow's Nest Module                           │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │ Manifest     │   │ OSV Query    │   │ Staleness Engine       │  │
│  │ Parser       │   │ Engine       │   │                        │  │
│  │              │   │              │   │  GitHub API ─────────┐ │  │
│  │ shard.yml    │──▶│ OSV.dev API  │   │  Hex API      ──────┤│ │  │
│  │ gleam.toml   │   │ (batch)      │   │  Composite score  ◀──┘│ │  │
│  └──────────────┘   └──────┬───────┘   └──────────┬────────────┘  │
│                            │                       │               │
│                     ┌──────▼───────────────────────▼──────┐        │
│                     │        Result Aggregator            │        │
│                     │                                     │        │
│                     │  CVE + Staleness + Reachability     │        │
│                     │  → Hiss / Meow / Purr per dep       │        │
│                     └──────────────┬──────────────────────┘        │
│                                    │                                │
│                     ┌──────────────▼──────────────────────┐        │
│                     │  Local Cache (.catseye/crowsnest.db)│        │
│                     │  SQLite, 24h TTL, offline fallback  │        │
│                     └──────────────┬──────────────────────┘        │
└────────────────────────────────────┼──────────────────────────────┘
                                     │
                                     ▼
                          Terminal / JSON / SARIF
```

---

## New Files Summary

| File | Purpose |
|------|---------|
| `lib/catseye_crowsnest/manifest.ml` | Parse `shard.yml` and `gleam.toml` |
| `lib/catseye_crowsnest/osv.ml` | OSV.dev API client with caching |
| `lib/catseye_crowsnest/staleness.ml` | GitHub/Hex activity + composite score |
| `lib/catseye_crowsnest/reachability.ml` | Dep reachability via Predator Vision adjacency |
| `lib/catseye_crowsnest/aggregator.ml` | Merge CVE + staleness + reachability → per-dep result |
| `lib/catseye_crowsnest/cache.ml` | SQLite cache layer for OSV + staleness queries |
| `lib/catseye_cli/crowsnest_format.ml` | Terminal heatmap formatting for Crow's Nest |
| `rules/sca.kdl` | SCA rule definitions (thresholds, ecosystems) |

---

## Design Principles

1. **Network is optional.** The Crow's Nest should work offline with cached data. Network failures degrade gracefully — a warning, not a crash.
2. **Cache aggressively.** Dependency vulnerability data changes slowly. A 24-hour cache is fine. Don't hammer APIs.
3. **Signal, not noise.** Only surface actionable findings. "This dep has a CVE and you're using it" is actionable. "This dep has 12 open issues" is noise unless combined with other staleness signals.
4. **No API keys required.** Works out of the box with public APIs. `GITHUB_TOKEN` is optional for higher rate limits.
5. **Reachability doubles the value.** A vulnerable dep that nothing imports is informational. A vulnerable dep that's on your hot path is critical. The combination with Predator Vision is what makes this unique.
6. **Crystal + Gleam first, extensible later.** Start with the two ecosystems Catseye already supports. The architecture is generic enough to add `npm`, `pypi`, `rubygems` later via new manifest parsers.

---

## Relationship to Other Hunter Features

| Feature | Connection |
|---------|-----------|
| **Hunter Persona** | Crow's Nest uses the same Hiss/Meow/Purr severity levels in terminal output |
| **Predator Vision** | Dep reachability reuses the call adjacency map from Predator Vision |
| **Taint Engine** | Orthogonal — SCA runs independently of taint analysis, but results are merged in the same output |
| **KDL Rules** | Future: `rules/sca.kdl` defines staleness thresholds and CVE severity mappings |
