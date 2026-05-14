# Predator Vision — Reachability-First Analysis

**Status:** Phase 0 ✅ Phase 1 ✅ Phase 2 ✅ — Phase 3 (stretch) remaining
**Target:** OCaml rewrite (`src/ocaml/`)
**Depends on:** Hunter persona terminal output (planning/hunter-persona.md)

---

## The Problem

Static scanners produce noise. A SQL injection in a utility function that's only called from internal test scripts is flagged identically to one that's hit by every HTTP endpoint. Developers learn to ignore findings — "the scanner cried wolf again."

**Reachability changes everything.** A vulnerability that a user can actually reach from an internet-facing endpoint is *orders of magnitude more dangerous* than one buried in an internal codepath. Predator Vision makes this distinction visible at a glance.

---

## What "Reachability" Means Here

We're not building a full call graph or doing type-level analysis. That's a research project. Instead, we use what Catseye already has — the taint engine — and extend it with a lightweight "entry point" concept:

```
Entry Point (HTTP handler, CLI main, test harness)
  │
  ├── reachable → tainted code → sink    = 🔴 LIVE PREY (reachable vuln)
  ├── reachable → tainted code → sanitized = ✅ (handled)
  │
  └── unreachable → tainted code → sink  = 🟡 SLEEPING PREY (unreachable, but real)
```

An entry point is any function that receives data from outside the program:
- Crystal: methods that take `HTTP::Request` or `HTTP::Server::Context` params
- Gleam: functions taking `gleam/http/request.Request` or `mist.Request`
- CLI: `main` / `ARGV`-reading functions
- Config: `[predator_vision] entry_point_patterns = ["handle_*", "MyController.*"]`

---

## The Heatmap

The terminal output gets a new "Predator Vision" section — an attack surface heatmap:

```
  🔴 PREDATOR VISION — Attack Surface Heatmap

  src/controllers/user_controller.cr
    ████████████████░░░░  4/5 sinks reachable
    ├── 🔴 LIVE   [SQLInjection]      :78   db.query(tainted)
    ├── 🔴 LIVE   [PathTraversal]     :112  File.read(tainted)
    ├── 🔴 LIVE   [CommandInjection]  :134  Process.run(tainted)
    ├── ✅ SAFE   [SQLInjection]      :156  db.query(URI.parse(tainted))
    └── 🟡 DORMANT [SSRF]             :189  HTTP::Client.get(url)
         ↑ Sink exists but not reachable from entry points

  src/lib/helpers.cr
    ██████░░░░░░░░░░░░░░  1/3 sinks reachable
    ├── 🟡 DORMANT [CommandInjection]  :22   system(cmd)
    ├── 🟡 DORMANT [CommandInjection]  :45   system(cmd)
    └── 🔴 LIVE   [CommandInjection]  :67   system(cmd)
         ↑ Reachable via handle_request → build_cmd → system

  ────────────────────────────────────────
  5 LIVE PREY  •  3 DORMANT  •  2 SAFE
  71% of sinks are reachable from entry points
```

### Heatmap bar

The `████████████████░░░░` bar shows the ratio at a glance:
- Full red bar = all sinks reachable (dangerous file)
- Half bar = mixed
- Nearly empty = most sinks are dormant (low priority)

### Finding categories

| Category    | Icon  | Meaning                                              | Exit code |
|-------------|-------|------------------------------------------------------|-----------|
| **Live**    | 🔴    | Taint reaches sink AND path from entry point exists  | 1         |
| **Dormant** | 🟡    | Taint reaches sink, but no entry point path found    | 0         |
| **Safe**    | ✅    | Sink called but taint is sanitized                   | 0         |

### JSON/SARIF extension

In `--format json`, each finding gets a `reachability` field:

```json
{
  "rule": "SQLInjection",
  "severity": "high",
  "reachability": {
    "status": "live",
    "entry_point": "src/controllers/user_controller.cr:12",
    "entry_function": "handle_create",
    "path_length": 3,
    "path": [
      {"file": "user_controller.cr", "line": 12, "function": "handle_create"},
      {"file": "user_controller.cr", "line": 34, "function": "process_input"},
      {"file": "user_controller.cr", "line": 78, "function": "save_user"}
    ]
  }
}
```

In `--format sarif`, the reachability path becomes additional `threadFlows` in the existing `codeFlows` structure — no schema change needed.

---

## Implementation Plan

### Phase 0: Entry Point Detection (engine layer)

**Files:** New module `src/ocaml/lib/catseye_engine/reachability.ml`

- [x] Define `entry_point` type with `function_name`, `file`, `line`, `kind` — `reachability.ml`
- [x] Auto-detect entry points from `Security_node.t` list (Crystal HTTP params, Gleam Request, CLI main/ARGV)
- [x] Build lightweight call adjacency map from `Call` nodes inside `Def` scopes — `call_adjacency` type
- [x] BFS from entry points through call adjacency — `reachable_from` function
- [x] Tag each finding with reachability status (`Live`/`Dormant`/`Safe`) — `analyze` function

### Phase 1: Heatmap Formatter (CLI layer)

**Files:** New module `src/ocaml/lib/catseye_cli/heatmap.ml`

- [x] Group findings by file — `group_by_file` in `heatmap.ml`
- [x] Compute per-file heatmap bars (ratio of live/total) — `heatmap_bar` function
- [x] Format heatmap with ANSI colors + Live/Dormant/Safe icons — `print_heatmap`
- [x] Integrate into `orchestrator.ml` after analysis, before finding output (Terminal + `--predator-vision` only)
- [x] `--predator-vision` / `-pv` flag in `args.ml`
- [x] `[predator_vision] enabled = true` in `config.ml` via `load_toml`

### Phase 2: Reachability in Structured Output

- [x] `Finding.t` extended with `reachability` field (`reachability_status`, `entry_point`, `entry_function`, `path_length`, `path`) — `finding.ml`
- [x] `Finding.encode` / `decode` include reachability when present — `finding.ml`
- [x] `Sarif.to_sarif` includes reachability path as additional `codeFlow` + `properties.reachability` — `sarif.ml`
- [x] `Markdown.to_markdown` includes reachability label + entry point path — `markdown.ml`
- [x] JSON output: reachability included per-finding via `encode_reachability`

### Phase 3: Smarter Reachability (future)

- [ ] **Weighted heat**: Not all entry points are equal. An unauthenticated endpoint is hotter than an admin-only one. Config-driven weights.
- [ ] **Delta heatmaps**: `--watch` mode that highlights newly reachable paths when code changes
- [x] **Call graph export**: `--format dot` exports the call adjacency as a Graphviz DOT file — `dot.ml`

---

## What This Is NOT

- This is **not** a full call graph construction. We build a lightweight adjacency map from `Call` nodes inside `Def` scopes — best-effort, no type resolution.
- This is **not** sound. Dynamic dispatch, reflection, and callbacks may create false "dormant" classifications. Better to under-report reachability than over-report it.
- This does **not** replace severity. A "Dormant" Critical finding is still Critical — it's just not immediately exploitable. The heatmap adds *prioritization*, not *downgrading*.

---

## Design Principles

1. **Reachable first, dormant second.** The heatmap puts live findings at the top. Developers should fix those first.
2. **Never suppress.** Dormant findings are still shown — just deprioritized. A dormant SQL injection is still a SQL injection.
3. **Best-effort is good enough.** We're not building an academic tool. If 80% of reachability is correct, that's a massive improvement over 0% (what every other lightweight scanner gives you).
4. **Terminal-first.** The heatmap is the feature. JSON/SARIF get the data, but the visual heatmap is what makes developers say "oh, that's actually useful."
5. **Configurable entry points.** Auto-detection covers common frameworks. `entry_point_patterns` in `.catseye.toml` covers everything else.

---

## Relationship to Existing Engine

| Component | Current Role | Predator Vision Addition |
|-----------|-------------|--------------------------|
| `Security_node.t` | AST node with `node_type`, `name`, `args`, `file`, `line` | No changes — entry points detected from existing `Def` nodes |
| `Db.t` (TaintDB) | Tracks tainted variables per file | No changes — reachability is orthogonal to taint |
| `engine.ml` | `build_taint_db` → `analyze` → findings | Add `reachability.ml` call after `analyze`, before output |
| `dag.ml` | Builds vulnerability DAG from sink to sources | No changes — DAG traces taint, reachability traces call paths |
| `interpreter.ml` | Matches rules against tainted nodes | No changes — reachability tags are applied after rule matching |
| `orchestrator.ml` | Runs pipeline, formats output | Add heatmap formatting + reachability flag |
| `Finding.t` | Rule result with flow | Add optional `reachability` field |
