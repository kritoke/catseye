# Catseye — Project Status

**Last updated:** 2026-05-07
**Repo:** github.com/kritoke/catseye
**Commits:** 17 on main

## Architecture

```
Crystal (.cr) ──→ Crystal AST Extractor ──→ Security Node JSON
                                                  ↓
Gleam (.gleam) ─→ Nim + tree-sitter XML ──→ Security Node JSON ──→ Gleam/BEAM Engine ──→ Findings JSON
                                                                                              ↓
                                                                           Nim CLI (terminal / JSON / SARIF)
```

| Component | Language | Purpose |
|-----------|----------|---------|
| CLI | Nim 2.2 | File discovery, orchestration, output formatting |
| Crystal Extractor | Crystal 1.18 | AST parsing via Crystal::Parser, taint seeding |
| Gleam Extractor | Nim + tree-sitter | XML CST parsing of .gleam files |
| Logic Engine | Gleam/Erlang | Taint propagation, vulnerability rules |
| Nix Flake | Nix | Reproducible dev shell with all toolchains |

## Completed Features

### Extractors
- [x] Crystal extractor — `Crystal::Parser` + `Crystal::Visitor`, full taint seeding
- [x] Gleam extractor — tree-sitter XML CST, accurate node extraction
- [x] File dispatch in CLI — `.cr` → Crystal, `.gleam` → Gleam
- [x] Crystal string interpolation fix — only tainted if interpolated expr is tainted

### Logic Engine
- [x] Modular rules — one file per rule in `catseye/rules/`
- [x] 4 vulnerability rules: SSRF, CommandInjection, PathTraversal, SQLInjection
- [x] Hand-rolled JSON parser in Erlang FFI (zero deps)
- [x] `db.exec` / `db.query` whitelist (eliminates Crystal DB false positives)
- [x] Gleam/Erlang patterns: hackney, req, httpc, os.command, simplifile

### Taint Analysis Engine (v2)
- [x] Multi-hop assignment propagation: `request → a → b → c`
- [x] Source seeding: function params + extractor-flagged assigns
- [x] Fixed-point iteration until no new taint found
- [x] **Sanitizer recognition** — URI.parse, Path.*, String.*, encode.*, escape.* clear taint
- [x] **Return value tracking** — functions returning tainted data marked as tainted
- [x] **Inter-procedural propagation** — `url = get_url(params)` → url is tainted
- [x] Flow tracing: source → propagation → sink chain per finding
- [x] **Field-sensitive tracking** — `is_tainted_field(db, var, field)` for per-field taint
- [x] **Scope-aware analysis** — def nodes create scope boundaries via `next_def_line()`
- [x] **Sanitized propagation** — assigns from sanitizer calls don't propagate taint
- [x] **Config-driven sources** — `build_taint_db_with_config()` for project-specific sources/sanitizers
- [x] 33 unit tests

### CLI Output Formats
- [x] Terminal — colored, human-readable with flow arrows (← source, ↓ sink)
- [x] JSON (`--format json`) — machine-readable for CI
- [x] SARIF v2.1.0 (`--format sarif`) — GitHub Code Scanning compatible
- [x] **SARIF codeFlows** — threadFlow with source→sink locations per finding

### Configuration
- [x] `.catseye.toml` config file — auto-discovered by walking up from target
- [x] `[taint]` section: `extra_sources`, `extra_sinks`, `extra_sanitizers`
- [x] `--config` flag for explicit config path
- [x] **Full config bridge** — Nim CLI → JSON → Erlang FFI → Gleam engine

### Testing & CI
- [x] 33 engine unit tests (custom runner, no eunit)
- [x] Test samples: vulnerable.cr, vulnerable.gleam, safe.cr, safe.gleam
- [x] Linting: `gleam format`, `ameba`, `nim check`
- [x] E2E pipeline verified
- [x] GitHub Actions CI workflow (`.github/workflows/scan.yml`)

### Infrastructure
- [x] Nix flake — Nim 2.2.4, Crystal 1.18.2, Gleam 1.16.0, Erlang 28, tree-sitter 0.26.8
- [x] Justfile for build/dev tasks
- [x] Scan scripts: `scripts/scan_gleam.sh`, `scripts/scan_crystal.sh`

## Real-World Scan Results

| Target | Language | Files | Nodes | Findings | Notes |
|--------|----------|-------|-------|----------|-------|
| facet_pi | Gleam | 36 | 3,001 | 0 | Client-side app, no vuln sinks |
| quickheadlines/src | Crystal | 66 | 5,337 | 1 | PathTraversal in favicon_cache.cr (real) |
| test/samples | Both | 4 | 41 | 6 | 4 SSRF + 2 CmdInjection |

## Known Limitations

| Limitation | Description |
|------------|-------------|
| No file-level scope isolation | Variables with same name in different files share taint namespace |
| Sanitizer only suppresses direct args | `f(URI.parse(x))` suppressed, but `y = URI.parse(x); f(y)` still flagged |
| No conditional analysis | `if x != "" then use x` doesn't reduce taint |
| Field-sensitive is read-only API | `is_tainted_field` exists but extractors don't emit field-level taint yet |
| No call graph | Inter-procedural is limited to direct function name matching |

## Next Steps

### Short-term
- [ ] Extractor field-level taint (Crystal: `params["url"]` → field="url")
- [ ] File-level scope isolation (namespace vars by file)
- [ ] Conditional taint: `if validator.is_valid(x)` → clear taint on true branch

### Medium-term
- [ ] Language extractors: Ruby, Python, Elixir
- [ ] HTML template injection rule
- [ ] Insecure dependency checker (cross-reference with OSV/CVE)
- [ ] IDE integration (LSP diagnostics)

### Long-term
- [ ] Whole-program inter-procedural analysis
- [ ] Call graph construction
- [ ] Dataflow graph visualization
- [ ] Custom rule DSL for project-specific checks
