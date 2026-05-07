# Catseye — Project Status

**Last updated:** 2025-05-07
**Repo:** github.com/kritoke/catseye
**Commits:** 13 on main

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
- [x] 25 unit tests (5 taint, 3 sanitizer, 1 interprocedural, 16 rule/integration)

### CLI Output Formats
- [x] Terminal — colored, human-readable
- [x] JSON (`--format json`) — machine-readable for CI
- [x] SARIF v2.1.0 (`--format sarif`) — GitHub Code Scanning compatible

### Testing & CI
- [x] 25 engine unit tests (custom runner, no eunit)
- [x] Test samples: vulnerable.cr, vulnerable.gleam, safe.cr, safe.gleam
- [x] Linting: `gleam format`, `ameba`, `nim check`
- [x] E2E pipeline verified

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
| No field-sensitive tracking | `req.params` vs `req.method` not distinguished |
| Scope is file-level | Def nodes don't create real scopes — body assigns can leak across functions |
| Sanitizer list is static | No way to configure custom sanitizers per project |
| No conditional analysis | `if x != "" then use x` doesn't reduce taint |
| SARIF missing codeFlows | Flow data in engine JSON but not yet in SARIF threadFlow format |
| Extractor taint is string-match | Crystal extractor uses `TAINT_SOURCES` set, not semantic analysis |

## Next Steps

### Short-term (next sprint)
- [ ] Add SARIF `codeFlows` with `threadFlow` locations
- [ ] Field-sensitive taint: track `req.params` separately from `req.method`
- [ ] Crystal extractor: reduce string interpolation false positives
- [ ] Configurable sanitizer/sink/source lists via config file
- [ ] CI integration: GitHub Actions workflow with `--format sarif`

### Medium-term
- [ ] Language extractors: Ruby, Python, Elixir
- [ ] Conditional taint refinement (path-sensitive)
- [ ] HTML template injection rule
- [ ] Insecure dependency checker (cross-reference with OSV/CVE)
- [ ] IDE integration (LSP diagnostics)

### Long-term
- [ ] Whole-program inter-procedural analysis
- [ ] Call graph construction
- [ ] Dataflow graph visualization
- [ ] Custom rule DSL for project-specific checks
