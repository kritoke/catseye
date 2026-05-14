# Catseye

**Static security analysis for Crystal and Gleam.**

> ⚠️ **Highly experimental.** Expect breakage, false positives, and frequent API changes until the project stabilizes. Not ready for production use.

## Requirements

- **OCaml** 5.x + **Dune** 3.x
- **Crystal** 1.x (needed for the Crystal language extractor)
- **tree-sitter** + tree-sitter-gleam grammar (needed for Gleam parsing)
- **just** (task runner)
- OCaml libs: yojson, cmdliner, bos, rresult, logs, fmt, toml, kdl, ocamlgraph

The easiest way to get all of these is `nix develop` (see [flake.nix](flake.nix) for the full dev shell). But you can install them however you want.

## Quick Start

```bash
# With Nix (handles all dependencies)
nix develop

# Build
just build

# Scan a project
just scan path/to/project/src

# Scan with all checks
just scan-full path/to/project/src

# JSON output
just scan-json path/to/project/src

# Run tests
just test
```

## CLI Reference

```
catseye [options] <directory>

  -f, --format <fmt>       terminal (default), json, sarif, markdown, dot
  -o, --output <path>      write results to file
  -r, --rules <path>       rules directory (default: rules/)
  --lang <lang>            all (default), crystal, gleam
  --no-color               disable colored output
  --no-cache               disable extraction cache
  --clear-cache            clear cache and run full scan
  --cache-dir <path>       cache directory (default: .catseye)
  --predator-vision        enable reachability analysis (live/dormant/safe)
  --crows-nest             enable supply chain audit (CVE + staleness)
  --claws                  enable code smell detection
  --ai-lint                enable AI antipattern detection
  -p, --parallelism <n>    parallel workers (0 = auto)
  -v, --version            show version
  -h, --help               show help
```

## What It Detects

### Security Rules (taint-based)

| Rule | Severity | What it catches |
|------|----------|-----------------|
| **SSRF** | Critical | HTTP client calls with user-controlled URLs |
| **CommandInjection** | Critical | `system`/`exec`/`Process.run` with tainted input |
| **PathTraversal** | High | File I/O with user-controlled paths |
| **SQLInjection** | Critical | SQL queries with tainted arguments |
| **OpenRedirect** | Medium | Redirect handlers with unvalidated URLs |
| **EnvInjection** | High | Environment variable manipulation |
| **LDAPInjection** | High | LDAP queries with user input |
| **ScentLeakage** | High | Sensitive data leaked to logs/output |
| **ReDoS** | Medium | Regex patterns with catastrophic backtracking |
| **WeakCryptography** | Medium | MD5/SHA1 usage |
| **MissingTimeout** | Medium | HTTP clients without timeouts |
| **HardcodedSecrets** | Medium | Hardcoded API keys, tokens, passwords |

Rules are KDL files in `src/ocaml/rules/` — add your own by creating a `.kdl` file.

### AI Antipattern Detection (`--ai-lint`)

Catches patterns common in AI-generated code: hallucinated method calls, hardcoded secrets, non-idiomatic constructs.

| Rule | Languages | What it catches |
|------|-----------|-----------------|
| `hallucinated-stdlib` | Crystal | Calls to methods that don't exist (37-entry database) |
| `hardcoded-secrets` | Both | API key patterns (Stripe, GitHub, AWS, JWT, Slack) |
| `hardcoded-urls` | Crystal | Hardcoded http:// and IP addresses |
| `deprecated-syntax` | Crystal | `puts`, `p`, `pp` in production code |
| `primitive-obsession` | Crystal | Functions with 3+ parameters |
| `redundant-conversion` | Crystal | Unnecessary type conversions |
| `panic-call` | Gleam | `panic` used instead of `Result` |
| `list-wrap-unnecessary` | Gleam | `List.wrap` on collections |

### Code Smells (`--claws`)

| Detector | Threshold |
|----------|-----------|
| Cyclomatic complexity | M ≥ 10 |
| Long parameter list | ≥ 5 params |
| Deep nesting | ≥ 4 levels |
| God objects | ≥ 20 definitions per file |

### Supply Chain Audit (`--crows-nest`)

CVE scanning via [OSV.dev](https://osv.dev) and staleness detection for Crystal Shards and Gleam Hex packages. Results cached in SQLite (24h TTL).

## Example Output

```
  Catseye v0.4.0
  Target:   ./src
  Files:    66 Crystal, 0 Gleam

  → Running analysis engine (5507 nodes)...

  🔴 Error  SSRF  src/controllers/proxy_controller.cr:32
       Potential SSRF via HTTP::Client.get with tainted argument(s): url.
      ← Source: params (proxy_controller.cr:28)

  🔴 Error  PathTraversal  src/controllers/asset_controller.cr:17
       Potential path traversal via File.read with variable argument(s): path.
      ← Source: params (asset_controller.cr:15)

  Found 2 Error(s), 0 Warning(s) across 66 files.
  Review the findings above.
```

## How It Works

```
Source files
    │
    ├─ Crystal (.cr) ──→ Crystal extractor (AST → JSON)
    │
    └─ Gleam (.gleam) ─→ tree-sitter (AST → XML → JSON)
                            │
                            ▼
                    Security Node JSON
                            │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         Taint Engine    AI Linter      Code Smells
         (KDL rules)    (AST rules)    (complexity, etc.)
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                     Terminal / JSON / SARIF / Markdown / DOT
```

**Taint pipeline:** seed → propagate → returns → interproc → guards → rules

1. **Seed** — Params named like taint sources (`url`, `request`, `params`) are marked tainted
2. **Propagate** — Fixed-point; taint flows through assignments and call chains
3. **Returns** — Functions with tainted bodies return tainted data
4. **Inter-procedural** — Taint crosses function boundaries
5. **Guards** — `unless path.starts_with?("/safe/")` suppresses taint
6. **Rules** — KDL rules match sinks against tainted variables

### Adding a Security Rule

Create `src/ocaml/rules/my_rule.kdl`:

```kdl
rule "MyRule" severity="Medium" {
    sinks {
        sink "Dangerous.call" {
            sanitizer "Safe.wrapper"
        }
    }
    sources {
        source "params"
        source "url"
    }
    message "My rule: {sink} with tainted argument(s): {tainted_vars}."
}
```

Rebuild with `just build` and test.

## Configuration

Optional `.catseye.toml` in your project root:

```toml
[scan]
exclude = ["node_modules", ".git", "vendor", "spec"]

[analysis]
extra_sources = ["user_input", "raw_params"]
extra_sanitizers = ["sanitize_path", "escape_shell"]
parallelism = 4

[claws]
complexity_warning = 10
max_params = 5
```

## Justfile Recipes

```
just build               Build the engine
just test                Unit tests + E2E
just scan <dir>          Scan with terminal output
just scan-full <dir>     Scan with all checks enabled
just scan-json <dir>     Scan with JSON output
just scan-ai <dir>       AI antipattern detection only
just scan-reports <dir>  Generate JSON + SARIF + Markdown reports
just fmt                 Format OCaml code
just lint                Check formatting
just clean               Clean build artifacts
just extract <file>      Run Crystal extractor on a single file (debug)
```

## Project Structure

```
catseye/
├── src/
│   ├── ocaml/
│   │   ├── bin/main.ml                 # CLI entry point
│   │   ├── lib/
│   │   │   ├── catseye_engine/          # Taint analysis
│   │   │   ├── catseye_ast/             # Unified AST + mappers
│   │   │   ├── ai_linter/              # AI antipattern rules
│   │   │   ├── catseye_claws/           # Code smell detection
│   │   │   ├── catseye_crowsnest/       # Supply chain audit
│   │   │   ├── catseye_rules/           # KDL rule interpreter
│   │   │   ├── catseye_cli/             # CLI, orchestrator, output formats
│   │   │   └── catseye_types/           # Shared types
│   │   └── rules/                       # 12 KDL rule files
│   └── extractor/extractor.cr           # Crystal AST extractor
├── test/samples/                        # Test corpus
├── .github/workflows/                   # CI
├── flake.nix                            # Nix dev shell
└── justfile                             # Build tasks
```

## Performance

| Scan | Extraction | Analysis |
|------|-----------|----------|
| 66-file Crystal (cold) | ~0.12s | ~0.06s |
| 66-file Crystal (cached) | ~0.02s | ~0.06s |

## License

MIT
