# Catseye

**Static security analysis for Crystal and Gleam applications.**

> ⚠️ **Highly experimental.** Expect breakage, false positives, and frequent API changes until the project stabilizes. Not ready for production use.

Catseye finds vulnerabilities like SSRF, command injection, path traversal, and more by combining AST-based extraction with taint tracking and pattern-matching rules. It also detects code smells (complexity, god objects, DRY violations) and performs supply chain audits via OSV.dev.

## Quick Start

```bash
# Enter dev shell (requires nix)
nix develop

# Build
just build

# Scan a project
just scan path/to/project/src

# Scan with all analysis passes
just scan-hunter path/to/project/src

# JSON output
just scan-json path/to/project/src
```

## Usage

```
catseye [options] <directory>

Options:
  -h, --help             Show help
  -v, --version          Show version
  -f, --format <fmt>     Output: terminal (default), json, sarif, markdown, dot
  -o, --output <path>    Write results to file
  -r, --rules <path>     Rules directory (default: rules/)
  --lang <lang>          Language filter: all (default), crystal, gleam
  --no-color             Disable colored output
  --no-cache             Disable extraction cache
  --clear-cache          Clear cache and run full scan
  --cache-dir <path>     Cache directory (default: .catseye)
  --predator-vision      Enable reachability heatmap
  --crows-nest           Enable supply chain audit (CVE + staleness)
  --claws                Enable code smell & DRY detection
  --ai-lint              Enable AI antipattern detection (Gleam & Crystal)
  -p, --parallelism <n>  Parallel workers (0 = auto)
```

## Detection Rules

### Security (Taint-based)

| Rule | Severity | Description |
|------|----------|-------------|
| **SSRF** | Critical | HTTP client calls with user-controlled URLs |
| **CommandInjection** | Critical | `system`/`exec`/`Process.run` with tainted input |
| **PathTraversal** | High | File I/O with user-controlled paths |
| **SQLInjection** | Critical | SQL queries with tainted arguments |
| **OpenRedirect** | Medium | Redirect handlers with unvalidated URLs |
| **HardcodedSecrets** | Medium | Hardcoded API keys, tokens, passwords |
| **MissingTimeout** | Medium | HTTP clients without connect/read timeouts |
| **WeakCryptography** | Medium | MD5/SHA1 usage |
| **ReDoS** | Medium | Regex patterns with catastrophic backtracking |
| **EnvInjection** | High | Environment variable manipulation |
| **LDAPInjection** | High | LDAP queries with user input |
| **Deserialization** | High | Unsafe deserialization of untrusted input |
| **ScentLeakage** | High | Sensitive data leaked to logs/output |

### AI Antipattern Detection (`--ai-lint`)

Detects AI-generated code patterns that are syntactically valid but semantically wrong:

| Rule | Severity | Languages | Description |
|------|----------|-----------|-------------|
| `hallucinated-stdlib` | Error | Crystal | Calls to methods that don't exist (37-entry database) |
| `hardcoded-secrets` | Error | Both | API key patterns (Stripe, GitHub, AWS, JWT, Slack) |
| `hardcoded-urls` | Warning | Crystal | Hardcoded http:// and IP addresses |
| `deprecated-syntax` | Warning | Crystal | `puts`, `p`, `pp` in production code |
| `primitive-obsession` | Hint | Crystal | Functions with 3+ parameters |
| `redundant-conversion` | Hint | Crystal | Unnecessary type conversions |
| `panic-call` | Error | Gleam | `panic` used instead of `Result` |
| `list-wrap-unnecessary` | Warning | Gleam | `List.wrap` on collections |
| `deprecated-result-check` | Hint | Gleam | `Result.is_ok/is_err` — use pattern matching |

### Code Smells (`--claws`)

| Detector | Description |
|----------|-------------|
| Cyclomatic complexity | Functions with M ≥ 10 |
| Long parameter list | Functions with ≥ 5 params |
| Deep nesting | ≥ 4 levels of control flow |
| God objects | Files with ≥ 20 definitions |
| DRY violations | Structural code duplication (window hashing) |

### Supply Chain Audit (`--crows-nest`)

- **CVE scanning** via OSV.dev API
- **Staleness detection** — last release, commit activity, retirement status
- **Offline cache** in SQLite with 24h TTL

## Config File

Place a `.catseye.toml` in your project root:

```toml
[scan]
exclude = ["node_modules", ".git", "vendor", "spec"]

[analysis]
extra_sources = ["user_input", "raw_params"]
extra_sanitizers = ["sanitize_path", "escape_shell"]
parallelism = 4

[predator_vision]
enabled = false

[crows_nest]
enabled = false

[claws]
enabled = false
complexity_warning = 10
max_params = 5
dry_window_size = 6
```

## Architecture

```
Crystal (.cr) ──→ Crystal Extractor ──→ Security Node JSON
                                                  │
Gleam (.gleam) ─→ OCaml + tree-sitter ──→ Security Node JSON ──→ Taint Engine ──→ Findings
                                                                                     │
                                                          Terminal / JSON / SARIF / Markdown / DOT
```

| Component | Language | Role |
|-----------|----------|------|
| CLI + Engine | OCaml 5 | File discovery, taint analysis, rule matching, output |
| Crystal Extractor | Crystal | Parses `.cr` via `Crystal::Parser`, emits JSON |
| Gleam Extractor | OCaml + tree-sitter | Parses `.gleam` via tree-sitter XML |
| Rules | KDL | Declarative sink/source/sanitizer definitions |
| AI Linter | OCaml | AST-based antipattern detection (hallucinated stdlib, etc.) |
| Claws | OCaml | Code smell & DRY detection |

## Taint Analysis Pipeline

**seed → propagate → returns → interproc → propagate → guards → rules**

1. **Seed** — Function params named like taint sources (`url`, `request`, `params`) are marked tainted
2. **Propagate** — Fixed-point loop; assignments from tainted vars propagate taint, including through call chains (`x = URI.parse(url)`)
3. **Returns** — Functions with tainted bodies are marked as returning tainted data
4. **Inter-procedural** — Return-value and call-arg taint across function boundaries
5. **Guards** — `unless path.starts_with?("/safe/")` suppresses taint after the guard line
6. **Rules** — KDL rules match sinks against tainted variables

### Adding a New Rule

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

## Real-World Results

| Project | Files | Findings | Details |
|---------|-------|----------|---------|
| quickheadlines | 66 Crystal | 2 | SSRF (proxy), PathTraversal (assets) |
| fetcher.cr | 53 Crystal | 4 | SSRF in YouTube/software fetchers |
| sassd.cr | 5 Crystal | 2 | CommandInjection, PathTraversal in compiler |
| carafe.cr | 40 Crystal | 2 | ScentLeakage to logs |
| vug.cr | 26 Crystal | 1 | SSRF in fetcher |
| PrismatIQ | 37 Crystal | 0 | Clean |
| test/samples | 23 files | 23 | All rule types covered |
| test/samples/safe* | 3 files | 0 | Zero false positives |

## Performance

| Metric | Time |
|--------|------|
| 66-file Crystal scan (cold) | ~0.12s extraction + ~0.06s analysis |
| 66-file Crystal scan (cached) | ~0.02s extraction + ~0.06s analysis |
| AI lint only | ~0.06s total (66 files) |

## Development

```bash
nix develop              # Enter dev shell
just build               # Build
just test                # Run tests + E2E
just scan dir/           # Scan a directory
just fmt                 # Format code
just clean               # Clean artifacts
just list                # List all recipes
```

## Project Structure

```
catseye/
├── src/
│   ├── ocaml/                    # OCaml engine
│   │   ├── bin/main.ml           # CLI entry point
│   │   ├── lib/
│   │   │   ├── catseye_engine/    # Taint engine (seed, propagate, interproc)
│   │   │   ├── catseye_ast/       # Unified AST (CatseyeAST.t)
│   │   │   ├── ai_linter/        # AI antipattern rules
│   │   │   ├── catseye_claws/     # Code smell detection
│   │   │   ├── catseye_crowsnest/ # Supply chain audit
│   │   │   ├── catseye_rules/     # KDL rule interpreter
│   │   │   ├── catseye_cli/       # CLI, orchestrator, output formats
│   │   │   └── catseye_types/     # Shared types (Finding, Security_node)
│   │   └── rules/                # KDL rule files (13 rules)
│   └── extractor/
│       └── extractor.cr          # Crystal AST extractor
├── test/samples/                 # Test corpus (vulnerable + safe)
├── .github/workflows/            # CI + self-scan
├── flake.nix                     # Nix dev shell
└── justfile                      # Build tasks
```

## License

MIT
