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

  -f, --format <fmt>         terminal (default), json, sarif, markdown, dot
  -o, --output <path>        write results to file
  -r, --rules <path>         rules directory (default: rules/)
  --lang <lang>              all (default), crystal, gleam
  --no-color                 disable colored output
  --no-cache                 disable extraction cache
  --clear-cache              clear cache and run full scan
  --cache-dir <path>         cache directory (default: .catseye)
  --cfg                      use IL/CFG-based taint engine (more sensitive)
  --no-cfg                   use flat taint engine (default, fewer findings)
  --analysis-timeout <ms>    timeout for analysis phase (0 = disabled)
  --cfg-max-blocks <n>       max blocks per function CFG (default: 500)
  --cfg-timeout-ms <ms>      timeout per function CFG build (default: 5000)
  --predator-vision          enable reachability analysis (live/dormant/safe)
  --crows-nest               enable supply chain audit (CVE + staleness)
  --claws                    enable code smell detection
  --ai-lint                  enable AI antipattern detection
  -p, --parallelism <n>      parallel workers (0 = auto)
  -v, --version              show version
  -h, --help                 show help
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

All code smell detectors use **AST-native analysis** via `CatseyeAST.t` for accurate, tree-based detection. The flat engine runs as fallback for rules not yet migrated.

| Detector | Rule ID | Threshold |
|----------|---------|-----------|
| Cyclomatic complexity | `HighComplexity` | M ≥ 10 |
| Long parameter list | `LongParameterList` | ≥ 5 params |
| Deep nesting | `DeepNesting` | ≥ 4 levels |
| God objects | `GodObject` | ≥ 20 defs/file |
| DRY violations | `DRYViolation` | 4+ duplicates |
| Long method | `LongMethod` | ≥ 30 nodes |
| Message chain | `MessageChain` | ≥ 5 links |
| Data class | `DataClass` | 2+ props, no behavior |
| Data clump | `DataClump` | 3+ params always together |
| Flag argument | `FlagArgument` | bool params |
| Complex match | `ComplexMatch` | ≥ 5 branches |
| Dead code | `DeadCode` | unreachable code |
| Feature envy | `FeatureEnvy` | excessive cross-class calls |
| Orphaned spawn | `OrphanedSpawn` | `spawn`/`go` without rescue/ensure |
| Muted pack | `MutedPack` | `Channel.send` without receive |
| Dead letter | `DeadLetter` | `Channel.close` before receive |

**Exempt patterns:** Factory methods (`from_*`, `build_*`, `create_*`), constructors (`initialize`, `new`), parsers (`decode*`, `parse_*`), DTO/serialization classes (`include JSON::Serializable`), and files in `/dtos/`, `/types/`, `/entities/` directories are automatically exempted from relevant detectors.

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
              ┌──────────────┴──────────────┐
              ▼                             ▼
        Flat Engine                   CFG Engine (--cfg)
     (default, fast)            (more sensitive, branch-aware)
              │                             │
              └──────────────┬──────────────┘
                             ▼
                    KDL Rule Interpreter
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         Findings        AI Linter      Code Smells
         (taint)        (AST rules)    (complexity, etc.)
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                     Terminal / JSON / SARIF / Markdown / DOT
```

**Flat taint pipeline:** seed → propagate → returns → interproc → propagate → cross-file → guards → rules

1. **Seed** — Params named like taint sources (`url`, `request`, `params`) are marked tainted
2. **Propagate** — Fixed-point; taint flows through assignments and call chains (sanitizer-aware: `File.expand_path`, `URI.parse`, `validate_*` cleanse taint)
3. **Returns** — Functions with tainted bodies return tainted data
4. **Inter-procedural** — Taint crosses function boundaries
5. **Guards** — `unless path.starts_with?("/safe/")` suppresses taint
6. **Rules** — KDL rules match sinks against tainted variables, with `arg=N` position matching

**CFG engine** (`--cfg`) converts CatseyeAST.t → IL → basic block CFG → forward dataflow taint analysis. Branch-aware: taint does not flow across dead branches. Field-sensitive lvalues.

### Adding a Security Rule

Create `src/ocaml/rules/my_rule.kdl`:

```kdl
rule "MyRule" severity="Medium" {
    sinks {
        sink "Dangerous.call" arg=0 {
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

`arg=0` means only flag when tainted data is in the first argument. Omit for any-arg matching.
`$var` metavariables match any receiver prefix: `sink "$client.get"` matches `http.get`, `conn.get`, `my_client.get`.

Rebuild with `just build` and test.

### Extraction Strategy

**Crystal projects** use two extraction paths:

1. **Flat extraction** (default): Extracts individual AST nodes as a flat list. Fast but loses hierarchy.
2. **Hierarchical extraction** (`--bridge`): Parses nested AST structure for accurate tree-based analysis.

For Crystal projects with `shard.yml`, scan only the `src/` directory to exclude shard dependencies:

```bash
./bin/catseye-ocaml --rules src/ocaml/rules --claws path/to/project/src/
```

The `--include-deps` flag is planned to automatically handle shard dependency exclusion.

## Configuration

Optional `.catseye.toml` in your project root (walked up from the target directory):

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

# Suppress code smell rules by file glob
[claws.suppress]
DataClump = ["**"]
LongParameterList = ["**/repositories/**"]

# Suppress security/taint findings by file glob
[taint.suppress]
SSRF = ["**/validated_http_client.cr"]
PathTraversal = ["**/safe_io.cr"]
```

### Glob Patterns

- `*` matches any characters except `/`
- `**` matches any characters including `/` (cross-directory)
- `?` matches a single character

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
│   │   │   ├── catseye_engine/          # Flat taint analysis + propagation, extractor registry
│   │   │   ├── catseye_il/              # IL types, CFG builder (ocamlgraph), CFG taint engine
│   │   │   ├── catseye_ast/             # Unified AST + Crystal/Gleam mappers
│   │   │   │   └── crystal_hierarchical_mapper.ml  # Hierarchical AST parsing
│   │   │   ├── ai_linter/              # AI antipattern rules (73 rules)
│   │   │   ├── catseye_claws/           # Code smell detection (AST-native)
│   │   │   │   ├── complexity_ast.ml    # Cyclomatic complexity
│   │   │   │   ├── anatomy_ast.ml       # Long params, deep nesting, god objects
│   │   │   │   ├── dry_ast.ml           # DRY violation detection
│   │   │   │   ├── extra_smells_ast.ml  # Long method, message chains, etc.
│   │   │   │   └── concurrency_ast.ml    # OrphanedSpawn, MutedPack
│   │   │   ├── catseye_crowsnest/       # Supply chain audit
│   │   │   ├── catseye_rules/           # KDL rule interpreter (arg, $var)
│   │   │   ├── catseye_cli/             # CLI, orchestrator, output formats
│   │   │   └── catseye_types/           # Shared types
│   │   └── rules/                       # 12 KDL rule files
│   └── extractor/extractor.cr           # Crystal AST extractor
├── test/samples/                        # Test corpus
├── openspec/                            # Spec-driven change tracking
├── .github/workflows/                   # CI
├── flake.nix                            # Nix dev shell
└── justfile                             # Build tasks
```

## Migration Status

**Claws → CatseyeAST Migration: ✅ Complete**

All 14 code smell detectors now use AST-native analysis:
- Complexity, Anatomy, DRY, Extra Smells (9 detectors), Concurrency (3 detectors)
- Flat engine runs as fallback for uncaptured rules

See `openspec/changes/claws-ast-migration/` for details.

## Performance

| Scan | Extraction | Analysis |
|------|-----------|----------|
| 66-file Crystal (cold) | ~0.12s | ~0.06s |
| 66-file Crystal (cached) | ~0.02s | ~0.06s |

**CFG engine** scales linearly: 500 sequential branches in 0.09ms, 10,000 nodes in 2.4ms, 500-block taint analysis in 0.75ms.

## License

MIT
