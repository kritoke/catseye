# <img src="assets/logo.svg" alt="Catseye logo" width="200"> Catseye

**Static security analysis for Crystal and Gleam applications.**

Catseye finds vulnerabilities like SSRF, command injection, path traversal, and more by combining AST-based extraction with taint tracking and pattern-matching rules.

## Architecture

```
OCaml (CLI + Engine)  →  Crystal (Extractor)  →  KDL (Rules)
```

| Component | Language | Role |
|-----------|----------|------|
| **CLI + Engine** | OCaml 5 | File discovery, taint analysis, rule matching, output formatting |
| **Crystal Extractor** | Crystal | Parses `.cr` files via `Crystal::Parser`, emits Security Node JSON |
| **Gleam Extractor** | OCaml + tree-sitter | Parses `.gleam` files via tree-sitter CLI, builds Security Nodes |
| **Rules** | KDL | Declarative rule definitions (sinks, sources, sanitizers, conditions) |

## Quick Start

```bash
# Enter dev shell (requires nix)
nix develop

# Build
just ocaml

# Scan a project (terminal, Hunter persona)
just scan path/to/project/src

# JSON output
just scan-json path/to/project/src

# All formats to planning/
just scan-all path/to/project/src
```

## Usage

```bash
catseye-ocaml [options] <directory>

Options:
  --format <fmt>         Output: terminal (default), json, sarif, markdown
  -o, --output <path>    Write results to file
  --rules <path>         Rules directory (default: rules/)
  --lang <lang>          Language filter: all (default), crystal, gleam
  --no-color             Disable colored output
  --no-cache             Disable extraction cache
  --no-persona           Disable Hunter persona (plain terminal output)
  --predator-vision      Enable reachability heatmap (attack surface analysis)
  --crows-nest           Enable supply chain audit (CVE + staleness)
  --claws                Enable code smell & DRY detection
  --parallelism <n>      Parallel extraction workers (0 = auto)
  -h, --help             Show help
```

### Config File

Place a `.catseye.toml` in your project root:

```toml
[scan]
exclude = ["node_modules", ".git", "vendor", "spec"]

[analysis]
extra_sources = ["user_input", "raw_params"]
extra_sanitizers = ["sanitize_path", "escape_shell"]
parallelism = 4

[persona]
enabled = true            # Set false for plain terminal output

[predator_vision]
enabled = false           # Set true to enable by default

[crows_nest]
enabled = false           # Set true to enable by default

[claws]
enabled = false           # Set true to enable by default
complexity_warning = 10   # Cyclomatic complexity threshold
max_params = 5           # Parameter count threshold
dry_window_size = 6       # DRY detection window size
```

## Hunter Persona

Catseye's terminal output uses a "Hunter" theme — a cat stalking prey through the tall grass of your codebase:

| Internal Severity | Catseye Level | Icon | Meaning |
|-------------------|---------------|------|---------|
| Critical / High | **Hiss** | 🐱⚡ | Dangerous vulnerability found |
| Medium / Low | **Meow** | 🐾 | Suspicious pattern, worth investigating |
| Info / Safe | **Purr** | 😸 | No issues found |

Example output:
```
 ╭──────────────────────────────────────────╮
 │  🐈‍⬛  Catseye v0.3.0                      │
 │     The Hunter enters the tall grass...  │
 ╰──────────────────────────────────────────╯
  Target:   ./src
  Files:    66 Crystal, 12 Gleam
  Scent:    Fresh code detected

  🐾 Stalking src/controller.cr
  👀 Watching... 5,337 nodes to inspect
  🎯 Pouncing on taint flows...

  🐱⚡ HISS  CommandInjection  src/controller.cr:42
       Found os.command() with tainted input
       ← Source: request.params (controller.cr:15)
       ↓  Sink: os.command(cmd) (controller.cr:42)

  😸 PURR  The codebase is clean.
  The Hunter rests.
```

Disable with `--no-persona` for plain output. JSON/SARIF/Markdown are unaffected.

## Predator Vision

Reachability-first analysis. Detects HTTP handlers and CLI entry points, builds a call graph, and tags findings as **Live** (reachable from the internet), **Dormant** (not reachable), or **Safe** (sanitized).

```bash
just scan-hunter path/to/project     # enables --predator-vision --crows-nest --claws
```

Terminal output includes a per-file heatmap showing the ratio of live vs dormant sinks.

## Crow's Nest

Supply chain audit for Crystal Shards and Gleam Hex packages:

- **CVE scanning** via OSV.dev API
- **Staleness detection** via GitHub/Hex APIs (last release, commit activity, retirement status)
- **Offline cache** in SQLite with 24h TTL

```bash
catseye-ocaml --rules rules/ --crows-nest path/to/project
```

## Claws — Code Smell & DRY Detection

Code health analysis that runs alongside security scanning. Detects:

- **Cyclomatic complexity** — functions with too many decision points (M ≥ 10 warning, ≥ 20 critical)
- **Long parameter lists** — functions with too many parameters (≥ 5 warning, ≥ 8 critical)
- **Deep nesting** — excessive control flow nesting (≥ 4 warning, ≥ 6 critical)
- **God objects** — files with too many definitions (≥ 20)
- **DRY violations** — structural code duplication via windowed hashing (window size 6, ≥ 2 occurrences)
- **Ameba integration** — optional Crystal linter delegation (`--claws` with `[claws] ameba_enabled = true` in config)

```bash
# Security + code smells
catseye-ocaml --rules rules/ --claws path/to/project

# Code smells only (with custom thresholds)
catseye-ocaml --rules rules/ --claws --format json path/to/project
```

Configure via `.catseye.toml`:

```toml
[claws]
enabled = true
complexity_warning = 10
max_params = 5
dry_enabled = true
dry_window_size = 6
ameba_enabled = false
```

All detectors individually toggleable. Findings use the Hunter taxonomy (HISS/MEOW/PURR).

## Detection Rules

| Rule | Severity | Languages | Description |
|------|----------|-----------|-------------|
| **SSRF** | High | Crystal, Gleam | HTTP client calls with user-controlled URLs |
| **CommandInjection** | Critical | Crystal, Gleam | `system`/`exec`/`Process.run` with tainted input |
| **PathTraversal** | High/Medium | Crystal, Gleam | File I/O with user-controlled paths |
| **SQLInjection** | Critical | Crystal | SQL queries with tainted arguments |
| **OpenRedirect** | Medium | Crystal | Redirect handlers with unvalidated URLs |
| **InsecureDeserialization** | High | Crystal | Unsafe deserialization of untrusted input |
| **LDAPInjection** | High | Crystal | LDAP queries with user input |
| **HardcodedSecrets** | Medium | Crystal | Hardcoded API keys, tokens, passwords |
| **MissingTimeout** | Medium | Crystal | HTTP clients without connect/read timeouts |
| **WeakCryptography** | Medium | Crystal | MD5/SHA1 usage |
| **InsecureRandom** | Low | Gleam | Non-cryptographic PRNG in security contexts |
| **ReDoS** | Medium | Crystal | Regex patterns with catastrophic backtracking |
| **EnvInjection** | High | Crystal | Environment variable manipulation |

Rules are defined as KDL files in `src/ocaml/rules/`. Each rule specifies sinks, sources, sanitizers, severity, and optional conditions (taint-based, pattern-matching, or skip-taint).

## Output Formats

### Terminal (default)
Colored, human-readable output with Hunter persona. Use `--no-persona` for plain output.

### JSON
Machine-readable with full metadata:
```bash
just scan-json path/to/project
```

### SARIF
GitHub Code Scanning compatible (SARIF 2.1.0):
```bash
catseye-ocaml --format sarif path/to/project
```

### Markdown
Human and AI-readable report:
```bash
catseye-ocaml --format markdown path/to/project
```

## Performance

| Project | Files | OCaml Time |
|---------|-------|------------|
| quickheadlines | 66 | 0.16s |
| PrismatIQ | 37 | 0.12s |
| test/samples | 8 | 0.14s |

The OCaml engine produces a single 4.8MB native binary with no runtime dependencies.

**Note:** Projects with large numbers of Call/Def nodes may experience slower analysis due to DAG construction. The `max_trace_depth` limit (50) prevents infinite recursion, but complex taint chains can still take time.

## How It Works

### 1. Crystal Extractor (`src/extractor/extractor.cr`)

Pre-built native binary. Parses Crystal source via `Crystal::Parser` and extracts calls, assignments, and definitions as Security Nodes.

### 2. Gleam Extractor (`src/ocaml/lib/catseye_engine/gleam.ml`)

Calls `tree-sitter parse --lib-path <grammar> --lang-name gleam -x <file>` and parses the XML output using a functional recursive descent parser. Requires `TREE_SITTER_GLEAM_GRAMMAR` env var (set automatically in `nix develop` or via `just` recipes).

### 3. OCaml Engine (`src/ocaml/`)

Taint analysis pipeline: **seed → propagate → returns → interproc → propagate → rules**

- **Seed**: Function params named like taint sources (`url`, `request`, `user_input`) are marked tainted
- **Propagate**: Fixed-point loop — assignments from tainted vars propagate taint
- **Returns**: Functions with tainted bodies are marked as returning tainted data
- **Inter-procedural**: Two strategies — return-value taint from known functions, and call-arg taint (if a call receives tainted args, its return is tainted)
- **Sanitizers**: Recognized calls (URI.parse, Path.basename, etc.) block taint propagation
- **Parallelism**: OCaml 5 Domains for parallel file extraction

### 4. KDL Rules (`src/ocaml/rules/`)

Declarative rule definitions. Example:

```kdl
rule "SSRF" severity="High" {
    sinks {
        sink "HTTP::Client.get" {
            sanitizer "URI.parse"
        }
        sink "HTTP::Client.post"
    }
    sources {
        source "params"
        source "url"
    }
    message "Potential SSRF via {sink} with tainted argument(s): {tainted_vars}."
}
```

Three rule condition types:
- **Taint-based** (default): flags sinks that receive tainted data
- **`skip_taint_check`**: flags any matching call regardless of taint (WeakCryptography, InsecureRandom)
- **`check_args_contain`**: flags if arg values contain specific substrings (ReDoS)
- **`check_args_missing`**: flags if no arg contains a required substring (MissingTimeout)

## Project Structure

```
catseye/
├── src/
│   ├── ocaml/                          # OCaml engine
│   │   ├── bin/main.ml                 # Entry point
│   │   ├── lib/
│   │   │   ├── catseye_engine/         # Taint analysis engine
│   │   │   │   ├── engine.ml           # Pipeline orchestrator
│   │   │   │   ├── db.ml              # TaintDB (Map-based)
│   │   │   │   ├── seed.ml            # Taint source seeding
│   │   │   │   ├── propagate.ml       # Fixed-point propagation
│   │   │   │   ├── interproc.ml       # Inter-procedural analysis
│   │   │   │   ├── returns.ml         # Return-value taint
│   │   │   │   ├── gleam.ml           # Gleam tree-sitter extractor
│   │   │   │   ├── reachability.ml    # Predator Vision reachability
│   │   │   │   ├── dag.ml             # Vulnerability DAG builder
│   │   │   │   ├── parallel.ml        # Domain parallelism
│   │   │   │   └── cache.ml           # Extraction cache
│   │   │   ├── catseye_crowsnest/      # Supply chain audit
│   │   │   │   ├── manifest.ml        # shard.yml + gleam.toml parsing
│   │   │   │   ├── osv.ml             # OSV.dev CVE query
│   │   │   │   ├── staleness.ml       # GitHub/Hex staleness scoring
│   │   │   │   ├── aggregator.ml      # CVE + staleness → Hiss/Meow/Purr
│   │   │   │   └── cache.ml           # SQLite cache (24h TTL)
│   │   │   ├── catseye_claws/          # Code smell & DRY detection
│   │   │   │   ├── types.ml           # Claws config + thresholds
│   │   │   │   ├── complexity.ml      # Cyclomatic complexity walker
│   │   │   │   ├── anatomy.ml         # Params, nesting, god objects
│   │   │   │   ├── dry.ml             # Structural duplication hashing
│   │   │   │   ├── ameba_hook.ml      # Ameba linter integration
│   │   │   │   └── smells.ml          # Unified smell pipeline
│   │   │   ├── catseye_rules/          # KDL rule system
│   │   │   │   ├── types.ml           # Rule type definitions
│   │   │   │   ├── loader.ml          # KDL → rule_def parser
│   │   │   │   └── interpreter.ml     # Rule matching engine
│   │   │   ├── catseye_cli/            # CLI and orchestration
│   │   │   │   ├── args.ml            # Argument parsing
│   │   │   │   ├── config.ml          # TOML config loader
│   │   │   │   ├── discovery.ml       # File discovery + exclusion
│   │   │   │   ├── orchestrator.ml    # Scan pipeline + Hunter persona
│   │   │   │   ├── heatmap.ml         # Predator Vision terminal heatmap
│   │   │   │   ├── crowsnest_format.ml # Crow's Nest terminal output
│   │   │   │   ├── sarif.ml           # SARIF output
│   │   │   │   └── markdown.ml        # Markdown output
│   │   │   └── catseye_types/          # Shared types
│   │   │       ├── security_node.ml   # Security Node type
│   │   │       ├── finding.ml         # Finding type + reachability
│   │   │       └── dag_types.ml       # DAG types
│   │   └── rules/                      # KDL rule files (11 rules)
│   └── extractor/
│       └── extractor.cr               # Crystal AST extractor
├── test/samples/                       # Vulnerable + safe test files
├── flake.nix                           # Nix dev shell
└── justfile                            # Task runner
```

## Development

```bash
nix develop             # Enter dev shell (OCaml 5.4, Crystal, tree-sitter)
just ocaml              # Build
just test               # Run tests
just scan path/to/dir   # Scan a project
just fmt-ocaml          # Format OCaml code
just lint-ocaml         # Check formatting
just clean              # Clean build artifacts
```

### Adding a New Rule

1. Create `src/ocaml/rules/my_rule.kdl`:
   ```kdl
   rule "MyRule" severity="Medium" {
       sinks {
           sink "Dangerous.call"
       }
       message "My rule: {sink} does something dangerous."
   }
   ```
2. Rebuild: `just ocaml`
3. Test: `just scan path/to/project`
4. For non-taint rules, add conditions:
   ```kdl
   conditions {
       skip_taint_check          # Flag any matching call
       # or
       check_args_contain "pattern"  # Flag if args contain pattern
   }
   ```

## License

MIT
