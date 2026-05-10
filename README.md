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

# Scan a project
just scan dir path/to/project/src

# JSON output
just scan-json path/to/project/src

# All formats to planning/
just scan-all path/to/project/src
```

## Usage

```bash
catseye-ocaml [options] <directory>

Options:
  --format <fmt>       Output: terminal (default), json, sarif, markdown
  -o, --output <path>  Write results to file
  --rules <path>       Rules directory (default: rules/)
  --lang <lang>        Language filter: all (default), crystal, gleam
  --no-color           Disable colored output
  --no-cache           Disable extraction cache
  --parallelism <n>    Parallel extraction workers (0 = auto)
  -h, --help           Show help
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
```

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
Colored, human-readable output with file locations and severity indicators.

### JSON
Machine-readable with full metadata:
```bash
./bin/catseye-ocaml --format json path/to/project
```

### SARIF
GitHub Code Scanning compatible (SARIF 2.1.0):
```bash
./bin/catseye-ocaml --format sarif path/to/project
```

### Markdown
Human and AI-readable report:
```bash
./bin/catseye-ocaml --format markdown path/to/project
```

## Performance

| Project | Files | OCaml Time |
|---------|-------|------------|
| quickheadlines | 66 | 0.16s |
| PrismatIQ | 37 | 0.12s |
| test/samples | 8 | 0.14s |

The OCaml engine produces a single 4.8MB native binary with no runtime dependencies.

## How It Works

### 1. Crystal Extractor (`src/extractor/extractor.cr`)

Pre-built native binary. Parses Crystal source via `Crystal::Parser` and extracts calls, assignments, and definitions as Security Nodes.

### 2. Gleam Extractor (`src/ocaml/lib/catseye_engine/gleam.ml`)

Calls `tree-sitter parse -l <grammar> --lang-name gleam -x <file>` and parses the XML output using a functional recursive descent parser. No external dependencies beyond the tree-sitter binary and Gleam grammar.

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
│   │   │   │   ├── dag.ml             # Vulnerability DAG builder
│   │   │   │   ├── parallel.ml        # Domain parallelism
│   │   │   │   └── cache.ml           # Extraction cache
│   │   │   ├── catseye_rules/          # KDL rule system
│   │   │   │   ├── types.ml           # Rule type definitions
│   │   │   │   ├── loader.ml          # KDL → rule_def parser
│   │   │   │   └── interpreter.ml     # Rule matching engine
│   │   │   ├── catseye_cli/            # CLI and orchestration
│   │   │   │   ├── args.ml            # Argument parsing
│   │   │   │   ├── config.ml          # TOML config loader
│   │   │   │   ├── discovery.ml       # File discovery + exclusion
│   │   │   │   ├── orchestrator.ml    # Scan pipeline
│   │   │   │   ├── sarif.ml           # SARIF output
│   │   │   │   └── markdown.ml        # Markdown output
│   │   │   └── catseye_types/          # Shared types
│   │   │       ├── security_node.ml   # Security Node type
│   │   │       ├── finding.ml         # Finding type + JSON encoding
│   │   │       └── dag_types.ml       # DAG types
│   │   └── rules/                      # KDL rule files
│   │       ├── ssrf.kdl
│   │       ├── command_injection.kdl
│   │       ├── sql_injection.kdl
│   │       └── ... (11 rules)
│   └── extractor/
│       └── extractor.cr               # Crystal AST extractor
├── test/samples/                       # Vulnerable + safe test files
├── planning/ocaml-rewrite/             # Rewrite plan + results
├── flake.nix                           # Nix dev shell
└── justfile                            # Task runner
```

## Development

```bash
nix develop             # Enter dev shell (OCaml 5.4, Crystal, tree-sitter)
just ocaml              # Build
just test               # Run tests
just scan dir path      # Scan a project
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
3. Test: `just scan dir path/to/project`
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
