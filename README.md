# <img src="assets/logo.svg" alt="Catseye logo" width="200"> Catseye

**Static security analysis for Crystal and Gleam applications.**

Catseye finds vulnerabilities like SSRF, command injection, path traversal, and more by combining AST-based extraction with taint tracking and pattern-matching rules. It uses a multi-language architecture where each component plays to its strengths.

## Architecture

```
Nim (CLI)  →  Crystal (Extractor)  →  Gleam/BEAM (Logic Engine)
```

| Component | Language | Role |
|-----------|----------|------|
| **CLI** | Nim | File discovery, dependency tracking, subprocess orchestration, colored output |
| **Extractor** | Crystal | Parses `.cr` files via `Crystal::Parser`, emits Security Node JSON |
| **Extractor** | Nim + Tree-sitter | Parses `.gleam` files, emits Security Node JSON |
| **Engine** | Gleam/Erlang | Decodes JSON, runs taint analysis + vulnerability rules |

## Quick Start

```bash
# Enter dev shell (requires nix)
nix develop

# Build everything
just build

# Scan a project (src/ only)
just scan path/to/project/src

# Scan a project including dependencies (lib/)
just scan path/to/project

# Run all tests
just test
```

## Usage

### Via Justfile

```bash
# Scan all supported languages in a directory
just scan path/to/project

# Scan specific languages
just scan-crystal path/to/project
just scan-gleam path/to/project

# Machine-readable output
just scan-json path/to/project
just scan-sarif path/to/project   # writes catseye-results.sarif

# Debug single files
just extract foo.cr               # Crystal extractor on one file
just extract-gleam foo.gleam      # Gleam extractor on one file
```

### Via CLI

```bash
catseye [options] <directory>

Options:
  --format <fmt>       Output: terminal (default), json, sarif
  --lang <lang>        Language filter: all (default), crystal, gleam
  --config <path>      Config file (.catseye.toml)
  --crystal-extractor  Path to Crystal extractor
  --gleam-extractor    Path to Gleam extractor binary
  --engine <path>      Path to Gleam engine directory
  --no-color           Disable colored output
  -h, --help           Show help
```

### Dependency Scanning

Point catseye at a project root (not just `src/`) to scan `lib/` dependencies alongside your code. Findings from dependencies are tagged with the package name:

```bash
# Scan project code only
just scan-crystal my-project/src

# Scan project code + dependencies (lib/)
just scan-crystal my-project
```

In terminal output, dependency findings show the package name:

```
[PathTraversal] High  lib/ameba/src/ameba/config.cr:151
  dependency: ameba
  Potential path traversal via File.read with variable argument(s): path...
```

In JSON output, dependency findings include a `"dependency"` field:

```json
{
  "rule": "PathTraversal",
  "file": "lib/ameba/src/ameba/config.cr",
  "line": 151,
  "dependency": "ameba",
  ...
}
```

The summary also breaks down how many issues are in dependencies:

```
Found 10 issue(s) across 409 file(s) (9 in dependencies).
```

### Config File

Place a `.catseye.toml` in your project root to customize taint analysis:

```toml
[taint]
extra_sources = "user_input,raw_params"
extra_sinks = "unsafe_eval,render_template"
extra_sanitizers = "sanitize_path,escape_shell"
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| **SSRF** | High | HTTP client calls with user-controlled URLs |
| **CommandInjection** | Critical | `system`/`exec`/`Process.run` with tainted input |
| **PathTraversal** | High/Medium | File I/O with user-controlled paths |
| **OpenRedirect** | Medium | Redirect handlers with unvalidated URLs |
| **MissingTimeout** | Medium | HTTP clients without connect/read timeouts |
| **InsecureRandom** | Low | Non-cryptographic PRNG for security-sensitive operations |
| **InsecureDeserialization** | High | YAML/JSON parsing of untrusted input |

All rules include **taint flow traces** showing how data flows from source to sink.

## Example Output

```
╔══════════════════════════════════════╗
║            Catseye v0.2.0            ║
╚══════════════════════════════════════╝
  Target:   src/app/
  Files:    12 Crystal, 0 Gleam
  Engine:   Gleam/BEAM (taint v2)

→ Extracting: src/app/client.cr
→ Extracting: src/app/runner.cr
→ Running analysis engine (84 nodes)...

[SSRF] High  src/app/client.cr:42
  Potential SSRF: HTTP::Client.get called with variable argument(s): url.
    ← url is a taint source (parameter)  (src/app/client.cr:10)
    ↓ Sink: HTTP::Client.get called with tainted data

[CommandInjection] Critical  src/app/runner.cr:17
  Potential command injection via system. User input may flow into a shell command.
    ← cmd tainted via source  (src/app/runner.cr:12)
    ↓ Sink: system called with tainted data

─────────────────────────────────────────
Found 2 issue(s) across 2 file(s).
```

## Output Formats

### Terminal (default)

Colored, human-readable output with taint flow traces.

### JSON

Machine-readable with full metadata:

```bash
just scan-json path/to/project
```

### SARIF

GitHub Code Scanning compatible:

```bash
just scan-sarif path/to/project
```

Results include `codeFlows` with the full taint trace for each finding.

## How It Works

### 1. Crystal Extractor (`src/extractor/extractor.cr`)

Parses Crystal source files using the compiler's own `Crystal::Parser` and `Crystal::Visitor`. Extracts:
- **Method calls** (`Call`) — tracks fully-qualified names like `HTTP::Client.get`
- **Assignments** (`Assign`) — propagates taint from sources to variables
- **Method definitions** (`Def`) — records function boundaries

Each node is emitted as a [Security Node](spec/security-node.schema.json) JSON object with type, name, args, line, and a taint flag.

### 2. Gleam Extractor (`src/extractor/gleam_extractor.nim`)

Parses Gleam source files using Tree-sitter. Extracts the same Security Node JSON format for Gleam code.

### 3. Gleam Logic Engine (`src/engine/`)

Consumes the JSON and runs recursive pattern-matching rules on BEAM:
- **Taint tracking** — variables assigned from `params`, `gets`, `request`, etc. are tracked across assignments and function calls
- **Source-to-sink analysis** — traces data flow from user input to dangerous operations
- **Configurable rules** — extend via `.catseye.toml` with custom sources, sinks, and sanitizers

Rules share a single taint analysis pass (DRY) and are easy to extend.

### 4. Nim CLI (`src/cli/catseye.nim`)

Orchestrates the pipeline: recursively discovers files, runs the appropriate extractor, detects `lib/` dependencies, sends aggregated JSON to the engine, and formats findings with dependency attribution.

## Development

```bash
nix develop           # Enter dev shell
just build            # Build all components
just unit-test        # Run Gleam unit tests
just test             # Full E2E pipeline test
just lint             # Lint all languages
just extract foo.cr   # Run Crystal extractor on a single file
just clean            # Remove all build artifacts
just list             # List all available recipes
```

### Adding a New Rule

1. Add the rule function in `src/engine/src/catseye/ssrf.gleam` (or create a new module)
2. Follow the existing pattern: filter by call name → filter by taint → map to `Finding`
3. Add the rule to `run_all_rules`
4. Add test cases in `src/engine/src/catseye/test_runner.gleam`
5. Run `just unit-test` to verify

## Project Structure

```
catseye/
├── assets/
│   ├── logo.png                    # Project logo (raster)
│   └── logo.svg                    # Project logo (vector)
├── spec/
│   └── security-node.schema.json   # JSON bridge schema
├── src/
│   ├── cli/catseye.nim             # Nim orchestrator
│   ├── extractor/
│   │   ├── extractor.cr            # Crystal AST extractor
│   │   └── gleam_extractor.nim     # Gleam Tree-sitter extractor
│   └── engine/
│       ├── gleam.toml
│       └── src/
│           ├── catseye.gleam             # Engine entry point
│           ├── catseye/node.gleam        # Node types + helpers
│           ├── catseye/ssrf.gleam        # Security rules
│           ├── catseye/test_runner.gleam # Unit tests
│           └── catseye_engine_ffi.erl    # Erlang FFI (JSON + stdin)
├── test/samples/                    # Vulnerable + safe .cr files
├── flake.nix                        # Nix dev shell
└── justfile                         # Task runner
```

## License

MIT
