# Catseye Architecture

## Overview

Catseye is a multi-language static security analysis tool that finds vulnerabilities
(SSRF, command injection, path traversal, SQL injection) in web applications using
AST-based analysis with taint tracking.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Nim CLI (Orchestrator)                         │
│  - Discovers .cr and .gleam files recursively                         │
│  - Dispatches to language-specific extractors                          │
│  - Pipes JSON to Gleam/Erlang engine                                   │
│  - Output: terminal (colored) / JSON / SARIF v2.1.0                    │
└──────────┬────────────────────────────────────┬─────────────────────────┘
           │ file path                          │ JSON (stdin)
           ▼                                    ▼
┌──────────────────────┐            ┌────────────────────────────────────┐
│  Crystal Extractor    │            │  Gleam Extractor (Nim + tree-sitter)│
│  Crystal::Parser      │            │  tree-sitter parse -x → XML CST    │
│  Crystal::Visitor     │            │  Nim XML walker → Security Nodes   │
│  Taint seed (strings) │            │  Taint seed (sources match)        │
└──────────┬───────────┘            └──────────┬─────────────────────────┘
           │ Security Node JSON                 │ Security Node JSON
           └──────────────┬─────────────────────┘
                          ▼
           ┌──────────────────────────────────────┐
           │  Gleam Logic Engine (BEAM/Erlang)     │
           │                                       │
           │  Taint Analysis Engine:                │
           │    seed → propagate (fixed-point)      │
           │    → track returns → inter-procedural  │
           │    → sanitizer recognition             │
           │                                       │
           │  Rules (catseye/rules/):               │
           │    ssrf.gleam                          │
           │    command_injection.gleam              │
           │    path_traversal.gleam                │
           │    sql_injection.gleam                 │
           │    taint.gleam (shared engine)         │
           │                                       │
           │  Output: Findings JSON with flow data  │
           └──────────────────────────────────────┘
```

## Data Flow

1. **Nim CLI** scans a target directory for `.cr` and `.gleam` files
2. For each `.cr` file: **Crystal Extractor** parses AST, emits Security Node JSON
3. For each `.gleam` file: **Gleam Extractor** (Nim+tree-sitter) parses XML CST, emits Security Node JSON
4. **Nim** aggregates all JSON and sends to **Gleam Engine** via `erl -noshell`
5. **Gleam Engine**: taint analysis → rule matching → findings with flow traces
6. **Nim** formats findings as terminal, JSON, or SARIF v2.1.0

## Bridge Format

JSON array of Security Node objects. See `spec/security-node.schema.json`.

```json
{
  "type": "call|assign|def",
  "name": "HTTP::Client.get",
  "args": [{"arg_type": "var", "value": "url"}],
  "line": 12,
  "taint": false,
  "file": "src/controller.cr"
}
```

## Taint Analysis Pipeline

```
1. SEED       Extractor flags assignments from taint sources (taint: true)
              + Function params named like sources (params, request, user_input, etc.)

2. PROPAGATE  Fixed-point: if `let y = x` and x is tainted → y is tainted
              Repeats until no new tainted vars found

3. RETURNS    Functions whose body produces tainted data → function name is tainted
              (handles def get_url(p) { p["url"] } → get_url is tainted)

4. INTERPROC  If `url = get_url(params)` and get_url is tainted → url is tainted

5. SANITIZE   is_suspect() checks: if ANY arg is a sanitizer call, skip the finding
              Sanitizers: URI.parse, Path.basename, String.strip, encode.*, etc.

6. FLOW       For each finding: trace tainted args back to source
              Output: List(FlowStep) with file, line, message
```

## Languages & Runtimes

| Component       | Language  | Runtime     | Why                              |
|-----------------|-----------|-------------|----------------------------------|
| CLI             | Nim 2.2   | Native      | Fast, zero-dep binaries          |
| Crystal Extractor | Crystal 1.18 | Native   | Direct access to Crystal compiler |
| Gleam Extractor | Nim 2.2 + tree-sitter | Native | tree-sitter XML CST parsing |
| Logic Engine    | Gleam 1.16 | BEAM/Erlang 28 | Pattern matching, fault-tolerant |

## Directory Layout

```
catseye/
├── flake.nix                  # Nix dev shell (all toolchains)
├── justfile                   # Build/dev tasks
├── spec/
│   └── security-node.schema.json
├── src/
│   ├── cli/
│   │   └── catseye.nim        # Nim orchestrator (terminal/JSON/SARIF)
│   ├── extractor/
│   │   ├── extractor.cr       # Crystal AST extractor
│   │   └── gleam_extractor.nim # Nim + tree-sitter extractor
│   └── engine/
│       ├── gleam.toml
│       └── src/
│           ├── catseye.gleam              # Entry point
│           ├── catseye/node.gleam         # Types + JSON FFI
│           ├── catseye/rules.gleam        # Facade (wires all rules)
│           ├── catseye/rules/ssrf.gleam
│           ├── catseye/rules/command_injection.gleam
│           ├── catseye/rules/path_traversal.gleam
│           ├── catseye/rules/sql_injection.gleam
│           ├── catseye/rules/taint.gleam  # Taint analysis engine
│           ├── catseye/test_runner.gleam  # 25 tests
│           └── catseye_engine_ffi.erl     # Erlang JSON FFI
├── scripts/
│   ├── scan_gleam.sh
│   └── scan_crystal.sh
├── test/samples/
│   ├── vulnerable.cr / safe.cr
│   └── vulnerable.gleam / safe.gleam
└── planning/
    ├── architecture.md         # This file
    ├── status.md               # Current status & roadmap
    └── archive/                # Completed plans
```
