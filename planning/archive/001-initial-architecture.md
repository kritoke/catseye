# Catseye Architecture

## Overview

Catseye is a multi-language static security analysis tool that finds vulnerabilities
(SSRF, command injection, etc.) in web applications using AST-based analysis.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Nim CLI (Orchestrator)                    │
│  - Recursive .cr file discovery                                  │
│  - Spawns Crystal extractor sub-processes                        │
│  - Pipes JSON to Gleam/Erlang engine                             │
│  - Formats findings with colored terminal output                 │
└──────────┬───────────────────────────────┬───────────────────────┘
           │ file path                     │ JSON (stdin/file)
           ▼                               ▼
┌─────────────────────┐         ┌─────────────────────────────────┐
│  Crystal Extractor   │         │  Gleam Logic Engine (BEAM)      │
│  - Crystal::Parser   │         │  - Decodes JSON → Node types    │
│  - Crystal::Visitor  │         │  - Recursive pattern matching   │
│  - Outputs JSON      │         │  - SSRF detection rules         │
│    Security Nodes    │         │  - Outputs findings JSON        │
└─────────────────────┘         └─────────────────────────────────┘
```

## Data Flow

1. **Nim** scans a target directory for `.cr` files
2. For each file, **Nim** runs the **Crystal Extractor** via `crystal run extractor.cr -- <file>`
3. The **Crystal Extractor** parses the AST, visits Call/Assign nodes, emits JSON
4. **Nim** aggregates all JSON and sends it to the **Gleam Engine** via `erl -noshell`
5. The **Gleam Engine** decodes the JSON, runs vulnerability rules, outputs findings
6. **Nim** formats the findings with colors and severity levels

## Bridge Format (Part 1)

A JSON array of "Security Node" objects. See `spec/security-node.schema.json`.

## Languages & Runtimes

| Component    | Language | Runtime    | Why                                 |
|--------------|----------|------------|-------------------------------------|
| CLI          | Nim 2.2  | Native     | Fast async I/O, zero-dep binaries   |
| Extractor    | Crystal  | Native     | Direct access to Crystal compiler   |
| Logic Engine | Gleam    | BEAM/Erlang| Fault-tolerant pattern matching     |

## Directory Layout

```
catseye/
├── flake.nix                  # Nix development environment
├── spec/
│   └── security-node.schema.json
├── src/
│   ├── cli/
│   │   └── catseye.nim        # Nim orchestrator
│   ├── extractor/
│   │   └── extractor.cr       # Crystal AST extractor
│   └── engine/
│       ├── gleam.toml         # Gleam project manifest
│       └── src/
│           ├── catseye.gleam          # Entry point + I/O
│           ├── catseye/node.gleam     # Node type + JSON decoding
│           └── catseye/ssrf.gleam     # SSRF rule
├── test/
│   └── samples/
│       ├── vulnerable.cr
│       └── safe.cr
└── planning/
    ├── architecture.md
    └── archive/               # Completed plans
```

## Future Extensions

- Additional rules: command injection, SQL injection, path traversal
- Language extractors: Ruby, Elixir, Python
- SARIF output format
- CI/CD integration
