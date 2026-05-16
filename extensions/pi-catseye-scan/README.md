# Pi Extension: Catseye Security Scan

Registers the `catseye_scan` tool that the LLM can call directly to scan a project directory for security vulnerabilities, code smells, and AI antipatterns.

## Features

- **Taint analysis** — SSRF, injection (SQL/command/path/LDAP), open redirects, hardcoded secrets
- **CFG engine** (`cfg: true`) — branch-aware dataflow analysis with field-sensitive tracking
- **Code smells** (`claws: true`) — complexity, god objects, deep nesting, long parameter lists
- **AI antipatterns** (`ai_lint: true`) — hallucinated methods, hardcoded URLs, non-idiomatic code
- **Taint flow traces** — findings include source → sink flow paths

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `directory` | string | auto | Directory to scan (defaults to `src/`) |
| `rules_dir` | string | auto | KDL rules directory |
| `cfg` | boolean | false | Use IL/CFG taint engine (more sensitive) |
| `ai_lint` | boolean | true | Enable AI antipattern detection |
| `claws` | boolean | true | Enable code smell detection |

## Install

```bash
# From the catseye repo
just install-pi

# Or manually — project-local
mkdir -p .pi/extensions/catseye-scan
cp extensions/pi-catseye-scan/index.ts .pi/extensions/catseye-scan/

# Or manually — global
mkdir -p ~/.pi/agent/extensions/catseye-scan
cp extensions/pi-catseye-scan/index.ts ~/.pi/agent/extensions/catseye-scan/
```

## Requirements

- `catseye-ocaml` binary in PATH, `~/.local/bin/`, or local `bin/`
- KDL rules directory at `~/.local/lib/catseye/rules/` or local `src/ocaml/rules/`

Both installed by `just install` or `just install prefix=~/.local`.
