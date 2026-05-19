# Catseye Quick Start

## Download

Download the binary for your system:

| Platform | Download |
|----------|----------|
| **Linux x86_64** | [catseye-linux-x86_64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz) |
| **Linux ARM64** | [catseye-linux-aarch64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-aarch64.tar.gz) |
| **macOS x86_64** | [catseye-macos-x86_64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-macos-x86_64.tar.gz) |
| **macOS ARM64** | [catseye-macos-aarch64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-macos-aarch64.tar.gz) |

```bash
# Example for Linux x86_64:
curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz | tar xz
```

---

## Setup Grammars

Tree-sitter grammars are needed for parsing. Run:

```bash
chmod +x install-grammars.sh
./install-grammars.sh
```

This downloads the required language parsers.

---

## Scan Your Code

```bash
# Security scan
./bin/catseye-ocaml --ai-lint your-project/

# Security + code smells (Claws)
./bin/catseye-ocaml --ai-lint --claws your-project/

# JSON output (CI/CD)
./bin/catseye-ocaml --ai-lint -f json your-project/ > results.json
```

---

## What It Detects

| Category | Examples |
|----------|----------|
| **Security** | SSRF, Command Injection, Path Traversal, SQL Injection, XSS |
| **AI Mistakes** | Hallucinated APIs, Framework confusion (React in Svelte, etc.) |
| **Code Smells** | Long methods, Feature envy, Deep inheritance |

**Supported:** Crystal, Gleam, JavaScript, TypeScript, Svelte, OCaml, Rust

---

## Build from Source

```bash
# Requires: opam, dune
git clone https://github.com/kritoke/catseye
cd catseye
opam install --deps-only .
cd src/ocaml && dune build
```

For more, see [install.md](install.md)