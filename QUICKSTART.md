# Catseye Quick Start

## TL;DR

```bash
# 1. Download the binary for your system
curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz | tar xz

# 2. Setup grammars (downloads tree-sitter parsers)
./SETUP_GRAMMARS.sh

# 3. Scan your project
./catseye-ocaml --ai-lint --claws ./your-project
```

**That's it.** No Nix, no OCaml, no dependencies.

---

## Download Binaries

| System | Command |
|--------|---------|
| **Linux x86_64** | `curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz \| tar xz` |
| **Linux ARM64** | `curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-aarch64.tar.gz \| tar xz` |
| **macOS Intel** | `curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-macos-x86_64.tar.gz \| tar xz` |
| **macOS Apple Silicon** | `curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-macos-aarch64.tar.gz \| tar xz` |

After downloading, run:
```bash
./SETUP_GRAMMARS.sh
```

---

## Scan Your Code

```bash
# Security scan (recommended)
./catseye-ocaml --ai-lint your-project/

# Security + code smells
./catseye-ocaml --ai-lint --claws your-project/

# Specific languages only
./catseye-ocaml --lang javascript,typescript your-project/

# JSON output (for CI/CD)
./catseye-ocaml --ai-lint -f json your-project/ > results.json
```

---

## What It Detects

**Security vulnerabilities:**
- SSRF, Command Injection, Path Traversal, SQL Injection, XSS

**AI coding mistakes:**
- Hallucinated APIs (Python `len()` in Rust, React hooks in Svelte, etc.)
- Framework confusion (Vue in React, Svelte 4 in Svelte 5 code)

**Code quality issues:**
- Long methods, complex conditionals, dead code, feature envy

**Supported languages:** Crystal, Gleam, JavaScript, TypeScript, Svelte, OCaml, Rust

---

## Need Help?

```bash
# See all options
./catseye-ocaml --help

# Or visit
# https://github.com/kritoke/catseye
```