# Catseye Quick Start

## Download & Install

```bash
# Download the latest release
curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz | tar xz

# Setup tree-sitter grammars
chmod +x SETUP_GRAMMARS.sh
./SETUP_GRAMMARS.sh
```

**That's it.** No Nix, no OCaml, no dependencies.

---

## Scan Your Code

```bash
# Security scan
./bin/catseye-ocaml --ai-lint your-project/

# Security + code smells
./bin/catseye-ocaml --ai-lint --claws your-project/

# JSON output (for CI/CD)
./bin/catseye-ocaml --ai-lint -f json your-project/ > results.json
```

---

## What It Detects

| Category | Examples |
|----------|----------|
| **Security** | SSRF, Command Injection, Path Traversal, SQL Injection, XSS |
| **AI Mistakes** | Hallucinated APIs, Framework confusion (Vue in React, Svelte 4 in Svelte 5) |
| **Code Smells** | Long methods, Complex conditionals, Feature envy |

**Supported:** Crystal, Gleam, JavaScript, TypeScript, Svelte, OCaml, Rust

---

## Build from Source

```bash
# Requires: opam, dune, tree-sitter
opam install --deps-only .
cd src/ocaml && dune build
```

Need help? [GitHub](https://github.com/kritoke/catseye)
