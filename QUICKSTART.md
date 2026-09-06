# Catseye Quick Start

## Download

Download the binary for your system:

| Platform         | Download                                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **Linux x86_64** | [catseye-linux-x86_64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz)   |
| **Linux ARM64**  | [catseye-linux-aarch64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-aarch64.tar.gz) |
| **macOS ARM64**  | [catseye-macos-aarch64.tar.gz](https://github.com/kritoke/catseye/releases/latest/download/catseye-macos-aarch64.tar.gz) |

```bash
# Example for Linux x86_64:
curl -L https://github.com/kritoke/catseye/releases/latest/download/catseye-linux-x86_64.tar.gz | tar xz
```

> **Note:** macOS Intel (x86_64) builds have been discontinued. Use macOS ARM64 for Apple Silicon Macs.

---

## Setup Grammars

Tree-sitter grammars are needed for parsing JavaScript, TypeScript, Svelte, Rust, and Nim. Run:

```bash
chmod +x install-grammars.sh
./install-grammars.sh
```

This downloads the required language parsers using `npx tree-sitter-cli`.

### F# Support (Optional)

F# analysis requires the .NET SDK 10.0+. If using Nix, run `nix develop` to get it automatically. Otherwise, install from [dotnet.microsoft.com](https://dotnet.microsoft.com/download).

### Nim Support (Optional)

Nim analysis uses tree-sitter-nim (included in `install-grammars.sh`). For enhanced analysis with nimalyzer, install [nimalyzer](https://github.com/thindil/nimalyzer) and place a `nimalyzer.cfg` in your project root. nimalyzer requires the [Nim compiler](https://nim-lang.org/install.html) on PATH.

---

## Basic Usage

```bash
# Scan a project
./catseye-ocaml /path/to/project

# With all checks enabled
./catseye-ocaml --rules src/ocaml/rules --cfg --claws --ai-lint /path/to/project
```

## Additional Documentation

- [RULES.md](RULES.md) — Complete rule reference
- [install.md](install.md) — Build from source instructions
- [README.md](README.md) — Full documentation
