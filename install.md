# Installing Catseye from Source

This guide covers building Catseye without Nix. If you have Nix installed, see [README.md](README.md) for the simpler `nix develop` approach.

## Prerequisites

### Required

- **OCaml** 5.0+ (with opam)
- **Dune** 3.0+
- **tree-sitter** CLI (for parsing non-Crystal languages)
- **tree-sitter grammars** for supported languages

### Optional (for Crystal support)

- **Crystal** 1.x (for the native Crystal extractor — without this, Crystal uses tree-sitter fallback)

### Optional (for F# support)

- **.NET SDK** 10.0+ (for the F# extractor using FSharp.Compiler.Service; the nix dev shell provides this automatically via `dotnetCorePackages.sdk_10_0`)

## Install Dependencies

### 1. Install OCaml and Dune

**macOS:**

```bash
brew install opam
opam init
opam switch create 5.4.1
eval $(opam env)
opam install dune
```

**Ubuntu/Debian:**

```bash
sudo apt-get install opam
opam init --disable-sandboxing  # needed for WSL or certain environments
opam switch create 5.4.1
eval $(opam env)
opam install dune
```

**Other distros:** See [opam binary distribution](https://opam.ocaml.org/doc/Install.html)

### 2. Install OCaml Dependencies

```bash
opam install \
  yojson \
  cmdliner \
  bos \
  rresult \
  logs \
  fmt \
  toml \
  kdl \
  ocamlgraph \
  alcotest
```

### 3. Install tree-sitter CLI

**macOS:**

```bash
brew install tree-sitter
```

**Linux (npm):**

```bash
npm install -g tree-sitter-cli
```

**From source:**

```bash
git clone https://github.com/tree-sitter/tree-sitter.git
cd tree-sitter
cargo build --release
cp target/release/tree-sitter ~/.local/bin/
```

### 4. Install tree-sitter Grammars

Catseye needs grammars for: JavaScript, TypeScript, Svelte, OCaml, Gleam, and Rust.

Create a grammars directory:

```bash
mkdir -p ~/.tree-sitter/grammars
cd ~/.tree-sitter/grammars
```

**JavaScript:**

```bash
git clone https://github.com/tree-sitter/tree-sitter-javascript.git
cd tree-sitter-javascript
npm install
npx tree-sitter generate src/parser.c --no-bindgen
cp src/parser.c ../javascript-parser.c
```

**TypeScript** (uses JavaScript grammar):

```bash
git clone https://github.com/tree-sitter/tree-sitter-typescript.git
cd tree-sitter-typescript
npm install
npx tree-sitter generate src/tsx/parser.c --no-bindgen
cp src/tsx/parser.c ../typescript-parser.c
```

**Svelte:**

```bash
git clone https://github.com/MetalDTO/tree-sitter-svelte.git  # fork with parser.c
cd tree-sitter-svelte
npm install
# If no pre-built parser, compile the grammar
npx tree-sitter generate src/parser.c --no-bindgen
cp src/parser.c ../svelte-parser.c
```

**OCaml:**

```bash
git clone https://github.com/tree-sitter/tree-sitter-ocaml.git
cd tree-sitter-ocaml
npm install
npx tree-sitter generate src/parser.c --no-bindgen
cp src/parser.c ../ocaml-parser.c
```

**Gleam:**

```bash
git clone https://github.com/aleclarsv/tree-sitter-gleam.git
cd tree-sitter-gleam
npm install
npx tree-sitter generate src/parser.c --no-bindgen
cp src/parser.c ../gleam-parser.c
```

**Rust:**

```bash
git clone https://github.com/tree-sitter/tree-sitter-rust.git
cd tree-sitter-rust
npm install
npx tree-sitter generate src/parser.c --no-bindgen
cp src/parser.c ../rust-parser.c
```

### 5. Set Environment Variables

```bash
export TREE_SITTER_GRAMMAR_DIR=~/.tree-sitter/grammars
# Or for specific grammars:
export TREE_SITTER_JAVASCRIPT_GRAMMAR=~/.tree-sitter/grammars/javascript-parser.c
export TREE_SITTER_TYPESCRIPT_GRAMMAR=~/.tree-sitter/grammars/typescript-parser.c
export TREE_SITTER_SVELTE_GRAMMAR=~/.tree-sitter/grammars/svelte-parser.c
export TREE_SITTER_OCAML_GRAMMAR=~/.tree-sitter/grammars/ocaml-parser.c
export TREE_SITTER_GLEAM_GRAMMAR=~/.tree-sitter/grammars/gleam-parser.c
export TREE_SITTER_RUST_GRAMMAR=~/.tree-sitter/grammars/rust-parser.c
```

Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) to persist them.

## Build Catseye

```bash
# Clone the repo
git clone https://github.com/catseye-scanner/catseye.git
cd catseye

# Create bin directory
mkdir -p bin

# Build Crystal extractors (optional, for faster Crystal parsing)
crystal build src/extractor/crystal/extractor.cr -o bin/catseye-crystal-extractor --release
crystal build src/extractor/crystal/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release

# Build OCaml engine
cd src/ocaml
opam install --deps-only -y .
dune build
cp _build/default/bin/main.exe ../../bin/catseye-ocaml
```

## Usage

```bash
# Set library path
export LD_LIBRARY_PATH=$HOME/.tree-sitter/grammars:$LD_LIBRARY_PATH

# Scan a project
./bin/catseye-ocaml --lang rust --ai-lint --claws path/to/project

# Or use the scripts from the release
./SETUP_GRAMMARS.sh
```

## Troubleshooting

### "No tree-sitter grammar found"

1. Check that grammars are compiled (`.c` files generated, not just `.js`)
2. Verify environment variables are set:
   ```bash
   echo $TREE_SITTER_GRAMMAR_DIR
   ls -la $TREE_SITTER_GRAMMAR_DIR
   ```
3. Check grammar compatibility — tree-sitter CLI and grammar must be compatible versions

### "Failed to load language"

The grammar parser binary may not be compiled with the `no-bindgen` flag. Regenerate:

```bash
cd tree-sitter-javascript
npx tree-sitter generate src/parser.c --no-bindgen
```

### Crystal extractor not working

Crystal is optional but provides faster parsing. If you don't have Crystal:

- The scanner falls back to tree-sitter for Crystal files
- Or use `crystal run src/extractor/crystal/extractor.cr` as a workaround

### ARM64 (Apple Silicon / aarch64)

Some grammars may need recompilation for ARM64:

```bash
# Install platform-specific tree-sitter
npm install -g tree-sitter-cli

# Regenerate grammars
cd tree-sitter-javascript
npx tree-sitter generate src/parser.c --no-bindgen
```

## Quick Reference

| Component         | Location                        | Notes                          |
| ----------------- | ------------------------------- | ------------------------------ |
| OCaml binary      | `bin/catseye-ocaml`             | Main scanner                   |
| Crystal extractor | `bin/catseye-crystal-extractor` | Optional, faster               |
| Grammars          | `~/.tree-sitter/grammars/`      | Must contain `.c` parser files |
| Config            | `.catseye.toml`                 | Per-project settings           |
| Cache             | `.catseye/`                     | Extraction cache               |
