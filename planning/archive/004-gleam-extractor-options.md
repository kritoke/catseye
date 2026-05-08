# Gleam Extractor Options

## The problem
Gleam's compiler is written in Rust (`gleam_core` crate). Unlike Crystal,
it does NOT expose a public parser/AST API or a `--dump-ast` CLI flag.

## Options (ranked)

### Option 1: Rust extractor using `gleam_core` (most accurate)
- Use the same parser Gleam's compiler uses
- Would be a small Rust binary: `gleam_extractor`
- Full AST fidelity, handles edge cases
- Downside: adds Rust toolchain to the project

### Option 2: Parse Gleam-compiled Erlang output
- Run `gleam build` on target project, then parse `.erl` files
- Erlang has `epp_dodger` for parsing Erlang AST
- But: loses Gleam-level semantics (module names get mangled)

### Option 3: Regex/pattern-matching extractor (current approach)
- Works for common patterns (fn calls, let bindings)
- Fragile on edge cases, misses complex expressions
- Zero additional deps, fast
- Good enough for v0.1 / proof-of-concept

### Option 4: Write a Gleam self-parser in Gleam
- Gleam doesn't have a self-parser library
- Would need to write one from scratch (significant effort)

## Recommendation
For now: **Option 3** (regex extractor in Crystal) for bootstrapping.
File a ticket for **Option 1** (Rust extractor) as the production path.
This mirrors the architecture: each language's extractor uses that
language's own compiler tools. Since Gleam's compiler is Rust, the
idiomatic extractor would be Rust + `gleam_core`.
