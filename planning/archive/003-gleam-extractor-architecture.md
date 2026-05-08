# Gleam Extractor Architecture

## Two-source approach

### Source 1: `gleam export package-interface`
Gives us the complete type/function signature info for every module:
- Module names, function names, parameter types, return types
- Type definitions (constructors, fields)
- Deprecation info, documentation

Limitation: No line numbers, no call sites, no actual argument values.

### Source 2: Nim + tree-sitter (treestand) parsing .gleam files
Gives us the actual source structure:
- Function call sites with real arguments
- Line numbers
- Let bindings and their RHS expressions
- Pipe chains

### Merging
Tree-sitter gives us the concrete AST with locations.
Package-interface gives us type info (what params a function expects).
Combined: we know WHERE a call happens (tree-sitter) and WHAT it expects
(package-interface), enabling better taint analysis.

### Why not Crystal for this?
Crystal's `Crystal::Parser` only parses Crystal syntax. Gleam has its own
syntax. We need a Gleam grammar parser, and tree-sitter has one built-in.
Nim is our orchestrator language, so it naturally owns this extractor.

### Why not regex?
Regex works for simple patterns but fails on:
- Nested parentheses in arguments
- Multi-line function calls
- Pipe chains (|>)
- Case expressions with pattern matching
- Block comments

Tree-sitter handles all of these correctly.
