# Rust Support Openspec

## Context

Rust support was added to Catseye scanner to enable:
1. File discovery for `.rs` files
2. Parsing via tree-sitter with WASM grammar support
3. AI antipattern detection for hallucinated Python/Ruby/Go APIs in Rust

## Current State

### Implemented
- [x] File discovery (`.rs` extension)
- [x] tree-sitter parsing via `--grammar-path` (WASM-compatible)
- [x] AI lint rules for hallucinated functions:
  - `range` → Rust: use `for i in 0..n`
  - `unwrap_result` → Rust: use `?` or `match`
  - `dict`, `list` → Rust: use `HashMap`, `Vec<T>`
  - Plus existing Python/Ruby patterns

### Current Limitations
- [ ] Security rules not yet implemented (no KDL rules for Rust)
- [ ] Code smells (Claws) not yet supported
- [ ] No test fixtures in `test/samples/rust/`
- [ ] No dedicated extractor (relies on tree-sitter WASM)
- [ ] Grammar requires `TREE_SITTER_RUST_GRAMMAR` environment variable

## Proposed Features

### 1. Rust Test Fixtures
Create `test/samples/rust/` with intentional vulnerability samples:
- Hallucinated API usage
- Unsafe patterns (unwrap, expect, panic)
- Inefficient code (unnecessary clones)

### 2. Rust Security Rules (Future)
KDL rules for:
- `unwrap-on-result` → suggest `?` operator
- `expect-on-option` → suggest `unwrap_or`, `unwrap_or_else`
- `panic-in-loop` → suggest proper error handling
- `use-after-move` detection

### 3. Enhanced AI Lint Rules
Expand `rust_rules.ml` with:
- `UnsafePanic` - detect `panic!()`, `unwrap()`, `expect()`
- `RustInefficiency` - unnecessary `.clone()`, `String::from(&var)`
- `TodoFound` - `TODO`/`FIXME` in production code

### 4. Self-Scan Verification
Add `test/samples/rust/` to catseye self-scan to verify clean findings

## Implementation Plan

### Phase 1: Test Fixtures
- [x] Create `test/samples/rust/hallucinated.rs` - intentional hallucinated API patterns
- [x] Create `test/samples/rust/unsafe.rs` - intentional unwrap/panic patterns
- [ ] Add to test suite

### Phase 2: Enhanced AI Lint
- [ ] Implement `UnsafePanic` rule
- [ ] Implement `RustInefficiency` rule
- [ ] Implement `TodoFound` rule

### Phase 3: Security Rules
- [ ] Create `rules/rust/` directory
- [ ] Add KDL rules for common Rust vulnerabilities

## Success Criteria
- Rust files can be scanned and show AI hallucination findings
- Test fixtures pass with expected findings
- Self-scan shows clean results for Rust code