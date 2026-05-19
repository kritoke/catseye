# Rust Idiomatic Pattern Detection

## Motivation

Like Gleam's `use-candidate` rule and Crystal's `sequential-blocking` rule,
Rust needs rules to detect non-idiomatic patterns that AI code generation
commonly produces.

## Problem

AI code generators often produce Rust that:
1. Uses `.clone()` unnecessarily instead of borrowing
2. Writes `.unwrap()` that can panic instead of proper error handling
3. Uses `for i in 0..n` loops where `.iter()` would work
4. Ignores Result/Option methods like `?` operator
5. Uses `Vec::new()` + `.push()` where `vec![]` is cleaner
6. Writes `match x { Some(v) => v, None => default }` instead of `unwrap_or(default)`
7. Uses `if x.is_some()` / `if x.is_none()` instead of pattern matching
8. Creates unnecessary owned copies in function arguments
9. Uses `Box::new()` unnecessarily
10. Ignores clippy warnings

## Proposed Rules

| Rule ID | Description | Threshold |
|---------|-------------|-----------|
| `rust-unwrap-panic` | `.unwrap()` calls that can panic | Function with external input |
| `rust-unnecessary-clone` | `.clone()` where borrow would work | Function argument |
| `rust-redundant-box` | `Box::new(x)` where `x` doesn't need heap | Expression |
| `rust-vec-new-push` | `Vec::new()` + `.push()` instead of `vec![]` | Function body |
| `rust-is-some-match` | `if x.is_some() { ... x.unwrap() ... }` instead of `if let Some(v) = x` | Expression |
| `rust-match-default` | `match x { Some(v) => v, None => default }` instead of `unwrap_or(default)` | Expression |
| `rust-for-range-index` | `for i in 0..vec.len()` where `.iter()` suffices | Loop |
| `rust-missing-question` | Nested `match` / `unwrap` on Results instead of `?` | Expression |

## Implementation Plan

1. Add rule detectors to `src/ocaml/lib/ai_linter/rust_rules.ml`
2. Add rule to `all()` function in same file
3. Ensure `analyze_module` is called in `orchestrator.ml` for Rust
4. Create test fixtures in `test/samples/rust_idioms/`
5. Verify with `dune runtest`

## Example Patterns

### `rust-unwrap-panic` (Safety - ERROR level)
```rust
// Non-idiomatic: panic on invalid input
fn parse_config(s: &str) -> Config {
    let parts: Vec<&str> = s.split(',').collect();
    Config {
        host: parts[0].to_string(),  // panics if no comma
        port: parts[1].parse().unwrap(),  // panics on invalid number
    }
}

// Idiomatic: proper error handling
fn parse_config(s: &str) -> Result<Config, ConfigError> {
    let parts: Vec<&str> = s.split(',').collect();
    Ok(Config {
        host: parts.first().ok_or(ConfigError::MissingHost)?.to_string(),
        port: parts.get(1).ok_or(ConfigError::MissingPort)?.parse().map_err(|_| ConfigError::InvalidPort)?,
    })
}
```

### `rust-missing-question` (TIPS-style)
```rust
// Non-idiomatic: nested matches
fn process(data: &[u8]) -> Result<String> {
    let parsed = parse_json(data)?;
    match parsed.get("name") {
        Ok(Some(name)) => match name.as_str() {
            Ok(s) => Ok(s.to_uppercase()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

// Idiomatic: using ?
fn process(data: &[u8]) -> Result<String> {
    let parsed = parse_json(data)?;
    let name = parsed.get("name")??;
    Ok(name.as_str()?.to_uppercase())
}
```

### `rust-vec-new-push` (Style)
```rust
// Non-idiomatic
let mut ids = Vec::new();
for item in items {
    ids.push(item.id);
}

// Idiomatic
let ids: Vec<_> = items.iter().map(|item| item.id).collect();
// or even better if items is owned:
let ids: Vec<_> = items.into_iter().map(|item| item.id).collect();
```

### `rust-is-some-match` (Style)
```rust
// Non-idiomatic
if value.is_some() {
    let v = value.unwrap();
    do_something(v);
}

// Idiomatic
if let Some(v) = value {
    do_something(v);
}
```

## Notes

- Many Rust rules overlap with clippy warnings - focus on patterns clippy misses
- Prioritize safety (unwrap vs ?) over style
- Consider adding auto-fix suggestions where straightforward