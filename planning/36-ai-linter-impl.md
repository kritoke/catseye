# AI Anti-Pattern Linter - Implementation Plan

## Overview
Build a linter that detects common AI-generated anti-patterns in Gleam and Crystal code.

## Architecture

```
ai-linter/
├── Cargo.toml           # Rust binary for speed
├── src/
│   ├── main.rs          # CLI entry, file walking
│   ├── lib.rs           # Core types and runner
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── gleam.rs     # Gleam rule registry
│   │   └── crystal.rs   # Crystal rule registry
│   ├── detectors/
│   │   ├── mod.rs
│   │   ├── regex.rs     # Regex-based pattern matching
│   │   └── heuristics.rs
│   └── reporters/
│       ├── mod.rs
│       └── json.rs      # JSON output format
├── justfile             # Commands
└── README.md
```

**Why Rust?** Pattern matching on large codebases needs speed. Gleam's JS target would be slower for scanning many files. Rust is fast and can be called from Gleam via ports if needed.

---

## Phases

### Phase 1: Core Infrastructure ⚡
**Goal**: Minimal working linter with regex-based detection

- [ ] Create `ai-linter/` directory with Cargo project
- [ ] Define `Rule`, `Violation`, `Severity` types
- [ ] Implement regex-based `Detector` trait
- [ ] JSON reporter
- [ ] CLI with `ai-linter --help`
- [ ] Config file support (`ai-linter.toml`)
- [ ] File glob walking

### Phase 2: Gleam Rules
**Goal**: Implement all Gleam anti-patterns

- [ ] List operation rules (`list-map-flatten`, `list-append-in-fold`)
- [ ] Result handling rules (`result-map-chain`, `case-result-unwrap`)
- [ ] String operation rules (`string-split-count`, `string-split-prefix`)
- [ ] Dict/Set rules (`dict-as-set`, `dict-member-check`)
- [ ] Control flow rules (`case-true-conditional`, `case-some-let`)
- [ ] **OTP rules** (`custom-process-loop`, `custom-spawn`, etc.)
- [ ] Stdlib rules (`custom-json-encode`, `custom-base64`)

### Phase 3: Crystal Rules
**Goal**: Implement all Crystal anti-patterns

- [ ] Type declaration rules (`array-new`, `class-immutable`)
- [ ] Control flow rules (`while-true`, `begin-end-inline`)
- [ ] Nil handling rules (`not-nil-bang`, `missing-safe-nav`)
- [ ] String operation rules (`string-int-loop`, `string-concat`)
- [ ] **Stdlib rules** (`custom-option-parser`, `custom-json-build`, `custom-logging`, etc.)

### Phase 4: Integration
**Goal**: Integrate with existing workflow

- [ ] `just ai-lint` command
- [ ] Git hook integration (pre-commit)
- [ ] CI/CD integration
- [ ] Editor integration (VS Code extension?)

### Phase 5: Refinements
**Goal**: Reduce false positives, improve accuracy

- [ ] AST-based rules (using tree-sitter)
- [ ] Suppression comments (`// ai-linter: disable custom-json`)
- [ ] Auto-fix suggestions
- [ ] HTML report generation

---

## Rule Definition Format

```toml
[[rules.gleam]]
id = "list-map-flatten"
severity = "warning"
category = "list-operations"
description = "Using list.map + list.flatten instead of list.flat_map"
pattern = '''
list\.map\([^,]+,\s*[^)]+\)\s*\|>\s*list\.flatten
'''
suggestion = "Use list.flat_map/2 instead"
example.bad = '''
list.map(items, fn(x) { process(x) }) |> list.flatten
'''
example.good = '''
list.flat_map(items, fn(x) { process(x) })
'''

[[rules.gleam]]
id = "custom-process-loop"
severity = "error"
category = "otp"
description = "Custom process loop instead of OTP actor"
pattern = '''
fn\s+loop\s*\([^)]*\)\s*\{[^}]*receive\s*\{
'''
suggestion = "Use gleam_otp/actor instead of manual loop"
```

---

## CLI Interface

```bash
# Lint all .gleam files in src/
ai-linter lint src/ --lang gleam

# Lint with config
ai-linter lint . --config ai-linter.toml

# Output formats
ai-linter lint . --format json
ai-linter lint . --format compact  # default
ai-linter lint . --format sarif    # for GitHub

# Check specific rules
ai-linter check src/ --rules list-map-flatten,custom-process-loop

# Show rule info
ai-linter rule list-map-flatten

# Fix suggestions
ai-linter fix src/ --dry-run
```

---

## Configuration File

```toml
# ai-linter.toml

[gleam]
enabled = true
exclude = ["test/", "gen/"]
exclude_paths = ["vendor/", "node_modules/"]

[crystal]
enabled = true
exclude = ["spec/", "tmp/"]

[rules]
# Enable/disable specific rules
list-map-flatten = true
custom-process-loop = true
custom-json-encode = true

# Severity overrides
"list-map-flatten".severity = "hint"

# Ignore specific files
[[ignore]]
file = "src/legacy/old_code.gleam"
rule = "case-true-conditional"
reason = "Legacy code, deprecating soon"
```

---

## Implementation Notes

### Pattern Matching Strategy
1. **Phase 1**: Regex on source text (fast, simple)
2. **Phase 5**: tree-sitter AST parsing (accurate, slower)

### Rule Testing
Each rule should have:
- Unit test with known bad/good examples
- Integration test against real AI-generated code

### Performance Targets
- Scan 10,000 Gleam files in < 5 seconds
- Scan 10,000 Crystal files in < 5 seconds
- Memory usage < 100MB for typical codebase

---

## Status
- [x] Plan created
- [x] Phase 1: Core Infrastructure
  - 20 Gleam rules (list ops, result handling, OTP, stdlib)
  - 23 Crystal rules (types, control flow, nil handling, stdlib)
  - Regex-based detection
  - JSON, compact, SARIF output formats
- [ ] Phase 2: AST-based pattern matching (inspired by ex_ast)
- [ ] Phase 3: Auto-fix capabilities
- [ ] Phase 4: Code duplication detection (inspired by ex_dna)
- [ ] Phase 5: Integration & IDE support
