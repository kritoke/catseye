# AI Anti-Pattern Linter - OCaml Implementation Plan

## Status: ✅ Complete

All phases of the AI Anti-Pattern Linter implementation are done and tested.

### Libraries Created

1. **tree_sitter** (`catseye.tree_sitter`)
   - XML tokenizer, CST parsing, navigation helpers
   - Position/range tracking
   - Language configurations for Gleam and Crystal

2. **generic_ast** (`catseye.generic_ast`)
   - Typed AST types (expressions, patterns, types, items, modules)
   - Gleam mapper from CST to typed AST

3. **ai_linter** (`catseye.ai_linter`)
   - `types.ml` - Core types (severity, violation, rule)
   - `gleam_rules.ml` - 6 Gleam anti-pattern rules
   - `crystal_rules.ml` - 23 Crystal anti-pattern rules
   - `ast_rules.ml` - 4 AST-based structural rules
   - `cli_rules.ml` - CLI-accessible rules with regex pattern matching

### CLI Integration

```bash
# Run with AI anti-pattern detection
catseye --ai-linter /path/to/project

# Combined with other flags
catseye --predator-vision --claws --ai-linter /path/to/project
```

### Crystal Rules (8 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| `array-new` | 📝 low | Array(Type).new is verbose |
| `puts-debug` | 📝 low | puts used for debugging |
| `pp-debug` | 📝 low | pp used for debugging |
| `hallucinated-method` | 🚫 high | Method may not exist (e.g., `to_map`) |
| `incorrect-crystal-syntax` | 🚫 high | Invalid syntax pattern (e.g., `let `) |
| `string-concat-in-loop` | 📝 low | String concatenation pattern |
| `unless-with-else` | ⚠️ medium | unless with else is confusing |
| `array-size-no-default` | ⚠️ medium | Array.new with size but no default |

### Gleam Rules (6 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| `unnecessary-list-wrap` | 📝 low | List.wrap is unnecessary |
| `deprecated-result-check` | 📝 low | Result.is_ok/is_err deprecated |
| `todo-in-code` | ⚠️ medium | Todo found in code |
| `panic-in-code` | ⚠️ medium | Panic found in code |
| `hallucinated-function` | 🚫 high | Function may not exist |
| `hallucinated-var` | 🚫 high | `var` is not valid Gleam keyword |

### AST-based Rules (4 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| `todo-in-code` | ⚠️ medium | Detects `todo`/`panic` in functions |
| `recursive-function` | ⚠️ medium | Detects infinite recursion |
| `duplicate-code` | 📝 low | Clone detection via structural hashing |
| `deep-nesting` | 📝 low | Functions with nesting depth >= 4 |

### Test Results

Scanned `test_ai/cr_sample.cr` (50 lines) with **16 violations**:
- 🚫 4 high (hallucinated methods, incorrect syntax)
- ⚠️ 3 medium (unless with else, array size issues)
- 📝 9 low (puts/pp debugging, string concatenation)

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Cat's Eye CLI                               │
├─────────────────────┬─────────────────────┬─────────────────────┤
│  Security Engine     │     AI Linter       │    Other Modules     │
│  (--predator)      │     (--ai-linter)    │    (--crows-nest)   │
├─────────────────────┴─────────────────────┴─────────────────────┤
│                   SHARED TREE-SITTER PARSER                   │
│                   (catseye.tree_sitter)                       │
├───────────────────────────────────────────────────────────────┤
│  Security_node  │  Generic_ast  │  Position  │  tree_sitter   │
└───────────────────────────────────────────────────────────────┘
```

### Grammar Compatibility

| Old Tag | New Tag (tree-sitter-gleam 0.1.5+) |
|---------|-----------------------------------|
| `function` | `function_statement` |
| `call` | `function_call` |
| `function_parameter` | `named_parameter` |
| `assignment` | `binding` |

### Key Fix Applied

Changed from `Str.string_match re line 0` to `Str.search_forward re line 0`:
- `string_match` only matches at the START of the string
- `search_forward` searches ANYWHERE in the string

### Verified Working

- ✅ Gleam parsing: functions, calls extracted
- ✅ Crystal parsing: modules, enums, structs found
- ✅ All dune tests pass
- ✅ Regex-based pattern matching (cli_rules.ml)
- ✅ AST-based rules (ast_rules.ml)
- ✅ Clone detection via structural hashing
- ✅ CLI integration with `--ai-linter` flag
- ✅ AI findings merged with security findings
- ✅ Tested on Crystal sample file (16 violations found)