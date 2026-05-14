# AI Anti-Pattern Linter - Architecture & Inspirations

## External Inspirations

### [elixir-vibe/ex_ast](https://github.com/elixir-vibe/ex_ast) ⭐ 19
**Search, replace, and diff Elixir code by AST pattern**

Key ideas:
- **AST-based pattern matching** using actual language syntax
- Patterns are valid Elixir code with special match semantics:
  - Variables (`name`, `expr`) capture matched nodes
  - `_` and `_name` are wildcards
  - Structs/maps match partially
  - **Pipe normalization** (`data |> Enum.map(f)` matches `Enum.map(data, f)`)
- CSS-like selectors with `ExAST.Selector`
- **Supports replacement** (not just detection)
- Syntax-aware diff

```elixir
# Find all IO.inspect calls
ExAST.search("lib/**/*.ex", "IO.inspect(_)")

# Replace dbg with the expression itself
ExAST.replace("lib/**/*.ex", "dbg(expr)", "expr")

# Relationship-aware queries
import ExAST.Query
query =
  from("def _ do ... end")
  |> where(contains("Repo.transaction(_)"))
  |> where(not contains("IO.inspect(...)"))
```

### [elixir-vibe/ex_slop](https://github.com/elixir-vibe/ex_slop) ⭐ ~20
**Credo checks that catch AI-generated code slop in Elixir**

40 checks organized into categories. Key patterns caught:

| Category | Examples |
|----------|----------|
| **Control Flow** | `case x do true -> a; false -> b end` → `if/else` |
| **Enum Anti-patterns** | `Enum.map(fn x -> x end)` → remove, `FlatMapFilter` → `Enum.filter` |
| **String Ops** | `Enum.reduce("", fn x, acc -> acc <> x end)` → `Enum.join/1` |
| **Identity Patterns** | `case r do {:ok, v} -> {:ok, v}; ... end` → `r` |
| **GenServer Misuse** | GenServer as simple KV store → use ETS or Agent |
| **Readability** | Narrator comments ("Here we fetch..."), Step comments |

**Key insight**: Most valuable checks catch **architectural/code smell issues**, not style.

### [elixir-vibe/ex_dna](https://github.com/elixir-vibe/ex_dna) ⭐ ~15
**Code duplication detector powered by Elixir AST analysis**

Key features:
- **Three clone types**: exact (I), renamed vars (II), near-miss similarity (III)
- **Multi-clause awareness**: consecutive `def` clauses analyzed as unit
- **Delegation pattern detection**: wrapper + body pairs
- **Pipe normalization**: `x |> f()` matches `f(x)`
- **Smart refactoring suggestions**: named after dominant pattern (`build_changeset`)

---

## Architecture Options for Gleam/Crystal Linter

### Option A: Regex-Based (Current - Phase 1)
**Pros**: Fast to implement, works for both languages
**Cons**: Can't understand AST, false positives/negatives

### Option B: AST-Based with Language Parsers (Recommended)
**Gleam**: Use `gleam_ast` crate or `gleam_parser`
**Crystal**: Use `crystal_parser` CLI + parse from Rust

**Pros**: Accurate, can provide auto-fix
**Cons**: More complex, need parsers for each language

### Option C: Hybrid (Regex + Heuristics)
Use regex for quick scan, AST for detailed analysis on matches.

---

## Proposed Architecture

```
ai-linter/
├── src/
│   ├── cli.rs              # CLI argument parsing
│   ├── lib.rs              # Core types
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── gleam.rs        # 22 Gleam rules
│   │   └── crystal.rs       # 23 Crystal rules
│   ├── detectors/
│   │   ├── mod.rs          # Detector trait
│   │   ├── regex.rs         # Regex-based (Phase 1)
│   │   └── ast.rs           # AST-based (Phase 2)
│   ├── reporters/
│   │   ├── mod.rs
│   │   ├── compact.rs       # Human-readable
│   │   ├── json.rs          # Machine-readable
│   │   └── sarif.rs         # GitHub integration
│   └── fixers/              # Phase 3
│       ├── mod.rs
│       ├── gleam.rs
│       └── crystal.rs
```

---

## Gleam Anti-Patterns (Updated from ex_slop inspiration)

### Category: List/Enum Operations
| ID | Pattern | Fix |
|----|---------|-----|
| `flat-map-filter` | `list.flat_map(fn x -> if cond, do: [x], else: [] end)` | `list.filter(fn x -> cond end)` |
| `identity-map` | `list.map(fn x -> x end)` | Remove the call |
| `identity-pipe` | `x \|> fn(y) { y }` | Just use `x` |
| `list-append-fold` | `list.fold([], fn acc -> list.append(acc, [x]) end)` | Prepend + reverse |
| `list-map-flatten` | `list.map(f) \|> list.flatten` | `list.flat_map(f)` |

### Category: Result/Option Handling
| ID | Pattern | Fix |
|----|---------|-----|
| `identity-result` | `case r do Ok(v) -> Ok(v); Error(e) -> Error(e) end` | `r` |
| `result-case-unwrap` | `case result do Ok(v) -> v; Error(_) -> default end` | `result \|> result.unwrap(or: default)` |
| `try-result-chain` | `Result.map(x, f) \|> Result.map(y, g)` | Use `use` keyword |
| `option-case-unwrap` | `case opt of Some(v) -> v; None -> default end` | `option.unwrap(opt, default)` |

### Category: Control Flow
| ID | Pattern | Fix |
|----|---------|-----|
| `case-true-false` | `case flag do true -> a; false -> b end` | `if flag { a } else { b }` |
| `boolean-if` | `if cond, do: true, else: false` | Use condition directly |
| `unless-else` | `unless x, do: a, else: b end` | Use `if` with positive condition |

### Category: OTP vs Custom ⚠️
| ID | Pattern | Fix |
|----|---------|-----|
| `custom-process-loop` | `fn loop(state) { receive { msg -> loop(handle(msg, state)) } }` | `gleam_otp/actor` |
| `custom-spawn` | `spawn(fn() { work() })` without linking | `supervisor.start_child` |
| `custom-state-dict` | `dict.new() \|> process.set_state` | Use `gen_server` state |
| `genserver-as-kv-store` | GenServer with just Map.get/Map.put on state | Use `agent` or `ets` |

### Category: Standard Library ⚠️
| ID | Pattern | Fix |
|----|---------|-----|
| `custom-json` | Manual JSON string building | `gleam_stdlib json` |
| `custom-base64` | Manual base64 encoding | `gleam_base64` |
| `custom-uuid` | Manual UUID generation | `gleam_uuid` |

---

## Crystal Anti-Patterns (from ex_slop inspiration)

### Category: Enum Equivalent Operations
| ID | Pattern | Fix |
|----|---------|-----|
| `flat-map-filter` | `array.flat_map { |x| x if cond }` | `array.select { |x| cond }` |
| `identity-map` | `array.map { |x| x }` | Remove |
| `reject-nil` | `array.reject { |x| x.nil? }` | `array.compact` |
| `map-then-join` | `array.map(&to_s).join` | `array.map_join` |
| `sort-then-reverse` | `array.sort.reverse` | `array.sort(:desc)` |

### Category: Control Flow
| ID | Pattern | Fix |
|----|---------|-----|
| `while-true` | `while true; ...; end` | `loop do ...; end` |
| `begin-rescue-inline` | `begin; x; rescue; y; end` | `x rescue y` |
| `rescue-exception` | `rescue ex : Exception` | Rescue specific types |
| `blanket-rescue` | `rescue _ -> nil` | Handle specific exceptions |

### Category: Nil Handling
| ID | Pattern | Fix |
|----|---------|-----|
| `not-nil-bang` | `x.not_nil!` | Handle nil properly |
| `missing-safe-nav` | `a.b.c.d` | `a&.b&.c&.d` |
| `dual-key-access` | `m[:key] \|\| m["key"]` | Normalize once |

### Category: Standard Library ⚠️
| ID | Pattern | Fix |
|----|---------|-----|
| `custom-option-parser` | Manual ARGV parsing | `OptionParser` |
| `custom-json` | String concatenation for JSON | `JSON::Builder` |
| `custom-logging` | `puts "ERROR: #{msg}"` | `Log.error { msg }` |
| `custom-http-server` | Raw sockets | `HTTP::Server` |
| `custom-command-run` | `system("cmd")` | `Process.run` |

### Category: Performance
| ID | Pattern | Fix |
|----|---------|-----|
| `string-concat-loop` | `str += x` in loop | `String.build` |
| `length-in-guard` | `when length(xs) == 0` | Pattern match `[]` |

---

## CLI Interface (Updated)

```bash
# Basic linting
ai-linter lint src/ --lang gleam
ai-linter lint src/ --lang crystal

# AST-based search (future)
ai-linter search "fn loop(state) { receive" --lang gleam

# Auto-fix (future)
ai-linter fix src/ --dry-run
ai-linter fix src/ --rule custom-process-loop

# Explain a rule
ai-linter rule list-map-flatten --lang gleam

# List rules by category
ai-linter rules --category otp --lang gleam
ai-linter rules --category stdlib --lang crystal
```

---

## Status
- [x] Phase 1: Regex-based core infrastructure built
- [ ] Phase 2: AST-based pattern matching (inspired by ex_ast)
- [ ] Phase 3: Auto-fix capabilities (inspired by ex_ast replace)
- [ ] Phase 4: Code duplication detection (inspired by ex_dna)
- [ ] Phase 5: IDE integration (LSP)

## Next Steps
1. Test current regex-based linter on real codebase
2. Investigate Gleam AST parser availability
3. Add remaining rules from ex_slop patterns
4. Build AST-based detector for more accurate matching
