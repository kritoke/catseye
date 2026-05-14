# Gleam & Crystal Anti-Pattern Linter

## Goal
Detect common AI-generated anti-patterns in Gleam and Crystal code before they land in production.

## Rationale
AI code generation consistently produces certain classes of errors in Gleam and Crystal. These are not caught by standard linters because they're not syntax errors or type errors — they're design/code smell issues. A targeted linter can catch these early.

---

## Gleam Anti-Patterns to Detect

### Category: List Operations

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `list-map-flatten` | `list.map(xs, f) |> list.flatten` | Two-pass; allocate intermediate list | Use `list.flat_map(xs, f)` |
| `list-flatten-fold` | `list.fold(xs, [], fn(acc, x) { list.append(acc, ...) })` | O(n²) appends | Prepend and `list.reverse` at end, or use `list.concat` |
| `list-append-in-fold` | same as above | same | Use `list.prepend` + `list.reverse`, or `list.concat` |

### Category: Result/Error Handling

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `result-map-chain` | `Result.map(x, f) |> Result.map(y, g)` | Verbose chaining | Use `use` keyword with `try` |
| `case-result-unwrap` | `case result { Ok(v) -> v; Error(_) -> default }` | Verbose | Use `result |> result.unwrap(or: default)` |

### Category: String Operations

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `string-split-count` | `list.length(string.split(text, sub)) - 1` | Count occurrences | Use `text |> string.split(sub) |> list.length |> fn(n) { n - 1 }` — or better, a dedicated helper |
| `string-split-prefix` | `string.split(text, prefix) |> list.first` | Getting prefix | Use `string.starts_with` + `string.drop_left` |
| `string-replace-prefix` | `string.replace(text, prefix, "")` | Stripping prefix | Use `string.starts_with` + `string.drop_left` |

### Category: Dict/Set

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `dict-as-set` | `dict.keys(dict.from_list(xs))` to deduplicate | Using dict as set | Use `set.from_list` |
| `dict-member-check` | `case dict.get(d, k) { Ok(_) -> True; Error(_) -> False }` | Check membership | Use `dict.has_key(d, k)` |

### Category: Control Flow

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `case-true-conditional` | `case condition { True -> a; False -> b }` | Redundant case | Use `if condition { a } else { b }` |
| `case-some-let` | `case x { Some(v) -> case v { Some(w) -> ... } }` | Nested options | Use `let some(x) = ...` or `use some` |
| `if-let-else-nil` | `case x { Some(v) -> v; None -> Nil }` | Unwrap option | Use `option.unwrap(x)` or `x \|> option.unwrap(or: Nil)` |

### Category: Type Annotations

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `unnec-type-ann` | `let x: String = "hello"` | Unnecessary local annotation | Let type inference work |
| `over-annotated-fn` | `fn(x: String, y: Int) -> Bool` where args unused | Over-annotation | Use `_` for unused params |

### Category: Pipe/Function

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `identity-pipe` | `x \|> fn(y) { y }` | No-op pipe | Just use `x` |
| `gleam-function-overuse` | `function.compose(f, g)(x)` | Over-engineering | `g(x) |> f` often clearer |


### Category: OTP vs Custom Implementations ⚠️

AI often generates custom actor/process implementations when Gleam's OTP library should be used.

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `custom-process-loop` | `fn loop(state) { receive { msg -> loop(handle(msg, state)) } }` | Custom process loop | Use `gleam_otp/actor` or `gen_server` |
| `custom-state-ref` | `dict.new() |> ref` with manual state updates | Manual state in process | Use `gen_server` with `state` |
| `custom-message-handler` | `receive { :stop -> ...; _ -> loop(state) }` pattern | Re-inventing actor pattern | Use OTP `handle_info` |
| `custom-spawn` | `spawn(fn() { loop(state) })` without linking | Unlinked process, no supervision | Use `supervisor.start_child` |
| `custom-queue-in-process` | `dict.get(state, "queue")` manual queue in actor | Custom queue | Use `actor.queued` or proper queue lib |
| `custom-pid-registry` | `dict.new()` storing pids manually | Manual pid registry | Use `gleam_otp/registry` |
| `missing-actor-callback` | Implementing actor behavior manually | Not using OTP behaviors | Implement `actor.Callback` |

### Category: Standard Library vs Custom (Gleam)

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `custom-string-split` | Manually splitting strings | Rolling own | Use `string.split`, `string.concat` |
| `custom-base64` | Manual base64 encoding/decoding | Rolling own | Use `gleam_stdlib` or `gleam_base64` |
| `custom-uuid` | Manually generating UUIDs | Rolling own | Use `gleam_uuid` |
| `custom-http-client` | Using `fetch` or raw sockets | Rolling own | Use `mist` or `wisp` |
| `custom-json-encode` | Manually building JSON strings | Rolling own | Use `gleam_stdlib` `json` module |

---

## Crystal Anti-Patterns to Detect

### Category: Type Declarations

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `array-new` | `Array(Type).new` | Verbose | `[] of Type` |
| `array-new-size` | `Array(Type).new(size)` | Misunderstood | `Array(Type).new(size, default)` |
| `class-immutable` | `class Foo { @x: Int }` | Classes are mutable by default | Use `struct` for immutable data |

### Category: Control Flow

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `while-true` | `while true; ...; end` | Not idiomatic | Use `loop` |
| `begin-end-inline` | `begin x rescue y end` | Verbose | Inline: `x rescue y` |
| `rescue-exception` | `rescue ex : Exception` | Too broad | Rescue specific subclasses |

### Category: Nil Handling

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `not-nil-bang` | `x.not_nil!` | Panics if nil | Handle nil properly: `if x` |
| `missing-safe-nav` | `obj.foo.bar.baz` | NPE if intermediate nil | `obj&.foo&.bar&.baz` |
| `nil-check-then-access` | `if x; x.foo; end` | Verbose | `x&.foo` |
| `unless-nil` | `unless x.nil?; x.foo; end` | Awkward | `x.try(&.foo)` |

### Category: String Operations

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `string-int-loop` | `"#{x}#{y}#{z}"` in loop | Many allocations | `strings << x; ...; strings.join` |
| `string-concat` | `str1 + str2` in loop | Creates many strings | Use `String.build` |
| `string-gsub-simple` | `str.gsub(pattern, "")` | Overkill for single char | `str.gsub(char, "")` |

### Category: Class Methods

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `missing-self` | `def foo; @x; end` in class method | Class method without self | `def self.foo; ...; end` or add explicit `self.` |


### Category: Standard Library vs Custom (Crystal) ⚠️

AI often re-implements stdlib functionality that Crystal provides.

| ID | Pattern | Problem | Suggestion |
|----|---------|---------|------------|
| `custom-option-parser` | Manually parsing `ARGV` with splits | Rolling own | Use `OptionParser` |
| `custom-json-build` | `"{\"key\": \"#{val}\"}"` string building | Rolling own | Use `JSON::Builder` |
| `custom-json-parse` | `JSON.parse(string).as_h["key"]` without type safe | Rolling own | Use `JSON.parse?` with `from_json` |
| `custom-time-format` | Manual date formatting with string ops | Rolling own | Use `Time#to_s("%Y-%m-%d")` |
| `custom-logging` | `puts "ERROR: #{msg}"` to stderr | Rolling own | Use `Log` module |
| `custom-http-server` | Using sockets directly | Rolling own | Use `HTTP::Server` |
| `custom-uuid` | Random string generation for IDs | Rolling own | Use `UUID.random` |
| `custom-file-read` | `File.read_lines.join("\n")` | Not handling encoding | Use `File.read` with proper types |
| `custom-env-var` | Manual `ENV["KEY"]` with string keys | Not typed | Use `ENV` with proper typing |
| `custom-range-loop` | `while i < len; ...; i += 1; end` | Not idiomatic | `0.upto(len - 1)` or `each` |
| `custom-closure-serialize` | `-> { x }.to_s` | Can't serialize procs | Use `JSON::Serializable` properly |
| `custom-command-run` | `system("cmd")` without capturing | Not handling exit codes | Use `Process.run` |


---

## Implementation Plan

### Option 1: Gleam-based Linter
Build a linter tool in Gleam that parses Gleam code and reports anti-patterns.

**Pros**: Same language ecosystem, native to project
**Cons**: Parsing Gleam from scratch is complex

### Option 2: Use existing parsers + rules
- **Gleam**: Use the existing `@luke//` or `gleam_parser` crate, write rules in Gleam
- **Crystal**: Use `crystal parser` CLI + custom Ruby/JS rules

### Option 3: Pattern-based scanner (simplest)
Use regex/grep-based rules to catch common patterns in source files.

**Pros**: Quick to implement, works for both languages
**Cons**: Can't understand AST, may have false positives/negatives

---

## Recommended Approach

1. Start with **Gleam linter in Gleam** using the existing Gleam parser
2. Rules defined as data (not hardcoded), making them easy to extend
3. Output structured warnings with file, line, rule ID, message
4. Integrate with existing `just lint` or create `just ai-lint`

## Deliverables

- [ ] `linter/` directory with Gleam linter
- [ ] `rules/gleam-rules.gleam` — rule definitions for Gleam (incl. OTP patterns)
- [ ] `rules/crystal-rules.gleam` — rule definitions for Crystal
- [ ] `just ai-lint` — command to run both linters
- [ ] Documentation of each rule with examples
- [ ] **Category: OTP vs Custom for Gleam**
- [ ] **Category: stdlib vs Custom for both languages**

## Status
Draft — needs validation against real AI-generated code samples
