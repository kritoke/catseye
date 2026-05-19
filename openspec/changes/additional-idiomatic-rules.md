# Additional Idiomatic Rules for Gleam & Crystal

## Motivation

Build on the existing `use-candidate` (Gleam) and `sequential-blocking` (Crystal)
rules with additional TIPS-style rules for patterns AI commonly generates incorrectly.

## Gleam Additional Rules

### 1. Pipeline Overuse
Long pipelines (5+) become hard to read. AI often chains too many operations.

```gleam
// Non-idiomatic: 7-step pipeline
result
|> filter_valid
|> remove_duplicates
|> normalize
|> validate
|> transform
|> format
|> render

// Idiomatic: break into named intermediates
let valid = filter_valid(result)
let unique = remove_duplicates(valid)
let normalized = normalize(unique)
let validated = validate(normalized)
render(transform(validated, format))
```

**Rule:** `pipeline-steps-overload` (Hint) — 5+ steps

### 2. Result in List.map
Using `map` on Results instead of `map2` or traversal.

```gleam
// Non-idiomatic
list
|> list.map(parse_user)  // List(Result(a, b))
|> list.filter(is_valid)  // filter on Result, not value

// Idiomatic
list
|> list.filter(is_valid)
|> list.try_map(parse_user)  // Stops on first Error
```

**Rule:** `result-in-map` (Warning) — `list.map` on Result-typed values

### 3. List.flatten on Singleton Lists
`list.flatten` on known single-element lists.

```gleam
// Non-idiomatic
[[value]]
|> list.flatten

// Idiomatic
[value]
// or if you need a list of lists:
[[value]]
```

**Rule:** `list-flatten-singleton` (Hint) — flatten called on single-element sources

### 4. Debug Print in Library Code
`io.debug`, `io.println` in library code (not examples/tests).

```gleam
// Non-idiomatic: logging in library
pub fn process(data) {
  io.debug(data)  // Should use proper logging library
  do_work(data)
}

// Idiomatic: logging only in main/examples, or proper log library
pub fn process(data) {
  do_work(data)
}
```

**Rule:** `debug-in-library` (Warning) — `io.debug` outside examples/tests

### 5. Todo with Message
`todo as "message"` indicates incomplete implementation; plain `todo` is cleaner.

```gleam
// Non-idiomatic
todo as "implement this"

// Idiomatic  
todo
```

**Rule:** `todo-with-message` (Hint) — `todo as` pattern

### 6. Redundant type annotations
Verbose type annotations that the compiler can infer.

```gleam
// Non-idiomatic: redundant annotations
fn add(a: Int, b: Int) -> Int {
  a + b
}

// Idiomatic: let type inference work
fn add(a, b) {
  a + b
}
```

**Rule:** `redundant-type-annotation` (Hint) — Only for simple cases where inference is obvious

### 7. Missing Error Context
Result types without descriptive Error variants.

```gleam
// Non-idiomatic: generic errors
type MyError {
  Error  // Too generic
}

// Idiomatic: descriptive errors
type MyError {
  InvalidInput(String)
  NetworkError(NetworkIssue)
  Timeout
}
```

**Rule:** `generic-error-type` (Hint) — Single-variant error types

---

## Crystal Additional Rules

### 1. Nilable Instance Vars Without Check
Accessing `@ivar` that could be nil without nil-checking.

```crystal
# Non-idiomatic
class Cache
  @data : Hash(String, String)?

  def fetch(key)
    @data[key]  # Could be nil!
  end
end

# Idiomatic
def fetch(key)
  @data.not_nil![key]  # Explicit about intent
  # OR
  @data.try(&.[key])   # Safe navigation
end
```

**Rule:** `nilable-ivar-access` (Warning) — `@ivar` access on potentially nil instance var

### 2. Missing `?` on Potentially Nil
Crystal methods often return nil, not using `?` on safe methods.

```crystal
# Non-idiomatic
items.find { |x| x.id == id }.not_nil!

# Idiomatic: already returns Item | Nil, use proper handling
items.find { |x| x.id == id }.try(&.process)
# or
items.find! { |x| x.id == id }  # if you want it to raise
```

**Rule:** `missing-safe-call` (Hint) — Method chain without `?` on potentially nil intermediate

### 3. Parallel Assignment Confusion
Multiple assignment where sequential would be clearer.

```crystal
# Non-idiomatic
a, b = b, a  # Swap - this is fine
a, b = compute, compute  # Calls compute twice!

# Idiomatic
temp = compute
a, b = temp, other(temp)
```

**Rule:** `parallel-assign-side-effects` (Warning) — Side-effecting calls in parallel assignment

### 4. Case When True/False
Using case/when as an if replacement.

```crystal
# Non-idiomatic
result = case condition
  when true then "yes"
  when false then "no"
end

# Idiomatic
result = condition ? "yes" : "no"
```

**Rule:** `case-when-bool` (Hint) — case/when with boolean conditions

### 5. Macro Interpolation in Loop
Macros evaluated in loops without proper escaping.

```crystal
# Non-idiomatic
{% for i in 1..3 %}
  {{ i }}  # Interpolated at compile time, always same value
{% end %}

# Idiomatic: use runtime code if you need runtime values
(1..3).each do |i|
  puts i  # Runtime, can change
end
```

**Rule:** `macro-loop-interpolation` (Warning) — Loop variable interpolation in macro

### 6. String Concatenation in Loop
Using `+` or string interpolation in loops instead of `String.build`.

```crystal
# Non-idiomatic
result = ""
items.each do |item|
  result += item.to_s  # Creates new string each iteration
end

# Idiomatic
result = String.build do |str|
  items.each do |item|
    str << item
  end
end
```

**Rule:** `string-concat-loop` (Hint) — String concatenation in loop

### 7. Class Instance Var Without Type
Untyped instance variables can lead to runtime errors.

```crystal
# Non-idiomatic
class Container
  @data  # No type declaration

  def initialize
    @data = 42
  end
end

# Idiomatic
class Container
  @data : Int32

  def initialize
    @data = 42
  end
end
```

**Rule:** `untyped-instance-var` (Hint) — Instance var without type declaration

### 8. Missing `do...end` on Multi-line Blocks
Single-line blocks with complex logic.

```crystal
# Non-idiomatic
items.map { |x| x.process; x.format; x.validate }

# Idiomatic
items.map do |x|
  x.process
  x.format
  x.validate
end
```

**Rule:** `inline-block-complex` (Hint) — Single-line block with semicolons

---

## Implementation Priority

### High Priority
1. Gleam: `result-in-map` — Common AI mistake
2. Gleam: `pipeline-steps-overload` — Readability
3. Crystal: `string-concat-loop` — Performance
4. Crystal: `nilable-ivar-access` — Safety

### Medium Priority
5. Gleam: `generic-error-type` — API design
6. Gleam: `debug-in-library` — Code hygiene
7. Crystal: `missing-safe-call` — Nil safety
8. Crystal: `parallel-assign-side-effects` — Correctness

### Low Priority
9. Gleam: `list-flatten-singleton` — Minor style
10. Gleam: `todo-with-message` — Minor style
11. Crystal: `case-when-bool` — Style
12. Crystal: `macro-loop-interpolation` — Advanced
13. Crystal: `untyped-instance-var` — Style
14. Gleam: `redundant-type-annotation` — Style

## Notes

- Some Crystal rules overlap with built-in compiler warnings - focus on patterns the compiler misses
- Gleam rules should take advantage of its strong type system
- Consider adding auto-fix suggestions for simple transformations