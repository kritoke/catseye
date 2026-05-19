# OCaml Idiomatic Pattern Detection

## Motivation

Like Gleam's `use-candidate` rule and Crystal's `sequential-blocking` rule,
OCaml needs rules to detect non-idiomatic patterns that AI code generation
commonly produces.

## Problem

AI code generators often produce OCaml that:
1. Uses verbose pattern matching where `Option.bind` or `let*` would suffice
2. Writes recursive functions with mutable state where tail-recursive solutions exist
3. Uses `List.hd` / `List.tl` instead of pattern matching
4. Builds lists with `List.append` in loops instead of `List.rev` + cons
5. Ignores labeled/optional arguments
6. Uses `failwith` instead of proper error types
7. Writes `if x = y then true else false` instead of `x = y`
8. Uses `List.length l > 0` instead of `l <> []`

## Proposed Rules

| Rule ID | Description | Threshold |
|---------|-------------|-----------|
| `ocaml-verbose-option` | Nested `match` on options where `let*` would be cleaner | 2+ nested option matches |
| `ocaml-non-tail-recursive` | Recursive functions without tail recursion in loops | List/array iteration |
| `ocaml-list-rev-append` | `List.append` in loop (O(n²)) instead of rev+cons | Loop with append |
| `ocaml-redundant-if-bool` | `if x = y then true else false` pattern | Function body |
| `ocaml-list-length-empty` | `List.length l > 0` instead of `l <> []` | Comparison |
| `ocaml-failwith-error` | `failwith` in library code instead of Result/Error type | Function returning Result |

## Implementation Plan

1. Add rule detectors to `src/ocaml/lib/ai_linter/ocaml_rules.ml`
2. Add rule to `all()` function in same file
3. Ensure `analyze_module` is called in `orchestrator.ml`
4. Create test fixtures in `test/samples/ocaml_idioms/`
5. Verify with `dune runtest`

## Example Patterns

### `ocaml-verbose-option` (TIPS-style)
```ocaml
(* Non-idiomatic: nested match on options *)
let result = match opt1 with
  | Some v1 -> (match opt2 v1 with
    | Some v2 -> Some (process v2)
    | None -> None)
  | None -> None

(* Idiomatic: using let* / Option.bind *)
let* v1 = opt1 in
let* v2 = opt2 v1 in
Some (process v2)
```

### `ocaml-list-rev-append` (Performance)
```ocaml
(* Non-idiomatic: O(n²) list building *)
let rec build_list n acc =
  if n = 0 then acc
  else build_list (n - 1) (List.append acc [n])

(* Idiomatic: O(n) with rev *)
let rec build_list n acc =
  if n = 0 then List.rev acc
  else build_list (n - 1) (n :: acc)
```

### `ocaml-failwith-error` (Error Handling)
```ocaml
(* Non-idiomatic: exceptions in library *)
let parse config =
  if not (valid config) then
    failwith "Invalid configuration"
  else
    parse_body config

(* Idiomatic: Result type *)
let parse config =
  if not (valid config) then
    Error `Invalid_config
  else
    Ok (parse_body config)
```

## Notes

- Focus on rules that provide clear TIPS-style recommendations
- Avoid rules that are too strict (OCaml has many valid styles)
- Prioritize safety and performance patterns