# Svelte/TypeScript Idiomatic Pattern Detection

## Motivation

We have Svelte 5 Rune Validation rules, but need more TIPS-style rules
for Svelte and TypeScript to detect non-idiomatic patterns that AI
code generation commonly produces.

## Problem

AI code generators often produce Svelte/TypeScript that:

### Svelte Issues

1. Uses legacy Svelte 4 stores (`$:` reactive declarations, `writable()`) in Svelte 5 context
2. Uses `createEventDispatcher` instead of callback props
3. Uses legacy lifecycle hooks (`onMount`, `onDestroy`) instead of `$effect`
4. Ignores `$state` runes for mutable data
5. Uses `{@html user_input}` without sanitization (XSS)

### TypeScript Issues

1. Uses `any` type instead of proper generics
2. Uses `as` type assertions instead of type guards
3. Uses `!` (non-null assertion) instead of proper null checks
4. Ignores readonly arrays where appropriate
5. Uses `Array.from()` where spread would work
6. Uses `typeof x === 'string'` instead of type predicates
7. Uses `interface` inconsistently with `type` aliases
8. Creates empty arrays/objects mutably instead of `as const`

## Proposed Rules

### Svelte Rules

| Rule ID                    | Description                                       | Severity               |
| -------------------------- | ------------------------------------------------- | ---------------------- |
| `svelte-legacy-store`      | Svelte 4 stores in code that should use runes     | Warning                |
| `svelte-event-dispatcher`  | `createEventDispatcher` instead of callback props | Warning                |
| `svelte-legacy-lifecycle`  | Legacy lifecycle hooks instead of `$effect`       | Hint                   |
| `svelte-mutable-primitive` | Primitive values without `$state`                 | Hint                   |
| `svelte-html-xss`          | `{@html}` with dynamic content                    | Error (already exists) |

### TypeScript Rules

| Rule ID                 | Description                                         | Threshold          |
| ----------------------- | --------------------------------------------------- | ------------------ |
| `ts-any-type`           | `any` type usage instead of proper generics         | Function signature |
| `ts-non-null-assertion` | `!` assertion instead of null check                 | Expression         |
| `ts-type-assertion`     | `as` instead of type guard                          | Expression         |
| `ts-array-from-spread`  | `Array.from(x)` instead of `[...x]`                 | Expression         |
| `ts-primitive-wrapper`  | `new Boolean/String/Number` instead of primitives   | Expression         |
| `ts-readonly-missing`   | Array/object literals without `readonly`/`as const` | Variable decl      |

## Implementation Plan

1. Add Svelte rules to `src/ocaml/lib/ai_linter/svelte_rules.ml`
2. Add TypeScript rules to `src/ocaml/lib/ai_linter/javascript_rules.ml`
3. Add rules to respective `all()` functions
4. Ensure Rust/Svelte/JS TypeScript analysis is called in `orchestrator.ml`
5. Create test fixtures in `test/samples/svelte_idioms/` and `test/samples/typescript_idioms/`
6. Verify with `dune runtest`

## Example Patterns

### Svelte

#### `svelte-legacy-store` (TIPS-style)

```svelte
<!-- Non-idiomatic: Svelte 4 store pattern -->
<script>
  import { writable } from 'svelte/store';
  const count = writable(0);
  $: doubled = $count * 2;
</script>

<!-- Idiomatic: Svelte 5 runes -->
<script>
  let count = $state(0);
  let doubled = $derived(count * 2);
</script>
```

#### `svelte-mutable-primitive` (Hint)

```svelte
<!-- Non-idiomatic: reactive but not stateful -->
<script>
  let name = "World";  // Won't trigger re-render on change
</script>

<!-- Idiomatic: use $state for mutable primitives -->
<script>
  let name = $state("World");
</script>
```

### TypeScript

#### `ts-any-type` (TIPS-style)

```typescript
// Non-idiomatic: any loses type safety
function processData(data: any) {
  return data.value; // No type checking
}

// Idiomatic: proper generics
function processData<T extends { value: unknown }>(data: T) {
  return data.value; // Type-safe
}
```

#### `ts-non-null-assertion` (Warning)

```typescript
// Non-idiomatic: can throw if value is null
const name = user!.profile!.name;

// Idiomatic: proper null checking
const name = user?.profile?.name ?? "Unknown";
```

#### `ts-primitive-wrapper` (Hint)

```typescript
// Non-idiomatic
const bool = new Boolean(true);
const str = new String("hello");
const num = new Number(42);

// Idiomatic
const bool = true;
const str = "hello";
const num = 42;
```

## Notes

- Svelte rules should distinguish between Svelte 4 and Svelte 5 contexts
- TypeScript rules should focus on type safety and modern patterns
- Consider adding auto-fix suggestions where straightforward
