# Claws Improvement Plan

## Current State (commit bcb9697)

| Project | DRY | LPL | GO | DN | HC | Total Smells |
|----------|---:|---:|---:|---:|---:|---:|
| quickheadlines | 15 | 20 | 4 | 1 | 0 | 40 |
| PrismatIQ | 14 | 19 | 3 | 1 | 0 | 37 |
| fetcher.cr | 78 | 16 | 5 | 14 | 0 | 113 |
| vug.cr | 14 | 4 | 0 | 3 | 0 | 21 |
| sassd.cr | 2 | 8 | 1 | 0 | 0 | 11 |
| lexis-minhash | 1 | 3 | 2 | 1 | 0 | 7 |
| azurite.cr | 0 | 4 | 0 | 0 | 0 | 4 |
| carafe.cr | 15 | 1 | 2 | 8 | 0 | 26 |

## Improvements

### I1: Skip `initialize` in LongParameterList (impact: -23 findings)
Crystal `initialize` methods with many params are DTOs/records — 
the params ARE the fields. Not a design flaw.
- Skip `Def` nodes named `initialize` from LPL check
- User feedback: unanimous "this is acceptable"

### I2: GodObject — exclude `initialize` from method count (impact: -some)
`initialize` is boilerplate. Counting it inflates method counts.
Also consider: include files with `include JSON::Serializable` 
(auto-generated methods) as lower priority.

### I3: DRY — skip `rows.read` / repetitive DB read patterns (impact: -big)
The `x = rows.read(T)` pattern in every Crystal DB repository 
normalizes identically. Not meaningful duplication.
- Skip windows where all calls are the same (rows.read, db.query, etc.)
- Alternative: skip windows where every assign has the same call arg

### I4: DRY — skip getter/setter/property call sequences (impact: -some)
Remaining property-like patterns after filtering.
Already partially handled.

### I5: LongParameterList — distinguish DTOs from functions (impact: better UX)
Functions with `initialize` AND `@x = x` patterns are DTOs — 
downgrade from Hiss to Meow or skip entirely.

### I6: DeepNesting — sequential vs nested heuristic (impact: fewer FP)
Current heuristic counts ALL if/unless/case as nesting.
Sequential ifs should not count.
Without full AST, approximate: if scope-creating nodes are on 
different lines but have the same indentation pattern, they're sequential.
Alternative: raise threshold from 4 to 5 for Meow.

### I7: DRY — `require` at file top should not create window overlap
Even after filtering, if require statements push other nodes 
into the same window, they create noise.
Already fixed by filtering imports from windows.

### I8: Add config for per-rule suppression in TOML
Users should be able to suppress specific findings:
```toml
[claws.suppress]
DRYViolation = ["**/dtos/**", "**/repositories/**"]
LongParameterList = ["initialize"]
```

### I9: Smarter GodObject — group by module/class, not file
Crystal files often contain one module with related methods.
If all defs belong to the same logical module, it's not a God Object.
Requires tracking module boundaries from the extractor.
