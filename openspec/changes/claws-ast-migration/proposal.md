# Migrate Claws to CatseyeAST.t

**Change:** `claws-ast-migration`
**Priority:** P1
**Size:** XL (363 Security_node.t refs across 7 files)
**Status:** Open
**Blocks:** A5 (Deprecate Security_node.t)

## Problem

Claws is the heaviest consumer of `Security_node.t` (363 refs). All smell detectors iterate flat node lists and match on `node_type`, `name`, `args`, and `metadata`. This forces Claws to work with heuristics (substring matching for decision points, line-range grouping for function bodies) rather than precise AST structure.

With `CatseyeAST.t` now producing rich expression trees (`EIf`, `ECase`, `EApp`, `ELet`, etc.), Claws can:
- Count cyclomatic complexity exactly (walk `EIf`/`ECase` branches) instead of substring-matching node names
- Get function parameters from `IFunction` pattern lists instead of flat `Def` arg counts
- Detect structural duplication by hashing expression subtrees instead of flat node windows
- Track module/class boundaries from `IModule`/`IClass` instead of file-level grouping

## Prerequisites (all ✅ Done)

- A1: Crystal mapper produces rich AST
- A2: Gleam mapper produces rich AST
- A3: Bridge module `to_security_node.ml` exists and produces identical nodes

## Strategy: Module-by-Module Migration

Rather than rewriting all 363 refs at once, migrate one Claws module at a time. Each module can be independently switched from `Security_node.t list` to `CatseyeAST.t` input.

**Key insight:** The bridge (`to_security_node.ml`) already derives `Security_node.t` from `CatseyeAST.t`. So we can keep existing Security_node code as a fallback while adding AST-native paths.

### Migration approach per module

| Module | Current input | AST-native approach | Bridge fallback |
|--------|--------------|---------------------|-----------------|
| `smells.ml` | `Security_node.t list` | Accept `CatseyeAST.t list`, dispatch to modules | Keep `Security_node.t list` overload |
| `complexity.ml` | Substring-match node names for decision points | Walk `EIf`, `ECase` in `IFunction` bodies — exact count | Use bridge nodes |
| `anatomy.ml` | Group `Def` nodes by file, count args | Read `IFunction` patterns, group by `IModule`/`IClass` | Use bridge nodes |
| `dry.ml` | Hash flat node windows | Hash expression subtrees — structural similarity | Use bridge nodes |
| `extra_smells.ml` | Scope building via line ranges, flat node iteration | Walk function bodies directly | Use bridge nodes |
| `concurrency.ml` | Find spawn/send/receive by node name | Walk `EApp` calls in function bodies | Use bridge nodes |
| `ameba_hook.ml` | Passes nodes to external ameba — no change needed | Keep as-is | Keep `Security_node.t` |

### Phase plan

**Phase 1: Entry point + types** — Add `CatseyeAST.t` overload to `smells.ml`, keep existing API
**Phase 2: Complexity** — Exact cyclomatic from AST (highest signal improvement)
**Phase 3: Anatomy** — Exact params, module-scoped god object detection
**Phase 4: DRY** — Subtree hashing (replace window hashing)
**Phase 5: Extra smells** — AST-native long method, message chains, etc.
**Phase 6: Concurrency** — AST-native spawn/send/receive analysis
**Phase 7: Cleanup** — Remove `Security_node.t` overload, verify zero regressions

## Files

```
src/ocaml/lib/catseye_claws/
  smells.ml          — entry point: add CatseyeAST.t dispatch
  types.ml           — add AST-specific config (no new fields needed initially)
  complexity.ml      — rewrite to walk EIf/ECase
  anatomy.ml         — rewrite to walk IFunction patterns
  dry.ml             — rewrite to hash expr subtrees
  extra_smells.ml    — rewrite scope building from AST
  concurrency.ml     — rewrite to walk EApp calls
  ameba_hook.ml      — keep as-is (external tool)
```

## Acceptance

- All Claws detectors produce identical findings on test corpus
- `dune build` succeeds
- Quickheadlines scan results unchanged
- Facet_pi (Gleam) scan results unchanged
- Zero `Security_node.t` refs remain in Claws (except ameba_hook.ml)
