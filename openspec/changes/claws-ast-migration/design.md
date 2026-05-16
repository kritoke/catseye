# Claws → CatseyeAST Migration — Design

## Current State

Every Claws module takes `Security_node.t list` and builds function scopes via a duplicated `build_scopes` pattern:

```
nodes → group by file → sort by line → find Def nodes → 
  body = nodes between Def[i].line and Def[i+1].line
```

This heuristic scope building appears **4 times** (complexity.ml:82, anatomy.ml:157, extra_smells.ml:38, concurrency.ml:154). It's imprecise because:
- Line-range grouping can miss or mis-assign nodes near boundary lines
- Cannot distinguish nested functions from sequential ones
- GodObject counts methods per file, not per class/module boundary

## Target State

Claws modules take `CatseyeAST.t list` (one per file). Function scopes come from the AST directly:

```
CatseyeAST.t → mod_items → walk items
  IFunction(name, params, ret, body) → scope = { def_item; body_expr }
  IClass(name, items) / IModule(name, items) → walk inner items for scoped GodObject
```

The `scope` type changes from `{ def: Security_node.t; body: Security_node.t list }` to `{ def: Catseye_ast.Types.item; body: Catseye_ast.Types.expr; file: string; lang: string }`.

## Migration Strategy: Dual API

Each module gets a new `analyze_ast : CatseyeAST.t list -> claws_config -> Finding.t list` function alongside the existing `analyze : Security_node.t list -> claws_config -> Finding.t list`. The entry point (`smells.ml`) dispatches based on input type.

This allows incremental migration — we can land module-by-module and compare results.

## New Scope Type

```ocaml
(* In a shared scope module or smells.ml *)
type ast_scope = {
  def_item : Catseye_ast.Types.item;   (* the IFunction item *)
  body : Catseye_ast.Types.expr;       (* the function body expression *)
  file : string;
  lang : string;
}
```

## Counting via AST Walk

Instead of substring-matching node names (`is_decision`), walk the expression tree:

```ocaml
let rec count_decisions (expr : Catseye_ast.Types.expr) : int =
  match expr.expr_value with
  | EIf (_, then_, Some else_) -> 2 + count_decisions then_ + count_decisions else_
  | EIf (_, then_, None) -> 1 + count_decisions then_
  | ECase (_, branches) -> List.length branches + List.sum ... branches
  | EBinOp (_, "&&", _) | EBinOp (_, "||", _) -> 1 + ...
  | EBlock es -> List.sum (fun e -> count_decisions e) es
  | ELet (_, _, e2) -> count_decisions e2
  | ... -> 0
```

## Module Migration Order

1. **smells.ml** — Add `analyze_ast` dispatch alongside `analyze`
2. **complexity.ml** — Highest signal: exact cyclomatic from EIf/ECase
3. **anatomy.ml** — Exact params from IFunction patterns, module-scoped GodObject
4. **extra_smells.ml** — Largest file (176 refs), most complex migration
5. **dry.ml** — Subtree hashing (separate algorithm, lower priority)
6. **concurrency.ml** — Walk EApp for spawn/send/receive
7. **ameba_hook.ml** — No change (external tool, keeps Security_node.t)
8. **Cleanup** — Remove `analyze` (Security_node.t) overloads, deprecate bridge

## File Changes

| File | Change | Lines affected |
|------|--------|---------------|
| `smells.ml` | Add `analyze_ast` entry point | ~30 new lines |
| `complexity.ml` | Rewrite to walk CatseyeAST expr | ~120 lines rewritten |
| `anatomy.ml` | Rewrite scope building, GodObject | ~180 lines rewritten |
| `dry.ml` | Rewrite to hash expr subtrees | ~120 lines rewritten |
| `extra_smells.ml` | Rewrite all 10 detectors | ~500 lines rewritten |
| `concurrency.ml` | Rewrite to walk EApp | ~150 lines rewritten |
| `types.ml` | No change needed | 0 |
| `ameba_hook.ml` | No change | 0 |
| `orchestrator.ml` | Call `analyze_ast` with parsed ASTs | ~5 lines |
| `dune` | Add `catseye.ast` dependency | 1 line |
