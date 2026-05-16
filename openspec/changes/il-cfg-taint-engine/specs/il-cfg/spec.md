## ADDED Requirements

### Requirement: IL types from CatseyeAST
The IL module SHALL provide types `il_node`, `il_block`, `lval`, and `il_expr` representing simplified program structure with field-sensitive lvalues and explicit branch/return nodes.

#### Scenario: Convert EIf to ILBranch
- **WHEN** `of_catseye_ast` encounters `EIf (cond, then_, Some else_)`
- **THEN** it produces `ILBranch (translate cond, translate then_, Some (translate else_))`

#### Scenario: Convert ELet to ILAssign
- **WHEN** `of_catseye_ast` encounters `ELet (PVar "x", e1, e2)`
- **THEN** it produces `ILAssign (LVVar "x", translate e1)` followed by translation of e2

#### Scenario: Convert EFieldAccess to nested lval
- **WHEN** `of_catseye_ast` encounters `EFieldAccess (EVar "params", "url")`
- **THEN** it produces `IEField (IEVar "params", "url")`

### Requirement: CFG builder from IL
The CFG builder SHALL convert an `il_block` into a list of `basic_block` records, each with an ID, node list, and successor IDs. Branches create separate blocks with merge points.

#### Scenario: Linear block
- **WHEN** a function body has no branches
- **THEN** the CFG contains a single basic block with all IL nodes and no successors

#### Scenario: If-else creates three blocks
- **WHEN** a function body has `ILBranch (cond, [a], Some [b])` followed by `[c]`
- **THEN** the CFG contains: entry block (up to branch), then-block with edge to merge, else-block with edge to merge, merge-block containing [c]

### Requirement: CatseyeAST conversion preserves line info
Every IL node SHALL carry source line information from the originating CatseyeAST node, so findings report correct line numbers.

#### Scenario: Line numbers match source
- **WHEN** `ILAssign` is produced from `ELet` at line 42
- **THEN** the IL node records line 42

### Requirement: Function-level CFG
The converter SHALL produce one CFG per function definition, with the function name and parameters recorded.

#### Scenario: Top-level function
- **WHEN** CatseyeAST contains `IFunction ("pull", [PVar "config"], None, body)`
- **THEN** a named CFG is produced with function="pull", params=["config"], and blocks from the body
