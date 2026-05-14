# Catseye AST Architecture — Unified Parsing Framework

**Status:** Implementation Phase  
**Last Updated:** 2026-05-13  
**Supersedes:** `35-gleam-crystal-linter.md`, `37-ai-linter-architecture.md`

---

## Core Principles

This document formalizes the **three pillars** of Catseye's AST architecture:

### P1: Ban the Regex

> **If a file cannot be parsed into an AST, it is marked as a "Parsing Failure" finding.**

Regex-based analysis is **explicitly forbidden** in the security engine, AI linter, and claws module. The only exception is user-facing search/replace features in the CLI (not analysis).

**Rationale:**
- Regex cannot understand code structure, leading to false positives/negatives
- Regex patterns break on code formatting variations
- AST is language-agnostic — one rule format works for both Gleam and Crystal

**Implementation:**
- All rules operate on `CatseyeAST.t` only
- If parsing fails → emit `ParsingFailure` finding with error details
- No regex in `ai_linter`, `catseye_engine`, or `catseye_claws`

---

### P2: Macro-Awareness

> **The Crystal Worker must use `Crystal::Parser` with macro expansion enabled, so the OCaml engine sees the "Final Scent" of the code.**

Macros in Crystal can dramatically change the code structure. Analyzing pre-macro code misses security issues that exist after expansion.

**Examples of macro effects:**
```crystal
# Before macro expansion
Log.context { user_input }  # Log macro wraps expression

# After expansion (simplified)
begin
  __log_context = [] of String
  # ... log setup ...
  user_input  # The taint still flows here
ensure
  # ... log teardown ...
end
```

**Implementation:**
```crystal
# In extractor.cr
parser = Crystal::Parser.new(source)
parser.filename = file_path
# Enable macro expansion (Crystal 1.8+)
parser.macros_enabled = true

ast = parser.parse
# For better control, use Crystal's macro expansion API:
# ast = Crystal::ASTNode.expand_macros(ast)
```

**Verification:**
- Files with macros should parse identically whether run through `crystal eval` or the extractor
- Taint propagation must work on expanded code

---

### P3: The JSON Bridge

> **Both Tree-sitter (Gleam) and Native Parser (Crystal) output to the same `CatseyeAST.t` schema. The OCaml Taint Engine doesn't care how the tree was built, only that it is structurally sound.**

```
┌─────────────────────────────────────────────────────────────────────┐
│                     UNIFIED AST PIPELINE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Gleam File ──▶ tree-sitter XML ──▶ GleamMapper ──┐                │
│                                                   │                │
│  Crystal File ──▶ Crystal::Parser ──▶ CrystalMapper ──┤            │
│                                                   │                │
│                                       CatseyeAST.t ◀┘                │
│                                              │                      │
│                                              ▼                      │
│              ┌──────────────────────────────────────────────┐       │
│              │         OCaml Engine (Language-Agnostic)     │       │
│              ├──────────────────────────────────────────────┤       │
│              │  Security Engine │ AI Linter │ Claws │ Crow's Nest    │
│              └──────────────────────────────────────────────┘       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**CatseyeAST.t Schema:**

```ocaml
(* src/ocaml/lib/catseye_ast/types.ml *)

type position = {
  line : int;
  column : int;
  byte_offset : int;
}

type range = {
  start : position;
  end_ : position;
}

(* ── Expressions ──────────────────────────────────────────────────── *)

type literal =
  | LString of string
  | LInt of string
  | LFloat of string
  | LBool of bool
  | LUnit
  | LNull
  | LChar of string

type pattern =
  | PVar of string
  | PDiscard
  | PLiteral of literal
  | PTuple of pattern list
  | PList of pattern list
  | PRecord of (string * pattern) list
  | PType of string * pattern  (* typed pattern: x : Type *)

type expr = {
  expr_value : expr_value;
  expr_location : range;
}
and expr_value =
  | EUnit
  | ELiteral of literal
  | EVar of string
  | EApp of expr * expr list
  | EFn of pattern list * expr
  | EIf of expr * expr * expr option
  | ECase of expr * (pattern * expr) list
  | ELet of pattern * expr * expr
  | ELetAssert of pattern * expr * expr
  | EBlock of expr list
  | EFieldAccess of expr * string
  | ERecord of (string * expr) list
  | ETuple of expr list
  | EList of expr list
  | EBinOp of expr * string * expr
  | EUnOp of string * expr
  | EError of string
  | EUnknown of string

(* ── Items (top-level declarations) ──────────────────────────────── *)

type item = {
  item_value : item_value;
  item_location : range;
}
and item_value =
  | IFunction of string * pattern list * typ option * expr
  | IImport of string * string option  (* module, alias *)
  | ITypeAlias of string * (string * typ) list * typ
  | ITypeDef of string * (string * typ) list * variant list
  | IExternal of string * typ
  | IModule of string * item list
  | IClass of string * item list
  | IUnknown of string

(* ── Types ────────────────────────────────────────────────────────── *)

and typ =
  | TVar of string
  | TInt | TFloat | TString | TBool | TUnit | TUnknown
  | TList of typ
  | TTuple of typ list
  | TRecord of (string * typ) list
  | TFn of typ list * typ

and variant = {
  variant_name : string;
  variant_args : typ list;
  variant_tag : int;
}

(* ── Module ────────────────────────────────────────────────────────── *)

type t = {
  mod_lang : [`Gleam | `Crystal];
  mod_path : string;
  mod_items : item list;
  parse_errors : string list;
}
```

---

## Migration Plan

### Phase M1: Create Unified AST Library

**File:** `src/ocaml/lib/catseye_ast/`

```
src/ocaml/lib/catseye_ast/
├── dune                    # Library definition
├── types.ml                # CatseyeAST.t schema (above)
├── parse.ml               # Unified parsing interface
├── error.ml               # ParsingFailure finding type
└── catseye_ast.opam       # Opam package
```

**Parse API:**
```ocaml
val parse_file : lang:[`Gleam | `Crystal] -> path:string -> (t, parse_error)
val parse_string : lang:[`Gleam | `Crystal] -> source:string -> (t, parse_error)
```

### Phase M2: Remove Regex from AI Linter

**Files to change:**
- `src/ocaml/lib/ai_linter/gleam_rules.ml` — convert regex to AST patterns
- `src/ocaml/lib/ai_linter/crystal_rules.ml` — convert regex to AST patterns
- `src/ocaml/lib/ai_linter/cli_rules.ml` — remove if exists

**AST Pattern Format:**
```ocaml
(* Instead of: *)
{ id = "array-new"; pattern = "Array\\.new" }

(* Use: *)
{ 
  id = "array-new";
  ast_pattern = EApp (EVar "Array", [EVar "new"]);
  check = fun expr -> match expr with ...;
}
```

### Phase M3: Enable Macro Expansion in Crystal Extractor

**File to change:** `src/extractor/extractor.cr`

```crystal
# Before
parser = Crystal::Parser.new(source)
ast = parser.parse

# After
parser = Crystal::Parser.new(source)
parser.filename = file_path
parser.expand_macros = true  # Crystal 1.7+
ast = parser.parse

# Fallback for older Crystal versions
# Crystal::ASTNode.expand_macros(ast) if ast.responds_to?(:expand_macros)
```

**Error Handling:**
```crystal
begin
  ast = parser.parse
rescue ex : Crystal::SyntaxException
  # Emit ParsingFailure JSON
  puts {
    type: "parsing_failure",
    file: file_path,
    error: ex.message,
    line: ex.line_number
  }.to_json
end
```

### Phase M4: Create CrystalMapper to CatseyeAST

**File:** `src/ocaml/lib/catseye_ast/crystal_mapper.ml`

Maps Crystal's native AST (from the extractor JSON output) to `CatseyeAST.t`.

**Challenge:** Crystal extractor outputs `Security_node.t` JSON, not native Crystal AST.

**Solution:** Two options:

**Option A (Preferred):** Crystal extractor outputs `CatseyeAST.t` JSON directly
- Eliminates intermediate `Security_node.t` schema
- Single schema end-to-end

**Option B:** Map `Security_node.t` → `CatseyeAST.t`
- Maintains compatibility with existing security engine
- Adds a translation layer

### Phase M5: Wire GleamMapper to CatseyeAST

**File:** `src/ocaml/lib/generic_ast/gleam_mapper.ml`

Already outputs `Generic_ast.Ast.t`. Rename/move to `catseye_ast/gleam_mapper.ml`.

---

## Parsing Failure Finding

When a file cannot be parsed:

```ocaml
(* src/ocaml/lib/catseye_ast/error.ml *)

type parse_error = {
  file : string;
  line : int option;
  column : int option;
  message : string;
  severity : [`Error];
}

let to_finding (err : parse_error) : Finding.t = {
  rule_id = "parsing-failure";
  severity = High;
  file = err.file;
  line = err.line |? 0;
  message = Printf.sprintf "Failed to parse: %s" err.message;
  source_var = None;
  sink_var = None;
  flow = [];
}
```

**JSON Output from Crystal Extractor:**
```json
{
  "type": "parsing_failure",
  "file": "/path/to/file.cr",
  "line": 42,
  "error": "unexpected token '}' expecting identifier"
}
```

**JSON Output from Gleam Mapper:**
```json
{
  "type": "parsing_failure",
  "file": "/path/to/file.gleam",
  "line": 15,
  "error": "Unexpected token: expected '->' but found ')'"
}
```

---

## File Structure (Target)

```
src/ocaml/lib/
├── catseye_ast/                    # NEW: Unified AST library
│   ├── dune
│   ├── types.ml                    # CatseyeAST.t schema
│   ├── error.ml                    # ParsingFailure finding
│   ├── parse.ml                    # Unified parse interface
│   ├── gleam_mapper.ml             # Moved from generic_ast/
│   └── crystal_mapper.ml           # NEW: Crystal → CatseyeAST
│
├── catseye_engine/                 # Uses CatseyeAST.t
│   ├── engine.ml
│   ├── propagate.ml
│   └── ...
│
├── ai_linter/                      # Uses CatseyeAST.t only
│   ├── types.ml
│   ├── gleam_rules.ml              # AST patterns only
│   ├── crystal_rules.ml            # AST patterns only
│   └── ast_rules.ml
│
├── catseye_claws/                  # Uses CatseyeAST.t only
│   ├── complexity.ml
│   ├── anatomy.ml
│   └── ...
│
├── catseye_rules/                  # KDL rules reference CatseyeAST
│   ├── interpreter.ml
│   └── loader.ml
│
├── generic_ast/                    # DEPRECATED - move contents to catseye_ast
│   ├── ast.ml
│   └── ...
│
extractor/
├── extractor.cr                    # Outputs CatseyeAST JSON (or Security_node with bridge)
└── ...
```

---

## Deprecation Timeline

| Old Component | New Component | Deprecation Date |
|--------------|---------------|-----------------|
| `generic_ast/` | `catseye_ast/` | After M4 |
| `Security_node.t` | `CatseyeAST.t` | After bridge is stable |
| Regex rules | AST pattern rules | After M2 |

---

## Exit Criteria

- [ ] `CatseyeAST.t` is the single AST type used by all modules
- [ ] No regex patterns in security engine, AI linter, or claws
- [ ] Crystal extractor enables macro expansion
- [ ] Parsing failures emit structured `ParsingFailure` findings
- [ ] Gleam and Crystal scanners produce equivalent `CatseyeAST.t` output
- [ ] All existing tests pass with new architecture