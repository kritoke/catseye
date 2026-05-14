# AI Anti-Patterns: Hunting Plan for Catseye & Claws

**Status:** Planning  
**Created:** 2026-05-13  
**Purpose:** Document how the Catseye scanner and Claws module detect AI-generated anti-patterns  

**Existing Coverage:** Some patterns overlap with existing Claws smells (`extra_smells.ml`) and reachability analysis. This document focuses on patterns **unique to AI generation** that need dedicated detection.

See: `src/ocaml/lib/catseye_claws/extra_smells.ml` (dead code, message chains, data clumps, etc.)  
See: `src/ocaml/lib/catseye_engine/reachability.ml` (unreachable code detection)

---

## Overview

AI models are "stochastic parrots" — they generate code based on statistical patterns rather than true understanding. For strict languages like Gleam and Crystal, this leads to systematic failures that Catseye can catch by verifying against the AST rather than guessing based on probability.

```
┌────────────────────────────────────────────────────────────────────┐
│                    AI PARROT vs CATSEYE                            │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  AI Model                          Catseye Engine                  │
│  ────────                          ──────────────                  │
│  Probability-based         ───▶   AST-verified                    │
│  Pattern matching           ───▶   Type checking                  │
│  Guesses from training      ───▶   Static analysis                │
│  Misses context             ───▶   Cross-references whole project  │
│                                                                    │
│  "This method might          "This method does NOT                 │
│   exist somewhere..."         exist in Crystal stdlib"             │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## Pattern Category Map

```
AI Anti-Patterns
├── 1. GHOST SCENT (Hallucinations & Legacy Syntax)
│   ├── 1.1 Non-existent Standard Library Methods
│   ├── 1.2 Legacy/Deprecated Syntax
│   └── 1.3 Mixing Ecosystems (Wrong Packages)
│
├── 2. THE FOREIGNER (Non-Idiomatic Translation)
│   ├── 2.1 Manual Loops vs Iterators
│   ├── 2.2 Imperative Gleam (Mutation)
│   └── 2.3 Primitive Obsession
│
├── 3. THE HAPPY PATH (Safety & Error Handling)
│   ├── 3.1 Nil-Chaser (Unchecked Nil)
│   ├── 3.2 Ignoring the Result
│   └── 3.3 Unsafe Pointers
│
├── 4. THE TANGLE (Structural Redundancy)
│   ├── 4.1 Redundant Conversions
│   ├── 4.2 Duplicate Validation
│   └── 4.3 Library Bloat
│
├── 5. THE MUTE TRAP (Security Blind Spots)
│   ├── 5.1 Hardcoded Secrets
│   └── 5.2 SSRF-Prone String Concatenation
│
├── 6. THE COPIER (Copy-Paste Errors)
│   ├── 6.1 Variable Name Leakage
│   ├── 6.2 Inconsistent State Updates
│   └── 6.3 Hardcoded IDs/URLs
│
├── 7. THE CONFUSED (Language Feature Misuse)
│   ├── 7.1 Wrong Enum/Module Access
│   └── 7.2 Misunderstanding Opaque Types
│
├── 8. THE LOOPER (Iteration Mistakes)
│   ├── 8.1 Infinite Recursion (same arg passed)
│   └── 8.2 Off-By-One Errors in Range
│
├── 9. AI-UNIQUE CODE SMELLS (Already in Claws extra_smells)
│   ├── ✅ Long Method → existing `check_long_method`
│   ├── ✅ Complex Conditional → existing `check_complex_conditionals`
│   ├── ✅ Message Chains → existing `check_message_chains`
│   ├── ✅ Data Clumps → existing `check_data_clumps`
│   ├── ✅ Flag Arguments → existing `check_flag_arguments`
│   ├── ✅ Complex Match/Case → existing `check_complex_match`
│   ├── ✅ Dead Code → existing `check_dead_code`
│   └── ✅ Data Class, Feature Envy → existing
│
└── 10. AI-UNIQUE PATTERNS (Beyond Standard Smells)
    ├── 10.1 Unreachable Branches (duplicate case patterns)
    └── 10.2 Empty Catch Blocks
```

---

## Category 1: Ghost Scent

**AI Behavior:** Mixing versions, languages, or using methods that don't exist.

### 1.1 Non-existent Standard Library Methods

**Hunt Method:** Standard Library Index + AST Call Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│                     STANDARD LIBRARY INDEX                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │
│  │  Crystal    │     │   Gleam     │     │  Language   │           │
│  │  Stdlib v1.9│     │  Stdlib 1.0 │     │   Version   │           │
│  │  ─────────  │     │  ─────────  │     │   ───────   │           │
│  │  Array.new  │     │  List.map   │     │  Detected   │           │
│  │  Hash.new   │     │  Result.map │     │  from file  │           │
│  │  String.split│    │  Option.all │     │             │           │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘           │
│         │                   │                   │                   │
│         └───────────────────┼───────────────────┘                   │
│                             ▼                                       │
│                  ┌─────────────────────┐                           │
│                  │  STANDARD LIB INDEX │                           │
│                  │  catseye_stdlib/    │                           │
│                  └──────────┬──────────┘                           │
│                             │                                      │
│                             ▼                                      │
│         ┌───────────────────────────────────────┐                  │
│         │  For each EApp node in AST:           │                  │
│         │  1. Extract module + method name       │                  │
│         │  2. Check if exists in index           │                  │
│         │  3. Flag if not found                  │                  │
│         └───────────────────────────────────────┘                  │
│                             │                                      │
│                             ▼                                      │
│                    ┌─────────────────┐                             │
│                    │ Finding:        │                             │
│                    │ "hallucinated-  │                             │
│                    │  method"        │                             │
│                    └─────────────────┘                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/ghost_scent/stdlib_checker.ml *)

type stdlib_index = {
  lang : [`Gleam | `Crystal];
  version : string;
  methods : Set.Make(String).t;
  modules : Set.Make(String).t;
}

(* Load index based on project language version *)
val load_index : lang:[`Gleam | `Crystal] -> version:string -> stdlib_index

(* Check if a call node references a valid stdlib method *)
val check_call : index:stdlib_index -> call_expr -> (violation, ok)
```

**Detection Logic:**
- Parse the import/use statement to detect exact language version
- For Crystal: Check against `Crystal::Stdlib::v1.9` (or detected version)
- For Gleam: Check against `gleam_stdlib@v1.0` 
- Flag `EApp` nodes where the callee isn't in the index

**Known Hallucinated Methods (Examples):**
| AI Suggested | Actual Crystal | Actual Gleam |
|-------------|----------------|--------------|
| `to_map` | `.to_h` | N/A |
| `Array(Type).new` | `Array(Type).new` (valid) | N/A |
| `.object_id` | `.object_id` (deprecated) | N/A |
| `String.join` | `Array.join` | `String.concat` |
| `list.to_list()` | N/A | `.to_list()` is redundant |

---

### 1.2 Legacy/Deprecated Syntax

**Hunt Method:** AST Pattern Matching against Deprecation Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEPRECATION PATTERN MAP                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  CRYSTAL DEPRECATIONS                    GLEAM DEPRECATIONS         │
│  ───────────────────                    ───────────────────         │
│  File.exists? → File.exists?            let var → let mut var       │
│  Def args; end → Def(args) end          is -> ==                    │
│  Macro {{x}} → macro {{x}}              use -> import               │
│  @[flags] enum → @[Flags] enum           Result.is_ok → case result  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  For each item/expr in AST:                                  │   │
│  │  Match against deprecation patterns                          │   │
│  │  If match → emit "deprecated-syntax" finding                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/ghost_scent/deprecation_rules.ml *)

type deprecation_rule = {
  id : string;
  lang : [`Gleam | `Crystal];
  pattern : expr_value;  (* AST pattern to match *)
  suggestion : string;
  since_version : string;
}

(* Example rules *)
let crystal_deprecations = [
  {
    id = "file-exists-question";
    lang = `Crystal;
    pattern = EFieldAccess (EVar "File", "exists?");
    suggestion = "Use File.exists? (without question mark)";
    since_version = "1.0";
  };
  {
    id = "macro-brace-interpolation";
    lang = `Crystal;
    pattern = EUnOp ("{{", EVar "_"));
    suggestion = "Use macro {{ x }} with spaces";
    since_version = "0.36";
  };
]

let gleam_deprecations = [
  {
    id = "result-is-ok";
    lang = `Gleam;
    pattern = EApp (EVar "Result.is_ok", [_]);
    suggestion = "Use case result { Ok(_) -> ... Error(_) -> ... }";
    since_version = "0.25";
  };
]
```

---

### 1.3 Mixing Ecosystems (Wrong Packages)

**Hunt Method:** Project Manifest Cross-Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PROJECT MANIFEST CHECK                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │
│  │  gleam.toml │     │ shards.yml  │     │  AST Import │           │
│  │  ─────────  │     │  ─────────  │     │    Nodes    │           │
│  │  packages:  │     │ dependencies:│    │  ──────     │           │
│  │  - name     │     │  crystal:   │     │  import "x" │           │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘           │
│         │                   │                   │                   │
│         └───────────────────┼───────────────────┘                   │
│                             ▼                                        │
│                  ┌─────────────────────┐                            │
│                  │  Project Package Set │                            │
│                  └──────────┬──────────┘                             │
│                             │                                        │
│                             ▼                                        │
│         ┌───────────────────────────────────────┐                    │
│         │  For each import node in AST:         │                    │
│         │  Check if package exists in manifest  │                    │
│         │  Flag if package not found             │                    │
│         └───────────────────────────────────────┘                    │
│                             │                                        │
│                             ▼                                        │
│                    ┌─────────────────┐                              │
│                    │ Finding:        │                              │
│                    │ "phantom-package"│                              │
│                    └─────────────────┘                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/ghost_scent/package_checker.ml *)

type manifest = {
  lang : [`Gleam | `Crystal];
  packages : string list;
  dev_packages : string list;
}

(* Parse project manifest *)
val parse_manifest : path:string -> manifest

(* Check import against manifest *)
val check_import : manifest:manifest -> import_node -> (violation, ok)
```

**AI Package Hallucination Examples:**
| AI Suggested | Reality |
|-------------|---------|
| `gleam_json` | Should be `gleam_stdlib` + manual JSON |
| `nimble` (Gleam) | Not a Gleam package, it's Elixir |
| `harka` (Crystal) | Package doesn't exist, use `ATHENA` |
| `uuid` (Crystal) | Deprecated, use `ecr` or built-in |

---

## Category 2: The Foreigner

**AI Behavior:** Writing code in the "style" of another language.

### 2.1 Manual Loops vs Iterators (Crystal)

**Hunt Method:** Loop Body Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LOOP → ITERATOR DETECTION                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                    CATSEYE SEES:                     │
│  ┌──────────────────────┐        ┌──────────────────────┐          │
│  │ i = 0                │        │ While node with:     │          │
│  │ while i < arr.size   │   →    │  - counter variable  │          │
│  │   result << arr[i]   │        │  - index access      │          │
│  │   i += 1             │        │  - push/concat       │          │
│  │ end                  │        │                      │          │
│  └──────────────────────┘        │ Flag as: "use-       │          │
│                                  │ iterator"            │          │
│                                  └──────────────────────┘          │
│                                                                     │
│  IDIOMATIC CRYSTAL:                                                │
│  ┌──────────────────────┐                                         │
│  │ result = arr.map do |x|                                        │
│  │   transform(x)                                                  │
│  │ end                                                             │
│  └──────────────────────┘                                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/foreigner/iterator_suggestion.ml *)

(* Detect manual loop patterns that could be iterators *)
val detect_manual_loop : expr -> iterator_suggestion option

(* Pattern: while with counter variable and index access *)
let is_manual_loop (expr : expr) : bool =
  match expr.expr_value with
  | EWhile (condition, body, _) ->
      (* Check if body has: counter += 1, arr[i], << or concat *)
      has_counter_increment body &&
      has_index_access body &&
      has_push_operator body
  | _ -> false

(* Suggest appropriate iterator based on body pattern *)
let suggest_iterator (loop : while_expr) : string =
  if has_push_operator loop.body && has_map_transform loop.body
  then "Try: array.map { |x| transform(x) }"
  else if has_push_operator loop.body && has_filter_predicate loop.body
  then "Try: array.select { |x| predicate(x) }"
  else "Consider using an iterator method"
```

**Severity:** 📝 Low — This is stylistic, not broken code.

---

### 2.2 Imperative Gleam (Mutation)

**Hunt Method:** Re-assignment Detection + Non-exhaustive Pattern Matching

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GLEAM MUTATION DETECTION                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                    CATSEYE SEES:                     │
│  ┌──────────────────────┐        ┌──────────────────────┐          │
│  │ let x = 1            │        │ ELet (PVar "x")      │          │
│  │ x = 2  ← ILLEGAL!   │   →    │ ELet (PVar "x")      │          │
│  │                      │        │                      │          │
│  │ let var count = 0    │        │ Reassignment to      │          │
│  │ count = count + 1    │        │ same variable        │          │
│  └──────────────────────┘        │ = IMPERATIVE GLEAM   │          │
│                                  └──────────────────────┘          │
│                                                                     │
│  ┌──────────────────────┐                                          │
│  │ case result of       │    ┌──────────────────────┐              │
│  │   Ok(v) -> v         │    │ Non-exhaustive case! │              │
│  │   # Incomplete       │ →  │ Missing: Error(_)   │              │
│  └──────────────────────┘    └──────────────────────┘              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/foreigner/imperative_gleam.ml *)

(* Track variable assignments and detect re-assignments *)
let detect_reassignment (items : item list) : violation list =
  let seen = Hashtbl.create 16 in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, body) ->
        let func_vars = extract_bindings patterns in
        let assigned = find_reassignments body func_vars in
        List.map (fun var ->
          make_violation ~id:"imperative-gleam" 
            ~message:(Printf.sprintf "Variable '%s' is reassigned. Gleam is immutable - use case expressions or update functions." var)
        ) assigned
    | _ -> []
  ) items

(* Detect non-exhaustive case expressions *)
let detect_non_exhaustive_case (expr : expr) : violation option =
  match expr.expr_value with
  | ECase (scrutinee, branches) ->
      let patterns = List.map fst branches in
      if not (is_exhaustive patterns)
      then Some (make_violation ~id:"non-exhaustive-case"
          ~message:"This case expression is non-exhaustive. AI often forgets Error branches in Result handling.")
      else None
  | _ -> None
```

---

### 2.3 Primitive Obsession

**Hunt Method:** Function Signature Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PRIMITIVE OBSESSION DETECTOR                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED (BAD):                                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ fn create_user(name: String, email: String, phone: String)  │   │
│  │   -> User                                                    │   │
│  │   User { name, email, phone }                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE DETECTS: 3+ String parameters in a row = "Primitive        │
│  Obsession" - AI likely missed a domain type or wrapper             │
│                                                                     │
│  IDIOMATIC:                                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ type ContactInfo = { email: Email, phone: Phone }            │   │
│  │ fn create_user(name: String, contact: ContactInfo) -> User  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/foreigner/primitive_obsession.ml *)

(* Detect 3+ consecutive primitive parameters *)
let detect_primitive_obsession (item : item) : violation option =
  match item.item_value with
  | IFunction (name, patterns, _, body) ->
      let params = List.map extract_param_type patterns in
      let consecutive_primitives = count_consecutive params in
      if consecutive_primitives >= 3
      then Some (make_violation ~id:"primitive-obsession"
          ~severity:Medium
          ~message:(Printf.sprintf "Function '%s' has %d consecutive primitive parameters. Consider using domain types for better type safety."
            name consecutive_primitives))
      else None
  | _ -> None

(* For Gleam: also check for stringly-typed enums *)
let detect_string_enum (typ : typ) : violation option =
  match typ with
  | TRecord fields when List.for_all (fun (_, t) -> t = TString) fields ->
      Some (make_violation ~id:"string-enum"
          ~message:"This record has only String fields - consider using a custom type enum for better type safety.")
  | _ -> None
```

---

## Category 3: The Happy Path

**AI Behavior:** Optimistically assuming things work, skipping error handling.

### 3.1 Nil-Chaser (Crystal)

**Hunt Method:** Type Union Analysis from Worker

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NIL SAFETY DETECTOR                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  TYPE INFO FROM WORKER:                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ user: User | Nil                                           │   │
│  │ items: Array(Item)                                          │   │
│  │ config: Config | Nil                                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  user.name  ← EFieldAccess node                             │   │
│  │                                                              │   │
│  │  Type of 'user' = User | Nil                                 │   │
│  │  Field 'name' accessed without nil check                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│              ┌─────────────────────────────────┐                   │
│              │ Finding: "unchecked-nil-access"  │                   │
│              │ Suggest: user.try(&.name)       │                   │
│              │    or: case user                │                   │
│              │          Some(u) -> u.name      │                   │
│              │          None -> default        │                   │
│              └─────────────────────────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/happy_path/nil_chaser.ml *)

(* Type info from worker (Crystal type signatures) *)
type type_info = {
  var : string;
  typ : [`Nullable of string | `NonNullable of string];
}

(* Get type info from worker response *)
val get_worker_types : file:string -> type_info list

(* Check if a field access is on a nullable type without guard *)
let check_field_access 
    (expr : expr) 
    (types : type_info list) 
    : violation option =
  match expr.expr_value with
  | EFieldAccess (obj, field_name) ->
      let obj_name = extract_var_name obj in
      (match List.assoc_opt obj_name types with
       | Some (`Nullable _) ->
           (* Check if there's a nil guard in scope *)
           if not (has_nil_guard obj_name expr)
           then Some (make_violation ~id:"unchecked-nil-access"
               ~severity:Medium
               ~message:(Printf.sprintf "Accessing '%s.%s' but '%s' may be Nil. Use '.try(&.%s)' or a nil check."
                 obj_name field_name obj_name field_name))
           else None
       | _ -> None)
  | _ -> None

(* Common AI mistake patterns *)
let ai_nil_patterns = [
  "user.name";           (* User | Nil *)
  "result.data";         (* Result | Nil *)
  "config.setting";      (* Config | Nil *)
  "items.first";         (* Array | Nil *)
]
```

---

### 3.2 Ignoring the Result (Gleam)

**Hunt Method:** Result Type + Unhandled Branch Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RESULT HANDLING DETECTOR                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED (BAD):                                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ let assert Ok(user) = find_user(id)                         │   │
│  │ // If Error, CRASH!                                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE DETECTS:                                                   │
│  • let assert in non-test code                                      │
│  • Missing Error branch in case expression                           │
│  • Unhandled Result from function call                              │
│                              │                                      │
│                              ▼                                      │
│  SUGGESTIONS:                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ case find_user(id)                                          │   │
│  │   Ok(user) -> do_something(user)                            │   │
│  │   Error(_) -> Error("User not found")  ← Handle it!          │   │
│  │ end                                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/happy_path/result_handler.ml *)

(* Detect let assert in non-test code *)
let detect_let_assert (item : item) : violation option =
  match item.item_value with
  | IFunction (name, patterns, _, body) ->
      if is_test_function name
      then None  (* let assert is fine in tests *)
      else find_let_asserts body
  | _ -> None

(* Find all let assert expressions recursively *)
let rec find_let_asserts (expr : expr) : violation option =
  match expr.expr_value with
  | ELetAssert (pattern, value, body) ->
      Some (make_violation ~id:"result-assert"
          ~severity:Medium
          ~message:"Using 'let assert' crashes on Error. Use case expression for graceful error handling.")
      (* Continue checking body for more violations *)
      :: (match body with Some b -> find_violations b | None -> [])
  | ELet (_, _, body) -> find_violations body
  | ECase (_, branches) ->
      List.concat_map (fun (_, expr) -> find_violations expr) branches
  | _ -> None

(* Detect unhandled Result returns *)
let detect_unhandled_result (expr : expr) : violation list =
  match expr.expr_value with
  | EApp (callee, args) ->
      if is_result_returning_function callee args
      && not (is_in_case_expression expr)
      then [make_violation ~id:"unhandled-result"
                ~message:"Result-returning function call not in case expression. Errors may be silently dropped."]
      else []
  | _ -> []
```

---

### 3.3 Unsafe Pointers (Crystal)

**Hunt Method:** Pointer Usage + Context Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    UNSAFE POINTER DETECTOR                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Pointer usage patterns flagged:                             │   │
│  │                                                             │   │
│  │ ✗ Pointer.malloc(size)          ← Raw pointer allocation    │   │
│  │ ✗ pointer.value                  ← Direct pointer access     │   │
│  │ ✗ Slice(Pointer(Int64), size)    ← Unsafe slice creation     │   │
│  │                                                             │   │
│  │ ✓ Pointer(Int64).new(address)   ← Embedded in safe class   │   │
│  │ ✓ SafeBuffer.read(index)         ← Wrapped in SafeBuffer     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  Rule: Pointer usage is flagged UNLESS:                             │
│  1. It's inside a class/method marked @[Safe]                        │
│  2. It's inside a file named *_safe.cr                              │
│  3. It's a @[RaisesException] annotated method                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Category 4: The Tangle

**AI Behavior:** Writing more code than necessary due to lack of context.

### 4.1 Redundant Conversions

**Hunt Method:** Type Equality Check on Cast Nodes

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REDUNDANT CONVERSION DETECTOR                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ "hello".to_s          ← String → String (redundant!)         │   │
│  │ my_list.to_a          ← Array → Array (redundant!)           │   │
│  │ number.to_i           ← Int64 → Int (possibly narrowing)    │   │
│  │ bytes.to_s            ← Bytes → String (encoding assumption) │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ For each type-cast expression (EApp of .to_X, .to_i, etc):  │   │
│  │   Get source type from worker/type inference                │   │
│  │   Get target type from cast method                           │   │
│  │   If source == target → Flag as redundant                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/tangle/redundant_conversion.ml *)

(* Redundant conversion patterns *)
let redundant_conversions = [
  (* Crystal *)
  ("to_s",   TString,  TString);   (* string.to_s *)
  ("to_a",   TList _, TList _);  (* array.to_a *)
  ("to_i",   TInt,    TInt);      (* int.to_i *)
  ("to_f",   TFloat,  TFloat);    (* float.to_f *)
  ("to_h",   TRecord, TRecord);   (* hash.to_h when already Hash *)
  
  (* Gleam - less common but possible *)
  ("to_string", TString, TString);
  ("to_list",   TList _, TList _);
]

let detect_redundant_conversion 
    (expr : expr) 
    (source_type : typ) 
    : violation option =
  match expr.expr_value with
  | EApp (obj, [EVar method]) 
       when List.mem method ["to_s"; "to_i"; "to_a"; "to_h"; "to_f"] ->
      let target_type = infer_target_type method in
      if types_equal source_type target_type
      then Some (make_violation ~id:"redundant-conversion"
          ~severity:Low
          ~message:(Printf.sprintf "Calling .%s on a %s is redundant - the value is already this type."
            method (typ_to_string source_type)))
      else None
  | _ -> None
```

---

### 4.2 Duplicate Validation (Claws)

**Hunt Method:** Structural Hashing for Duplicate Blocks

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DUPLICATE VALIDATION (CLAWS)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  CATSEYE FILES:                                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ user_controller │  │  api_handler    │  │   service       │     │
│  │ ──────────────── │  │  ──────────────  │  │  ─────────────  │     │
│  │ if email.empty? │  │ if email.empty?  │  │ if email.empty? │     │
│  │   error!        │  │   error!         │  │   error!        │     │
│  │ if email.valid? │  │ if email.valid?  │  │ if email.valid? │     │
│  │   error!        │  │   error!         │  │   error!        │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  CLAWS: Use Structural Hashing to find duplicate blocks     │   │
│  │  ┌───────────────────────────────────────────────────────┐  │   │
│  │  │  Block A ≅ Block B ≅ Block C                          │  │   │
│  │  │  Similarity: 95% (only variable names differ)          │  │   │
│  │  │  Suggest: Extract to validation module/function        │  │   │
│  │  └───────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation (Claws Module):**

```ocaml
(* src/ocaml/lib/catseye_claws/duplicate_validation.ml *)

(* Structural hash ignores variable names, focuses on structure *)
let structural_hash (expr : expr) : string =
  let rec go e =
    match e.expr_value with
    | EVar _ -> "VAR"  (* Ignore actual variable names *)
    | EFieldAccess (obj, field) -> 
        Printf.sprintf "FIELD[%s](%s)" field (go obj)
    | EApp (fn, args) ->
        let fn_name = extract_name fn in
        Printf.sprintf "CALL[%s](%s)" fn_name (String.concat "," (List.map go args))
    | EIf (cond, then_, else_) ->
        Printf.sprintf "IF(%s){%s}ELSE{%s}" (go cond) (go then_) 
          (match else_ with Some e -> go e | None -> "NIL")
    | ELet (pattern, value, body) ->
        (* Pattern contributes structure, not names *)
        Printf.sprintf "LET[%s=%s]{%s}" (pattern_structure pattern) 
          (go value) (go body)
    | _ -> Printf.sprintf "%s" (expr_variant_name e)
  in
  go expr

(* Find validation blocks (if/else checking common patterns) *)
let is_validation_block (expr : expr) : bool =
  match expr.expr_value with
  | EIf (cond, _, _) ->
      (* Heuristic: validation often checks .empty?, .valid?, length, etc. *)
      let cond_str = expr_to_string cond in
      List.exists (fun pattern -> Str.string_match (Str.regexp pattern) cond_str 0)
        ["empty\\?"; "valid\\?"; "nil\\?"; "length"; "size"; "is_valid"]
  | _ -> false

(* Group files by structural hash similarity *)
let find_duplicate_validations (files : (string * expr list) list) : duplicate_group list =
  let validation_blocks = 
    List.concat_map (fun (file, exprs) ->
      List.filter_map (fun expr ->
        if is_validation_block expr 
        then Some { file; block = expr; hash = structural_hash expr }
        else None
      ) exprs
    ) files
  in
  group_by_similarity validation_blocks ~threshold:0.8
```

---

### 4.3 Library Bloat

**Hunt Method:** Require/Import vs Standard Library Feature Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LIBRARY BLOAT DETECTOR                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI ADDS UNNECESSARY DEPENDENCIES:                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ require "json"          ← AI suggests JSON gem              │   │
│  │ data = JSON.parse(str) │                                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE KNOWS: Crystal 1.0+ has built-in JSON:                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ require "json"  ← NO LONGER NEEDED                           │   │
│  │ data = JSON.parse(str)  ← Built-in!                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ SHARDS.YML / MIX.Dependencies:                              │   │
│  │                                                             │   │
│  │ - Dependency "json"                                        │   │
│  │   Version: "~> 1.4"                                        │   │
│  │   Status: REDUNDANT - Crystal stdlib since 1.0             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Standard Library Equivalents (Crystal):**
| AI Suggests | Crystal Stdlib Has | Since |
|-------------|-------------------|-------|
| `json` gem | Built-in `JSON` module | Crystal 0.9 |
| `http` gem | Built-in `HTTP` module | Crystal 0.9 |
| `option_parser` | Built-in `OptionParser` | Crystal 0.9 |
| `base64` gem | Built-in `Base64` module | Crystal 0.9 |
| `regex` gem | Built-in `Regex` | Crystal 0.9 |
| `uri` gem | Built-in `URI` module | Crystal 0.9 |

---

## Category 5: The Mute Trap

**AI Behavior:** Generating insecure code to keep examples simple.

### 5.1 Hardcoded Secrets

**Hunt Method:** Entropy Analysis + Variable Name Matching

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECRET DETECTOR                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  HIGH ENTROPY STRING LITERALS:                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ "sk_live_51HxYz..."     ← API key pattern                  │   │
│  │ "ghp_xxxxxxxxxxxx..."   ← GitHub token                     │   │
│  │ "xoxb-xxxxx..."         ← Slack token                       │   │
│  │ "AIzaSy..."             ← Google API key                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ENTROPY CHECK:                                             │   │
│  │ Shannon entropy > 4.0 = suspicious                          │   │
│  │ Contains patterns: sk_, ghp_, xoxb-, AIza, -----BEGIN      │   │
│  │ Variable names: api_key, secret, token, password, creds    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│              ┌─────────────────────────────────┐                    │
│              │ Finding: "hardcoded-secret"    │                    │
│              │ Severity: 🚫 HIGH              │                    │
│              │ Use env vars or secret manager │                    │
│              └─────────────────────────────────┘                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/mute_trap/secret_detector.ml *)

(* Secret patterns with regex *)
let secret_patterns = [
  ("api_key", Str.regexp_case_factory "api[_-]?key" );
  ("github_token", Str.regexp_case_factory "ghp?_[a-zA-Z0-9]{36,}");
  ("slack_token", Str.regexp_case_factory "xoxb?-[a-zA-Z0-9-]{10,}");
  ("google_api", Str.regexp_case_factory "AIza[a-zA-Z0-9_-]{35}");
  ("aws_key", Str.regexp_case_factory "AKIA[0-9A-Z]{16}");
  ("generic_token", Str.regexp_case_factory "[a-zA-Z0-9+/]{40,}==?");
  ("private_key", Str.regexp_case_factory "-----BEGIN .* PRIVATE KEY-----");
]

(* Calculate Shannon entropy *)
let entropy (s : string) : float =
  let len = float_of_int (String.length s) in
  let counts = Array.make 256 0 in
  String.iter (fun c -> 
    counts.(int_of_char c) <- counts.(int_of_char c) + 1
  ) s;
  let ent = ref 0.0 in
  for i = 0 to 255 do
    if counts.(i) > 0 then
      let p = float_of_int counts.(i) /. len in
      ent := !ent -. (p *. (log2 p))
    fi
  done;
  !ent

let is_high_entropy (s : string) : bool =
  String.length s >= 20 && entropy s > 4.0

(* Check string literal assignments *)
let detect_secrets (item : item) : violation list =
  let rec go expr =
    match expr.expr_value with
    | ELet (PVar name, ELiteral (LString value), body) ->
        let violations = ref [] in
        (* Check variable name *)
        List.iter (fun (pattern_name, _) ->
          if Str.string_match (snd pattern_name) name 0
          then violations := 
            make_violation ~id:"hardcoded-secret" 
              ~severity:High
              ~message:(Printf.sprintf "Variable '%s' suggests a secret. Use environment variables instead." name)
            :: !violations
        ) secret_patterns;
        (* Check string content *)
        if is_high_entropy value
        then violations := 
          make_violation ~id:"high-entropy-string"
            ~severity:High
            ~message:"High-entropy string literal - possible hardcoded secret or key"
          :: !violations;
        (* Continue checking body *)
        go body @ !violations
    | _ -> collect_violations expr
  in
  match item.item_value with
  | IFunction (_, _, _, body) -> go body
  | _ -> []
```

---

### 5.2 SSRF-Prone String Concatenation

**Hunt Method:** Taint Engine + URL Building Pattern Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SSRF DETECTOR                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Tainted source ──────▶ String concat ──────▶ HTTP request          │
│  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐     │
│  │ user_input   │       │ "#{base}/api"|       │ HTTP.get(url)│     │
│  │ rss_feed     │  ───▶ │ "#{user}/res"│  ───▶ │ HTTP.post    │     │
│  │ request.param│       │ "#{feed}/xml"│       │ HTTP.put     │     │
│  └──────────────┘       └──────────────┘       └──────────────┘     │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ DETECTION:                                                 │   │
│  │ 1. SINK: HTTP.get/post/put/delete with URL argument        │   │
│  │ 2. SOURCE: User input, request params, RSS feeds           │   │
│  │ 3. FLOW: String interpolation/concatenation between them    │   │
│  │                                                           │   │
│  │ IF tainted → "ssrf-risk" finding                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/mute_trap/ssrf_detector.ml *)

(* Reuse existing taint engine from catseye_engine *)
module Taint = Catseye_engine.Taint

(* HTTP sinks that take URLs *)
let http_sinks = [
  "HTTP.get"; "HTTP.post"; "HTTP.put"; "HTTP.delete"; "HTTP.patch";
  "HTTP.client.get"; "HTTP.client.post";
  "Net::HTTP.get"; "Net::HTTP.post";
  "Curl.get"; "Curl.post";
]

(* Tainted sources *)
let tainted_sources = [
  "params"; "query_params"; "request.body"; "request.headers";
  "user_input"; "rss_feed"; "feed_url"; "external_url";
]

(* Check for SSRF risk *)
let detect_ssrf 
    (expr : expr) 
    (taint_map : Taint.taint_map) 
    : violation option =
  match expr.expr_value with
  | EApp (EVar sink, [url_arg]) 
       when List.mem sink http_sinks ->
      let sources = Taint.get_sources url_arg taint_map in
      if not (List.is_empty sources)
      then Some (make_violation ~id:"ssrf-risk"
          ~severity:High
          ~message:(Printf.sprintf "URL built from tainted source(s): %s. This can lead to SSRF attacks. Validate and sanitize the URL."
            (String.concat ", " sources)))
      else None
  | _ -> None
```

---

## Implementation Roadmap

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IMPLEMENTATION PHASES                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHASE A: Ghost Scent (Hallucinations)                              │
│  ├─ A1: Create stdlib index files for Crystal 1.9+, Gleam 1.0+     │
│  ├─ A2: Implement method existence checker                          │
│  ├─ A3: Add deprecation pattern map                                 │
│  └─ A4: Implement package manifest cross-reference                 │
│                                                                     │
│  PHASE B: The Foreigner (Non-Idiomatic)                             │
│  ├─ B1: Implement loop → iterator detector (Crystal)                │
│  ├─ B2: Implement reassignment detector (Gleam)                      │
│  ├─ B3: Implement non-exhaustive case detector (Gleam)               │
│  └─ B4: Implement primitive obsession detector                       │
│                                                                     │
│  PHASE C: The Happy Path (Safety)                                   │
│  ├─ C1: Integrate Crystal type info from worker                     │
│  ├─ C2: Implement nil-access detector                                │
│  ├─ C3: Implement let assert detector (Gleam)                        │
│  └─ C4: Implement pointer usage safety checker                       │
│                                                                     │
│  PHASE D: The Tangle (Redundancy)                                   │
│  ├─ D1: Implement redundant conversion detector                      │
│  ├─ D2: Extend Claws with duplicate validation detection             │
│  └─ D3: Create stdlib equivalents map for bloat detection           │
│                                                                     │
│  PHASE E: The Mute Trap (Security)                                  │
│  ├─ E1: Implement entropy-based secret detector                      │
│  ├─ E2: Implement SSRF detector using taint engine                   │
│  └─ E3: Add regex-based secret pattern matching                      │
│                                                                     │
│  PHASE F: The Copier (Copy-Paste)                                    │
│  ├─ F1: Implement undefined variable detector                        │
│  ├─ F2: Implement inconsistent state update detector                 │
│  └─ F3: Implement hardcoded ID/URL detector                          │
│                                                                     │
│  PHASE G: The Confused (Language Confusion)                          │
│  ├─ G1: Implement wrong enum/module access detector                  │
│  └─ G2: Implement opaque type violation detector                     │
│                                                                     │
│  PHASE H: The Looper (Iteration Issues)                             │
│  ├─ H1: Implement infinite recursion detector (same arg)             │
│  └─ H2: Implement off-by-one range detector                         │
│                                                                     │
│  PHASE I: AI-Unique Code Smells (Extensions to existing Claws)       │
│  ├─ I1: Add duplicate case branch detection to existing dead code    │
│  └─ I2: Add empty catch block detection                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Already Covered by Claws (`extra_smells.ml`)

The following patterns are **already detected** by existing Claws modules. AI linter can reference these but doesn't need to duplicate:

| Claws Rule | File | What it Catches |
|------------|------|-----------------|
| `LongMethod` | `extra_smells.ml` | Functions with >threshold AST nodes |
| `ComplexConditional` | `extra_smells.ml` | Expressions with 3+ `&&`/`\|\|` operators |
| `MessageChain` | `extra_smells.ml` | Dotted chains >4 segments (Law of Demeter) |
| `DataClump` | `extra_smells.ml` | Parameter pairs appearing together ≥3 functions |
| `FlagArgument` | `extra_smells.ml` | Boolean-style params (is_*, should_*, etc.) |
| `ComplexMatch` | `extra_smells.ml` | Case expressions with 5+ branches |
| `DeadCode` | `extra_smells.ml` | Code after unconditional return/raise |
| `DataClass` | `extra_smells.ml` | Classes with only getters, no behavior |
| `FeatureEnvy` | `extra_smells.ml` | 70%+ accesses on external object |

**AI Enhancement:** For these existing rules, AI linter can add context like "This pattern commonly appears in AI-generated code" to help prioritize findings.

---

## Rule Summary Table

| Pattern | Rule ID | Severity | Detection Method | Phase | Covered |
|---------|---------|----------|-------------------|-------|--------|
| Non-existent stdlib method | `hallucinated-method` | 🚫 High | Stdlib index | A1-A2 | NEW |
| Legacy syntax | `deprecated-syntax` | ⚠️ Medium | AST pattern | A3 | NEW |
| Wrong package import | `phantom-package` | 🚫 High | Manifest check | A4 | NEW |
| Manual loop vs iterator | `use-iterator` | 📝 Low | Loop body analysis | B1 | NEW |
| Variable reassignment | `imperative-gleam` | ⚠️ Medium | AST reassignment | B2 | NEW |
| Non-exhaustive case | `non-exhaustive-case` | ⚠️ Medium | Pattern exhaustiveness | B3 | NEW |
| Primitive obsession | `primitive-obsession` | 📝 Low | Param signature | B4 | NEW |
| Unchecked nil access | `unchecked-nil-access` | ⚠️ Medium | Type + guard check | C1-C2 | NEW |
| let assert in production | `result-assert` | ⚠️ Medium | AST analysis | C3 | NEW |
| Unsafe pointer usage | `unsafe-pointer` | 🚫 High | Context analysis | C4 | NEW |
| Redundant conversion | `redundant-conversion` | 📝 Low | Type equality | D1 | NEW |
| Duplicate validation | `duplicate-validation` | 📝 Low | Structural hash | D2 | NEW |
| Unnecessary dependency | `library-bloat` | 📝 Low | Stdlib map | D3 | NEW |
| Hardcoded secret | `hardcoded-secret` | 🚫 High | Entropy + patterns | E1 | NEW |
| SSRF risk | `ssrf-risk` | 🚫 High | Taint engine | E2 | NEW |
| Variable name leakage | `undefined-variable` | 🚫 High | Scope analysis | F1 | NEW |
| Inconsistent state update | `inconsistent-state` | ⚠️ Medium | Field tracking | F2 | NEW |
| Hardcoded ID/URL | `hardcoded-id` | ⚠️ Medium | Pattern match | F3 | NEW |
| Wrong enum access | `wrong-enum-access` | 🚫 High | Enum index | G1 | NEW |
| Opaque type violation | `opaque-violation` | 🚫 High | Type analysis | G2 | NEW |
| Infinite recursion | `infinite-recursion` | 🚫 High | Arg comparison | H1 | NEW |
| Off-by-one range | `off-by-one` | ⚠️ Medium | Boundary check | H2 | NEW |
| Duplicate case branch | `duplicate-case-branch` | ⚠️ Medium | Pattern dedup | I1 | EXTEND |
| Empty catch block | `empty-catch` | 🚫 High | Try body check | I2 | NEW |
| Long Method | `LongMethod` | ⚠️ Medium | AST node count | - | ✅ Claws |
| Complex Conditional | `ComplexConditional` | ⚠️ Medium | Operator count | - | ✅ Claws |
| Message Chain | `MessageChain` | 📝 Low | Segment count | - | ✅ Claws |
| Data Clump | `DataClump` | 📝 Low | Pair frequency | - | ✅ Claws |
| Flag Argument | `FlagArgument` | 📝 Low | Name pattern | - | ✅ Claws |
| Complex Match | `ComplexMatch` | ⚠️ Medium | Branch count | - | ✅ Claws |
| Dead Code | `DeadCode` | 🚫 High | CFG analysis | - | ✅ Claws |
| Feature Envy | `FeatureEnvy` | 📝 Low | Access ratio | - | ✅ Claws |

---

## File Structure Changes

```
src/ocaml/lib/
├── ai_linter/                          # NEW AI-specific rules
│   ├── ghost_scent/
│   │   ├── stdlib_index.ml
│   │   ├── stdlib_crystal.ml
│   │   ├── stdlib_gleam.ml
│   │   ├── deprecation_rules.ml
│   │   └── package_checker.ml
│   │
│   ├── foreigner/
│   │   ├── iterator_suggestion.ml
│   │   ├── imperative_gleam.ml
│   │   ├── non_exhaustive_case.ml
│   │   └── primitive_obsession.ml
│   │
│   ├── happy_path/
│   │   ├── nil_chaser.ml
│   │   ├── result_handler.ml
│   │   └── unsafe_pointer.ml
│   │
│   ├── tangle/
│   │   ├── redundant_conversion.ml
│   │   └── library_bloat.ml
│   │
│   ├── mute_trap/
│   │   ├── secret_detector.ml
│   │   ├── ssrf_detector.ml
│   │   └── secret_patterns.ml
│   │
│   ├── copier/                          # NEW
│   │   ├── variable_leakage.ml
│   │   ├── inconsistent_state.ml
│   │   └── hardcoded_ids.ml
│   │
│   ├── confused/                        # NEW
│   │   ├── enum_access.ml
│   │   └── opaque_type.ml
│   │
│   ├── looper/                          # NEW
│   │   ├── infinite_recursion.ml
│   │   └── off_by_one.ml
│   │
│   └── existing files...
│
├── catseye_claws/
│   ├── extra_smells.ml                   # EXTEND: add duplicate case, empty catch
│   └── existing files...
│
└── stdlib/
    ├── crystal/
    │   └── v1_9.ml                      # etc.
    └── gleam/
        └── v1_0.ml
```

---

## Success Criteria

- [ ] All 26 AI-specific patterns from this document have corresponding rules
- [ ] Each rule has test cases covering AI-generated examples
- [ ] Rules emit findings in standard `Finding.t` format
- [ ] False positive rate < 5% on real AI-generated code
- [ ] All rules use CatseyeAST.t only (no regex for structural analysis)
- [ ] Performance: < 100ms overhead per file for full scan
- [ ] 9 existing Claws rules cross-referenced for AI enhancement context

---

## References

- Existing implementation: `planning/38-ai-linter-ocaml-plan.md`
- Unified AST: `planning/39-unified-ast-architecture.md`
- Claws module: `planning/phase7-claws.md`
- Taint engine: `planning/phase6-engine-hardening.md`
- Claws extra smells: `src/ocaml/lib/catseye_claws/extra_smells.ml`
- Reachability: `src/ocaml/lib/catseye_engine/reachability.ml`

---

## Category 6: The Copier

**AI Behavior:** Copy-pasting code and forgetting to update variable names, IDs, or internal references.

### 6.1 Variable Name Leakage

**Hunt Method:** Cross-reference variable usage within function scope

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VARIABLE NAME LEAKAGE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ fn process_user(user) =                                     │   │
│  │   order = find_order(user.id)                               │   │
│  │   # ... lots of code ...                                    │   │
│  │   item = find_item(order.id)  ← 'item' from another func!   │   │
│  │   item.price                                                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE DETECTS: 'item' used but not defined in function scope    │
│  The variable was likely copy-pasted from another function          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/copier/variable_leakage.ml *)

(* Track variables defined in function scope *)
let detect_undefined_variables (item : item) : violation list =
  match item.item_value with
  | IFunction (name, patterns, _, body) ->
      let defined = collect_defined_vars patterns body in
      let used = collect_used_vars body in
      let undefined = List.filter (fun v -> not (List.mem v defined)) used in
      List.map (fun v ->
        make_violation ~id:"undefined-variable"
          ~severity:High
          ~message:(Printf.sprintf "Variable '%s' used but not defined. Possible copy-paste error from another function." v)
      ) undefined
  | _ -> []
```

---

### 6.2 Inconsistent State Updates

**Hunt Method:** Track entity fields across update operations

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INCONSISTENT STATE UPDATES                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ user = User { name: "Alice", email: "a@b.com" }            │   │
│  │ user.name = "Bob"         ← Update name to "Bob"             │   │
│  │ # ... some code ...                                         │   │
│  │ user.name = "Charlie"     ← Update name to "Charlie"        │   │
│  │ return user              ← user.email seems missing?          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Multiple updates to same field without other fields       │
│  being set → Likely forgot to update all related fields             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/copier/inconsistent_state.ml *)

(* Track field updates within a scope *)
type field_update = {
  field : string;
  line : int;
}

let detect_inconsistent_updates (expr : expr) : violation list =
  let updates = ref [] in
  let rec go e =
    match e.expr_value with
    | EAssignment (EFieldAccess (obj, field), value) ->
        updates := { field; line = e.expr_location.start.line } :: !updates
    | _ -> iter_expr go e
  in
  go expr;
  (* Group by field, check for multiple updates without reads *)
  let multi_updates = List.filter (fun field ->
    List.length (List.filter (fun u -> u.field = field) !updates) > 1
  ) (unique_fields !updates) in
  List.map (fun field ->
    make_violation ~id:"inconsistent-state"
      ~severity:Medium
      ~message:(Printf.sprintf "Field '%s' updated multiple times without intermediate reads. Possible copy-paste error." field)
  ) multi_updates
```

---

### 6.3 Hardcoded IDs and URLs

**Hunt Method:** String literal + domain pattern analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HARDCODED IDENTIFIERS                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ user_id = "12345"          ← Hardcoded ID from example     │   │
│  │ api_url = "https://api.example.com/v1"  ← Hardcoded URL   │   │
│  │ webhook = "https://hooks.slack.com/xxx/yyy/zzz" ← Real URL   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: String literals matching ID/URL patterns in non-config    │
│  files → Flag as hardcoded configuration (likely copy-pasted)     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/copier/hardcoded_ids.ml *)

(* Hardcoded ID patterns *)
let id_patterns = [
  Str.regexp_case_factory "^[0-9]{5,}$";          (* Numeric IDs like 12345 *)
  Str.regexp_case_factory "^[a-zA-Z0-9]{20,}$";    (* Long alphanumeric IDs *)
]

(* Hardcoded URL patterns (excluding localhost) *)
let url_pattern = Str.regexp_case_factory "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

let detect_hardcoded_ids (expr : expr) : violation list =
  match expr.expr_value with
  | ELet (PVar name, ELiteral (LString value), body) ->
      let violations = ref [] in
      (* Check for hardcoded IDs *)
      if List.exists (fun p -> Str.string_match p value 0) id_patterns
      && not (is_config_var name)
      then violations := 
        make_violation ~id:"hardcoded-id"
          ~severity:Medium
          ~message:(Printf.sprintf "Variable '%s' assigned a hardcoded ID '%s...'. Use configuration or constants." name (String.sub value 0 (min 10 (String.length value))))
        :: !violations;
      (* Check for hardcoded URLs *)
      if Str.string_match url_pattern value 0
      && not (is_config_var name)
      && not (is_test_file ())
      then violations :=
        make_violation ~id:"hardcoded-url"
          ~severity:Medium
          ~message:(Printf.sprintf "Variable '%s' has hardcoded URL. Use configuration or environment variables." name)
        :: !violations;
      violations
  | _ -> []
```

---

## Category 7: The Confused

**AI Behavior:** Misunderstanding language-specific features, operators, or type system quirks.

### 7.1 Wrong Enum/Module Access

**Hunt Method:** Cross-reference enum variant usage with definition

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENUM VARIANT ACCESS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED (GLEAM - WRONG):                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ import OrderStatus                                          │   │
│  │ let status = Pending  ← WRONG! Needs module prefix          │   │
│  │ # Should be: OrderStatus.pending                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  AI GENERATED (CRYSTAL - WRONG):                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ enum Status                                                 │   │
│  │   Pending                                                   │   │
│  │   Complete                                                  │   │
│  │ end                                                        │   │
│  │ Status::Pending  ← WRONG! Crystal uses dot, not ::         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/confused/enum_access.ml *)

(* Build enum variant index from parsed AST *)
type enum_info = {
  name : string;
  module_path : string;
  variants : string list;
}

(* Detect unqualified enum variant access *)
let detect_unqualified_enum (expr : expr) (enums : enum_info list) : violation list =
  let rec check e =
    match e.expr_value with
    | EVar name ->
        (* Check if name matches an enum variant but isn't qualified *)
        (match List.find_opt (fun e -> List.mem name e.variants) enums with
         | Some enum when not (is_qualified name enum.module_path) ->
             [make_violation ~id:"unqualified-enum"
                 ~severity:Medium
                 ~message:(Printf.sprintf "Enum variant '%s' should be accessed as '%s.%s'." name enum.name name)]
         | _ -> [])
    | _ -> iter_expr check e
  in
  check expr

(* Detect wrong enum access operator (:: vs .) in Crystal *)
let detect_wrong_enum_operator (expr : expr) : violation option =
  match expr.expr_value with
  | EFieldAccess (EVar enum_name, variant) 
       when is_enum_type enum_name && String.contains variant ':' ->
      Some (make_violation ~id:"wrong-enum-operator"
          ~severity:High
          ~message:(Printf.sprintf "Use '.' not '::' for enum variant access: %s.%s" enum_name variant))
  | _ -> None
```

---

### 7.2 Misunderstanding Opaque Types

**Hunt Method:** Field access on opaque type definitions

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OPAQUE TYPE VIOLATIONS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED (GLEAM):                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ pub type UserId                                               │   │
│  │   opaque UserId(id: String)                                   │   │
│  │                                                                │   │
│  │ fn get_id(user: UserId) -> String                             │   │
│  │   user.id  ← ERROR! Cannot access internal of opaque type     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Field access on opaque type without exposing function    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/confused/opaque_type_access.ml *)

(* Track opaque type definitions *)
type opaque_def = {
  name : string;
  internal_fields : string list;
}

(* Detect illegal field access on opaque types *)
let detect_opaque_violation (expr : expr) (opaques : opaque_def list) : violation option =
  match expr.expr_value with
  | EFieldAccess (obj, field) ->
      let obj_type = infer_type obj in
      (match List.find_opt (fun o -> o.name = obj_type) opaques with
       | Some opaque when List.mem field opaque.internal_fields ->
           Some (make_violation ~id:"opaque-violation"
               ~severity:High
               ~message:(Printf.sprintf "Cannot access internal field '%s' of opaque type '%s'. Export a function to expose this value." field obj_type))
       | _ -> None)
  | _ -> None
```

---

## Category 8: The Looper

**AI Behavior:** Generating loops with incorrect termination conditions, especially recursive ones.

### 8.1 Infinite Recursion (Same Argument Passed)

**Hunt Method:** Recursive call graph + termination condition analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INFINITE RECURSION DETECTOR                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED (WRONG):                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ fn find_item(items: List(a), target: a) -> Option(a)        │   │
│  │   case items of                                             │   │
│  │     [] -> None                                              │   │
│  │     [head, ..rest] ->                                       │   │
│  │       if head == target                                     │   │
│  │       then Some(head)                                       │   │
│  │       else find_item(items, target)  ← BUG! Should be rest  │   │
│  │   end                                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Same variable passed to recursive call in loop position   │
│  Check: Is the passed argument modified between calls?             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/looper/infinite_recursion.ml *)

(* Analyze recursive calls for non-termination *)
let detect_infinite_recursion (item : item) : violation option =
  match item.item_value with
  | IFunction (name, params, _, body) ->
      let recursive_calls = find_calls name body in
      let rec check_calls calls depth =
        match calls with
        | [] -> None  (* No infinite recursion detected *)
        | call :: rest ->
            (* Check if same variable passed as in first call *)
            let call_args = extract_args call in
            let param_names = extract_param_names params in
            (* If ALL arguments are the same params, no progress *)
            if List.for_all2 (fun arg param -> arg = param) call_args param_names
            then Some (make_violation ~id:"infinite-recursion"
                ~severity:High
                ~message:(Printf.sprintf "Recursive call to '%s' passes same arguments - will not terminate. Did you mean to pass a different value (e.g., 'rest' instead of 'items')?" name))
            else check_calls rest depth
      in
      check_calls recursive_calls 0
  | _ -> None
```

---

### 8.2 Off-By-One Errors in Range

**Hunt Method:** Loop boundary analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OFF-BY-ONE DETECTION                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ for i in 0..arr.size                                         │   │
│  │   process(arr[i])  ← May access arr[arr.size] on last iter!  │   │
│  │ end                                                             │   │
│  │ # '0..size' is inclusive, so last i = size                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Range with .size/.length as upper bound                  │
│  Suggests: Use '0..<size' (exclusive range) or '<=.size - 1'       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/looper/off_by_one.ml *)

(* Detect inclusive range with size/length as upper bound *)
let detect_off_by_one (expr : expr) : violation option =
  match expr.expr_value with
  | ERange (start, EBinOp (arr, ("size" | "length"), _), true)
       (* Inclusive range: 0..arr.size includes arr.size *)
    | ERange (start, EApp (EVar "size", [EVar arr]), true)
    | ERange (start, EApp (EVar "length", [EVar arr]), true) ->
      Some (make_violation ~id:"off-by-one"
          ~severity:Medium
          ~message:"Inclusive range with .size/.length upper bound includes out-of-bounds index. Use exclusive range '0..<arr.size' instead.")
  | _ -> None

(* Crystal: array[index] when index could equal array.size *)
let detect_bounds_risk (arr_access : expr) : violation option =
  match arr_access.expr_value with
  | EIndex (arr, idx) ->
      (match idx.expr_value with
       | EBinOp (size, ("<" | "<="), _) ->
           (* If using <, check if it should be <= *)
           if String.equal (get_op idx) "<"
           then Some (make_violation ~id:"bounds-check"
              ~severity:Low
              ~message:"Array access with '<'. Consider if '<=' is needed for inclusive check.")
           else None
       | _ -> None)
  | _ -> None
```

---

## Category 10: The Zombie (AI-Unique Extensions)

**AI Behavior:** Generating code that can never execute, or catch blocks that ignore errors. These extend the existing Claws `check_dead_code`.

### 10.1 Unreachable Branches (Duplicate Case Patterns)

**Hunt Method:** Control flow graph + constant condition analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DUPLICATE CASE BRANCHES                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ case value of                                              │   │
│  │   Some(x) -> process(x)                                    │   │
│  │   None -> return None                                      │   │
│  │   None -> return Some(default)  ← DUPLICATE - unreachable  │   │
│  │ end                                                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Duplicate patterns in case branches (beyond Claws dead   │
│  code detection, focuses on AI-specific copy-paste of patterns)    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation (extend extra_smells.ml):**

```ocaml
(* Add to catseye_claws/extra_smells.ml *)

(* Detect duplicate case branches *)
let detect_duplicate_branches (case_expr : expr) : violation list =
  match case_expr.expr_value with
  | ECase (scrutinee, branches) ->
      let seen_patterns = Hashtbl.create 16 in
      let duplicates = ref [] in
      List.iter (fun (pattern, _) ->
        let pattern_key = pattern_to_key pattern in
        if Hashtbl.mem seen_patterns pattern_key
        then duplicates := pattern :: !duplicates
        else Hashtbl.add seen_patterns pattern_key true
      ) branches;
      List.map (fun p ->
        make_violation ~id:"unreachable-branch"
          ~severity:Medium
          ~message:"Duplicate case pattern - second branch is unreachable."
      ) !duplicates
  | _ -> []
```

---

### 10.2 Empty Catch Blocks

**Hunt Method:** Try-catch body analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    EMPTY CATCH BLOCKS                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AI GENERATED:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ try                                                         │   │
│  │   risky_operation()                                          │   │
│  │ rescue                                                         │   │
│  │   # Ignore error - just continue                             │   │
│  │ end                                                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  CATSEYE: Catch/rescue block with no operations                    │
│  → Silent failure, errors swallowed                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Rule Implementation:**

```ocaml
(* src/ocaml/lib/ai_linter/zombie/empty_catch.ml *)

(* Detect empty catch/rescue blocks *)
let detect_empty_catch (try_expr : expr) : violation option =
  match try_expr.expr_value with
  | ETry (body, catch_vars, catch_body, ensure) ->
      if is_empty_expr catch_body
      then Some (make_violation ~id:"empty-catch"
          ~severity:High
          ~message:"Empty catch/rescue block - errors are silently swallowed. Add logging or proper error handling.")
      else if is_only_logging catch_body
      then Some (make_violation ~id:"silent-catch"
          ~severity:Medium
          ~message:"Catch block only logs error without handling it. Consider re-raising or returning an error.")
      else None
  | _ -> None
```

---

## Category 9: The Scribbler (Naming & Style)

**AI Behavior:** Ignoring naming conventions, style guides, and documentation standards. These overlap with existing Claws rules but are AI-specific.

### 9.1 Wrong Naming Conventions

**Hunt Method:** Identifier pattern matching against language conventions

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NAMING CONVENTION VIOLATIONS                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  GLEAM CONVENTIONS (snake_case):                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ fn GetUserByID(userId: Int)  ← WRONG (camelCase)           │   │
│  │ type UserRecord                  ← WRONG (PascalCase)        │   │
│  │ MAX_COUNT = 100                  ← Correct for constants     │   │
│  │ let API_KEY = "xxx"             ← Wrong (should be API_KEY)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  CRYSTAL CONVENTIONS:                                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ def get_user_by_id(user_id : Int)  ← Correct (snake_case)   │   │
│  │ def GetUserById(userId : Int)     ← Wrong (CamelCase)        │   │
│  │ MAX_COUNT = 100                   ← Correct (SCREAMING_SNAKE) │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Note:** This is partially covered by Claws `FlagArgument` pattern detection, but AI often makes systematic naming errors that warrant dedicated detection.
