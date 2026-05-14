# Phase 9: Cross-File Taint & Symbol Resolution

**Phase:** 9  
**Priority:** Medium-High (significant analysis capability improvement)  
**Depends on:** Phase 6 (F1: file-level scope isolation must be done first)  
**Parent:** `planning/roadmap.md`  
**Status:** Design complete

---

## Overview

Enable taint to propagate across file boundaries via function calls. Currently, if `get_url()` is defined in `a.cr` and returns tainted data, a call to `get_url()` from `b.cr` will NOT receive taint — the engine can't resolve the cross-file reference.

This is the **highest-risk** phase because it touches both the extraction layer (parsing imports) and the engine (symbol table, cross-file propagation).

---

## Problem Statement

### Current Behavior

```
── src/helpers.cr ──────────────
def get_url(params)
  params["url"]          # tainted
end

── src/controller.cr ───────────
def handle(req)
  url = get_url(req)     # url is NOT tainted (cross-file gap)
  HTTP::Client.get(url)  # MISSED — should flag SSRF
end
```

The engine sees:
1. `get_url` returns tainted data (via `returns.ml`) — recorded in `helpers.cr`'s scope
2. `url = get_url(req)` in `controller.cr` — `get_url` is not in `controller.cr`'s taint records
3. Result: **SSRF is missed**

### Root Cause

Three missing capabilities:

| Gap | Description |
|-----|-------------|
| **No import tracking** | Extractors don't emit which symbols are imported from where |
| **No symbol table** | Engine has no `module.function → (file, def_node)` map |
| **No cross-file propagation** | `propagate.ml` uses `is_tainted_in_file` — strictly single-file |

---

## X1: Import Extraction

### Crystal Imports

Crystal uses `require` for file inclusion (not module imports). This means all public symbols from a required file are available in the requiring file's namespace.

```crystal
require "./helpers"  # brings in get_url, etc.
```

The Crystal extractor needs to emit **import nodes**:

```json
{
  "type": "import",
  "name": "require",
  "args": [{"arg_type": "literal", "value": "./helpers", "field": ""}],
  "line": 1,
  "taint": false,
  "file": "src/controller.cr",
  "language": "crystal",
  "metadata": {}
}
```

**New node type:** Add `Import` to `Security_node.node_type`:

```ocaml
type node_type =
  | Call
  | Assign
  | Def
  | Var
  | Literal
  | Import    (* NEW *)
```

**Crystal extractor changes:** Add a `visit` handler for `Crystal::Require`:

```crystal
def visit(node : Crystal::Require) : Bool
  @nodes << {
    type:     "import",
    name:     "require",
    args:     [{arg_type: "literal", value: node.string, field: ""}],
    line:     location_line(node),
    taint:    false,
    file:     @file_path,
    language: "crystal",
    metadata: nil,
  }
  true
end
```

### Gleam Imports

Gleam uses explicit imports:

```gleam
import helpers.{get_url}
import wibble as wibble_module
```

The Gleam extractor (`gleam.ml`) needs to emit import nodes when parsing `import` statements in the tree-sitter XML output.

**Tree-sitter XML for Gleam imports:**

```xml
<import module="helpers" srow="1">
  <unqualified_name name="get_url" srow="1"/>
</import>
```

Extract the module name and optional specific imports.

### Import Resolution

Converting `require "./helpers"` to a file path requires path resolution:

```ocaml
let resolve_require (source_file : string) (require_path : string) : string option =
  (* Relative require: "./helpers" → "src/helpers.cr" *)
  if String.length require_path > 0 && require_path.[0] = '.' then
    let dir = Filename.dirname source_file in
    let candidate = Filename.concat dir require_path in
    (* Try with extensions *)
    let extensions = [".cr"; "/index.cr"; ""] in
    List.find_opt (fun ext ->
      Sys.file_exists (candidate ^ ext)
    ) extensions
    |> Option.map (fun ext -> candidate ^ ext)
  else
    (* Absolute/lib require: "http/client" — resolve against lib dirs *)
    None  (* Skip lib requires for now *)
```

**Scope:** For Phase 9, only resolve **relative requires** (`"./foo"`, `"../bar"`). Library requires (`"http/client"`) are out of scope — those are external dependencies with no source available.

---

## X2: Symbol Table

### Design

A global symbol table maps function names to their defining location:

```ocaml
(* symbol_table.ml *)

type symbol = {
  name : string;            (* function name *)
  file : string;            (* defining file *)
  line : int;               (* def line *)
  module_path : string;     (* resolved from require, e.g., "src/helpers.cr" *)
  args : Security_node.arg list;  (* parameter list *)
}

type t = symbol list StringMap.t
(** Map from function name → list of symbols with that name *)
(** (Multiple files may define the same function name — we keep all) *)
```

### Construction

Build the symbol table from `Def` nodes and `Import` nodes:

```ocaml
let build (nodes : Security_node.t list) : t =
  (* 1. Collect all Def nodes → local symbols *)
  let defs_by_file = Hashtbl.create 16 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Def then begin
      let file = n.Security_node.file in
      let defs = try Hashtbl.find defs_by_file file with Not_found -> [] in
      Hashtbl.replace defs_by_file file (n :: defs)
    end
  ) nodes;

  (* 2. Collect all Import nodes → require map *)
  let requires_by_file = Hashtbl.create 16 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Import then begin
      let file = n.Security_node.file in
      let reqs = try Hashtbl.find requires_by_file file with Not_found -> [] in
      Hashtbl.replace requires_by_file file (n :: reqs)
    end
  ) nodes;

  (* 3. For each file, resolve its imports to get imported symbols *)
  let table = ref StringMap.empty in

  (* First pass: register all local defs *)
  Hashtbl.iter (fun file defs ->
    List.iter (fun def ->
      let sym = {
        name = def.Security_node.name;
        file = def.Security_node.file;
        line = def.Security_node.line;
        module_path = file;
        args = def.Security_node.args;
      } in
      let existing = try StringMap.find sym.name !table with Not_found -> [] in
      table := StringMap.add sym.name (sym :: existing) !table
    ) defs
  ) defs_by_file;

  !table
```

### Lookup

```ocaml
(** Find the definition of a function called from a specific file.
    Uses import resolution to pick the right definition when multiple
    files define the same function name. *)
let resolve (tbl : t) (caller_file : string) (fn_name : string)
    (imports : string list) : symbol option =
  match StringMap.find_opt fn_name tbl with
  | None -> None
  | Some [sym] -> Some sym  (* Unique name → unambiguous *)
  | Many ->
    (* Multiple definitions — prefer one from an imported file *)
    List.find_opt (fun sym ->
      List.mem sym.file imports
    ) Many
    |> Option.default (List.hd Many)
    |> Option.some
```

---

## X3: Cross-File Propagation

### Modified Pipeline

The current pipeline is:

```
seed → propagate (per-file) → returns → interproc → propagate (2nd)
```

The new pipeline adds cross-file propagation:

```
seed → propagate (per-file) → returns → interproc (local)
     → merge per-file DBs
     → cross-file propagate (using symbol table)
     → interproc (global)
     → propagate (2nd)
```

### Implementation

#### Step 1: Per-File Analysis

```ocaml
(* engine.ml — modified *)

(** Run per-file taint analysis *)
let per_file_analysis (nodes : Security_node.t list) : Db.t StringMap.t =
  (* Group nodes by file *)
  let files = group_by_file nodes in
  List.fold_left (fun acc (file, file_nodes) ->
    let seeded = seed_sources file_nodes Db.empty in
    let propagated = propagate file_nodes seeded in
    let with_returns = track_return_taint file_nodes propagated in
    let with_interproc = propagate_interprocedural file_nodes with_returns in
    StringMap.add file with_interproc acc
  ) StringMap.empty files
```

#### Step 2: Cross-File Propagation

```ocaml
(** Propagate taint across file boundaries using the symbol table. *)
let cross_file_propagate (symbol_table : Symbol_table.t)
    (per_file_dbs : Db.t StringMap.t)
    (nodes : Security_node.t list) : Db.t =
  let imports_by_file = build_import_map nodes in
  let merged_db = ref Db.empty in

  (* For each file's Assign nodes that call external functions *)
  List.iter (fun node ->
    if node.Security_node.node_type <> Security_node.Assign then ()
    else begin
      let file = node.Security_node.file in
      let imports = try Hashtbl.find imports_by_file file with Not_found -> [] in
      let file_db = try StringMap.find file per_file_dbs with Not_found -> Db.empty in

      (* Check if RHS is a call to a function defined in another file *)
      match find_arg_call node with
      | Some call_name ->
        (match Symbol_table.resolve symbol_table file call_name imports with
         | None -> ()  (* Can't resolve — skip *)
         | Some sym ->
           (* Check if the function returns tainted data in its defining file *)
           let def_file_db = try StringMap.find sym.file per_file_dbs
             with Not_found -> Db.empty in
           if Db.has_record def_file_db sym.name then begin
             (* Cross-file taint: mark the assigned variable as tainted *)
             let new_record = {
               var_name = node.Security_node.name;
               file = node.Security_node.file;
               line = node.Security_node.line;
               description = Printf.sprintf
                 "%s assigned from cross-file tainted call: %s (defined in %s)"
                 node.Security_node.name call_name sym.file;
               source_var = call_name;
               field = None;
               status = Tainted {
                 source = call_name;
                 field = None;
                 origin = From_var call_name
               }
             } in
             merged_db := Db.add_record !merged_db new_record
           end)
        | None -> ()
    end
  ) nodes;

  !merged_db
```

#### Step 3: Merge and Final Analysis

```ocaml
(** Build the full taint database with cross-file support. *)
let build_taint_db_cross_file ?(extra_sources = [])
    (nodes : Security_node.t list) : Db.t =
  let symbol_table = Symbol_table.build nodes in
  (* Per-file analysis *)
  let per_file = per_file_analysis nodes in
  (* Cross-file propagation *)
  let cross_file_db = cross_file_propagate symbol_table per_file nodes in
  (* Merge all per-file DBs *)
  let merged = StringMap.fold (fun _ db acc -> Db.merge_db acc db)
    per_file Db.empty in
  (* Add cross-file taint *)
  let merged_with_cross = Db.merge_db merged cross_file_db in
  (* Second pass propagation *)
  propagate nodes merged_with_cross
```

---

## X4: Wire merge_db

`merge.ml` already implements `merge_db` correctly. It just needs to be called in the pipeline (see X3 above). This is a trivial wiring change:

```ocaml
(* Already in merge.ml *)
let merge_db (a : Db.t) (b : Db.t) : Db.t = ...

(* Used in engine.ml via StringMap.fold *)
let merged = StringMap.fold (fun _ db acc -> Db.merge_db acc db)
  per_file_dbs Db.empty
```

---

## X5: Cross-File Test Corpus

### New Test Files

Create `test/samples/cross_file/`:

```
test/samples/cross_file/
├── helpers.cr          # Defines utility functions that return tainted data
├── controller.cr       # Calls helpers — should receive cross-file taint
├── safe_helpers.cr     # Returns clean data
├── safe_controller.cr  # Calls safe_helpers — should NOT flag
└── README.md           # Expected findings
```

#### `helpers.cr`

```crystal
# Defines functions that return tainted data

def fetch_user_url(params)
  url = params["url"]
  url
end

def build_command(params)
  cmd = params["cmd"]
  cmd
end

def safe_constant
  "https://example.com"
end
```

#### `controller.cr`

```crystal
require "./helpers"

def handle_request(params)
  # Cross-file SSRF: fetch_user_url returns tainted data from helpers.cr
  url = fetch_user_url(params)
  HTTP::Client.get(url)
end

def run_task(params)
  # Cross-file command injection: build_command returns tainted data
  cmd = build_command(params)
  system(cmd)
end

def fetch_safe
  # SAFE: returns hardcoded value
  url = safe_constant()
  HTTP::Client.get(url)
end
```

### Expected Findings

| Finding | Rule | Cross-File? | File |
|---------|------|-------------|------|
| `HTTP::Client.get(url)` in `handle_request` | SSRF | ✅ Yes — taint flows from `helpers.cr` | `controller.cr` |
| `system(cmd)` in `run_task` | CommandInjection | ✅ Yes — taint flows from `helpers.cr` | `controller.cr` |
| `HTTP::Client.get(url)` in `fetch_safe` | None | ❌ No — `safe_constant()` is clean | `controller.cr` |

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Import resolution fails for complex require paths | Medium | Only support relative requires; skip unresolvable imports |
| Multiple files define same function name | Medium | Prefer imported file; fall back to first match |
| Performance regression from per-file analysis | Low | Cache per-file results; only re-analyze changed files |
| False positives from overly aggressive cross-file propagation | Medium | Same sanitizer checks apply; only propagate through verified returns |
| New node type breaks existing rules | Low | `Import` nodes are filtered out by `node_type = Call` checks in rules |

---

## Implementation Order

```
X5 (test corpus)     ← Write test files first, verify they DON'T work yet
  │
X1 (import extraction) ← Crystal extractor changes + Security_node.ml changes
  │
X2 (symbol table)     ← New module, no engine changes yet
  │
X3 (cross-file propagation) ← Core engine changes
  │
X4 (wire merge_db)    ← Trivial, part of X3
  │
Verify: test corpus findings match expectations
```

---

## Exit Criteria

- [ ] `Import` nodes emitted by Crystal extractor for `require` statements
- [ ] Symbol table correctly maps `function_name → (file, def_line)`
- [ ] Cross-file taint propagates: `a.cr` → `b.cr` via function call
- [ ] `safe_controller.cr` produces zero findings (no cross-file false positives)
- [ ] No regression on existing single-file test corpus
- [ ] No regression on real-world scan targets (quickheadlines, facet_pi)
- [ ] `merge_db` is used in the pipeline

---

## Future Extensions

- **Gleam cross-file:** Gleam has explicit imports with module names — cleaner resolution than Crystal's `require`
- **Type-aware resolution:** Use Crystal's type system to distinguish `String#size` from `Array#size`
- **Whole-program analysis:** Build a call graph, not just pairwise cross-file links
- **Cross-file DRY:** Extend Claws DRY detection to find duplicate code across all files (already planned)
