# Interprocedural Guard Detection — Spec

## Interface

### IL Call Graph

```ocaml
(* il_call_graph.ml *)

(** Call graph built from IL function bodies.
    Vertices are function names, edges represent call-site relationships. *)
type call_graph = {
  graph : CallGraph.t;                    (* ocamlgraph string digraph *)
  call_sites : (string * string, int list) Hashtbl.t;  (* (caller, callee) -> block IDs in caller's CFG *)
}

(** Build a call graph from all functions in an IL unit.
    Scans ILCall nodes to find caller→callee relationships.
    Returns the graph and a map of call site locations. *)
val build : il_unit -> call_graph

(** Find all functions that call the given function (predecessors in call graph). *)
val callers : call_graph -> string -> string list

(** Find all functions called by the given function (successors in call graph). *)
val callees : call_graph -> string -> string list
```

### Dominator Cache

```ocaml
(* In cfg_dominator.ml or new dominator_cache.ml *)

(** Compute dominator analysis for every function in a unit.
    Results cached by function name for reuse. *)
val compute_all : il_unit -> (string, Cfg_dominator.t) Hashtbl.t
```

### Interprocedural Guard Check

```ocaml
(* In cfg_dominator.ml *)

(** Check if a sink is interprocedurally guarded by a sanitizer.
    
    Walks the call graph from the sink function upward, checking at
    each caller whether a sanitizer dominates the call to the callee.
    
    Returns true only if EVERY path from any entry point to the sink
    passes through a sanitizer. *)
val is_interprocedurally_guarded :
  call_graph: Il_call_graph.call_graph ->
  dom_cache:(string, Cfg_dominator.t) Hashtbl.t ->
  sink_fn:string ->
  sink_block:int ->
  sanitizers:string list ->
  bool
```

## Behavior

### Guarded case (should suppress)

Given:
```
function A():
  x = tainted_input()
  result = B(x)              ← calls B with tainted data

function B(arg):
  validate(arg)              ← sanitizer dominates the sink
  http.get(arg)              ← sink
```

Expected: `is_interprocedurally_guarded` returns `true` for the `http.get` sink in `B` because:
- In `B`'s CFG, `validate` dominates `http.get`
- Even though `A` calls `B` with tainted data, the sanitizer guards it

### Unguarded case (should NOT suppress)

Given:
```
function A():
  x = tainted_input()
  result = B(x)

function B(arg):
  http.get(arg)              ← sink, no sanitizer in B
```

Expected: returns `false` because no sanitizer dominates the sink in `B`.

### Partially guarded case (should NOT suppress)

Given:
```
function A():
  x = tainted_input()
  result = B(x)

function C():
  y = safe_input()
  result = B(y)              ← safe caller

function B(arg):
  http.get(arg)              ← sink
```

Expected: returns `false` because `A` calls `B` without sanitizing (even though `C` does). Not all paths are guarded.

### Recursive case

Given:
```
function A():
  B()

function B():
  A()
  http.get(arg)
```

Expected: depth limit prevents infinite recursion. Returns `false` (conservative).

## Integration Point

In `cfg_taint.ml`, `check_call_sinks`, after the existing sanitizer-in-args check:

```ocaml
(* Check if the sink function is a call to an internal function
   that has an interprocedural sanitizer guard *)
let is_iprocedurally_guarded = 
  match !current_dom_cache with
  | None -> false
  | Some (cache, cg) ->
    is_interprocedurally_guarded
      ~call_graph:cg ~dom_cache:cache
      ~sink_fn:fn_name ~sink_block:!current_block_id
      ~sanitizers:sink.sanitizers
in
if is_iprocedurally_guarded then []
```

## Test Cases

1. **Intra-procedural guard** — sanitizer in same function → already handled by existing dominator
2. **One-hop interprocedural** — sanitizer in the sink function itself (not caller) → should suppress
3. **Two-hop** — sink calls helper, helper has sanitizer before the real sink → should suppress  
4. **Unguarded path** — at least one call chain without sanitizer → should NOT suppress
5. **Library call** — sink calls external function (no IL available) → should NOT suppress (conservative)
6. **Recursive** — mutual recursion → depth limit, return false
7. **Multiple callers** — some guarded, some not → should NOT suppress
