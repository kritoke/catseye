# OxCaml Exploration for Catseye

**Date:** 2026-05-11  
**Repo:** [oxcaml/oxcaml](https://github.com/oxcaml/oxcaml) — 720 stars  
**Based on:** OCaml 5.2.0 + Jane Street patches  

---

## What is OxCaml?

OxCaml (formerly "0xCaml") is Jane Street's performance-focused fork of OCaml. It's the home of the **Flambda 2** optimizer and adds several extensions that go beyond upstream OCaml 5.x. It's the compiler Jane Street uses internally for their production systems.

## Key Extensions Relevant to Catseye

### 1. Stack Allocation (`stack_` keyword)
**Impact: HIGH — reduces GC pressure during large scans**

OxCaml automatically allocates values on the stack when they don't escape their region. You can annotate with `stack_` to enforce it:

```ocaml
(* Security_node.t records that are created during extraction and
   immediately processed — stack-allocated, zero GC pressure *)
let node = stack_ { node_type = Call; name = "File.read"; args; line = 42; ... } in
```

For Catseye, where we create thousands of `Security_node.t` records during extraction and immediately consume them in the engine, this could eliminate significant GC pressure. The taint DB operations (creating/removing records) are also hot paths.

**Estimated win:** 10-30% throughput improvement on large scans (192-file scans like facet_pi).

### 2. Unboxed Types
**Impact: MEDIUM — faster taint DB lookups**

Unboxed types (`float#`, `int32#`, etc.) store values directly in registers instead of heap-allocated boxes:

```ocaml
(* Currently: line numbers are boxed ints *)
type taint_record = { line: int; ... }

(* With OxCaml: line numbers could be unboxed for tighter records *)
(* Record layout would be more compact in memory → better cache behavior *)
```

For the taint DB which stores thousands of records with integer fields, unboxed representations would improve cache locality during the propagation phase.

### 3. Modes System
**Impact: MEDIUM — compile-time concurrency safety**

OxCaml's mode system tracks how values are used (local, global, read-only, etc.). This would make the worker pool safer:

```ocaml
(* The mode system would verify at compile time that we don't
   share mutable state between Crystal workers *)
let process_file (nodes @ local) (db @ local) : Finding.t list =
  (* Compiler ensures nodes/db don't escape to other domains *)
  ...
```

### 4. Parallelism (Capsules)
**Impact: MEDIUM — safer Domain parallelism**

Built on OCaml 5's multicore, with Jane Street's higher-level primitives:

```ocaml
(* Parallel extraction with proper capsule semantics *)
let extract_all files =
  Parallel.map ~f:(fun file ->
    (* Each file extraction is a capsule — no shared mutable state *)
    extract_file file
  ) files
```

This is a safer alternative to our current `Domain`-based parallelism in `parallel.ml`.

### 5. SIMD Intrinsics
**Impact: LOW — specialized use case**

OxCaml has `ocaml_simd` for SIMD operations. Not directly useful for Catseye's string-heavy analysis, but could accelerate future byte-level pattern matching (e.g., regex-based rule matching).

## Migration Assessment

### Compatibility
- Based on OCaml 5.2.0 — Catseye uses 5.4.1
- Some 5.3/5.4 APIs may not be available yet
- `pkgsMusl` toolchain would need updating
- Third-party opam packages (yojson, sqlite3, etc.) should mostly work

### Effort
| Task | Effort | Risk |
|------|--------|------|
| Switch compiler in flake.nix | Low | Low (if deps compile) |
| Add `stack_` annotations to hot paths | Medium | Low |
| Use unboxed types for taint records | Medium | Medium (layout changes) |
| Adopt mode system for safety | High | Low (incremental) |
| Adopt parallelism capsules | High | Medium |

### Recommendation

**Defer for now.** The benefits are real but the migration cost and version gap (5.2 vs 5.4) make it premature. Revisit when:
1. OxCaml rebases onto OCaml 5.4+
2. Catseye's performance on large codebases (1000+ files) becomes a bottleneck
3. The mode system proves valuable for the worker pool's safety

The single highest-impact change would be stack allocation of `Security_node.t` records — but this requires OxCaml's compiler, which means maintaining a separate build pipeline.

**Alternative:** Profile Catseye's current GC behavior first. If GC pauses are <5% of scan time, OxCaml's stack allocation won't help much.

---

## Quick Reference

| Feature | OxCaml | Upstream OCaml |
|---------|--------|---------------|
| Stack allocation | `stack_ { ... }` | No |
| Unboxed types | `int32#`, `float64#` | No |
| Mode system | `x @ local`, `x @ global` | No |
| SIMD | `ocaml_simd` | No |
| Flambda 2 optimizer | Default | Experimental |
| Capsules/Parallelism | `Parallel.map` | `Domain` (lower level) |
| Based on | OCaml 5.2.0 | 5.4.1 |
