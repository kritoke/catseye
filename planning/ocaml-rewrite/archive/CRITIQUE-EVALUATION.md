# Critique Evaluation: OCaml Rewrite Plan

**Date**: 2026-05-09

Five critiques were raised against the initial OCaml rewrite plan. This document evaluates each and decides what to incorporate.

---

## Critique 1: Leverage OCaml 5.x Parallelism

### The Argument
The plan mentions worker pools for Crystal processes but doesn't use OCaml 5's multicore for the analysis engine itself. Parallelizing the fixed-point iteration across CPU cores could speed up taint analysis on large codebases.

### Evaluation: ✅ Valid — Incorporate

**Why it's right**:
- OCaml 5's `Domain` module provides true parallelism (separate heaps, no GIL)
- Taint analysis on independent files is embarrassingly parallel
- The current plan only parallelizes extraction, not analysis

**Where it fits**:
```
Phase 1: Seed sources per file (parallel — no cross-file deps)
Phase 2: Propagate within file scope (parallel — each file is independent)
Phase 3: Merge per-file TaintDBs into global TaintDB (sequential — needs synchronization)
Phase 4: Inter-procedural propagation (sequential — cross-file references)
Phase 5: Rule matching (parallel — each rule is independent)
```

**Concrete approach**:
```ocaml
(* Phase 1+2: Parallel per-file analysis *)
let analyze_file (nodes : security_node list) : taint_db =
  let db = seed_sources(nodes, []) in
  propagate(nodes, db)

(* Using Domain for CPU-bound parallelism *)
let analyze_all_files (files : (string * security_node list) list) : taint_db =
  let per_file_dbs = Domain.parallel_map ~n:(Domain.recommended_count())
    (fun (_, nodes) -> analyze_file nodes) files
  in
  (* Phase 3: Merge — sequential *)
  let global_db = List.fold_left merge_db empty_db per_file_dbs in
  (* Phase 4: Inter-procedural — sequential *)
  let final_db = propagate_interprocedural all_nodes global_db in
  (* Phase 5: Rule matching — parallel again *)
  Domain.parallel_map ~n:(Domain.recommended_count())
    (fun rule -> rule.check all_nodes final_db) all_rules
```

**Important nuance**: Not all phases can be parallelized. The merge step and inter-procedural propagation need sequential processing. But seed + propagate per file is the bulk of the work and that's parallel.

**Risk**: Low. OCaml 5 Domains are well-documented. The challenge is correct merge semantics (what if two files define the same variable name? — answer: file-scoped, so they're independent).

**Library choice**: Raw `Domain` for CPU-bound work. `Eio` if we also need async I/O (for Crystal worker pool). Can use both — `Eio` for I/O, `Domain` for analysis.

---

## Critique 2: Incremental Analysis & Persistence

### The Argument
Catseye shouldn't re-scan the entire codebase when one line changes. Cache the TaintDB state; load previous summaries for unchanged files.

### Evaluation: ✅ Valid — Incorporate, But With Caveats

**Why it's right**:
- On a 5000-file codebase, changing one file shouldn't require re-extracting 4999 others
- CI pipelines benefit enormously from incremental analysis
- File extraction is the most expensive phase (especially Crystal)

**Why it's harder than it sounds**:
1. **Cross-file taint propagation invalidation**: If file A depends on a function in file B, and file B changes, file A's taint analysis may change too. You can't just cache per-file results independently.
2. **Cache invalidation**: Content-hash based (file hash → cached extraction) is straightforward. But taint analysis results depend on the *global* TaintDB, not just the file's local state.
3. **Merge semantics**: When you re-analyze one file, you need to re-run inter-procedural propagation across ALL files.

**Practical approach — Two-tier cache**:

```
Tier 1: Extraction cache (easy, high value)
  file_path + content_hash → [security_node]
  - Skip extraction entirely for unchanged files
  - This is the biggest win (Crystal extraction is expensive)

Tier 2: Analysis cache (harder, lower value initially)
  file_path + content_hash + dependency_hashes → taint_summary
  - Cache the per-file taint analysis result
  - Invalidate when dependencies change
  - Only worth doing if inter-procedural propagation is slow
```

**Implementation**:
```ocaml
module Cache : sig
  type t
  val load : string -> t                          (* Load from .catseye-cache/ *)
  val get_extraction : t -> string -> digest -> security_node list option
  val set_extraction : t -> string -> digest -> security_node list -> unit
  val save : t -> unit                             (* Persist to disk *)
end

(* On disk: .catseye-cache/extractions/<sha256-of-path-hash> *)
(* Format: Yojson (debuggable, no binary dependency needed) *)
```

**Why SQLite/LMDB may be overkill**: The cache is keyed by (file_path, content_hash). A simple directory of JSON files works fine. Yojson is fast enough. The cache size is bounded by the number of source files (thousands, not millions).

**Decision**: Implement Tier 1 (extraction cache) in Phase 1. Tier 2 (analysis cache) is a later optimization — measure first to see if it's needed.

---

## Critique 3: Differential Testing

### The Argument
Formally compare old Gleam/BEAM engine and new OCaml engine outputs on the same vulnerability corpus in CI. Flag any discrepancies.

### Evaluation: ✅ Excellent — Incorporate Fully

**Why this is the best critique of the five**:
- Silent false negatives are the most dangerous failure mode in a security tool
- Unit tests only cover known cases; differential testing covers EVERYTHING
- This is how you prove the rewrite is correct

**Implementation**:
```bash
# CI pipeline step
just build                    # Build both engines
just build-ocaml              # Build OCaml engine

# Run both on same input
cat test_corpus.json | erl ... -eval 'catseye:main()' > /tmp/gleam_out.json
cat test_corpus.json | catseye_ocaml analyze > /tmp/ocaml_out.json

# Compare
python3 scripts/diff_findings.py /tmp/gleam_out.json /tmp/ocaml_out.json
# Exit 1 if findings differ
```

**Diff script behavior**:
- Normalize both outputs (sort by file:line:rule)
- Compare: finding count, rule names, severities, flow traces
- Output: added findings, removed findings, changed findings
- CI fails on ANY difference (strict mode) or only on removed findings (lenient mode)

**Vulnerability corpus**:
- Current `test/samples/vulnerable.cr` and `vulnerable.gleam` (start here)
- Add real-world samples: open-source Crystal/Gleam projects with known CVEs
- Add edge cases: deeply nested taint, multi-hop propagation, sanitizer interactions

**Decision**: Make this a non-negotiable part of the migration. No phase is "done" until differential tests pass.

---

## Critique 4: Decoupled Rule Definition (DSL vs Native Code)

### The Argument
Rules as native OCaml modules require OCaml expertise to modify. A YAML/JSON DSL (like Semgrep) would let users add rules without recompiling.

### Evaluation: ⚠️ Partially Valid — Design For It, Don't Build It Yet

**Why it sounds right**:
- Semgrep's success is largely due to their YAML rule format
- Non-OCaml developers should be able to add security checks
- Recompilation for every rule change is friction

**Why it's premature**:
1. Catseye has 10 rules. Semgrep has thousands. The DSL problem doesn't exist at this scale.
2. Building a rule DSL is a significant engineering effort: parser, validator, error messages, documentation, testing framework for rules
3. The current rules are tightly coupled to the taint engine (they call `is_suspect`, `build_finding_flow`, `var_names_from_args`). A DSL would need to abstract over all of these.
4. Semgrep's DSL works because their rules are primarily pattern-matching, not taint-aware. Catseye's rules ARE taint-aware, which is harder to express declaratively.

**The real question**: What does a DSL for taint-aware rules look like?

```yaml
# Hypothetical Catseye rule DSL
- id: ssrf
  severity: high
  sinks:
    - pattern: "HTTP::Client.get($ARG)"
    - pattern: "HTTP::Client.post($ARG)"
  message: "Potential SSRF via $FUNC with user-controlled URL"
```

This works for simple cases but can't express:
- "Flag this only if `$ARG` flows through `String.concat` but NOT through `URI.parse`"
- "Check if the function has a timeout parameter"
- "Cross-reference with `tls_verify: false` in the same call"

**Middle ground — Design the interface**:
```ocaml
(* Rule module type that COULD be backed by a DSL interpreter *)
module type Rule = sig
  val id : string
  val severity : string
  val check : Taint_db.t -> Security_node.t list -> Finding.t list
end

(* Native OCaml rule *)
module Ssrf : Rule = struct
  let id = "SSRF"
  let severity = "High"
  let check db nodes = (* current implementation *)
end

(* Future: DSL-backed rule *)
module DslRule (D : Dsl_rule_def) : Rule = struct
  let id = D.id
  let severity = D.severity
  let check db nodes = Dsl_interpreter.run D.definition db nodes
end
```

**Decision**: Keep native OCaml rules. Design the `Rule` module type so a DSL interpreter can be plugged in later. Add DSL as a future milestone, not a current requirement.

---

## Critique 5: Memory-Mapped ASTs / Binary Serialization

### The Argument
Use Cap'n Proto or similar zero-copy format instead of JSON for the Crystal↔OCaml boundary. Reduces CPU time spent on serialization.

### Evaluation: ⚠️ Premature — Keep JSON, Design for Later Swap

**Why it's tempting**:
- JSON parsing has measurable cost at scale (50,000 nodes × Yojson = noticeable)
- Binary formats are 5-10x faster to serialize/deserialize
- Zero-copy sounds efficient

**Why it's wrong for now**:
1. **The Crystal boundary is the only IPC boundary** — and the bottleneck is process spawn overhead, not JSON parsing. A pre-built Crystal binary eliminates spawn overhead. After that, JSON parsing is maybe 50-100ms for a large corpus. Not the bottleneck.
2. **Cap'n Proto adds complexity to both sides**: Crystal doesn't have a mature Cap'n Proto library. You'd need to write/maintain bindings. OCaml has `capnp-ocaml` but it's not well-maintained.
3. **Debuggability matters**: JSON is human-readable. When the Crystal extractor produces wrong output, you can `cat` the JSON and see the problem. Binary formats make debugging harder.
4. **Protocol stability**: The Security Node JSON format is still evolving. Binary schemas are harder to evolve than JSON.

**What to actually do**:
```ocaml
(* Design the protocol as a module, so the format can be swapped *)
module Protocol : sig
  type encoder
  type decoder
  val encode_nodes : security_node list -> string
  val decode_nodes : string -> security_node list
  (* Future: val encode_nodes_bin : security_node list -> Bytes.t *)
end
```

**If profiling later shows JSON is a bottleneck** (unlikely), consider:
- `yojson` → `yojson` with `Buffer` (avoid string allocation)
- Or `biniou` (binary Yojson-compatible format, same OCaml library)
- Not Cap'n Proto (too heavy for this use case)

**Decision**: Keep JSON. Abstract the serialization behind a module interface. Add binary format only if profiling proves JSON is the bottleneck.

---

## Summary: What Gets Incorporated

| Critique | Decision | Phase |
|----------|----------|-------|
| 1. OCaml 5 Parallelism | ✅ Incorporate | Phase 3 (engine) |
| 2. Incremental Analysis | ✅ Tier 1 only (extraction cache) | Phase 1 (CLI) |
| 3. Differential Testing | ✅ Full incorporation | Phase 3 (engine validation) |
| 4. Rule DSL | ⚠️ Design interface only | Phase 3 (engine) |
| 5. Binary Serialization | ❌ Keep JSON, abstract interface | Phase 2 (extractors) |

---

*This evaluation feeds into the updated PLAN.md.*