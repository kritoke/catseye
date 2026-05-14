# Catseye — Technical Design Document

**Document ID:** TDD-CATSEYE-001  
**Classification:** Internal — Architecture  
**Status:** Living Document  
**Author:** Principal Systems Architect  
**Last Updated:** 2026-05-11  
**Applies To:** Catseye v0.4.0 (OCaml 5.x Rewrite + Claws Module)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Hunter Persona](#2-the-hunter-persona)
3. [System Architecture](#3-system-architecture)
4. [Dune Workspace Layout](#4-dune-workspace-layout)
5. [Data Models](#5-data-models)
6. [Module I: Catseye — Security & Taint Analysis](#6-module-i-catseye--security--taint-analysis)
7. [Module II: Claws — Code Smells & DRY Detection](#7-module-ii-claws--code-smells--dry-detection)
8. [Worker Protocol](#8-worker-protocol)
9. [Configuration & Rules — The Hybrid Model](#9-configuration--rules--the-hybrid-model)
10. [Persistence Layer — Incremental Cache](#10-persistence-layer--incremental-cache)
11. [Infrastructure — Nix & Static Linking](#11-infrastructure--nix--static-linking)
12. [Performance Budget](#12-performance-budget)
13. [Appendix A: Threat Model for the Analyzer](#13-appendix-a-threat-model-for-the-analyzer)
14. [Appendix B: Glossary of Hunter Terminology](#14-appendix-b-glossary-of-hunter-terminology)

---

## 1. Executive Summary

Catseye is a high-performance, multi-language static analysis platform built from two specialized modules:

| Module | Domain | Responsibility |
|--------|--------|----------------|
| **Catseye** | Security | Inter-procedural taint analysis, vulnerability detection, reachability scoring |
| **Claws** | Health | Code smell detection, cyclomatic complexity, DRY violation discovery |

The platform operates as a **native binary** compiled from OCaml 5.x with a persistent **Crystal Worker Pool** for AST extraction. It speaks the language of the **Hunter**: findings are categorized as **Hiss** (Critical), **Meow** (Warning), or **Purr** (Clean).

### Design Principles

1. **Sound over complete.** False negatives are worse than false positives. The engine prefers to flag suspicious patterns and let the Hunter triage.
2. **Incremental by default.** Content-addressed caching ensures only changed files are re-extracted. The Hunter does not stalk the same ground twice.
3. **Deterministic output.** Sequential extraction by default. Parallelism is available but opt-in, only after stability is proven.
4. **Hybrid configuration.** TOML for orchestration (paths, workers, exclusions). KDL for rule logic (sinks, sources, conditions).

---

## 2. The Hunter Persona

The Hunter persona is Catseye's terminal identity. It transforms raw static analysis output into a narrative experience while remaining fully machine-parseable in structured formats.

### 2.1 Severity Taxonomy

| Internal Severity | Hunter Level | Icon | Terminal Color | Meaning |
|-------------------|-------------|------|---------------|---------|
| `Critical`, `High` | **HISS** | 🐱⚡ | Red `\027[31m` | Exploitable vulnerability. The prey is cornered. |
| `Medium`, `Low` | **MEOW** | 🐾 | Yellow `\027[33m` | Suspicious pattern. Worth investigating. |
| Info / Clean | **PURR** | 😸 | Green `\027[32m` | No issues. The codebase is clean. |

### 2.2 Atmospheric Elements

The persona adds narrative layering to terminal output:

- **Banner:** `🐈‍⬛  Catseye v0.x.x — The Hunter enters the tall grass...`
- **Scent lines:** Random atmospheric messages during extraction (e.g., *"Something rustles in the undergrowth..."*)
- **Stalking narrative:** `🐾 Stalking src/controller.cr` during file extraction
- **Prey report:** `🐱 Found 2 Hiss, 1 Meow across 15 files.`
- **Rest state:** `😸 PURR — The codebase is clean.` / `The Hunter rests.`

### 2.3 Opt-Out

The `--no-persona` flag disables all Hunter terminology, reverting to standard severity labels and a plain ASCII banner. Structured output formats (JSON, SARIF, Markdown) use canonical severity strings regardless of persona state.

---

## 3. System Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                        OCaml 5.x — The Orchestrator                         │
│                                                                               │
│   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│   │  CLI + Args  │──▶│  Discovery   │──▶│  Cache Check │──▶│  Extraction  │  │
│   │  (cmdliner)  │   │  (.cr/.gleam)│   │  (Hashtbl)   │   │  Dispatch    │  │
│   └─────────────┘   └──────────────┘   └──────┬───────┘   └──────┬───────┘  │
│                                                │                   │          │
│                                    ┌───────────┘        ┌─────────┘          │
│                                    ▼                    ▼                    │
│                            ┌──────────────┐    ┌──────────────────┐          │
│                            │ Cached Nodes │    │ Crystal Worker   │          │
│                            │ (Hashtbl)    │    │ Pool (stdin/stdout│          │
│                            └──────┬───────┘    │ JSON protocol)   │          │
│                                   │            └────────┬─────────┘          │
│                                   │                     │                    │
│                                   └─────────┬───────────┘                    │
│                                             ▼                                │
│                                   ┌──────────────────┐                       │
│                                   │  Security Nodes  │                       │
│                                   │  (Normalized)    │                       │
│                                   └────────┬─────────┘                       │
│                                            │                                 │
│                          ┌─────────────────┼─────────────────┐               │
│                          ▼                 ▼                  ▼               │
│                  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│                  │   Catseye    │  │    Claws     │  │ Crow's Nest  │       │
│                  │   Engine     │  │    Engine    │  │ Supply Chain │       │
│                  │              │  │              │  │              │        │
│                  │ • Seed       │  │ • Complexity │  │ • OSV.dev    │       │
│                  │ • Propagate  │  │ • Anatomy    │  │ • Staleness  │       │
│                  │ • Returns    │  │ • DRY Hash   │  │ • SQLite     │       │
│                  │ • Interproc  │  │ • Ameba Hook │  │              │       │
│                  │ • Reachable  │  │              │  │              │       │
│                  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│                         │                 │                  │               │
│                         └────────┬────────┘──────────────────┘               │
│                                  ▼                                          │
│                         ┌──────────────────┐                                │
│                         │  Finding Graph   │                                │
│                         │  (DAG)           │                                │
│                         └────────┬─────────┘                                │
│                                  ▼                                          │
│                    ┌────────────────────────────────┐                        │
│                    │       Output Formatters        │                        │
│                    │  Terminal │ JSON │ SARIF │ MD  │                        │
│                    └────────────────────────────────┘                        │
└───────────────────────────────────────────────────────────────────────────────┘
                         │                              │
              ┌──────────┘                              └──────────┐
              ▼                                                    ▼
   ┌──────────────────────┐                           ┌──────────────────────┐
   │  Crystal Extractor    │                           │  Gleam Extractor     │
   │  (Crystal::Parser)    │                           │  (tree-sitter XML)   │
   │  Persistent Worker    │                           │  In-process (OCaml)  │
   └──────────────────────┘                           └──────────────────────┘
```

### 3.1 Component Responsibilities

| Component | Language | Role | Process Model |
|-----------|----------|------|---------------|
| Orchestrator | OCaml 5.x | File discovery, cache management, analysis dispatch, output formatting | Main process |
| Crystal Extractor | Crystal 1.18 | AST parsing via `Crystal::Parser`, taint seeding, timeout annotation | Worker pool (stdin/stdout JSON) |
| Gleam Extractor | OCaml | tree-sitter XML CST parsing, security node emission | In-process |
| Catseye Engine | OCaml | Taint analysis: seed → propagate → returns → interproc → reachability | In-process |
| Claws Engine | OCaml | Code smell detection, DRY structural hashing | In-process |
| Crow's Nest | OCaml | Supply chain audit: OSV.dev, staleness, SQLite cache | In-process |

### 3.2 Data Flow (End-to-End)

```
1. DISCOVER     Walk target directory → filter by extension + exclude patterns
2. CACHE CHECK  Content-addressed lookup → skip unchanged files
3. EXTRACT      Crystal: worker pool → JSON Security Nodes
                Gleam:  in-process tree-sitter → Security Nodes
4. NORMALIZE    All nodes → Security_node.t list (language-agnostic)
5. ANALYZE      Catseye: taint pipeline (seed → propagate → returns → interproc)
                Claws:   smell walkers + DRY hashing
6. REACHABLE    BFS from entry points → tag findings Live/Dormant/Safe
7. REPORT       Terminal (Hunter) / JSON / SARIF v2.1.0 / Markdown / DOT
```

---

## 4. Dune Workspace Layout

### 4.1 Directory Structure

```
catseye/
├── flake.nix                          # Nix Flake — full toolchain
├── flake.lock
├── justfile                           # Build tasks
├── .catseye.toml                      # Project-level config
├── README.md
│
├── src/
│   ├── extractor/
│   │   └── extractor.cr               # Crystal AST extractor
│   │
│   └── ocaml/
│       ├── dune-project               # (lang dune 3.16)
│       │
│       ├── bin/
│       │   ├── dune                   # (executable (name main))
│       │   └── main.ml                # CLI entry point
│       │
│       ├── lib/
│       │   ├── catseye_types/         # Shared type definitions
│       │   │   ├── dune
│       │   │   ├── security_node.ml   # Security Node (AST output unit)
│       │   │   ├── finding.ml         # Finding + flow steps + reachability
│       │   │   └── dag_types.ml       # Vulnerability DAG types
│       │   │
│       │   ├── catseye_engine/        # Core taint analysis engine
│       │   │   ├── dune
│       │   │   ├── constants.ml       # Known sources, sanitizers
│       │   │   ├── db.ml              # Taint database (file-keyed map)
│       │   │   ├── seed.ml            # Taint seeding from params + flags
│       │   │   ├── propagate.ml       # Fixed-point propagation
│       │   │   ├── returns.ml         # Return-value taint tracking
│       │   │   ├── interproc.ml       # Inter-procedural propagation
│       │   │   ├── dag.ml             # Vulnerability DAG construction
│       │   │   ├── engine.ml          # Pipeline orchestrator
│       │   │   ├── reachability.ml    # Predator Vision (BFS from entry points)
│       │   │   ├── parallel.ml        # OCaml 5 Domain parallel extraction
│       │   │   ├── cache.ml           # Content-addressed incremental cache
│       │   │   ├── merge.ml           # Taint DB union (for cross-file)
│       │   │   └── gleam.ml           # Gleam tree-sitter extractor
│       │   │
│       │   ├── catseye_rules/         # KDL rule loading + interpretation
│       │   │   ├── dune
│       │   │   ├── types.ml           # Rule type definitions
│       │   │   ├── loader.ml          # KDL → rule_def parser
│       │   │   └── interpreter.ml     # Rule evaluation engine
│       │   │
│       │   ├── catseye_claws/         # Code smells & DRY detection (NEW)
│       │   │   ├── dune
│       │   │   ├── complexity.ml      # Cyclomatic complexity walker
│       │   │   ├── anatomy.ml         # Parameter lists, nesting, god objects
│       │   │   ├── dry.ml             # Structural hashing for DRY detection
│       │   │   ├── ameba_hook.ml      # Ameba linter integration
│       │   │   └── smells.ml          # Unified smell detection pipeline
│       │   │
│       │   ├── catseye_crowsnest/     # Supply chain audit
│       │   │   ├── dune
│       │   │   ├── manifest.ml        # Manifest discovery (shard.yml, gleam.toml)
│       │   │   ├── osv.ml             # OSV.dev API client
│       │   │   ├── staleness.ml       # Staleness scoring
│       │   │   ├── aggregator.ml      # Dependency audit pipeline
│       │   │   ├── cache.ml           # SQLite cache
│       │   │   └── dep_reachability.ml # Dependency reachability via import scanning
│       │   │
│       │   └── catseye_cli/           # CLI + output formatting
│       │       ├── dune
│       │       ├── args.ml            # Command-line argument parsing
│       │       ├── config.ml          # TOML config loading
│       │       ├── discovery.ml       # File discovery
│       │       ├── orchestrator.ml    # Main analysis pipeline
│       │       ├── sarif.ml           # SARIF v2.1.0 output
│       │       ├── markdown.ml        # Markdown report output
│       │       ├── dot.ml             # DOT graph output
│       │       ├── heatmap.ml         # Predator Vision terminal heatmap
│       │       └── crowsnest_format.ml # Supply chain terminal output
│       │
│       ├── rules/                     # KDL rule definitions
│       │   ├── ssrf.kdl
│       │   ├── command_injection.kdl
│       │   ├── sql_injection.kdl
│       │   ├── path_traversal.kdl
│       │   ├── open_redirect.kdl
│       │   ├── hardcoded_secrets.kdl
│       │   ├── ldap_xml_injection.kdl
│       │   ├── missing_timeout.kdl
│       │   ├── redos.kdl
│       │   ├── weak_crypto.kdl
│       │   └── deserialization.kdl
│       │
│       └── test/
│           ├── dune
│           ├── test_gleam.ml
│           ├── test_weak.ml
│           └── debug_rules.ml
│
├── test/
│   └── samples/
│       ├── vulnerable.cr
│       ├── safe.cr
│       ├── vulnerable.gleam
│       └── safe.gleam
│
├── spec/
│   └── security-node.schema.json
│
├── bin/                               # Built binaries (git-ignored)
│   └── catseye-ocaml
│
├── assets/
│
└── planning/                          # Design documents
    ├── TDD.md                         # ← This document
    ├── architecture.md
    ├── status.md
    ├── tasks.md
    ├── DNF.md
    └── archive/
```

### 4.2 Dune Library Dependencies

```
catseye_types          ← (no deps, pure types + JSON codec)
catseye_engine         ← catseye_types
catseye_rules          ← catseye_types, kdl
catseye_claws          ← catseye_types          (NEW)
catseye_crowsnest      ← catseye_types, sqlite3
catseye_cli            ← catseye_engine, catseye_rules, catseye_claws,
                          catseye_crowsnest, cmdliner, bos, toml, yojson
```

---

## 5. Data Models

### 5.1 Security Node — The Universal AST Unit

The `Security_node.t` is the lingua franca between extractors and the analysis engine. Every extractor (Crystal, Gleam, future Ruby/Python) emits this format.

```ocaml
(* lib/catseye_types/security_node.ml *)

type node_type =
  | Call        (* Function/method call *)
  | Assign      (* Variable assignment *)
  | Def         (* Function/method definition *)
  | Var         (* Variable reference *)
  | Literal     (* Literal value *)

type arg_type =
  | ArgVar      (* Variable reference *)
  | ArgLiteral  (* String/number/bool literal *)
  | ArgCall     (* Nested function call *)
  | ArgUnknown  (* Unclassified *)

type arg = {
  arg_type : arg_type;
  value : string;       (* The variable name, literal value, or call name *)
  field : string;       (* Field access: params["url"] → field="url" *)
}

type t = {
  node_type : node_type;
  name : string;                    (* Function name, variable name, etc. *)
  args : arg list;                  (* Arguments / RHS of assignment *)
  line : int;                       (* Source line number *)
  taint : bool;                     (* Extractor-flagged taint seed *)
  file : string;                    (* Source file path *)
  language : string;                (* "crystal" | "gleam" | etc. *)
  metadata : (string * string) list;(* Extensible key-value pairs *)
}
```

**Key design decisions:**
- `field` on `arg` enables field-sensitive tracking (`params["url"]` vs `params["id"]`)
- `metadata` is an escape hatch for extractor-specific data (e.g., `parameterized_query=true`)
- `language` enables per-language rule filtering via KDL `languages` blocks
- `taint` is the extractor's initial assessment; the engine re-validates during propagation

### 5.2 Taint Database

```ocaml
(* lib/catseye_engine/db.ml — core types *)

type taint_source =
  | Known_source of string    (* Standard source name: "params", "request" *)
  | From_var of string        (* Propagated from another tainted variable *)

type taint_status =
  | Clean
  | Tainted of {
      source : string;          (* Origin variable or source name *)
      field : string option;    (* Field name for field-sensitive tracking *)
      origin : taint_source;    (* Provenance chain *)
    }
  | Sanitized of { by : string }

type taint_record = {
  var_name : string;
  file : string;
  line : int;
  description : string;         (* Human-readable provenance *)
  source_var : string;          (* Immediate source variable *)
  field : string option;
  status : taint_status;
}

type t = taint_record list StringMap.t
(** Map from file path → list of taint records for that file *)
```

**Key invariants:**
- Variables are scoped by file: `is_tainted_in_file` checks file-local records first
- `add_record` deduplicates by `(file, var_name)` — no double-counting
- `taint_status` is a three-state enum: Clean, Tainted (with provenance), Sanitized (with suppressor)
- The `StringMap.t` structure enables O(log n) file lookup and O(n) global scan

### 5.3 Finding Graph (DAG)

```ocaml
(* lib/catseye_types/dag_types.ml *)

type node_id = string

type dag_node = {
  id : node_id;
  label : string;
  node_type : [ `Source | `Propagator | `Sink | `Sanitizer ];
  file : string;
  line : int;
}

type dag_edge = {
  src : node_id;
  dst : node_id;
  label : string;    (* "flows to" | "defines" *)
}

type vulnerability_dag = {
  nodes : dag_node list;
  edges : dag_edge list;
  entry_points : node_id list;  (* Source nodes (taint origins) *)
  exit_point : node_id;         (* Sink node (vulnerable call) *)
}
```

**DAG construction algorithm** (in `dag.ml`):
1. Start from the sink call node
2. For each tainted arg, walk backwards through assignments
3. At each assignment, find the RHS source variable (if any)
4. Recurse until reaching a parameter (Source) or root assignment
5. Cycle prevention via `StringSet` of visited variables
6. Depth capped at 50 to prevent runaway traces

### 5.4 Finding

```ocaml
(* lib/catseye_types/finding.ml *)

type flow_step = {
  file : string;
  line : int;
  message : string;
}

type reachability_status =
  | Live      (* Reachable from a public entry point — HISS priority *)
  | Dormant   (* In dead code or unreachable paths *)
  | Safe      (* Explicitly sanitized or validated *)

type reachability = {
  status : reachability_status;
  entry_point : string option;     (* e.g., "src/routes.cr:42" *)
  entry_function : string option;  (* e.g., "handle_get_request" *)
  path_length : int;               (* BFS hop count *)
  path : (string * int) list;      (* [(file, line), ...] *)
}

type t = {
  rule : string;                    (* e.g., "SSRF", "SQLInjection" *)
  severity : string;                (* "Critical" | "High" | "Medium" | "Low" *)
  file : string;
  line : int;
  message : string;
  flow : flow_step list;            (* Taint trace: source → ... → sink *)
  language : string;
  dependency : string option;       (* For supply chain findings *)
  reachability : reachability option;
}
```

---

## 6. Module I: Catseye — Security & Taint Analysis

### 6.1 Taint Analysis Pipeline

The Catseye engine implements **inter-procedural taint analysis** using a **fixed-point iteration** model. The pipeline has six stages:

```
┌─────────┐    ┌───────────┐    ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐
│  SEED   │───▶│ PROPAGATE │───▶│ RETURNS │───▶│ INTERPROC │───▶│PROPAGATE │───▶│ DAG BUILD │
│         │    │ (fixpoint)│    │         │    │           │    │ (2nd)    │    │           │
└─────────┘    └───────────┘    └─────────┘    └───────────┘    └──────────┘    └───────────┘
```

#### Stage 1: SEED — Initial Taint Marking

Two seeding strategies identify initial tainted variables:

**Strategy A — Parameter Names:** Function parameters whose names match known source patterns (`params`, `request`, `query`, `url`, etc.) are marked tainted. The source list is configurable via `.catseye.toml` `analysis.extra_sources`.

```ocaml
(* From seed.ml *)
let seed_from_params nodes extra_sources db =
  (* For each Def node, check if any arg matches known_sources @ extra_sources *)
  (* Add taint record with Known_source origin *)
```

**Strategy B — Extractor Flags:** The Crystal extractor sets `taint=true` on assignments where the RHS is a known tainted value (e.g., `url = params["url"]`). This is a first-pass heuristic refined by the engine.

#### Stage 2: PROPAGATE — Fixed-Point Iteration

Assignment propagation continues until no new tainted variables are discovered:

```ocaml
(* From propagate.ml — simplified *)
let rec loop db count =
  if count >= 100 then db   (* Safety bound *)
  else
    let size_before = Db.db_size db in
    let db' = do_propagate nodes db in  (* One pass over all assigns *)
    let size_after = Db.db_size db' in
    if size_after > size_before         (* New vars found? *)
    then loop db' (count + 1)           (* Continue iterating *)
    else db'                            (* Fixed point reached *)
```

**Propagation rule:** If `x = y` and `y` is tainted → `x` is tainted.  
**Sanitizer rule:** If `x = URI.parse(y)` → `x` is NOT tainted (even if `y` is).  
**Scope rule:** Taint is checked file-locally first (`is_tainted_in_file`), then globally.

#### Stage 3: RETURNS — Function Return Taint

Functions whose body produces tainted data are themselves marked as tainted:

```
def fetch_url(params)
  url = params["url"]    ← tainted (from params)
  HTTP::Client.get(url)  ← uses tainted data
end
```

`returns.ml` detects that `fetch_url`'s body contains tainted assignments, so `fetch_url` itself enters the taint database. Any caller that assigns from `fetch_url(...)` will receive taint during inter-procedural propagation.

**Scope detection:** Function boundaries are determined by line ranges — a `Def` at line L owns all nodes until the next `Def` in the same file.

#### Stage 4: INTERPROC — Inter-Procedural Propagation

Two strategies for cross-function taint:

**Strategy 1 — Return Value:** If `url = get_url(params)` and `get_url` is in the taint DB (from Stage 3), then `url` is tainted.

**Strategy 2 — Tainted Arguments:** If `result = process(data)` and `data` is tainted, then `result` is tainted (conservative assumption for external/unanalyzed functions).

```ocaml
(* From interproc.ml — Strategy 1 *)
let tainted_call =
  node.args
  |> List.find_opt (fun a ->
    a.arg_type = ArgCall && Db.has_record acc a.value)
in
(* If found and not a sanitizer → propagate taint to assign target *)
```

**Sanitizer override:** If the call is a known sanitizer (`URI.parse`, `Path.basename`, etc.), the result is clean regardless of input taint.

#### Stage 5: Second PROPAGATION

After inter-procedural taint has been applied, a second pass of propagation ensures all transitive assignments are caught. This handles chains like:

```
url = get_url(params)       ← interproc marks url
path = url                  ← 2nd propagation catches this
```

#### Stage 6: DAG BUILD — Vulnerability Graph Construction

For each finding, the engine builds a DAG tracing the taint path from source to sink:

```
Source ──→ Propagator ──→ Propagator ──→ Sink
  │                         │
  └──→ Propagator ──────────┘         (diamond pattern)
```

The DAG is converted to `flow_step list` for reports via DFS with post-order append, then reversed to produce source→sink ordering.

### 6.2 Rule System

Rules are defined in KDL files (see §9.2) and interpreted by the rule engine:

```ocaml
(* From catseye_rules/types.ml *)
type rule_def = {
  id : string;                  (* "SSRF", "SQLInjection", etc. *)
  severity : string;            (* "Critical", "High", "Medium", "Low" *)
  sinks : sink_def list;        (* Vulnerable function patterns *)
  sources : source_def list;    (* Known taint sources *)
  conditions : conditions;      (* Rule applicability conditions *)
  message_template : string;    (* "{sink} with {tainted_vars}" *)
}
```

**Rule evaluation order** (per node):
1. Language filter — skip if node language is excluded
2. Sink match — does the node's call name match a sink pattern (substring)?
3. Condition evaluation — taint check, literal check, metadata suppression
4. Sanitizer check — if any arg is a sanitizer call, suppress the finding
5. Finding emission — create `Finding.t` with substituted message template

### 6.3 Predator Vision — Reachability Analysis

Predator Vision distinguishes between vulnerabilities in **live code** (reachable from a public entry point) and **dormant code** (dead code, internal utilities, unreachable paths).

#### Algorithm

```
1. SCOPE DETECTION
   Group nodes by file, sort by line, identify function boundaries
   (Def at line L owns nodes until next Def in same file)

2. CALL ADJACENCY
   For each Call node, find its enclosing function scope
   Build map: caller_function → [(called_function, file, line)]

3. ENTRY POINT DETECTION
   Scan Def nodes for:
   - HTTP handlers: params matching {params, request, req, conn, ...}
   - HTTP patterns: function names matching {handle_, get_, post_, ...}
   - CLI entry: function names matching {main, run, cli, ...}

4. BFS REACHABILITY
   From each entry point, BFS through call adjacency
   Result: StringSet.t of reachable function names

5. FINDING TAGGING
   For each finding, find its enclosing function scope
   If function ∈ reachable set → Live
   If function ∉ reachable set → Dormant
```

#### Reachability Statuses

| Status | Hunter Level | Meaning | Report Priority |
|--------|-------------|---------|-----------------|
| `Live` | 🔴 HISS | Reachable from a public entry point via call chain | Immediate triage |
| `Dormant` | 🟡 MEOW | Not reachable from any detected entry point | Lower priority |
| `Safe` | 🟢 PURR | Explicitly sanitized or validated | Informational |

#### Path Tracing

For `Live` findings, BFS with parent tracking reconstructs the shortest call path from entry point to the vulnerable function. This produces:
- `entry_point`: `"src/routes.cr:42"`
- `entry_function`: `"handle_get_request"`
- `path`: `[(src/routes.cr, 42), (src/service.cr, 15)]`
- `path_length`: 2

---

## 7. Module II: Claws — Code Smells & DRY Detection

Claws is the health analysis module, responsible for detecting code quality issues that degrade maintainability and increase bug surface area.

### 7.1 Smell Detection — Recursive AST Walkers

Claws operates on the same `Security_node.t` stream as Catseye, applying pattern-matching walkers to detect three categories of smells:

#### 7.1.1 Complexity — Cyclomatic Complexity

**Metric:** McCabe's cyclomatic complexity, approximated from the AST.

```ocaml
(* lib/catseye_claws/complexity.ml — design spec *)

type complexity_config = {
  warning_threshold : int;   (* Default: 10 → MEOW *)
  critical_threshold : int;  (* Default: 20 → HISS *)
}

(** Approximate cyclomatic complexity for a function.
    Count decision points in the function body:
    - Each `if`/`unless`/`case`/`select` → +1
    - Each `&&`/`||` in conditions → +1
    - Each `.each`/`loop`/`while`/`for` → +1
    - Base complexity: 1
*)
let compute_complexity (fn_nodes : Security_node.t list) : int
```

**Thresholds:**

| Complexity | Hunter Level | Response |
|-----------|-------------|----------|
| 1–9 | PURR | Clean. No action needed. |
| 10–19 | MEOW | Warning. Consider refactoring. |
| 20+ | HISS | Critical. Function is a maintenance hazard. |

**Implementation strategy:** Walk all nodes within a function's scope (line range from Def to next Def). Count decision points heuristically: nodes with names matching `if`, `unless`, `case`, `select`, `when`, `&&`, `||`, `loop`, `while`, `for`, `.each`, `.map`, `.select`.

**Limitation:** Without full AST structure, this is an approximation. The Crystal extractor could be extended to emit explicit complexity metadata.

#### 7.1.2 Anatomy — Structural Smells

Three detectors in `anatomy.ml`:

**a) Long Parameter Lists**

```ocaml
type anatomy_config = {
  max_params : int;          (* Default: 5 → MEOW *)
  max_params_critical : int; (* Default: 8 → HISS *)
  max_nesting_depth : int;   (* Default: 4 → MEOW *)
  max_nesting_critical : int;(* Default: 6 → HISS *)
  max_methods_per_class : int; (* Default: 20 → MEOW *)
}

(** Check Def nodes for parameter count *)
let check_param_count (node : Security_node.t) : smell option =
  match node.node_type with
  | Def ->
    let count = List.length node.args in
    if count >= config.max_params_critical then
      Some { rule = "LongParameterList"; severity = "Critical"; ... }
    else if count >= config.max_params then
      Some { rule = "LongParameterList"; severity = "Medium"; ... }
    else None
  | _ -> None
```

**b) Deep Nesting**

Nesting depth is approximated by tracking indentation increases in the node stream. Each scope transition (line number jump backward + new Def/Call) increments depth. Functions with nesting > threshold are flagged.

**c) God Objects**

Track method density per file: if a file has > `max_methods_per_class` Def nodes, it's flagged as a potential God Object.

#### 7.1.3 Ameba Hook — Crystal-Specific Linting

For Crystal projects, Claws can delegate to the [Ameba](https://github.com/crystal-ameba/ameba) linter for idiomatic checks:

```ocaml
(* lib/catseye_claws/ameba_hook.ml — design spec *)

(** Run Ameba on Crystal files and convert results to Finding.t.
    Ameba is invoked as an external process:
      ameba --format json <file.cr>
    Output is parsed and converted to Catseye findings.
*)
let run_ameba (files : string list) : Finding.t list
```

**Integration points:**
1. Check if `ameba` is available in `$PATH`
2. Run `ameba --format json` on Crystal files
3. Parse JSON output, map Ameba severities to Hunter levels
4. Convert to `Finding.t` with `rule = "Ameba:<rule_name>"`
5. Merge with Claws findings

**Ameba is optional.** If not installed, Claws skips this step silently.

### 7.2 DRY Detection — Structural Hashing

#### 7.2.1 Algorithm Overview

Structural hashing identifies duplicate code blocks across files by hashing normalized AST sub-trees:

```
1. SLICE       Divide each file's AST into overlapping windows of N nodes
2. NORMALIZE   Strip variable names, literals, line numbers → canonical form
3. HASH        Compute structural hash of each normalized window
4. BUCKET      Group windows by hash value
5. REPORT      Buckets with ≥2 entries → DRY violation
```

#### 7.2.2 Data Model

```ocaml
(* lib/catseye_claws/dry.ml — design spec *)

type window = {
  file : string;
  start_line : int;
  end_line : int;
  nodes : Security_node.t list;  (* The original nodes in this window *)
  normalized : string;           (* Canonical representation *)
  hash : string;                 (* Structural hash *)
}

type dry_violation = {
  hash : string;
  occurrences : window list;     (* ≥2 occurrences *)
  similarity : float;            (* 0.0–1.0, always 1.0 for exact matches *)
}

(** Window size in AST nodes. Default: 6 (roughly a function body). *)
let default_window_size = 6

(** Normalize a window: strip var names, literals, line numbers. *)
let normalize (nodes : Security_node.t list) : string =
  (* For each node, emit: node_type | canonical_name_pattern | arg_count
     e.g., "Call|HTTP::Client.get|2" "Assign|_|1" "Def|_|3" *)
  ...

(** Compute structural hash of a normalized window. *)
let structural_hash (normalized : string) : string =
  (* Hashtbl.hash normalized → hex string
     Same approach as cache.ml — adequate for structural fingerprinting *)
  Printf.sprintf "%08x" (Hashtbl.hash normalized)
```

#### 7.2.3 Detection Pipeline

```ocaml
(** Detect DRY violations across all files.
    Returns list of violations, each with ≥2 occurrences. *)
let detect_dry (nodes_by_file : (string * Security_node.t list) list)
    ~(window_size : int) : dry_violation list =
  (* 1. Generate windows for each file *)
  let windows = List.concat_map (fun (file, nodes) ->
    generate_windows file nodes window_size
  ) nodes_by_file in
  (* 2. Group by hash *)
  let buckets = Hashtbl.create 256 in
  List.iter (fun w ->
    let existing = try Hashtbl.find buckets w.hash with Not_found -> [] in
    Hashtbl.replace buckets w.hash (w :: existing)
  ) windows;
  (* 3. Filter to violations (≥2 occurrences, different files or locations) *)
  Hashtbl.fold (fun _hash windows acc ->
    if List.length windows >= 2 then
      (* Check they're not the same location *)
      let unique = List.sort_uniq (fun a b ->
        compare (a.file ^ string_of_int a.start_line)
                (b.file ^ string_of_int b.start_line)
      ) windows in
      if List.length unique >= 2 then
        { hash; occurrences = unique; similarity = 1.0 } :: acc
      else acc
    else acc
  ) buckets []
```

#### 7.2.4 Normalization Strategy

Normalization produces a canonical string representation that ignores superficial differences:

| Original | Normalized |
|----------|-----------|
| `x = params["url"]` | `Assign|_|1` |
| `HTTP::Client.get(url)` | `Call|HTTP::Client.get|1` |
| `result = process(data, opts)` | `Assign|_|2` |
| `y = params["id"]` | `Assign|_|1` |

The first and last examples hash identically — same shape, different variable names. This catches copy-paste duplication with variable renaming.

**Future enhancement:** Fuzzy matching via edit distance on normalized strings (similarity < 1.0 but > 0.8).

---

## 8. Worker Protocol

### 8.1 Crystal Worker Pool

The Crystal extractor runs as an external process communicating via JSON over stdin/stdout. This section specifies the wire protocol.

#### 8.1.1 Current Model (Per-File Spawn)

Currently, each Crystal file spawns a new process:

```
OCaml ──spawn──→ crystal run extractor.cr -- <file>
                         │
                         ▼
              Crystal::Parser → SecurityVisitor
                         │
                         ▼
              JSON array of Security Nodes → stdout
                         │
OCaml ←──read──── stdout (pipe)
```

#### 8.1.2 Persistent Worker Pool (Target Architecture)

For performance, the Crystal extractor should run as a **persistent pool** of worker processes:

```
┌──────────────┐                    ┌──────────────────┐
│   OCaml      │   stdin (JSON)     │  Crystal Worker   │
│   Orchestr.  │───────────────────▶│  (persistent)     │
│              │                    │                    │
│              │◀───────────────────│  Loop:             │
│              │   stdout (JSON)    │  1. Read request   │
└──────────────┘                    │  2. Parse file     │
                                    │  3. Extract nodes  │
                                    │  4. Write response │
                                    │  5. Goto 1         │
                                    └──────────────────┘
```

#### 8.1.3 Protocol Messages

**Request (OCaml → Crystal):**

```json
{
  "id": 1,
  "method": "extract",
  "file": "src/controller.cr",
  "content": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Request ID for response correlation |
| `method` | string | `"extract"` (future: `"ping"`, `"shutdown"`) |
| `file` | string | Absolute path to the source file |
| `content` | string\|null | File content (if pre-loaded), null = worker reads file |

**Response (Crystal → OCaml):**

```json
{
  "id": 1,
  "status": "ok",
  "nodes": [
    {
      "type": "def",
      "name": "handle_request",
      "args": [{"arg_type": "var", "value": "params", "field": ""}],
      "line": 12,
      "taint": false,
      "file": "src/controller.cr",
      "language": "crystal"
    }
  ]
}
```

**Error Response:**

```json
{
  "id": 1,
  "status": "error",
  "error": "Parse error: unexpected token at line 42"
}
```

#### 8.1.4 Protocol Rules

1. **One JSON object per line** (newline-delimited JSON / NDJSON)
2. **Request-response correlation** via `id` field
3. **Worker lifecycle:** Workers persist until orchestrator sends `{"id": N, "method": "shutdown"}` or pipe closes
4. **Pool size:** Configured via `analysis.crystal_workers` in TOML (default: 2)
5. **Timeout:** 30 seconds per extraction request. On timeout, OCaml kills and respawns the worker.
6. **Error handling:** Parse errors return `status: "error"` with a message. The orchestrator logs the error and skips the file.

#### 8.1.5 Crystal Worker Implementation (Pseudocode)

```crystal
# Persistent worker loop
loop do
  line = STDIN.gets
  break if line.nil?

  request = JSON.parse(line)
  id = request["id"].as_i

  case request["method"].as_s
  when "extract"
    file = request["file"].as_s
    source = File.read(file)
    ast = Crystal::Parser.new(source).parse
    visitor = SecurityVisitor.new(file)
    ast.accept(visitor)
    annotated = SecurityVisitor.annotate_timeouts(visitor.nodes)

    response = {
      id: id,
      status: "ok",
      nodes: annotated
    }
    STDOUT.puts(response.to_json)
    STDOUT.flush
  when "shutdown"
    break
  end
rescue ex
  STDOUT.puts({id: id, status: "error", error: ex.message}.to_json)
  STDOUT.flush
end
```

---

## 9. Configuration & Rules — The Hybrid Model

### 9.1 TOML — Orchestration Configuration

Project-level settings are defined in `.catseye.toml`, discovered by walking up from the target directory.

```toml
# .catseye.toml — Project-level orchestration config

[scan]
# File extensions to scan (default: .cr, .gleam)
# extensions = [".cr", ".gleam"]

# Directories to exclude
exclude = ["node_modules", ".git", "vendor", "lib", "spec"]

# Maximum file size to scan (bytes)
# max_file_size = 1_000_000

# Path to Crystal extractor binary
# crystal_extractor = "bin/catseye-crystal-extractor"

# Rules directory
# rules_dir = "rules"

[analysis]
# Extra taint sources (beyond built-in list)
# extra_sources = ["my_source"]

# Extra sanitizer patterns
# extra_sanitizers = ["my_sanitizer"]

# Parallelism (0 = auto-detect CPU count)
# parallelism = 0

# Crystal worker pool size
# crystal_workers = 2

[output]
# Default output format: terminal, json, sarif, markdown
# format = "terminal"

[persona]
# Hunter persona (set to false for plain output)
# enabled = true

[predator_vision]
# Reachability analysis (set to true for Live/Dormant tagging)
# enabled = false

[crows_nest]
# Supply chain audit
# enabled = false

[claws]
# Code smell detection
# enabled = false

# Complexity thresholds
# complexity_warning = 10
# complexity_critical = 20

# Anatomy thresholds
# max_params = 5
# max_nesting = 4
# max_methods_per_class = 20

# DRY detection
# dry_window_size = 6
# dry_min_occurrences = 2

[caching]
# Cache directory
# dir = ".catseye"

# Disable caching
# no_cache = false
```

**Loading order:** CLI args → `.catseye.toml` overlay → final config. TOML values override defaults but CLI flags override TOML.

### 9.2 KDL — Rule Logic DSL

Security and smell rules are defined in KDL (KDL Document Language), chosen for its hierarchical structure that maps naturally to the rule system's nested definitions.

#### 9.2.1 KDL Structure

```
rule <id> [props] {
    sinks {
        sink <pattern> {
            sanitizer <sanitizer_pattern>
        }
    }
    sources {
        source <name> [field=<field>]
    }
    conditions {
        skip_taint_check
        skip_all_literals
        check_args_contain <pattern>
        check_args_missing <pattern>
    }
    languages {
        include <language>
        exclude <language>
    }
    message "<template>"
}
```

#### 9.2.2 KDL → OCaml Mapping

| KDL Construct | OCaml Type | Mapping |
|---------------|-----------|---------|
| `rule "SSRF"` | `rule_def.id` | First positional arg of `rule` node |
| `severity="High"` | `rule_def.severity` | Property on `rule` node |
| `sink "HTTP::Client.get"` | `sink_def.pattern` | First positional arg of `sink` node |
| `sanitizer "URI.parse"` | `sink_def.sanitizers` | Child of `sink` node |
| `source "params" field="url"` | `source_def.{name, field}` | Arg + property on `source` node |
| `skip_taint_check` | `conditions.requires_tainted_args = false` | Presence of condition node |
| `check_args_contain "password"` | `conditions.check_args_contain` | Arg of condition node |
| `include "crystal"` | `conditions.include_languages` | Child of `languages` node |
| `message "..."` | `rule_def.message_template` | First positional arg of `message` node |

#### 9.2.3 Example: Complete Rule

```kdl
rule "SSRF" severity="High" {
    sinks {
        sink "HTTP::Client.get" {
            sanitizer "URI.parse"
            sanitizer "URI.encode"
        }
        sink "HTTP::Client.post" {
            sanitizer "URI.parse"
        }
        sink "HTTP::Client.put"
        sink "HTTP::Client.patch"
        sink "HTTP::Client.delete"
        sink "HTTP::Client.exec"
    }
    sources {
        source "params" field="url"
        source "request" field="body"
        source "user_url"
        source "url"
        source "query"
    }
    message "Potential SSRF via {sink} with user-controlled URL"
}
```

**Hierarchical mapping:**
1. The `rule` node becomes a `rule_def`
2. `sinks` children become `sink_def list`
3. `sanitizer` grandchildren become `sink_def.sanitizers`
4. `sources` children become `source_def list`
5. `message` becomes the template with `{sink}` and `{tainted_vars}` placeholders

#### 9.2.4 Template Substitution

The `{sink}` and `{tainted_vars}` placeholders in message templates are substituted at finding emission time:

- `{sink}` → the matched call's full name (e.g., `"HTTP::Client.get"`)
- `{tainted_vars}` → comma-separated list of tainted variable names from the call's args

---

## 10. Persistence Layer — Incremental Cache

### 10.1 Design Overview

The cache enables **incremental scans**: files whose content hasn't changed since the last scan are served from cache, skipping AST extraction entirely.

```
┌─────────────┐     ┌─────────────┐     HIT    ┌─────────────┐
│  File Path   │────▶│  Hash Check │───────────▶│ Cached Nodes│
│  on Disk     │     │             │            └─────────────┘
└─────────────┘     └──────┬──────┘
                            │ MISS
                            ▼
                    ┌───────────────┐
                    │   Extract     │
                    │   (Crystal /  │
                    │    Gleam)     │
                    └──────┬────────┘
                           │
                           ▼
                    ┌───────────────┐
                    │  Store in     │
                    │  Cache        │
                    └───────────────┘
```

### 10.2 Content Addressing

Files are keyed by path and fingerprinted by content hash:

```ocaml
(* From cache.ml *)

(** Fingerprint: OCaml's Hashtbl.hash — fast, deterministic.
    Not cryptographic — adequate for local content-addressing.
    Future: swap for Blake3 when bindings are available. *)
let fingerprint (content : string) : string =
  Printf.sprintf "%08x" (Hashtbl.hash content)

let file_hash (path : string) : string =
  (* Read file, compute fingerprint *)
```

### 10.3 Storage

Currently in-memory (`Hashtbl`), with a migration path to SQLite:

```ocaml
module Store = struct
  type entry = {
    path : string;
    hash : string;
    nodes : Security_node.t list;
    analyzed_at : float;  (* Unix timestamp *)
  }

  let tbl : (string, entry) Hashtbl.t = Hashtbl.create 64

  let get path = try Some (Hashtbl.find tbl path) with Not_found -> None
  let put path hash nodes = Hashtbl.replace tbl path { path; hash; nodes; analyzed_at = Unix.gettimeofday () }

  let is_fresh path current_hash =
    match get path with
    | Some e -> e.hash = current_hash
    | None -> false
end
```

### 10.4 Cache Operations

```ocaml
(** Check if a file needs re-extraction.
    Returns Some cached_nodes if fresh, None if stale/missing. *)
val check : string -> Security_node.t list option

(** Store extraction results. *)
val store : string -> Security_node.t list -> unit

(** Invalidate cache for a specific file. *)
val invalidate : string -> unit

(** Clear entire cache. *)
val clear : unit -> unit

(** Cache statistics: (fresh_count, total_count) *)
val stats : unit -> int * int
```

### 10.5 SQLite Migration Path

The current `Hashtbl`-based cache is ephemeral (lost between runs). The migration path to persistent caching:

1. **Phase 1 (current):** In-memory `Hashtbl` — session-only, no persistence
2. **Phase 2 (planned):** SQLite-backed cache — persists across runs
   - Table: `cache (path TEXT PRIMARY KEY, hash TEXT, nodes_json TEXT, analyzed_at REAL)`
   - Nodes serialized as JSON via `Security_node.encode_many`
   - `check` queries by path, compares hash
   - `store` upserts path + hash + nodes_json
3. **Phase 3 (future):** Shared cache for CI — content-addressed by hash, not path

---

## 11. Infrastructure — Nix & Static Linking

### 11.1 Nix Flake

The development environment is fully managed by Nix:

```nix
# Key toolchain versions (from flake.nix)
Crystal 1.18         # AST extraction
OCaml 5.x            # Main engine
Dune 3.16            # Build system
tree-sitter + gleam   # Gleam parsing
SQLite3              # Crow's Nest cache
```

### 11.2 Build Pipeline

```bash
# Development build
just build-ocaml          # dune build → bin/catseye-ocaml

# Release build (optimized)
just build-ocaml-release  # dune build --profile release

# Crystal extractor
crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release
```

### 11.3 Static Linking (Target)

For distribution as single binaries:

- **OCaml:** `dune build --profile release` with `ocamlfind` + `musl` toolchain
  - `ocamlfind ocamlopt -linkpkg -package ... -ccopt -static`
  - Produces fully static ELF binary (no libc dependency)
- **Crystal:** `crystal build --release --static`
  - Produces static binary linked against musl

### 11.4 CI Integration

The `justfile` provides CI-friendly commands:

```bash
just test           # Unit tests + E2E validation
just scan-json dir  # JSON output for CI parsing
just scan-sarif dir # SARIF for GitHub Code Scanning
just lint           # OCaml format check
```

---

## 12. Performance Budget

Based on real-world scan results from the current codebase:

| Metric | Budget | Current (Observed) | Notes |
|--------|--------|---------------------|-------|
| File discovery | < 100ms | ~5ms (66 files) | Directory walk + filter |
| Single file extraction | < 50ms | ~20ms (Crystal) | Crystal::Parser + JSON |
| Single file extraction | < 10ms | ~5ms (Gleam) | tree-sitter XML |
| Cache hit serving | < 1ms | ~0.1ms | Hashtbl lookup |
| Taint analysis (1K nodes) | < 500ms | ~200ms | Full pipeline |
| Reachability analysis | < 100ms | ~30ms | BFS over call graph |
| SARIF report generation | < 50ms | ~10ms | JSON serialization |
| **Total scan (66 files)** | **< 5s** | **~2s** | Including extraction |

### Scaling Targets

| Codebase Size | Node Count | Target Time | Strategy |
|---------------|-----------|-------------|----------|
| Small (< 50 files) | < 5K | < 3s | Sequential |
| Medium (50–500 files) | 5K–50K | < 15s | Cached + parallel extraction |
| Large (500+ files) | 50K+ | < 60s | Incremental + parallel + persistent workers |

---

## 13. Appendix A: Threat Model for the Analyzer

Catseye analyzes source code. It does **not** execute it. The following threat model applies to the analyzer itself:

| Threat | Mitigation |
|--------|-----------|
| Malicious source file exploits extractor | Crystal extractor runs in subprocess, isolated from engine |
| Path traversal in file discovery | Discovery is limited to the target directory |
| Worker process hang | 30-second timeout per extraction; kill + respawn |
| Cache poisoning | Content-addressed: hash mismatch → re-extract |
| Rule injection via malicious KDL | KDL parser validates structure; malformed rules are skipped with warning |
| Resource exhaustion (huge files) | `max_file_size` config option skips oversized files |

---

## 14. Appendix B: Glossary of Hunter Terminology

| Term | Technical Meaning |
|------|-------------------|
| **Hiss** | Critical/High severity finding — exploitable vulnerability |
| **Meow** | Medium/Low severity finding — suspicious pattern |
| **Purr** | Clean — no issues detected |
| **Scent** | File discovery phase — "picking up a scent trail" |
| **Stalk** | AST extraction — "stalking a file" |
| **Pounce** | Analysis engine — "pouncing on taint flows" |
| **Prey** | A confirmed finding — "the prey is cornered" |
| **Predator Vision** | Reachability analysis — distinguishing Live from Dormant |
| **Crow's Nest** | Supply chain audit — watching from above for CVEs |
| **Claws** | Code smell detection — sharpening the tools |
| **The Hunter rests** | Scan complete with zero findings |

---

*End of Technical Design Document. The Hunter is always watching.*
