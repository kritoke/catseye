# Catseye OCaml Rewrite Plan

## Status: Rev 3 — Comprehensive Architecture

**Date**: 2026-05-09 (rev 3)

**Revision history**:
| Rev | Date | Changes |
|-----|------|---------|
| 1 | 2026-05-09 | Initial plan |
| 2 | 2026-05-09 | Incorporated 5 external critiques |
| 3 | 2026-05-09 | KDL rule DSL, TOML config, Blake3 cache, Phase 0 diff testing, DAG output, Crystal worker pool |

---

## Executive Summary

Migrate Catseye from Nim + Gleam/BEAM + Crystal to **OCaml + Crystal**, keeping the Crystal extractor for its `Crystal::Parser` advantage.

**Architecture in one line**: OCaml CLI reads TOML config + KDL rules → extracts via tree-sitter (or Crystal worker pool) → parallel taint analysis with OCaml 5 Domains → vulnerability DAG output.

**New in rev 3**:
- **Hybrid Configuration**: TOML (`otaml`) for orchestration, KDL for rule DSL
- **OCaml 5 Multicore**: Domains for parallel taint analysis, Eio for Crystal worker pool
- **State Persistence**: Blake3-hash-keyed cache backed by SQLite
- **Phase 0**: Differential testing against legacy Gleam engine before any migration
- **Vulnerability DAGs**: Directed Acyclic Graphs replace linear flow traces

---

## 1. Current Architecture & Bottlenecks

### 1.1 Current Components

| Component | Language | Lines | Role |
|-----------|----------|-------|------|
| CLI | Nim | 651 | File discovery, orchestration, output formatting |
| Gleam Extractor | Nim + tree-sitter | 269 | Parse .gleam files → Security Node JSON |
| Crystal Extractor | Crystal | 298 | Parse .cr files → Security Node JSON |
| Engine | Gleam/BEAM | 2657 | Taint analysis, rule matching, findings |

### 1.2 Bottlenecks on Large Codebases

**B1: Sequential extraction** — 500 Crystal files → 500 `crystal run` spawns @ 400ms each = ~200s just on process startup.

**B2: Multiple process boundaries** — Nim↔Crystal↔BEAM, each with JSON serialization round-trips.

**B3: Disk I/O in pipeline** — Writes entire node corpus to `/tmp/catseye-engine-input.json` before piping to `erl`.

**B4: No parallelism** — Extraction and analysis are fully sequential.

**B5: No caching** — Every scan re-extracts and re-analyzes every file, even if unchanged.

---

## 2. Target Architecture

### 2.1 System Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        catseye.toml          rules/                         │
│                        (TOML/otaml)          (*.kdl — Rule DSL)             │
└──────────────┬──────────────────────────────────────┬────────────────────────┘
               │                                      │
               ▼                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         OCaml CLI (Catseye)                                  │
│                                                                              │
│  Config Layer (otaml)          Rule Loader (kdl OCaml)                      │
│  - project metadata            - Parse .kdl rule files                      │
│  - file exclusions             - Compile to Rule.t at startup               │
│  - output paths                - Hot-reload on --watch (future)              │
│  - engine tuning                                                              │
│                                                                              │
│  State Persistence (SQLite)                                                  │
│  - Blake3 file hashes          → skip unchanged extractions                 │
│  - Cached TaintDB summaries    → skip unchanged analysis                    │
│  - Stored at .catseye/state.db                                               │
└──────────────────────┬───────────────────────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌─────────────────────┐  ┌──────────────────────────────────────────────────┐
│ Crystal Worker Pool  │  │          OCaml tree-sitter Extractors            │
│ (Eio-managed)        │  │                                                  │
│                      │  │  Gleam ── Python ── Rust ── JS/TS ── ...        │
│  ┌─────┐ ┌─────┐    │  │  (all in-process, zero IPC overhead)             │
│  │ W1  │ │ W2  │    │  │                                                  │
│  │stdin│ │stdin│    │  └──────────────────────┬───────────────────────────┘
│  │stdout│stdout│   │                         │
│  └─────┘ └─────┘    │                         │
│                      │                         │
│  Pre-built binary    │                         │
│  Persistent lifetime │                         │
└──────────┬───────────┘                         │
           │                                      │
           └──────────────┬───────────────────────┘
                          │ Security Nodes (in-memory)
                          ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    OCaml Taint Analysis Engine (OCaml 5 Multicore)           │
│                                                                              │
│  ┌─────────────────────────┐    ┌─────────────────────────────────────────┐ │
│  │ Phase A: Per-File       │    │ Phase B: Global                         │ │
│  │ (Domain.parallel_map)   │    │ (Sequential — cross-file deps)          │ │
│  │                         │    │                                         │ │
│  │  Seed sources per file  │    │  Merge per-file TaintDBs               │ │
│  │  Propagate within file  │──→ │  Inter-procedural propagation          │ │
│  │  Cache result to SQLite │    │                                         │ │
│  └─────────────────────────┘    └────────────────┬────────────────────────┘ │
│                                                  │                          │
│  ┌───────────────────────────────────────────────┘                          │
│  │  Phase C: Rule Matching (Domain.parallel_map)                            │
│  │  Each KDL-loaded rule checks independently                              │
│  └──────────────────────┬──────────────────────────────────────────────────┘ │
│                          │                                                   │
│  ┌───────────────────────┘                                                   │
│  │  ┌────────────────────────────────────────────────────────────────────┐  │
│  └─→│  Vulnerability DAG Builder                                         │  │
│     │  - Nodes: Source, Assignment, Call, Sanitizer, Sink                │  │
│     │  - Edges: Taint propagation, Sanitization (typed)                  │  │
│     │  - Multiple source convergence, dead-path tracking                 │  │
│     │  - Serialized to SARIF codeFlows / DOT / JSON                      │  │
│     └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
             Output Formatters (terminal / JSON / SARIF / Markdown / DOT)
```

### 2.2 Key Changes from Current

| Aspect | Current | Target |
|--------|---------|--------|
| **CLI language** | Nim | OCaml |
| **Configuration** | `.catseye.toml` (Nim parsecfg) | `.catseye.toml` (otaml) + `.kdl` rules |
| **Rule definitions** | Hardcoded Gleam modules | KDL files → OCaml rule interpreter |
| **Gleam extractor** | Nim + tree-sitter CLI subprocess | OCaml native tree-sitter (in-process) |
| **Crystal extractor** | `crystal run` per file | Pre-built binary + persistent worker pool (Eio) |
| **Engine** | Gleam/BEAM | OCaml 5 (pure, multicore Domains) |
| **Parallelism** | None | Domain.parallel_map for CPU phases, Eio for I/O |
| **Caching** | None | Blake3 hash → SQLite (extraction + analysis summaries) |
| **Output** | Linear flow traces | Vulnerability DAGs |
| **Validation** | Manual | Differential testing (Phase 0, CI) |

---

## 3. Hybrid Configuration Model

### 3.1 Why Two Formats?

TOML and KDL serve fundamentally different purposes:

| | TOML (`catseye.toml`) | KDL (`rules/*.kdl`) |
|---|---|---|
| **Purpose** | Project orchestration | Security rule definitions |
| **Structure** | Flat key-value, sections | Hierarchical tree |
| **Who edits** | Project developers | Security engineers |
| **Changed often** | No (project config) | Yes (new rules, tuning) |
| **Maps to** | CLI flags, paths, exclusions | AST nodes, taint patterns |

TOML is correct for flat configuration (paths, flags, tuning knobs). KDL is correct for rules because security rules are **hierarchical** — they nest sinks inside patterns, sanitizers inside flows, and conditions inside checks. KDL's tree structure maps directly to AST node hierarchies.

### 3.2 TOML Configuration (otaml)

```toml
# catseye.toml — Project Configuration

[project]
name = "my-crystal-app"
version = "1.0.0"

[scan]
# Directories to scan (relative to project root)
include = ["src/", "lib/"]
# Directories or files to exclude
exclude = ["lib/cache/**", "vendor/**", "**_test.cr"]
# Languages to scan (empty = all)
languages = ["crystal", "gleam"]

[output]
# Default output format (terminal, json, sarif, markdown)
format = "terminal"
# Default output path (empty = stdout)
path = ""
# Enable colored output
color = true

[engine]
# Number of parallel workers for analysis (0 = auto-detect CPUs)
parallelism = 0
# Cache directory (relative to project root)
cache_dir = ".catseye"
# Enable incremental analysis
incremental = true

[crystal]
# Path to pre-built Crystal extractor binary
extractor = "bin/catseye-crystal-extractor"
# Number of persistent worker processes
worker_pool_size = 2

[extractors.gleam]
# tree-sitter grammar path (auto-detected if empty)
grammar_path = ""

[taint]
# Additional taint source variable names
extra_sources = ["user_id", "session_id", "cookie_value"]
# Additional sanitizer function patterns
extra_sanitizers = ["my_lib.sanitize", "clean_input"]
```

**OCaml implementation**:
```ocaml
(* lib/catseye_cli/config.ml *)
module Toml_config : sig
  type t = {
    project : project_section;
    scan : scan_section;
    output : output_section;
    engine : engine_section;
    crystal : crystal_section;
    taint : taint_section;
  }
  val load : string -> (t, [> `Msg of string ]) result
  val find_in_parents : string -> string option
end
```

**Dependency**: `otaml` — OCaml TOML parser

### 3.3 KDL Rule DSL

KDL (KDL Document Language) is a node-based document format. Its hierarchical structure maps naturally to how security rules compose: a rule contains sinks, sinks contain patterns, patterns have conditions.

#### Why KDL Over YAML/TOML for Rules

```
YAML: flat lists with indentation meaning     → ambiguous nesting
TOML: arrays of tables with dotted paths      → deeply nested = ugly
KDL:  explicit parent-child node relationships → maps to AST naturally
```

Example: expressing "SSRF when HTTP call has tainted URL, but not if URI.parse sanitizes it":

```yaml
# YAML — flat, loses the relationship between sink and sanitizer
- id: ssrf
  sinks:
    - "HTTP::Client.get"
    - "HTTP::Client.post"
  sanitizers:
    - "URI.parse"
  # How do you express "sanitizer applies to THIS sink, not THAT sink"?
  # You can't — it's a flat list.
```

```
// KDL — hierarchy makes sink-sanitizer relationship explicit
rule "SSRF" severity="High" {
    sinks {
        // Each sink can have its own sanitizers
        sink "HTTP::Client.get" {
            sanitizer "URI.parse"
            sanitizer "URI.encode"
        }
        sink "HTTP::Client.post" {
            sanitizer "URI.parse"
        }
        sink "HTTP::Client.exec"
        // No sanitizer — always flagged if tainted
    }
    sources {
        source "params" field="url"
        source "request" field="body"
        source "user_url"
    }
    conditions {
        // Flag even if only some args are tainted
        requires_tainted_args=true
        // Don't flag if ALL args are literals
        skip_all_literals=true
    }
    message "Potential SSRF: {sink} called with user-controlled argument(s): {tainted_vars}. "
            "Ensure URL validation and allowlisting is applied."
}
```

#### KDL Schema for Catseye Rules

The full rule schema, expressed as a KDL grammar:

```
rule <id: String> severity=<"Critical"|"High"|"Medium"|"Low"|"Info"> {
    sinks {
        sink <pattern: String> {
            sanitizer <pattern: String>     // 0..n
            requires_field=<String>         // optional field-sensitive match
        }                                   // 1..n sinks
    }
    sources {
        source <name: String> field=<String>?   // 0..n
    }
    conditions {
        requires_tainted_args=<Bool>        // default: true
        skip_all_literals=<Bool>            // default: true
        check_insecure_tls=<Bool>           // rule-specific extension
        check_missing_timeout=<Bool>        // rule-specific extension
    }
    message <format: String>
}
```

#### Additional Rule Examples

**Command Injection**:
```
rule "CommandInjection" severity="Critical" {
    sinks {
        sink "system"
        sink "Process.run"
        sink "os.command"
        sink "os.cmd"
    }
    sinks {
        sink "ENV[]=" {
            // ENV injection is separate sub-detection
        }
    }
    sources {
        source "params"
        source "gets"
        source "STDIN"
        source "ARGV"
        source "env"
    }
    conditions {
        requires_tainted_args=true
        skip_all_literals=true
    }
    message "Potential command injection via {sink}. "
            "User input may flow into a shell command."
}
```

**SQL Injection**:
```
rule "SQLInjection" severity="Critical" {
    sinks {
        sink "db.exec"
        sink "db.query"
        sink "db.scalar"
        sink "database.exec"
    }
    sources {
        source "params"
        source "query"
        source "user_input"
        source "request"
    }
    conditions {
        requires_tainted_args=true
        skip_all_literals=true
    }
    message "Potential SQL injection via {sink} with tainted argument(s): {tainted_vars}."
}
```

**Path Traversal**:
```
rule "PathTraversal" severity="High" {
    sinks {
        sink "File.read" {
            sanitizer "Path.basename"
            sanitizer "Path.dirname"
            sanitizer "Path.posix"
        }
        sink "File.write" {
            sanitizer "Path.basename"
        }
        sink "File.delete"
        sink "simplifile.read"
        sink "simplifile.write"
    }
    sinks {
        // Separate sub-detection for path joins
        sink "File.join"
        sink "Path.join"
    }
    sources {
        source "params" field="path"
        source "path"
        source "url"
    }
    conditions {
        requires_tainted_args=true
        skip_all_literals=true
    }
    message "Potential path traversal via {sink} with variable argument(s): {tainted_vars}. "
            "Validate and sanitize path components."
}
```

#### OCaml KDL Rule Loading

```ocaml
(* lib/catseye_rules/loader.ml *)

type sink_def = {
  pattern : string;
  sanitizers : string list;
  requires_field : string option;
}

type source_def = {
  name : string;
  field : string option;
}

type conditions = {
  requires_tainted_args : bool;
  skip_all_literals : bool;
  extensions : (string * string) list;  (* rule-specific key=value pairs *)
}

type rule_def = {
  id : string;
  severity : string;
  sinks : sink_def list;
  sources : source_def list;
  conditions : conditions;
  message_template : string;
}

val load_rules : string -> (rule_def list, [> `Msg of string ]) result
  (* Loads all .kdl files from rules/ directory *)
  (* Returns compiled rule definitions ready for the engine *)

val load_rules_from_path : string list -> (rule_def list, [> `Msg of string ]) result
  (* Load from specific paths (for testing) *)
```

#### Built-in vs Custom Rules

```
catseye/
├── rules/                         # User-defined rules (KDL)
│   ├── custom_checks.kdl         # Project-specific rules
│   └── overrides.kdl             # Override built-in severities
├── catseye.toml                   # Project configuration
└── src/

# Built-in rules are embedded in the binary (compiled from KDL at build time)
# User rules are loaded at runtime and merged with built-in rules
# User rules can override built-in rule severity or add new sinks/sources
```

**Dependency**: `kdl` — OCaml KDL parser

---

## 4. OCaml 5 & Performance Scaling

### 4.1 Multicore Engine Architecture

OCaml 5's `Domain` module provides true parallelism (separate heaps, no global lock). The taint analysis pipeline is split into phases based on their parallelizability:

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Analysis Pipeline                                    │
│                                                                        │
│  Phase A: Per-File (PARALLEL)           CPU cores: N                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                               │
│  │ File 1   │ │ File 2   │ │ File N   │  Domain.parallel_map          │
│  │ seed +   │ │ seed +   │ │ seed +   │  Each domain:                 │
│  │ propagate│ │ propagate│ │ propagate│   - owns its TaintDB copy     │
│  │ cache    │ │ cache    │ │ cache    │   - no shared mutation        │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘                               │
│       └────────────┼────────────┘                                       │
│                    ▼                                                    │
│  Phase B: Merge (SEQUENTIAL)            CPU cores: 1                   │
│  ┌──────────────────────────────┐                                      │
│  │ Merge all per-file TaintDBs  │  Fold left, associative merge       │
│  │ Inter-procedural propagation │  Cross-file function return taint    │
│  └──────────────┬───────────────┘                                      │
│                 │                                                       │
│                 ▼                                                       │
│  Phase C: Rule Matching (PARALLEL)      CPU cores: N                   │
│  ┌────────┐ ┌────────┐ ┌────────┐                                     │
│  │ SSRF   │ │ CmdInj │ │ PathTr │  Domain.parallel_map                │
│  │ check  │ │ check  │ │ check  │  Each rule is independent           │
│  └───┬────┘ └───┬────┘ └───┬────┘                                     │
│      └──────────┼──────────┘                                            │
│                 ▼                                                       │
│  Phase D: DAG Build (SEQUENTIAL)        CPU cores: 1                   │
│  ┌──────────────────────────────┐                                      │
│  │ Build vulnerability DAGs     │  Trace flows through TaintDB         │
│  │ Deduplicate findings         │  Merge overlapping paths             │
│  └──────────────────────────────┘                                      │
└────────────────────────────────────────────────────────────────────────┘
```

```ocaml
(* lib/catseye_engine/parallel.ml *)

let analyze_all ~config ~rules files =
  let n_domains = match config.engine.parallelism with
    | 0 -> Domain.recommended_count ()
    | n -> n
  in
  (* Phase A: Per-file — parallel *)
  let per_file_results =
    Domain.parallel_map ~n:n_domains
      (fun (path, nodes) ->
        let db = Taint.seed_sources ~config nodes in
        let db' = Taint.propagate nodes db in
        Cache.persist_analysis config.cache_dir path db';
        (path, nodes, db')
      ) files
  in
  (* Phase B: Merge + inter-procedural — sequential *)
  let global_db =
    List.fold_left Taint.merge_db Taint.empty_db
      (List.map (fun (_, _, db) -> db) per_file_results)
  in
  let global_db' = Taint.propagate_interprocedural
    (List.concat_map (fun (_, nodes, _) -> nodes) per_file_results)
    global_db
  in
  (* Phase C: Rule matching — parallel *)
  let findings_per_rule =
    Domain.parallel_map ~n:n_domains
      (fun rule ->
        Rule_interpreter.check rule global_db'
          (List.concat_map (fun (_, nodes, _) -> nodes) per_file_results)
      ) rules
  in
  let all_findings = List.concat findings_per_rule in
  (* Phase D: DAG build — sequential *)
  let dags = List.map (Dag.build_from_finding global_db') all_findings in
  dags
```

**Dynamic threshold**: If `List.length files < 8`, skip Domain overhead and run sequentially.

### 4.2 Eio for Crystal Worker Pool I/O

`Domain` handles CPU-bound parallelism. `Eio` (effects-based, OCaml 5 native) handles I/O-bound parallelism for the Crystal worker pool.

```ocaml
(* lib/catseye_crystal/worker_pool.ml *)

module Worker_pool : sig
  type t
  val create : config:crystal_config -> t Eio.Promise.t
  val extract : t -> string -> security_node list Eio.Promise.t
  val extract_batch : t -> string list -> (string * security_node list) list Eio.Promise.t
  val shutdown : t -> unit Eio.Promise.t
end = struct
  type worker = {
    to_worker : string Eio.Stream.t;    (* send file paths *)
    from_worker : string Eio.Stream.t;  (* receive JSON *)
    cancel : Eio.Cancel.handle;
  }
  type t = {
    workers : worker array;
    next : int Atomic.t;  (* round-robin index *)
  }

  let create ~config =
    let n = config.worker_pool_size in
    let workers = Array.init n (fun _ ->
      (* Spawn persistent Crystal process *)
      let to_w = Eio.Stream.create 1 in
      let from_w = Eio.Stream.create 1 in
      (* Eio.Process.spawn runs the pre-built binary *)
      (* stdin/stdout wired to Eio.Streams *)
      { to_worker = to_w; from_worker = from_w; cancel = ... }
    ) in
    Eio.Promise.return { workers; next = Atomic.make 0 }

  let extract t path =
    let idx = Atomic.fetch_and_add t.next 1 mod Array.length t.workers in
    let w = t.workers.(idx) in
    (* Send file path, receive JSON *)
    Eio.Stream.add w.to_worker path;
    let json = Eio.Stream.take w.from_worker in
    Eio.Promise.return (Protocol.decode_nodes json)
end
```

### 4.3 State Persistence Layer (Incremental Analysis)

#### Design

```
┌─────────────────────────────────────────────────────────────────┐
│                    State Persistence Layer                       │
│                                                                  │
│  Input: file path                                                │
│    │                                                             │
│    ▼                                                             │
│  Compute Blake3 hash of file contents                           │
│    │                                                             │
│    ▼                                                             │
│  Lookup: SQLite → SELECT nodes, taint_summary FROM cache        │
│    WHERE path = ? AND blake3 = ?                                 │
│    │                                                             │
│    ├── Hit: return cached (security_node list, taint_db option) │
│    │                                                             │
│    └── Miss: extract + analyze → INSERT into cache               │
│                                                                  │
│  Cache Invalidation:                                             │
│    - Automatic: hash mismatch = re-extract                       │
│    - Manual: --clear-cache flag                                  │
│    - Scoped: .catseye/state.db is per-project                    │
│                                                                  │
│  Cross-file dependency tracking:                                 │
│    - Phase B (merge) always re-runs (cheap, sequential)          │
│    - Phase A (per-file) is the expensive part → cached           │
│    - If file B calls function in file A, and file A changed,     │
│      inter-procedural propagation re-runs for affected files     │
└─────────────────────────────────────────────────────────────────┘
```

#### SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS extraction_cache (
    path        TEXT NOT NULL,
    blake3      TEXT NOT NULL,    -- Blake3 hex digest of file contents
    nodes_json  TEXT NOT NULL,    -- Yojson-encoded security_node list
    extracted_at INTEGER NOT NULL, -- Unix timestamp
    PRIMARY KEY (path, blake3)
);

CREATE TABLE IF NOT EXISTS analysis_cache (
    path        TEXT NOT NULL,
    blake3      TEXT NOT NULL,
    taint_json  TEXT NOT NULL,    -- Yojson-encoded per-file TaintDB
    analyzed_at INTEGER NOT NULL,
    PRIMARY KEY (path, blake3)
);

CREATE TABLE IF NOT EXISTS file_dependencies (
    source_path TEXT NOT NULL,    -- file that defines a function
    target_path TEXT NOT NULL,    -- file that calls the function
    func_name   TEXT NOT NULL,    -- the function name
    PRIMARY KEY (source_path, target_path, func_name)
);

-- Invalidate analysis cache when dependencies change
-- SELECT target_path FROM file_dependencies WHERE source_path = <changed_file>
```

#### OCaml Implementation

```ocaml
(* lib/catseye_cli/state.ml *)

module State : sig
  type t
  val open_db : string -> (t, [> `Msg of string ]) result
  (* string = path to .catseye/state.db *)

  val lookup_extraction : t -> string -> Blake3.t ->
    (security_node list option, [> `Msg of string ]) result

  val store_extraction : t -> string -> Blake3.t -> security_node list ->
    (unit, [> `Msg of string ]) result

  val lookup_analysis : t -> string -> Blake3.t ->
    (Taint_db.t option, [> `Msg of string ]) result

  val store_analysis : t -> string -> Blake3.t -> Taint_db.t ->
    (unit, [> `Msg of string ]) result

  val get_dependents : t -> string ->
    (string list, [> `Msg of string ]) result
  (* Returns files that depend on the given file via inter-proc calls *)

  val invalidate : t -> string list ->
    (unit, [> `Msg of string ]) result
  (* Invalidate cache entries for given paths *)

  val clear_all : t -> (unit, [> `Msg of string ]) result
  (* Wipe entire cache *)
end
```

**Why Blake3 over SHA-256**: Blake3 is ~14x faster than SHA-256 on large files, parallelizable, and designed for content-addressed storage. For a tool that hashes every source file on every scan, this matters.

**Why SQLite over plain files**: Atomic transactions, concurrent reads, indexed lookups, dependency tracking queries. A directory of JSON files can't do `SELECT target_path FROM file_dependencies WHERE source_path = ?`.

**Dependency**: `sqlite3` (ocaml-sqlite3), `blake3`

---

## 5. Crystal Extractor Optimization

### 5.1 Why Crystal Stays in Crystal

The Crystal extractor uses `Crystal::Parser` to access the full Crystal AST with type information:

```crystal
parser = Crystal::Parser.new(source)
ast = parser.parse
ast.accept(SecurityVisitor.new(file_path))
```

No OCaml equivalent exists. tree-sitter-crystal provides syntax highlighting but not the compiler-grade AST with type resolution.

### 5.2 Three-Layer Optimization

```
Layer 1: Pre-built Binary (eliminates 95% of per-file overhead)
  crystal build --release src/extractor/extractor.cr -o bin/catseye-crystal-extractor
  Impact: 400ms → 8ms per file (50x speedup)

Layer 2: Extraction Cache (eliminates extraction for unchanged files)
  Blake3 hash → SQLite lookup → return cached nodes
  Impact: 8ms → 0ms for unchanged files

Layer 3: Persistent Worker Pool (eliminates remaining process spawn overhead)
  OCaml manages N long-lived Crystal processes communicating via stdin/stdout
  Impact: 0ms spawn overhead, only actual parse time (~2-4ms per file)
```

### 5.3 Worker Pool Protocol

The Crystal extractor binary runs in a "server mode" when invoked with `--serve`:

```crystal
# extractor.cr — server mode
if ARGV.includes?("--serve")
  # Read file paths from stdin, write JSON to stdout, one line per request
  STDIN.each_line do |path|
    begin
      source = File.read(path)
      parser = Crystal::Parser.new(source)
      parser.filename = path
      ast = parser.parse
      visitor = SecurityVisitor.new(path)
      ast.accept(visitor)
      puts visitor.nodes.to_json
      STDOUT.flush
    rescue ex
      STDERR.puts "Error: #{ex.message}"
      puts "[]"
      STDOUT.flush
    end
  end
else
  # Original single-file mode for debugging
  # ... existing code ...
end
```

```ocaml
(* OCaml side: send path, receive JSON *)
(* Eio manages the pool lifecycle *)

let extract_worker path =
  Eio.Stream.add worker.to_worker path;
  let json = Eio.Stream.take worker.from_worker in
  Protocol.decode_nodes json
```

### 5.4 Fallback Strategy

```ocaml
let extract_crystal config path =
  match config.crystal.worker_pool_size with
  | 0 -> extract_single_process config.crystal.extractor path  (* No pool *)
  | n when n > 0 -> extract_via_pool config.pool path          (* Pool mode *)
  | _ -> extract_single_process config.crystal.extractor path  (* Fallback *)
```

If the pool crashes (worker OOM, Crystal GC issue), gracefully fall back to single-process mode and log a warning.

---

## 6. Vulnerability DAG Output

### 6.1 Why DAGs Over Linear Flows

The current Gleam engine produces linear flow traces:
```json
{
  "flow": [
    { "file": "api.cr", "line": 15, "message": "url assigned from tainted: params" },
    { "file": "api.cr", "line": 42, "message": "Sink: HTTP::Client.get called with tainted data" }
  ]
}
```

This can't represent:
- **Multiple sources converging** on one sink (e.g., `params["url"]` + `env["API_HOST"]`)
- **Sanitization dead-ends** (e.g., `safe_url = URI.parse(url)` — taint stops here)
- **Branching paths** (e.g., tainted variable used in two different sinks)
- **Inter-procedural hops** (e.g., `get_url()` returns tainted data, used in 3 places)

A DAG represents all of these naturally.

### 6.2 DAG Types

```ocaml
(* lib/catseye_types/vulnerability_dag.ml *)

type dag_node = {
  id : int;
  node_type : [
    | `Source          (* Taint origin: params, request, STDIN *)
    | `Assignment      (* Variable assignment *)
    | `Function_return (* Return value of a tainted function *)
    | `Call            (* Intermediate function call *)
    | `Sanitizer       (* Sanitization breakpoint *)
    | `Sink            (* Dangerous function call *)
  ];
  file : string;
  line : int;
  label : string;       (* Human-readable description *)
  var_name : string;    (* Variable involved, if applicable *)
  language : string;    (* "crystal", "gleam", etc. *)
}

type dag_edge_type =
  | Taint_propagation     (* Data flows from A to B *)
  | Sanitization_break    (* Taint is cleaned at this point *)
  | Inter_procedural      (* Cross-function taint flow *)

type dag_edge = {
  from_id : int;
  to_id : int;
  edge_type : dag_edge_type;
  description : string;
}

type vulnerability_dag = {
  rule_id : string;
  severity : string;
  root_sink : dag_node;           (* The sink that triggered the finding *)
  nodes : dag_node list;
  edges : dag_edge list;
  source_paths : (int list) list; (* All paths from sources to sink *)
  sanitized_paths : (int list) list; (* Paths that go through a sanitizer *)
}
```

### 6.3 DAG Construction

```ocaml
(* lib/catseye_engine/dag/builder.ml *)

let build_from_finding (db : Taint_db.t) (finding : Finding.t) : vulnerability_dag =
  let nodes = ref [] in
  let edges = ref [] in
  let next_id = ref 0 in

  let make_node ~node_type ~file ~line ~label ~var_name ~lang =
    let id = !next_id in
    incr next_id;
    let node = { id; node_type; file; line; label; var_name; language = lang } in
    nodes := node :: !nodes;
    id
  in

  (* Create the sink node (the finding itself) *)
  let sink_id = make_node
    ~node_type:`Sink ~file:finding.file ~line:finding.line
    ~label:finding.message ~var_name:"" ~lang:finding.language
  in

  (* For each tainted argument, trace back to sources *)
  let trace_tainted_arg arg =
    let var_name = arg.value in
    let rec trace parent_id var =
      match Taint_db.find_record db var with
      | None ->
        (* Root source reached *)
        let source_id = make_node
          ~node_type:`Source ~file:finding.file ~line:0
          ~label:(var ^ " (external taint source)")
          ~var_name:var ~lang:finding.language
        in
        edges := { from_id = source_id; to_id = parent_id;
                    edge_type = Taint_propagation;
                    description = var ^ " is a taint source" } :: !edges
      | Some record ->
        let node_type = if record.is_sanitized then `Sanitizer else `Assignment in
        let node_id = make_node
          ~node_type ~file:record.file ~line:record.line
          ~label:record.description ~var_name:var ~lang:finding.language
        in
        edges := { from_id = node_id; to_id = parent_id;
                    edge_type = Taint_propagation;
                    description = record.description } :: !edges;
        (* Continue tracing if there's a source variable *)
        if record.source_var <> "" then
          trace node_id record.source_var
    in
    trace sink_id var_name
  in

  List.iter trace_tainted_arg finding.tainted_args;

  { rule_id = finding.rule; severity = finding.severity
  ; root_sink = List.find (fun n -> n.id = sink_id) !nodes
  ; nodes = List.rev !nodes
  ; edges = List.rev !edges
  ; source_paths = compute_source_paths !nodes !edges sink_id
  ; sanitized_paths = compute_sanitized_paths !nodes !edges sink_id
  }
```

### 6.4 DAG → SARIF codeFlows

```ocaml
(* SARIF codeFlows are derived from DAG by finding all paths source → sink *)
let dag_to_sarif_code_flows (dag : vulnerability_dag) : Sarif.code_flow list =
  dag.source_paths
  |> List.map (fun path ->
    { threadFlows = [{
       locations = path |> List.map (fun node_id ->
         let node = List.find (fun n -> n.id = node_id) dag.nodes in
         {
           location = { uri = node.file; startLine = node.line };
           state = dag_node_type_to_sarif_state node.node_type;
           message = { text = node.label };
         })
     }]
    })
```

### 6.5 DAG → DOT (GraphViz)

```ocaml
let dag_to_dot (dag : vulnerability_dag) : string =
  let buf = Buffer.create 1024 in
  Buffer.add_string buf "digraph vulnerability {\n";
  Buffer.add_string buf "  rankdir=TB;\n";
  Buffer.add_string buf "  node [shape=box];\n";
  (* Nodes *)
  List.iter (fun n ->
    let color = match n.node_type with
      | `Source -> "red" | `Sink -> "orange" | `Sanitizer -> "green" | _ -> "black"
    in
    Buffer.add_string buf
      (Printf.sprintf "  n%d [label=\"%s:%d %s\" color=%s];\n"
         n.id n.file n.line n.label color)
  ) dag.nodes;
  (* Edges *)
  List.iter (fun e ->
    let style = match e.edge_type with
      | Taint_propagation -> "solid" | Sanitization_break -> "dashed"
      | Inter_procedural -> "dotted"
    in
    Buffer.add_string buf
      (Printf.sprintf "  n%d -> n%d [style=%s label=\"%s\"];\n"
         e.from_id e.to_id style e.description)
  ) dag.edges;
  Buffer.add_string buf "}\n";
  Buffer.contents buf
```

---

## 7. Phase-Based Roadmap

### Phase 0: Differential Testing Infrastructure

**Goal**: Establish the validation framework BEFORE writing any OCaml analysis code.

**Why Phase 0**: If we can't measure regression, we can't ship. Differential testing is the safety net for every subsequent phase.

**Tasks**:
1. Build the vulnerability corpus
   - Port existing test samples (`test/samples/vulnerable.cr`, `vulnerable.gleam`, `safe.cr`, `safe.gleam`)
   - Add real-world Crystal projects with known CVEs
   - Add synthetic edge cases: deeply nested taint, multi-hop propagation, sanitizer interactions
   - Add negative cases: safe patterns that should NOT trigger findings

2. Create the diff harness
   ```bash
   scripts/diff_findings.py --strict \
     <(catseye_gleam corpus/) \
     <(catseye_ocaml corpus/)
   ```

3. Create CI workflow
   ```yaml
   # .github/workflows/diff-test.yml
   name: Differential Engine Test
   on: [push, pull_request]
   jobs:
     diff-test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Build legacy engine
           run: just build-gleam-engine
         - name: Build OCaml engine
           run: just build-ocaml-engine
         - name: Run differential tests
           run: |
             for corpus in test/diff/corpus/*/; do
               just run-gleam "$corpus" > /tmp/gleam.json
               just run-ocaml "$corpus" > /tmp/ocaml.json
               python3 test/diff/diff_findings.py --strict /tmp/gleam.json /tmp/ocaml.json
             done
   ```

4. Diff script behavior:
   - Normalize both outputs (sort by `file:line:rule`)
   - Compare: finding count, rule names, severities, file/line, flow completeness
   - Exit 1 on ANY difference in strict mode
   - Exit 1 only on REMOVED findings in lenient mode

**Deliverables**: Corpus, diff script, CI workflow
**Dependencies**: None (uses existing Gleam engine)
**Risk**: Low — infrastructure only

### Phase 1: OCaml CLI + TOML Config + State Persistence

**Goal**: Replace Nim CLI with OCaml, load TOML config, set up SQLite state cache.

**Tasks**:
1. Create Dune workspace structure (see Section 8)
2. Implement `Cmdliner` argument parsing (same flags as current Nim CLI)
3. Implement TOML config loading via `otaml`
4. Implement file discovery with exclusion patterns
5. Build Crystal extractor binary: `crystal build --release src/extractor/extractor.cr -o bin/catseye-crystal-extractor`
6. Implement SQLite state persistence layer (Blake3 hashing, extraction cache)
7. Wire up: CLI → config → file discovery → Crystal extraction (single-process, pre-built binary) → output formatting
8. Re-use existing Gleam engine via subprocess (temporary bridge)

**Deliverables**: Working `catseye` binary that scans Crystal files using pre-built extractor + legacy Gleam engine, with TOML config and extraction caching
**Dependencies**: `cmdliner`, `otaml`, `yojson`, `sqlite3`, `blake3`, `bos`
**Validation**: Differential test passes (OCaml CLI → Gleam engine output matches Nim CLI → Gleam engine)

### Phase 2: KDL Rule DSL + OCaml Extractors

**Goal**: Implement KDL rule loading, replace Nim Gleam extractor with OCaml native.

**Tasks**:
1. Implement KDL parser for rule definitions
2. Build rule interpreter that compiles KDL → `rule_def` records
3. Implement OCaml tree-sitter Gleam extractor
4. Abstract serialization protocol (`Protocol` module)
5. Register Gleam extractor in CLI
6. Wire KDL rules into engine (rules loaded from `rules/*.kdl`)
7. Verify: existing built-in rules ported to KDL produce identical results

**Deliverables**: KDL rule loading, OCaml Gleam extractor, both languages scannable
**Dependencies**: `kdl`, `tree-sitter`, tree-sitter-gleam grammar
**Validation**: Differential test passes for Gleam language scanning

### Phase 3: OCaml Taint Analysis Engine (Multicore)

**Goal**: Replace Gleam/BEAM engine with OCaml, add Domain parallelism, DAG output.

**Tasks**:
1. Port `taint.gleam` → `taint/db.ml`, `taint/seed.ml`, `taint/propagate.ml`, `taint/returns.ml`, `taint/interproc.ml`
2. Implement `Map.Make(String)`-based TaintDB
3. Implement fixed-point propagation loop (same semantics as Gleam)
4. Implement `parallel.ml` with `Domain.parallel_map`
5. Implement `dag/builder.ml` for vulnerability DAG construction
6. Port all rule matching to use KDL-loaded `rule_def` records
7. Implement analysis cache (Tier 2) in SQLite
8. Run differential tests continuously during porting

**Deliverables**: Working OCaml engine with parallel analysis and DAG output
**Dependencies**: OCaml 5.x stdlib (`Domain`), `ocamlgraph`
**Validation**: Differential tests pass for ALL rules on ALL corpus samples

### Phase 4: Crystal Worker Pool + Full Integration

**Goal**: Add Eio-managed Crystal worker pool, finalize integration.

**Tasks**:
1. Add `--serve` mode to Crystal extractor
2. Implement Eio-based worker pool in OCaml
3. Wire pool into extraction pipeline
4. Implement graceful fallback (pool failure → single-process)
5. Implement all output formatters from DAG (terminal, JSON, SARIF, Markdown, DOT)
6. Performance benchmarking and tuning
7. Remove Nim + Gleam dependencies from flake.nix

**Deliverables**: Full OCaml + Crystal system, no Nim/Gleam dependencies
**Dependencies**: `eio`
**Validation**: Differential tests pass, benchmark shows improvement over legacy

### Phase 5: Polish & Release

**Goal**: Production readiness, documentation, edge cases.

**Tasks**:
1. Error handling and edge cases
2. Documentation (user guide, rule authoring guide)
3. Performance benchmarks (publish results)
4. Windows/macOS testing
5. Release binary (static linking with musl)
6. Archive legacy Nim + Gleam codebase

**Deliverables**: Release-ready Catseye v1.0
**Dependencies**: None

### Roadmap Summary

```
Phase 0: Differential Testing (1-2 days)
    │   Build corpus, diff harness, CI workflow
    │   Success = CI green on legacy engine
    ▼
Phase 1: CLI + Config + Cache (3-5 days)
    │   OCaml CLI, otaml config, SQLite state, Crystal binary build
    │   Success = OCaml CLI scans Crystal via legacy engine, diff tests pass
    ▼
Phase 2: KDL Rules + OCaml Extractors (4-6 days)
    │   KDL rule loader, tree-sitter Gleam extractor
    │   Success = Both languages scannable, KDL rules match built-in rules
    ▼
Phase 3: OCaml Engine (Multicore + DAG) (7-10 days)
    │   Full taint engine port, Domain parallelism, DAG builder
    │   Success = Diff tests pass for ALL corpus samples
    ▼
Phase 4: Worker Pool + Integration (3-5 days)
    │   Eio Crystal pool, output formatters, Nim/Gleam removal
    │   Success = Benchmark shows improvement, all tests pass
    ▼
Phase 5: Polish & Release (3-5 days)
    │   Edge cases, docs, static binary, benchmarks
    │   Success = Catseye v1.0 released
    ╰ → Total: ~21-33 days
```

---

## 8. Dune Workspace Structure

```
catseye-ocaml/
├── catseye.opam
├── dune-project
├── dune-workspace
│
├── bin/
│   ├── dune
│   └── main.ml                        (* CLI entry point *)
│
├── lib/
│   ├── catseye_cli/
│   │   ├── dune
│   │   ├── args.ml                    (* Cmdliner argument definitions *)
│   │   ├── config.ml                  (* TOML config loading via otaml *)
│   │   ├── discovery.ml              (* File discovery with exclusions *)
│   │   ├── state.ml                  (* SQLite state persistence *)
│   │   └── orchestrator.ml           (* Main scan pipeline *)
│   │
│   ├── catseye_rules/
│   │   ├── dune
│   │   ├── loader.ml                 (* KDL rule file loader *)
│   │   ├── interpreter.ml            (* Execute rule_def against TaintDB *)
│   │   ├── types.ml                  (* rule_def, sink_def, source_def *)
│   │   └── builtins/                 (* Built-in rules compiled from KDL *)
│   │       ├── dune
│   │       ├── ssrf.kdl
│   │       ├── command_injection.kdl
│   │       ├── path_traversal.kdl
│   │       ├── sql_injection.kdl
│   │       ├── redos.kdl
│   │       ├── hardcoded_secrets.kdl
│   │       ├── open_redirect.kdl
│   │       ├── deserialization.kdl
│   │       ├── ldap_xml_injection.kdl
│   │       └── weak_crypto.kdl
│   │
│   ├── catseye_engine/
│   │   ├── dune
│   │   ├── engine.ml                 (* Main entry point *)
│   │   ├── taint/
│   │   │   ├── dune
│   │   │   ├── db.ml                 (* TaintDB Map *)
│   │   │   ├── seed.ml               (* Source seeding *)
│   │   │   ├── propagate.ml          (* Fixed-point loop *)
│   │   │   ├── returns.ml            (* Return value tracking *)
│   │   │   ├── interproc.ml          (* Cross-function propagation *)
│   │   │   └── parallel.ml           (* Domain-based orchestrator *)
│   │   ├── dag/
│   │   │   ├── dune
│   │   │   ├── types.ml              (* vulnerability_dag type *)
│   │   │   ├── builder.ml            (* DAG construction from findings *)
│   │   │   └── paths.ml              (* Source-to-sink path computation *)
│   │   └── merge.ml                  (* Per-file TaintDB merge *)
│   │
│   ├── catseye_extractors/
│   │   ├── dune
│   │   ├── sig.ml                    (* Extractor module signature *)
│   │   ├── protocol.ml              (* Abstract serialization *)
│   │   ├── tree_sitter_base.ml      (* Generic tree-sitter utilities *)
│   │   ├── gleam.ml                  (* Gleam extractor *)
│   │   └── python.ml                 (* Future *)
│   │
│   ├── catseye_crystal/
│   │   ├── dune
│   │   ├── worker_pool.ml           (* Eio-managed Crystal workers *)
│   │   ├── protocol.ml              (* stdin/stdout protocol *)
│   │   └── fallback.ml              (* Single-process fallback *)
│   │
│   ├── catseye_output/
│   │   ├── dune
│   │   ├── terminal.ml              (* Colored terminal output *)
│   │   ├── json.ml                   (* JSON report *)
│   │   ├── sarif.ml                  (* SARIF v2.1.0 from DAG *)
│   │   ├── markdown.ml              (* Markdown report *)
│   │   └── dot.ml                    (* GraphViz DOT output *)
│   │
│   └── catseye_types/
│       ├── dune
│       ├── security_node.ml         (* Shared node types *)
│       ├── finding.ml               (* Finding types *)
│       └── dag_types.ml             (* DAG node/edge types *)
│
├── test/
│   ├── dune
│   ├── diff/
│   │   ├── diff_findings.py         (* Differential test harness *)
│   │   ├── run_diff_test.sh         (* CI script *)
│   │   └── corpus/
│   │       ├── basic_crystal/
│   │       │   ├── vulnerable.cr
│   │       │   └── safe.cr
│   │       ├── basic_gleam/
│   │       │   ├── vulnerable.gleam
│   │       │   └── safe.gleam
│   │       ├── multi_file/
│   │       │   ├── controller.cr    (* Cross-file taint *)
│   │       │   ├── helpers.cr
│   │       │   └── expected_findings.json
│   │       ├── sanitizer_patterns/
│   │       │   ├── sanitized.cr
│   │       │   └── expected_findings.json
│   │       └── real_world/          (* Open-source projects with known CVEs *)
│   ├── engine/
│   │   ├── taint_test.ml
│   │   ├── dag_test.ml
│   │   └── parallel_test.ml
│   ├── rules/
│   │   ├── kdl_loader_test.ml
│   │   └── rule_interpreter_test.ml
│   ├── extractors/
│   │   ├── gleam_test.ml
│   │   └── fixtures/
│   ├── config/
│   │   └── toml_test.ml
│   ├── state/
│   │   └── cache_test.ml
│   └── e2e/
│       └── scan_test.ml
│
└── rules/                            (* Default rules shipped with catseye *)
    ├── README.md
    ├── ssrf.kdl
    ├── command_injection.kdl
    ├── path_traversal.kdl
    ├── sql_injection.kdl
    ├── redos.kdl
    ├── hardcoded_secrets.kdl
    ├── open_redirect.kdl
    ├── deserialization.kdl
    ├── ldap_xml_injection.kdl
    └── weak_crypto.kdl
```

---

## 9. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| KDL parser immaturity in OCaml | Medium | High | Write minimal KDL parser if library insufficient; schema is simple |
| Taint logic translation bugs | Medium | Critical | Phase 0 differential testing; every phase must pass |
| Crystal worker pool crashes | Medium | Medium | Graceful fallback to single-process; log warning; auto-restart |
| Domain merge semantics | Low | High | Per-file DBs are file-scoped; merge is associative; unit test extensively |
| SQLite concurrent access | Low | Medium | WAL mode; single writer (main process); read-only from Domains |
| Blake3 OCaml bindings | Low | Low | Fallback to stdlib `Digest.sha256` if blake3 unavailable |
| DAG→SARIF mapping complexity | Medium | Medium | Start with linear paths extracted from DAG; full multi-path later |
| Cross-file cache invalidation | Medium | Medium | Dependency tracking table; conservative invalidation (re-run when unsure) |

---

## 10. Open Questions

1. Does `otaml` support all TOML features needed (arrays, nested tables)?
2. Does the `kdl` OCaml library support KDL v2 spec sufficiently?
3. What is the optimal Domain count for taint analysis? (Needs benchmarking)
4. Should the SQLite cache use WAL or DELETE journal mode?
5. How to handle Crystal worker pool lifecycle during Ctrl+C?
6. Should DAG output include sanitized paths (false positive paths) or only tainted paths?
7. How to version the KDL rule schema for backward compatibility?
8. Should built-in KDL rules be embedded in the binary or loaded from filesystem?
9. What is the Blake3 hashing overhead for 10,000 files? (Needs measurement)
10. Should Phase 3 be split further (taint engine first, then DAG builder)?

---

## Appendix A: OCaml Libraries

| Purpose | Package | Version | Notes |
|---------|---------|---------|-------|
| CLI args | `cmdliner` | latest | Standard OCaml CLI framework |
| TOML config | `otaml` | latest | TOML parser for catseye.toml |
| KDL rules | `kdl` | latest | KDL document parser |
| JSON | `yojson` | 3.0+ | JSON serialization (nodes, findings, cache) |
| Parallelism | `Domain` (stdlib) | OCaml 5.x | CPU-bound parallel analysis |
| Async I/O | `eio` | latest | Effects-based I/O for Crystal worker pool |
| Process mgmt | `bos` | latest | Unix process utilities |
| Tree-sitter | `tree-sitter` | latest | In-process AST parsing |
| Graph algorithms | `ocamlgraph` | latest | DAG path computation |
| SQLite | `sqlite3` | latest | State persistence cache |
| Hashing | `blake3` | latest | Fast content-addressed hashing |
| Testing | `alcotest` | latest | Unit + integration tests |

---

## Appendix B: Lines of Code Comparison

| Component | Current (Nim+Gleam) | Estimated OCaml |
|-----------|---------------------|-----------------|
| CLI + Config | 651 (Nim) | ~500-600 |
| KDL rule loader + interpreter | 0 | ~400-500 |
| Built-in rules (KDL files) | ~700 (Gleam) | ~400 (declarative, smaller) |
| OCaml extractors | 269 (Nim) | ~300-400 |
| Engine (taint) | 559 (Gleam) | ~400-500 |
| DAG builder | 0 | ~300-400 |
| Parallel orchestrator | 0 | ~100-150 |
| State persistence (SQLite) | 0 | ~200-250 |
| Output formatters | ~200 (Nim) | ~300-400 |
| Diff test harness | 0 | ~200 |
| Crystal worker pool | 0 | ~200-250 |
| **Total** | ~2380 | ~3300-4100 |

Larger than current codebase but eliminates two language runtimes (BEAM, Nim) and adds significant new capabilities (KDL rules, DAGs, caching, parallelism, worker pool).

---

*End of plan — Rev 3*