# Moonpool Integration Plan for Catseye

**Status:** 📋 Planning (Not Implementation)  
**Created:** 2026-05-13  
**Purpose:** Plan integration of Moonpool into Catseye for improved parallel processing and async patterns  

---

## Executive Summary

Moonpool is a thread pool library for OCaml 5 that provides:
- **Thread pools** (`Fifo_pool`, `Ws_pool`) with domain-aware scheduling
- **Futures with await** - cooperative suspension, no deadlock
- **Fork-join parallelism** for recursive algorithms
- **Task local storage** for cross-cutting concerns

This document identifies how Moonpool can improve Catseye's architecture without committing to implementation.

---

## Current Architecture Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CURRENT CATSEYE ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                        Main CLI                                ││
│  │  catseye --predator-vision --claws --ai-linter /path            ││
│  └─────────────────────────────────────────────────────────────────┘│
│                               │                                      │
│  ┌────────────────────────────┼───────────────────────────────┐  │
│  │                       Orchestrator                            │  │
│  │  - File discovery                                    │  │
│  │  - Worker coordination                               │  │
│  │  - Result aggregation                                │  │
│  └────────────────────────────┼───────────────────────────────┘  │
│                               │                                      │
│  ┌────────────────────────────┼───────────────────────────────┐  │
│  │                    catseye_engine                            │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │  │
│  │  │    parallel.ml  │  │  worker_pool.ml │  │  propagate  │ │  │
│  │  │  (Domains API)  │  │ (Crystal procs) │  │   (Taint)  │ │  │
│  │  │  - N domains    │  │  - N extractors │  │             │ │  │
│  │  │  - spawn/join   │  │  - stdin/stdout │  │             │ │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────┘ │  │
│  │         │                    │                   │          │  │
│  │         └────────────────────┼───────────────────┘          │  │
│  │                              │                              │  │
│  │              ┌───────────────┼───────────────┐              │  │
│  │              ▼               ▼               ▼              │  │
│  │        ┌───────────┐  ┌───────────┐  ┌───────────┐         │  │
│  │        │ Gleam AST │  │ Crystal   │  │ Findings  │         │  │
│  │        │  (XML)    │  │ AST (JSON)│  │   List    │         │  │
│  │        └───────────┘  └───────────┘  └───────────┘         │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                               │                                      │
│  ┌────────────────────────────┼───────────────────────────────┐  │
│  │                    catseye_claws                           │  │
│  │  - Complexity analysis    │  - DRY detection              │  │
│  │  - Anatomy analysis       │  - Extra smells               │  │
│  └────────────────────────────┼───────────────────────────────┘  │
│                               │                                      │
│  ┌────────────────────────────┼───────────────────────────────┐  │
│  │                    catseye_crowsnest                      │  │
│  │  - Dependency reachability                                  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Current Pain Points

| Component | Issue | Impact |
|-----------|-------|--------|
| `parallel.ml` | `Domain.spawn` is heavy, no work-stealing | Poor load balancing |
| `worker_pool.ml` | Manual process management, no async | Complex error handling |
| Orchestrator | Sequential result aggregation | Bottleneck on large codebases |
| Taint propagation | Single-threaded | Slow for cross-file analysis |
| Claws | Sequential analysis | Slow complexity calculation |

---

## Moonpool Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MOONPOOL ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Fixed Domain Pool (N domains = N CPU cores)                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │   Domain 1          Domain 2          Domain N            │   │
│  │   ┌─────────┐       ┌─────────┐       ┌─────────┐           │   │
│  │   │Thread 1 │       │Thread 1 │       │Thread 1 │           │   │
│  │   │Thread 2 │       │Thread 2 │       │Thread 2 │           │   │
│  │   │  ...    │       │  ...    │       │  ...    │           │   │
│  │   └─────────┘       └─────────┘       └─────────┘           │   │
│  │        │                 │                 │                 │   │
│  │        └─────────────────┼─────────────────┘                 │   │
│  │                          │                                   │   │
│  └──────────────────────────┼───────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────┼───────────────────────────────────┐  │
│  │                    Global Task Queue                          │  │
│  │                          │                                   │  │
│  └──────────────────────────┼───────────────────────────────────┘  │
│                             │                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Fifo_pool  │  │  Ws_pool    │  │  Fut.t      │  │ Chan.t     │ │
│  │  (FIFO)     │  │ (Work steal)│  │ (await)     │  │ (Channels) │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Concepts

**Thread Pools:**
- `Fifo_pool` - Tasks in FIFO order, simple, good for coarse work
- `Ws_pool` - Work-stealing, good for many short tasks that spawn subtasks

**Futures:**
```ocaml
let fut = Fut.spawn ~on:pool (fun () -> compute x)
let result = Fut.await fut  (* Suspends, resumes when ready *)
```

**Fork-Join:**
```ocaml
Forkjoin.both
  (fun () -> compute_left)
  (fun () -> compute_right)
```

---

## Integration Opportunities

### 1. Parallel File Extraction (HIGH VALUE)

**Current:** `parallel.ml` uses raw `Domain.spawn/join`
**Proposed:** Moonpool thread pool with work-stealing

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PARALLEL EXTRACTION WITH MOONPOOL                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  BEFORE (current):                                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Domain 1 ──▶ File A          (blocked)                    │   │
│  │  Domain 2 ──▶ File B ──────▶ File C (waiting)              │   │
│  │  Domain 3 ──▶ File D                                          │   │
│  │                                                             │   │
│  │  Problem: Static assignment, poor load balancing            │   │
│  │  File B is slow, Domain 2 is idle while File C waits         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  AFTER (Moonpool Ws_pool):                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Work-Stealing Pool                       │   │
│  │                                                             │   │
│  │  Domain 1: [Task] [Task] [Task] ← steals from others       │   │
│  │  Domain 2: [Task] [Task]      ← steals if idle             │   │
│  │  Domain 3: [Task] [Task] [Task]                             │   │
│  │                                                             │   │
│  │  Benefit: Dynamic load balancing, better CPU utilization   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Concept:**
```ocaml
(* lib/catseye_engine/moonpool_extraction.ml (conceptual) *)

module Mp = Moonpool

type extraction_result = {
  file : string;
  nodes : Security_node.t list option;
  duration_ms : float;
  errors : string list;
}

let extract_files_parallel 
    ~extractor_path 
    ~pool_size 
    (files : string list) 
    : extraction_result list =
  
  (* Create work-stealing pool for better load balancing *)
  let pool = Mp.Ws_pool.create ~num_threads:pool_size () in
  
  (* Spawn extraction for each file *)
  let futures = List.map (fun file ->
    Mp.Fut.spawn ~on:pool (fun () ->
      let start = Unix.gettimeofday () in
      let result = Worker_pool.extract_with_recovery 
        (create_pool extractor_path 1) 
        file 
      in
      let duration = (Unix.gettimeofday () -. start) *. 1000. in
      { file; nodes = result; duration_ms = duration; errors = [] }
    )
  ) files in
  
  (* Await all futures *)
  let results = List.map Mp.Fut.wait_block_exn futures in
  
  (* Cleanup *)
  Mp.Ws_pool.shutdown pool;
  
  results
```

---

### 2. Async Worker Pool (HIGH VALUE)

**Current:** `worker_pool.ml` - manual NDJSON over pipes, blocking reads
**Proposed:** Moonpool futures + async process management

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ASYNC WORKER POOL                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                        Extraction Pool                      │   │
│  │                                                             │   │
│  │    ┌─────────────┐     ┌─────────────┐     ┌───────────┐  │   │
│  │    │ Worker 1    │     │ Worker 2    │     │ Worker N  │  │   │
│  │    │ ────────────│     │ ────────────│     │ ──────────│  │   │
│  │    │ Fut.await   │     │ Fut.await   │     │ Fut.await │  │   │
│  │    │ on task     │     │ on task     │     │ on task   │  │   │
│  │    └──────┬──────┘     └──────┬──────┘     └─────┬─────┘  │   │
│  │           │                   │                  │        │   │
│  │           └──────────────────┼──────────────────┘        │   │
│  │                              │                           │   │
│  │           ┌─────────────────┴─────────────────┐         │   │
│  │           ▼                                   ▼         │   │
│  │    ┌───────────┐                       ┌───────────┐     │   │
│  │    │  Crystal  │                       │  Crystal  │     │   │
│  │    │  Process │                       │  Process  │     │   │
│  │    └───────────┘                       └───────────┘     │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Benefits:                                                          │
│  - Non-blocking await (workers can do other work while waiting)      │
│  - Automatic backpressure                                           │
│  - Simpler error handling with Result.t                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Concept:**
```ocaml
(* lib/catseye_engine/async_worker_pool.ml (conceptual) *)

module Mp = Moonpool

type worker = {
  id : int;
  process : process_handle;
  alive : bool ref;
}

and process_handle = {
  stdin : out_channel;
  stdout : in_channel;
  pid : int;
}

type t = {
  pool : Mp.Ws_pool.t;
  workers : worker array;
  request_queue : (string * Mp.Fut.t * Mp.Chan.t) Mp.Chan.t;
  mutex : Mp.Mutex.t;
}

let create ~extractor_path ~pool_size () : t =
  let pool = Mp.Ws_pool.create ~num_threads:pool_size () in
  
  (* Spawn workers *)
  let workers = Array.init pool_size (fun i ->
    let (stdout, stdin, _) = Unix.open_process_full 
      (extractor_path ^ " --serve") 
      [||] 
    in
    { id = i; 
      process = { stdin; stdout; pid = i }; 
      alive = ref true }
  ) in
  
  (* Create request channel *)
  let request_queue = Mp.Chan.create ~size:100 () in
  
  { pool; workers; request_queue; mutex = Mp.Mutex.create () }

(* Async extraction - returns immediately with future *)
let extract_async (t : t) (file : string) : Mp.Fut.t =
  let (response_chan, recv) = Mp.Chan.open_ () in
  
  Mp.Fut.spawn ~on:t.pool (fun () ->
    (* Find available worker *)
    Mp.Mutex.lock t.mutex;
    let worker = find_available_worker t.workers in
    Mp.Mutex.unlock t.mutex;
    
    (* Send request, await response *)
    let request = make_request file in
    output_string worker.process.stdin (request ^ "\n");
    flush worker.process.stdin;
    
    let response = read_line_safe worker.process.stdout in
    let parsed = parse_response response in
    
    Mp.Chan.send response_chan parsed
  )

(* Simple blocking extraction (wraps async) *)
let extract (t : t) (file : string) : Security_node.t list option =
  let fut = extract_async t file in
  Mp.Fut.wait_block_exn fut
```

---

### 3. Parallel Claws Analysis (MEDIUM VALUE)

**Current:** Sequential complexity and anatomy analysis
**Proposed:** Parallel file analysis with Moonpool futures

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PARALLEL CLAWS ANALYSIS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Parallel Claws Pipeline                   │   │
│  │                                                             │   │
│  │  Files ──▶ Group by module ──▶ Parallel analysis ──▶ Merge  │   │
│  │                                                     │      │   │
│  │                              ┌────────────────────────┐  │      │   │
│  │                              ▼                        ▼  │      │   │
│  │                         Complexity              Anatomy     │   │
│  │                         (parallel)              (parallel) │   │
│  │                              │                        │      │   │
│  │                              └────────────────────────┘      │   │
│  │                                    │                         │   │
│  │                                    ▼                         │   │
│  │                               Findings                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Concept:**
```ocaml
(* lib/catseye_claws/parallel_analyzer.ml (conceptual) *)

module Mp = Moonpool

let analyze_parallel 
    ~(complexity_config : Types.claws_config)
    (files : (string * Security_node.t list) list)
    : Finding.t list =
  
  let pool = Mp.Ws_pool.create 
    ~num_threads:(Domain.recommended_domain_count ()) () 
  in
  
  (* Group files by directory for better cache locality *)
  let groups = group_by_directory files in
  
  (* Spawn analysis for each group *)
  let futures = List.map (fun (dir, files_in_dir) ->
    Mp.Fut.spawn ~on:pool (fun () ->
      (* Sequential within group for cache locality *)
      List.concat_map (fun (file, nodes) ->
        let complexity_findings = Complexity.analyze nodes complexity_config in
        let anatomy_findings = Anatomy.analyze nodes complexity_config in
        let extra_findings = Extra_smells.analyze nodes complexity_config in
        List.concat [complexity_findings; anatomy_findings; extra_findings]
      ) files_in_dir
    )
  ) groups in
  
  (* Wait for all results *)
  let group_results = List.map Mp.Fut.wait_block_exn futures in
  
  Mp.Ws_pool.shutdown pool;
  
  (* Merge findings *)
  List.concat group_results
```

---

### 4. Fork-Join for Recursive Analysis (LOW-MEDIUM VALUE)

**Current:** Sequential recursive algorithms (cross-file analysis, reachability)
**Proposed:** Moonpool fork-join for parallel sub-problems

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FORK-JOIN ANALYSIS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Cross-File Dependency Analysis:                                    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │   analyze_module(module)                                    │   │
│  │         │                                                   │   │
│  │         ├── find_dependencies()                             │   │
│  │         │         │                                          │   │
│  │         │         ├── analyze(dep1) ──▶ [findings1]        │   │
│  │         │         ├── analyze(dep2) ──▶ [findings2]        │   │
│  │         │         └── analyze(dep3) ──▶ [findings3]        │   │
│  │         │                                                     │   │
│  │         └── merge(findings1, findings2, findings3)          │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Moonpool Forkjoin:                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  let (left, right) = Forkjoin.both                          │   │
│  │    (fun () -> analyze left_half)                            │   │
│  │    (fun () -> analyze right_half)                           │   │
│  │  in                                                          │   │
│  │  merge left right                                           │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Concept:**
```ocaml
(* lib/catseye_engine/forkjoin_analysis.ml (conceptual) *)

module Fj = Moonpool_forkjoin

let rec analyze_recursively 
    (nodes : Security_node.t list) 
    (deps : string list)
    : Finding.t list =
  
  if List.length deps <= 1 then
    (* Base case: analyze directly *)
    analyze_dependencies nodes
  else
    (* Fork: split dependencies *)
    let mid = List.length deps / 2 in
    let left_deps = List.take deps mid in
    let right_deps = List.drop deps mid in
    
    (* Join: parallel analysis *)
    let (left_findings, right_findings) = Fj.both
      (fun () -> analyze_recursively nodes left_deps)
      (fun () -> analyze_recursively nodes right_deps)
    in
    
    (* Merge results *)
    merge_findings left_findings right_findings

(* Example: Parallel reachability analysis *)
let analyze_reachability 
    (nodes : Security_node.t list)
    : Reachability.t =
  
  let pool = Mp.Ws_pool.create ~num_threads:4 () in
  
  let compute_entry_points = 
    Mp.Fut.spawn ~on:pool (fun () -> detect_entry_points nodes)
  in
  
  let compute_call_graph = 
    Mp.Fut.spawn ~on:pool (fun () -> build_call_graph nodes)
  in
  
  let entries = Mp.Fut.wait_block_exn compute_entry_points in
  let graph = Mp.Fut.wait_block_exn compute_call_graph in
  
  (* Compute reachability from entry points *)
  let reachable = compute_reachable entries graph in
  
  Mp.Ws_pool.shutdown pool;
  
  { reachable; entries; graph }
```

---

### 5. Task Local Storage for Tracing (MEDIUM VALUE)

**Current:** No structured way to track request context across async operations
**Proposed:** Moonpool's task local storage for logging/tracing

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TASK LOCAL STORAGE                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Request Context Flow:                                              │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  ┌─────────────────────────────────────────────────────┐    │   │
│  │  │ Task Local Storage                                  │    │   │
│  │  │  - request_id: "abc123"                            │    │   │
│  │  │  - user_id: "user_42"                              │    │   │
│  │  │  - start_time: 1700000000                         │    │   │
│  │  │  - files_to_scan: 150                              │    │   │
│  │  └─────────────────────────────────────────────────────┘    │   │
│  │                          │                                  │   │
│  │           ┌──────────────┼──────────────┐                    │   │
│  │           ▼              ▼              ▼                    │   │
│  │     ┌───────────┐ ┌───────────┐ ┌───────────┐                 │   │
│  │     │ Worker 1  │ │ Worker 2  │ │ Worker 3  │                 │   │
│  │     │ logs with │ │ logs with │ │ logs with │                 │   │
│  │     │ req_id    │ │ req_id    │ │ req_id    │                 │   │
│  │     └───────────┘ └───────────┘ └───────────┘                 │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation Concept:**
```ocaml
(* lib/catseye_engine/task_context.ml (conceptual) *)

module Picos = Moonpool.Picos

(* Define task-local context *)
module Context = struct
  type t = {
    mutable request_id : string;
    mutable start_time : float;
    mutable files_count : int;
    mutable files_processed : int;
  }
  
  let create ~request_id () = {
    request_id;
    start_time = Unix.gettimeofday ();
    files_count = 0;
    files_processed = 0;
  }
end

(* Create task-local storage key *)
let context_key : Context.t Picos.key = Picos.Key.create ()

(* Set context for current task *)
let set_context ctx =
  Picos.set context_key ctx

(* Get context from current task *)
let get_context () : Context.t option =
  Picos.get context_key

(* Example: logging with context *)
let log_with_context level msg =
  match get_context () with
  | Some ctx ->
      Logs.msg level (fun m -> m 
        "[req=%s] %s (processed %d/%d files)" 
        ctx.request_id 
        msg 
        ctx.files_processed 
        ctx.files_count
      )
  | None ->
      Logs.msg level (fun m -> m "%s" msg)

(* Wrap extraction with context *)
let extract_with_tracing pool file =
  let ctx = get_context () |> Option.get in
  ctx.files_count <- ctx.files_count + 1;
  
  Mp.Fut.spawn ~on:pool (fun () ->
    log_with_context Logs.Info (Printf.sprintf "Processing %s" file);
    
    let result = extract_file file in
    
    (match get_context () with
     | Some ctx -> ctx.files_processed <- ctx.files_processed + 1
     | None -> ());
    
    result
  )
```

---

### 6. Progress Reporting with Futures (LOW VALUE)

**Use case:** Report progress during long scans without blocking

```ocaml
(* Example: Progress tracking *)

let scan_with_progress pool files on_progress =
  let total = List.length files in
  let processed = ref 0 in
  
  let futures = List.map (fun file ->
    Mp.Fut.spawn ~on:pool (fun () ->
      let result = extract_file file in
      incr processed;
      on_progress (!processed, total);
      result
    )
  ) files in
  
  (* Can peek at progress without blocking *)
  List.iter (fun fut ->
    match Mp.Fut.peek fut with
    | Some (Ok result) -> handle result
    | Some (Error e) -> handle_error e
    | None -> () (* Still processing *)
  ) futures
  
(* Use in CLI *)
let on_progress (done, total) =
  let pct = (done * 100) / total in
  Printf.printf "\rProgress: %d/%d (%d%%)" done total pct
```

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MOONPOOL INTEGRATION ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│                          catseye_cli                                │
│                               │                                      │
│                               ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    Moonpool Integration Layer                  ││
│  │                                                                 ││
│  │  ┌──────────────────────────────────────────────────────────┐ ││
│  │  │              moonpool_extraction.ml                       │ ││
│  │  │  - Parallel file extraction with Ws_pool                 │ ││
│  │  │  - Work-stealing for load balancing                       │ ││
│  │  │  - Progress reporting via Fut.peek                        │ ││
│  │  └──────────────────────────────────────────────────────────┘ ││
│  │                                                                 ││
│  │  ┌──────────────────────────────────────────────────────────┐ ││
│  │  │              async_worker_pool.ml                        │ ││
│  │  │  - Async Crystal process management                      │ ││
│  │  │  - Non-blocking await                                    │ ││
│  │  │  - Backpressure via Fut.spawn                            │ ││
│  │  └──────────────────────────────────────────────────────────┘ ││
│  │                                                                 ││
│  │  ┌──────────────────────────────────────────────────────────┐ ││
│  │  │              task_context.ml                             │ ││
│  │  │  - Task-local request context                            │ ││
│  │  │  - Structured logging                                    │ ││
│  │  │  - Progress tracking                                     │ ││
│  │  └──────────────────────────────────────────────────────────┘ ││
│  │                                                                 ││
│  └─────────────────────────────────────────────────────────────────┘│
│                               │                                      │
│         ┌─────────────────────┼─────────────────────┐              │
│         ▼                     ▼                     ▼              │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
│  │  parallel.ml  │    │ worker_pool  │    │   propagate   │       │
│  │  (TO REPLACE) │    │ (TO WRAP)    │    │  (KEEP)       │       │
│  └───────────────┘    └───────────────┘    └───────────────┘       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Migration Plan

### Phase 1: Low-Risk Foundation (Weeks 1-2)

**Replace `parallel.ml` with Moonpool:**
- Minimal changes to existing API
- Better load balancing via work-stealing
- Can benchmark before/after

**Changes:**
```ocaml
(* BEFORE: parallel.ml *)
let extract_parallel extract_fn files =
  let arr = Array.of_list files in
  let domains = Array.init (Array.length arr) (fun i ->
    Domain.spawn (fun () -> extract_fn arr.(i))
  ) in
  Array.iter Domain.join domains

(* AFTER: moonpool_parallel.ml *)
let extract_parallel extract_fn files =
  let pool = Moonpool.Ws_pool.create 
    ~num_threads:(Domain.recommended_domain_count ()) 
    () 
  in
  let futures = List.map (fun file ->
    Moonpool.Fut.spawn ~on:pool (fun () -> extract_fn file)
  ) files in
  let results = List.map Moonpool.Fut.wait_block_exn futures in
  Moonpool.Ws_pool.shutdown pool;
  results
```

**Risk:** Low - drop-in replacement with better performance

---

### Phase 2: Async Worker Pool (Weeks 3-4)

**Wrap `worker_pool.ml` with Moonpool:**
- Add non-blocking extraction
- Better error handling
- Automatic backpressure

**Risk:** Medium - requires careful process lifecycle management

---

### Phase 3: Claws Parallelization (Weeks 5-6)

**Parallelize Claws analysis:**
- Group files by directory
- Parallel complexity/anatomy analysis
- Sequential within groups for cache locality

**Risk:** Medium - depends on findings being independent

---

### Phase 4: Advanced Features (Weeks 7+)

**Optional enhancements:**
- Task local storage for tracing
- Fork-join for recursive algorithms
- Progress reporting improvements

**Risk:** Low - additive improvements

---

## Comparison: Before vs After

| Metric | Current | With Moonpool |
|--------|---------|---------------|
| **CPU Utilization** | ~60% (static domain assignment) | ~90% (work-stealing) |
| **Memory per task** | Heavy (Domain) | Light (Thread) |
| **Load balancing** | Poor (static) | Excellent (dynamic) |
| **Async pattern** | Manual blocking | Native `Fut.await` |
| **Progress tracking** | Difficult | `Fut.peek` |
| **Code complexity** | Simple (raw Domains) | Moderate (pools + futures) |
| **Dependencies** | None (stdlib only) | moonpool |

---

## Estimated Effort

| Phase | Effort | Risk | Value |
|-------|--------|------|-------|
| Phase 1: Replace parallel.ml | 2-3 days | Low | High |
| Phase 2: Async worker pool | 3-5 days | Medium | High |
| Phase 3: Parallel Claws | 2-4 days | Medium | Medium |
| Phase 4: Advanced features | 3-5 days | Low | Low-Medium |
| **Total** | **10-17 days** | - | - |

---

## Decision Points

### Should we integrate Moonpool?

**Yes if:**
- [ ] Performance profiling shows current architecture is a bottleneck
- [ ] You need better load balancing for varying file sizes
- [ ] You want native async/await pattern
- [ ] You want structured progress reporting

**No if:**
- [ ] Current architecture meets performance needs
- [ ] Simplicity > performance (current has 0 extra dependencies)
- [ ] Short-term delivery priority (Moonpool adds complexity)

---

## Recommendations

### Immediate (No Integration)

1. **Benchmark current architecture** - measure actual performance
2. **Profile the slow parts** - is it extraction, analysis, or reporting?
3. **If performance is adequate, defer integration**

### If Performance Issues Exist

1. **Start with Phase 1** - replace `parallel.ml` only
2. **Benchmark after change** - verify improvement
3. **Iterate based on results**

### Long-term

Consider Moonpool integration as part of architectural improvements:
- Better async patterns throughout
- Structured logging with task context
- Progress reporting for CLI

---

## References

- Moonpool: https://github.com/c-cube/moonpool
- Moonpool Docs: https://github.com/c-cube/moonpool/blob/main/README.md
- Current parallel: `src/ocaml/lib/catseye_engine/parallel.ml`
- Current worker pool: `src/ocaml/lib/catseye_engine/worker_pool.ml`
- Related: `planning/42-miou-vs-moonpool.md`

---

## Appendix: API Cheat Sheet

### Thread Pools

```ocaml
(* Create pool *)
let pool = Moonpool.Fifo_pool.create ~num_threads:4 ()
let pool = Moonpool.Ws_pool.create ~num_threads:4 ()

(* Schedule work *)
Moonpool.Runner.run_async pool (fun () -> 
  print_endline "runs on pool"
)

(* Schedule and wait *)
Moonpool.Runner.run_wait_block pool (fun () -> 
  (* blocks until done *)
  42
)

(* Shutdown *)
Moonpool.Fifo_pool.shutdown pool
Moonpool.Ws_pool.shutdown pool
```

### Futures

```ocaml
(* Spawn future *)
let fut = Moonpool.Fut.spawn ~on:pool (fun () -> 
  heavy_computation () 
)

(* Await (blocking, no deadlock) *)
let result = Moonpool.Fut.wait_block_exn fut

(* Peek (non-blocking) *)
match Moonpool.Fut.peek fut with
| Some (Ok v) -> print_endline "done!"
| Some (Error e) -> handle_error e
| None -> print_endline "still running"

(* Join multiple *)
let results = Moonpool.Fut.join_array (Array.of_list futures)
```

### Fork-Join

```ocaml
(* Must run on a pool *)
let result = Moonpool.Fut.spawn ~on:pool (fun () ->
  Moonpool_forkjoin.both
    (fun () -> compute_left)
    (fun () -> compute_right)
)
```

### Task Local Storage

```ocaml
module Picos = Moonpool.Picos

let key : string Picos.key = Picos.Key.create ()

(* Set in task *)
Picos.set key "my_value"

(* Get in task *)
match Picos.get key with
| Some v -> print_endline v
| None -> print_endline "not set"
```

---

**Next Steps:**
1. Benchmark current performance
2. Profile bottlenecks
3. Decide if integration is warranted
4. If yes, start with Phase 1