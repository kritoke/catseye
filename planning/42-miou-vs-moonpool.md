# Miou vs Moonpool: Architecture Comparison

**Status:** 🔭 Analysis  
**Created:** 2026-05-13  
**Purpose:** Compare Miou and Moonpool to determine best fit for Catseye's worker pool  

---

## Overview

Both libraries are OCaml 5+ schedulers for concurrent/parallel programming, but they take fundamentally different approaches:

| Library | Maintainer | Focus | OCaml Version |
|---------|------------|-------|----------------|
| **Miou** | Robur Cooperative | Minimal scheduler with strict rules | OCaml 5.0+ |
| **Moonpool** | Simon Cruanes | Thread pools + futures | OCaml >= 4.08, optimized for 5.0 |

---

## Quick Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         RECOMMENDATION                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  For Catseye's use case: Worker Pool + Parallel Extraction         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    MOONPOOL                                │   │
│  │                                                                 │   │
│  │  ✅ Pre-built thread pools (Fifo_pool, Ws_pool)              │   │
│  │  ✅ Futures with await support (suspends, no deadlock)       │   │
│  │  ✅ Domain-aware (N domains = N cores)                       │   │
│  │  ✅ Fork-join for recursive parallelism                      │   │
│  │  ✅ Simpler mental model for worker pool use case            │   │
│  │  ✅ Active development, well-documented                     │   │
│  │                                                                 │   │
│  │  ⚠️  Requires OCaml 5 for best features                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Why not Miou:                                                    │
│  - Strict "must await all children" rules add complexity           │
│  - No pre-built pool abstraction                                   │
│  - Designed for unikernels and systems programming                 │
│  - More restrictive programming model                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Comparison

### Miou Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MIOU MODEL                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Miou.run ──▶ Task Graph (strict parent-child relationships)       │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │   Parent Task                                               │   │
│  │   ┌─────────────────────────────────────────────────────┐   │   │
│  │   │                                                     │   │   │
│  │   │  Miou.async ──▶ Concurrent Task (same domain)        │   │   │
│  │   │                                                     │   │   │
│  │   │  Miou.call ──▶ Parallel Task (different domain)     │   │   │
│  │   │                                                     │   │   │
│  │   │  Miou.await ──▶ Must wait for children              │   │   │
│  │   │                                                     │   │   │
│  │   │  Miou.cancel ──▶ Abnormal termination               │   │   │
│  │   │                                                     │   │   │
│  │   └─────────────────────────────────────────────────────┘   │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Rules:                                                           │
│  - Each task must await its own children                           │
│  - Task hierarchy is strict (parent-child only)                    │
│  - No cross-task communication without explicit channels          │
│  - Cancellation propagates to children                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Moonpool Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       MOONPOOL MODEL                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Fixed Domain Pool ──▶ Thread Pools ──▶ Tasks                     │
│  (N domains = N cores)    ↑                    ↑                    │
│                           │                    │                    │
│                    ┌───────┴───────┐    ┌──────┴──────┐             │
│                    │  Fifo_pool   │    │   Ws_pool   │             │
│                    │  (FIFO queue)│    │ (Work steal)│             │
│                    └──────────────┘    └─────────────┘             │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  Moonpool.Fut ──▶ Future + await                            │   │
│  │                                                             │   │
│  │  ┌─────────────────────────────────────────────────────┐   │   │
│  │  │  spawn ~on:pool (fun () -> ...)  ──▶ Fut.t          │   │   │
│  │  │  Fut.await fut                  ──▶ suspend + resume│   │   │
│  │  └─────────────────────────────────────────────────────┘   │   │
│  │                                                             │   │
│  │  Moonpool_forkjoin.both_ignore (fun () -> ...)              │   │
│  │                              (fun () -> ...)               │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Feature Comparison

| Feature | Miou | Moonpool | Catseye Need |
|---------|------|----------|--------------|
| **Pre-built pools** | ❌ No | ✅ Fifo_pool, Ws_pool | ✅ Critical |
| **Parallel tasks** | ✅ `Miou.call` | ✅ `Fut.spawn` | ✅ Needed |
| **Concurrent tasks** | ✅ `Miou.async` | ✅ `Fut.spawn` | ✅ Needed |
| **Future/await** | ❌ No native | ✅ `Fut.await` | ✅ Critical |
| **Domain-aware** | ✅ Yes | ✅ N domains = N cores | ✅ Good |
| **Work-stealing** | ❌ No | ✅ Ws_pool | ⚠️ Nice to have |
| **Fork-join** | ❌ No | ✅ `Moonpool_forkjoin` | ❌ Not needed |
| **Thread pools** | ❌ No | ✅ Yes | ✅ Critical |
| **Channels** | ✅ Yes | ✅ `Chan` | ⚠️ Maybe later |
| **Task local storage** | ❌ No | ✅ Via picos | ⚠️ Nice to have |
| **OCaml 4.08+** | ❌ 5.0+ only | ✅ Yes | ✅ Good |
| **Unikernel support** | ✅ Yes | ❌ No | ❌ Not needed |

---

## API Comparison

### Miou - Strict Parent-Child Model

```ocaml
(* Miou: Every task must be awaited by its creator *)

let () = Miou.run @@ fun () ->
  (* Create async task (concurrent, same domain) *)
  let p0 = Miou.async @@ fun () ->
    (* spawn children *)
    let q = Miou.async @@ fun () -> Miou_unix.sleep 1.
    in
    42
  in
  
  (* MUST await - otherwise raises Still_has_children *)
  Miou.await_exn p0

(* Cancellation propagates to children *)
let () = Miou.run @@ fun () ->
  let p = Miou.async @@ fun () ->
    let q = Miou.async @@ fun () -> 
      (* This gets cancelled too *)
      Miou_unix.sleep 10.
    in
    raise (Failure "error")
  in
  Miou.await p  (* Waits for q to be cancelled too *)
```

### Moonpool - Flexible Pool Model

```ocaml
(* Moonpool: Use thread pools with futures *)

(* Create a pool *)
let pool = Moonpool.Fifo_pool.create ~num_threads:4 ()

(* Spawn a future *)
let fut = Moonpool.Fut.spawn ~on:pool (fun () ->
  process_file "example.cr"
)

(* Await the result (suspends, no deadlock) *)
let result = Moonpool.Fut.wait_block_exn fut

(* Multiple futures *)
let fibs = Array.init 10 (fun n ->
  Moonpool.Fut.spawn ~on:pool (fun () -> fib n)
)
let results = Moonpool.Fut.join_array fibs 
              |> Moonpool.Fut.wait_block

(* Work-stealing pool for many short tasks *)
let ws_pool = Moonpool.Ws_pool.create ~num_threads:8 ()

(* Fork-join for recursive parallelism *)
Moonpool_forkjoin.both_ignore
  (fun () -> sort_left)
  (fun () -> sort_right)
```

---

## For Catseye's Use Case

### Current Architecture

```
Main ──▶ Worker Pool (round-robin) ──▶ Crystal Extractors (N processes)
  │                                                          │
  └────── Domains (parallel file processing) ◀────────────────┘
```

### What Catseye Needs

1. **Process N files in parallel** → Thread pools needed
2. **Manage Crystal extractor processes** → Process lifecycle
3. **Collect results** → Futures with await
4. **Crash recovery** → Worker restart
5. **Simple mental model** → Don't want complex task hierarchy

### Moonpool Fit

```ocaml
(* Proposed: Moonpool-based worker pool *)

open Moonpool

(* Each worker processes files from a pool *)
let worker_pool = Ws_pool.create ~num_threads:8 ()

(* Spawn file processing *)
let process_file file =
  Fut.spawn ~on:worker_pool (fun () ->
    let extractor = spawn_extractor () in
    let result = extractor##extract(file) in
    let _ = extractor##shutdown in
    result
  )

(* Process multiple files *)
let files = [ "a.cr"; "b.cr"; "c.cr"; ... ] in
let futures = List.map process_file files in

(* Wait for all results *)
let results = List.map Fut.wait_block_exn futures in

(* Shutdown *)
Ws_pool.shutdown worker_pool
```

### Miou Fit (More Complex)

```ocaml
(* Miou: Requires careful task management *)

let () = Miou.run @@ fun () ->
  (* Each file spawns a parallel task (different domain) *)
  let tasks = List.map (fun file ->
    Miou.call @@ fun () ->
      let extractor = spawn_extractor () in
      let result = extractor##extract(file) in
      extractor##shutdown;
      result
  ) files in
  
  (* Must await each - but who owns what? *)
  let results = List.map Miou.await tasks in
  ()
(* If we forget to await, raises Still_has_children *)
```

---

## Detailed Analysis

### Miou Strengths

| Strength | Why It Matters |
|----------|---------------|
| **Unikernel-ready** | Can compile to small images for embedded systems |
| **Strict rules** | Prevents common concurrency bugs |
| **Small footprint** | Few dependencies, good for constrained environments |
| **Conservative design** | Less likely to have surprising behavior |
| **Parent-child model** | Clear ownership of tasks |

### Miou Weaknesses for Catseye

| Weakness | Impact |
|----------|--------|
| **No pre-built pools** | Must implement own pool abstraction |
| **Strict await requirements** | Adds complexity for dynamic task creation |
| **No fork-join** | Harder to parallelize recursive algorithms |
| **No futures/await** | Must implement own async pattern |
| **Systems focus** | Not designed for application-level parallelism |

### Moonpool Strengths

| Strength | Why It Matters |
|----------|---------------|
| **Pre-built pools** | `Fifo_pool` and `Ws_pool` directly solve our use case |
| **Futures with await** | Natural async/await pattern, no deadlock risk |
| **Domain-aware** | Automatically uses all CPU cores |
| **Work-stealing** | Good for unbalanced workloads |
| **Fork-join** | Easy recursive parallelism if needed |
| **OCaml 4.08+** | Works with older OCaml, optimized for 5 |
| **Active development** | Well-maintained by c-cube |

### Moonpool Weaknesses

| Weakness | Impact |
|----------|--------|
| **More dependencies** | Uses `picos` for task local storage |
| **Not unikernel-ready** | Not designed for constrained environments |
| **Less strict** | More freedom = more ways to make mistakes |
| **Thread-based** | Slightly heavier than pure effect-based |

---

## Comparison Matrix

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SUITABILITY FOR CATSEYE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Criteria: How well does this solve Catseye's worker pool?         │
│                                                                     │
│  ┌────────────────────────────┬───────────┬───────────┐            │
│  │ Criterion                 │   Miou    │  Moonpool │            │
│  ├────────────────────────────┼───────────┼───────────┤            │
│  │ Pre-built pools           │    1/5    │    5/5    │            │
│  │ Futures/await             │    1/5    │    5/5    │            │
│  │ Simple mental model       │    2/5    │    5/5    │            │
│  │ OCaml 5 integration       │    5/5    │    5/5    │            │
│  │ Crash recovery pattern     │    2/5    │    4/5    │            │
│  │ Documentation             │    3/5    │    5/5    │            │
│  │ Active maintenance        │    3/5    │    4/5    │            │
│  ├────────────────────────────┼───────────┼───────────┤            │
│  │ TOTAL SCORE               │   17/35   │   33/35   │            │
│  └────────────────────────────┴───────────┴───────────┘            │
│                                                                     │
│  Scoring: 1=Poor, 3=OK, 5=Excellent                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Recommendation

### Primary: Moonpool

Moonpool is the better fit for Catseye because:

1. **Pre-built thread pools** solve 80% of our needs
2. **Futures with await** give us the async pattern we want
3. **Simpler model** - no strict parent-child rules
4. **Domain-aware** - automatically uses all cores
5. **Work-stealing** - good for varying file sizes

### Migration Path

```ocaml
(* Phase 1: Replace current Domains with Moonpool *)

(* Current (parallel.ml) *)
let extract_parallel extract_fn files =
  let arr = Array.of_list files in
  let domains = Array.init (Array.length arr) (fun i ->
    Domain.spawn (fun () -> extract_fn arr.(i))
  ) in
  Array.iter Domain.join domains

(* New with Moonpool *)
let extract_parallel extract_fn files =
  let pool = Moonpool.Ws_pool.create ~num_threads:(Domain.recommended_domain_count ()) in
  let futures = List.map (fun file ->
    Moonpool.Fut.spawn ~on:pool (fun () -> extract_fn file)
  ) files in
  let results = List.map (fun fut ->
    match Moonpool.Fut.wait_block fut with
    | Ok r -> r
    | Error e -> None
  ) futures in
  Moonpool.Ws_pool.shutdown pool;
  List.filter_map Fun.id results

(* Phase 2: Wrap worker pool in Moonpool *)
(* Keep existing Crystal process management, add Moonpool on top *)
```

### If Miou is Required (Why?)

If you need Miou for specific reasons (unikernel, strict correctness):

1. Implement custom pool manager
2. Use `Miou.call` for parallel file processing
3. Track task ownership carefully
4. Implement crash recovery manually

---

## Code Example: Moonpool Worker Pool

```ocaml
(* lib/catseye_engine/moonpool_worker.ml *)

open Moonpool

type extractor = {
  pid : int;
  stdin : out_channel;
  stdout : in_channel;
}

type worker = {
  id : int;
  pool : Ws_pool.t;
  active : bool;
}

type t = {
  pool : Ws_pool.t;
  mutable next_id : int;
  extractors : (int, extractor) Hashtbl.t;
  mutex : Mutex.t;
}

let create ~num_workers () =
  let pool = Ws_pool.create ~num_threads:num_workers () in
  {
    pool;
    next_id = 0;
    extractors = Hashtbl.create 16;
    mutex = Mutex.create ();
  }

let spawn_extractor (t : t) : extractor =
  let id = t.next_id in
  t.next_id <- t.next_id + 1;
  (* Spawn Crystal extractor process *)
  let cmd = "bin/catseye-crystal-extractor --serve" in
  let (stdout, stdin, _) = Unix.open_process_full cmd [||] in
  let ext = { pid = id; stdin; stdout } in
  Mutex.lock t.mutex;
  Hashtbl.add t.extractors id ext;
  Mutex.unlock t.mutex;
  ext

let extract (t : t) (file : string) : Security_node.t list option =
  let ext = spawn_extractor t in
  let fut = Fut.spawn ~on:t.pool (fun () ->
    (* Send extraction request *)
    let req = Printf.sprintf "{\"id\":0,\"method\":\"extract\",\"file\":\"%s\"}\n" file in
    output_string ext.stdin req;
    flush ext.stdin;
    
    (* Read response *)
    let rec read_response acc =
      try
        let line = input_line ext.stdout in
        match parse_response line with
        | Some nodes -> nodes
        | None -> read_response acc
      with End_of_file -> None
    in
    read_response []
  ) in
  Fut.wait_block fut

let extract_batch (t : t) (files : string list) : (string * Security_node.t list option) list =
  let futures = List.map (fun file ->
    Fut.spawn ~on:t.pool (fun () -> (file, extract t file))
  ) files in
  List.map (fun fut ->
    match Fut.wait_block fut with
    | Ok result -> result
    | Error _ -> ("unknown", None)
  ) futures

let shutdown (t : t) : unit =
  Mutex.lock t.mutex;
  Hashtbl.iter (fun _ ext ->
    (try close_in ext.stdout with _ -> ());
    (try close_out ext.stdin with _ -> ())
  ) t.extractors;
  Mutex.unlock t.mutex;
  Ws_pool.shutdown t.pool
```

---

## Alternative: Keep Current Architecture

Given the complexity of migration, consider:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    KEEP CURRENT + ADD MONITORING                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Current Architecture:                                             │
│  - Domains for parallel file processing                             │
│  - Worker pool for Crystal process management                       │
│  - Works well for current needs                                    │
│                                                                     │
│  Improvements without Moonpool:                                    │
│  - Add Prometheus metrics to worker pool                           │
│  - Implement exponential backoff for restarts                      │
│  - Add health checks for extractor processes                      │
│  - Use structured logging                                          │
│                                                                     │
│  Only migrate to Moonpool if:                                      │
│  - Current architecture has measurable performance issues           │
│  - Need work-stealing for unbalanced workloads                     │
│  - Want simpler async/await pattern                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## References

- Miou: https://github.com/robur-coop/miou
- Moonpool: https://github.com/c-cube/moonpool
- Current parallel: `src/ocaml/lib/catseye_engine/parallel.ml`
- Current worker pool: `src/ocaml/lib/catseye_engine/worker_pool.ml`

---

## Appendix: Miou Book Reference

Miou has a comprehensive book: https://robur-coop.github.io/miou

Key chapters for understanding:
1. Introduction to effects in OCaml 5
2. Building a simple scheduler
3. Implementing an echo server
4. Task management and cancellation

---

**Verdict:** Moonpool is the better fit for Catseye's worker pool use case due to its pre-built pools, futures/await support, and simpler mental model. Miou is better suited for unikernel and systems programming where strict correctness rules are beneficial.