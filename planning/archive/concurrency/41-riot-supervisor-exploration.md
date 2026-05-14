# Riot Supervisor Architecture Exploration

**Status:** 🔭 Exploration (Not Implementation)  
**Created:** 2026-05-13  
**Purpose:** Explore using Riot (https://riot.ml) as a supervisor for Catseye's worker pool  

---

## Background

Riot is an actor-model multi-core scheduler for OCaml 5 that brings Erlang-style concurrency to OCaml. It includes:
- **Supervisors** for building process hierarchies
- **Type-safe message passing** between processes
- **Process links and monitors** for lifecycle management
- **Generic Servers** (similar to Elixir's GenServer)

Catseye currently uses:
- `Domains` (OCaml 5) for parallel file extraction
- A `Worker_pool` module that manages persistent Crystal extractor processes
- NDJSON over stdin/stdout for worker communication

This document explores whether Riot's supervisor model could improve Catseye's reliability and architecture.

---

## Current Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CURRENT CATSEYE ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │
│  │   Main      │     │  Worker Pool │     │   Crystal   │           │
│  │  Process    │────▶│  (Round-robin)│────▶│ Extractors  │           │
│  │             │     │              │     │             │           │
│  │  - Schedule │     │  - N workers │     │  - Parse AST│           │
│  │  - Collect   │◀────│  - Respawn   │◀────│  - Type info│           │
│  │  - Report    │     │  - Recovery  │     │  - Errors   │           │
│  └─────────────┘     └─────────────┘     └─────────────┘           │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Domains (OCaml 5)                                           │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐               │   │
│  │  │Domain 1│ │Domain 2│ │Domain 3│ │Domain N│               │   │
│  │  │ File A │ │ File B │ │ File C │ │ File N │               │   │
│  │  └────────┘ └────────┘ └────────┘ └────────┘               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Current Weaknesses

1. **Worker crash recovery is manual** — `Worker_pool.respawn` is called after detection
2. **No process hierarchy** — All workers are peer-level, no supervision tree
3. **Round-robin scheduling** — Doesn't adapt to worker load or file complexity
4. **No message-based coordination** — Workers communicate via JSON pipes, not typed messages

---

## Riot Supervisor Model

Riot brings the Erlang/OTP supervisor concept to OCaml:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RIOT SUPERVISOR ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    SUPERVISOR TREE                             ││
│  │                                                                 ││
│  │                      ┌───────────────┐                          ││
│  │                      │    Root       │                          ││
│  │                      │  Supervisor   │                          ││
│  │                      └───────┬───────┘                          ││
│  │                              │                                  ││
│  │              ┌───────────────┼───────────────┐                  ││
│  │              ▼               ▼               ▼                  ││
│  │      ┌───────────────┐ ┌───────────────┐ ┌───────────────┐     ││
│  │      │  Extractor    │ │  Engine       │ │  Reporter      │     ││
│  │      │  Supervisor    │ │  Supervisor   │ │  Supervisor    │     ││
│  │      └───────┬───────┘ └───────────────┘ └───────────────┘     ││
│  │              │                                              │   │
│  │      ┌───────┼───────┐                                      │   │
│  │      ▼       ▼       ▼                                      │   │
│  │  ┌───────┐ ┌───────┐ ┌───────┐                              │   │
│  │  │Worker1│ │Worker2│ │WorkerN│                              │   │
│  │  └───────┘ └───────┘ └───────┘                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Riot Concepts

**Actor (Process):**
```ocaml
type Message.t +=
  | Extract of { file: string; reply_to: Pid.t }
  | Result of Security_node.t list
  | Crash of { worker_id: int; error: string }
```

**Supervisor Strategies:**
- **OneForOne** — Restart only crashed child
- **OneForAll** — Restart all children if one dies
- **RestForOne** — Restart crashed child and those started after it

---

## Proposed Supervisor Hierarchy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CATSEYE SUPERVISOR TREE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│                      ┌──────────────────┐                           │
│                      │  Catseye Root    │                           │
│                      │  (OneForOne)     │                           │
│                      └────────┬─────────┘                           │
│                               │                                      │
│         ┌─────────────────────┼─────────────────────┐               │
│         ▼                     ▼                     ▼               │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
│  │   Scheduler   │    │  Extractor    │    │   Reporter    │       │
│  │   Supervisor  │    │  Pool         │    │   Supervisor  │       │
│  │  (OneForOne)  │    │  Supervisor   │    │  (OneForOne)  │       │
│  │               │    │  (RestForOne) │    │               │       │
│  └───────┬───────┘    └───────┬───────┘    └───────────────┘       │
│          │                   │                                      │
│  ┌───────┴───────┐    ┌───────┴───────┐                            │
│  │ Scheduler     │    │ Extractor     │                            │
│  │ Actor         │    │ Actor 1       │──┐                         │
│  │               │    │ Actor 2       │──┼─▶ Extractor Actors       │
│  └───────────────┘    │ Actor N       │──┘                         │
│                       └───────────────┘                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Actor Definitions

**Scheduler Actor:**
```ocaml
(* Manages work distribution and coordination *)
type Message.t +=
  | Start of { files: string list }
  | FileComplete of { file: string; findings: Finding.t list }
  | AllComplete

let scheduler () =
  let pending = ref [] in
  let workers = ref [] in
  
  (* Receive messages *)
  match receive () with
  | Start { files; reply_to } ->
    pending := files;
    (* Distribute to extractor actors *)
    List.iter (fun file ->
      match !workers with
      | [] -> ()
      | w :: rest ->
        workers := rest;
        send w (Extract { file; reply_to = self () })
    ) files;
    
    (* Wait for results *)
    let rec wait () =
      match receive () with
      | Result { file; nodes } ->
        pending := List.filter ((<>) file) !pending;
        (* Forward to reporter *)
        (match !reporter with Some r -> send r (Nodes { file; nodes }) | None -> ());
        if List.is_empty !pending then send reply_to AllComplete
        else wait ()
      | Crash { worker_id } ->
        (* Restart worker through supervisor *)
        restart_worker worker_id;
        wait ()
    in
    wait ()
```

**Extractor Actor:**
```ocaml
(* Manages a single Crystal extractor process *)
type Message.t +=
  | Execute of { file: string; reply_to: Pid.t }
  | ExtractResult of Security_node.t list
  | ExtractionError of string

let extractor (id: int) () =
  (* Spawn the Crystal process *)
  let proc = spawn_extractor_process () in
  
  let rec loop () =
    match receive () with
    | Execute { file; reply_to } ->
      send_proc proc (extract_request file);
      loop ()
    | ExtractResult nodes ->
      send reply_to (Result { file; nodes });
      loop ()
    | ExtractionError err ->
      (* Notify supervisor, then die *)
      send (parent ()) (Crash { id; error = err });
      exit ()
  in
  loop ()

(* Supervisor handles crashes *)
let extractor_supervisor () =
  let children = ref [] in
  
  (* Start N extractor actors *)
  for i = 0 to pool_size - 1 do
    let child = spawn (extractor i) in
    children := (i, child) :: !children
  done;
  
  (* Monitor for crashes *)
  let rec loop () =
    match receive () with
    | ProcessDown { pid; reason } ->
      (* Find which child crashed *)
      (match List.assoc_opt pid !children with
       | Some id ->
         Logs.warn (fun m -> m "Extractor %d crashed: %s" id reason);
         (* Restart via supervisor *)
         restart pid;
         let new_pid = spawn (extractor id) in
         children := List.map (fun (i, p) -> 
           if i = id then (i, new_pid) else (i, p)
         ) !children
       | None -> ());
      loop ()
  in
  loop ()
```

---

## Benefits of Riot Supervisor Model

### 1. **Automatic Crash Recovery**

Current implementation:
```ocaml
(* Manual detection and recovery *)
match read_response worker with
| (-1, None) ->
  respawn pool idx;  (* Called manually after detection *)
  ...
```

With Riot:
```ocaml
(* Supervisor automatically restarts crashed children *)
(* No manual respawn logic needed *)
```

### 2. **Backpressure and Flow Control**

Riot actors can implement backpressure natively:

```ocaml
let extractor () =
  let mailbox_size = ref 0 in
  let max_pending = 10 in
  
  (* Track mailbox depth *)
  let rec loop () =
    mailbox_size := mailbox_size () + 1;
    
    match receive () with
    | Execute _ when !mailbox_size > max_pending ->
      (* Backpressure: ask scheduler to slow down *)
      send (parent ()) Ready;
      loop ()
    | Execute { file; reply_to } ->
      process_file file reply_to;
      mailbox_size := !mailbox_size - 1;
      loop ()
  in
  loop ()
```

### 3. **Typed Message Protocol**

Current: JSON over pipes (runtime errors on malformed messages)  
Riot: Type-safe messages at compile time

```ocaml
type Message.t +=
  | Extract of { file: string; reply_to: Pid.t }
  | Result of Security_node.t list

(* Compiler ensures all message handlers cover all cases *)
```

### 4. **Hierarchical Error Handling**

```ocaml
(* Different strategies for different failure types *)
type error +=
  | Transient of exn   (* Network timeout, retry *)
  | Permanent of exn   (* Bug in code, crash child *)
  | Fatal of exn      (* Corrupt state, restart all *)

let handle_error = function
  | Transient e ->
    Logs.info (fun m -> m "Transient error, retrying...");
    retry ()
  | Permanent e ->
    Logs.warn (fun m -> m "Permanent error, restarting...");
    restart_child ()
  | Fatal e ->
    Logs.err (fun m -> m "Fatal error, escalating...");
    escalate ()
```

---

## Comparison: Current vs Riot

| Aspect | Current (Domains + Worker Pool) | Riot (Actors + Supervisors) |
|--------|----------------------------------|------------------------------|
| **Concurrency Model** | Data parallelism via Domains | Process parallelism via Actors |
| **Crash Recovery** | Manual detection + respawn | Supervisor automatic restart |
| **Message Protocol** | JSON (untyped) | Type-safe variants |
| **Scheduling** | Round-robin | Priority + backpressure |
| **Process Hierarchy** | Flat (all workers equal) | Tree (supervisors + children) |
| **Fault Tolerance** | Per-worker recovery | Cascading based on strategy |
| **Code Complexity** | Simple pool management | Requires actor pattern knowledge |
| **OCaml Version** | OCaml 5.0+ (Domains) | OCaml 5.0+ (same) |

---

## Migration Path (Exploration Only)

### Phase 0: Investigation

1. **Check Riot Compatibility**
   ```bash
   opam show riot
   # Check: requires OCaml 5.0+, stdlib compat
   ```

2. **Test Riot Supervisor Pattern**
   ```ocaml
   (* Minimal test: spawn supervisor + child *)
   open Riot

   type Message.t += ChildReady

   let child () =
     send (parent ()) ChildReady;
     match receive () with
     | _ -> ()

   let supervisor () =
     let p = spawn child in
     match receive () with
     | ChildReady -> 
       Logs.info (fun m -> m "Child started!");
       shutdown ()
     | _ -> ()

   let () = Riot.run supervisor
   ```

3. **Benchmark Current Performance**
   - Baseline: current parallel extraction times
   - Compare against single-threaded for speedup

### Phase 1: Hybrid Approach

Keep current architecture but add Riot supervision layer:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HYBRID: RIOT OVERLAY                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│    ┌────────────────────────────────────────────────────────────┐  │
│    │                    Riot Supervisor                         │  │
│    │  (Monitors worker pool, handles restarts)                │  │
│    └────────────────────────────┬─────────────────────────────┘  │
│                                   │                                 │
│    ┌─────────────────────────────┼─────────────────────────────┐  │
│    │                    Worker Pool                             │  │
│    │  (Existing implementation unchanged)                        │  │
│    │                                                             │  │
│    │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐                      │  │
│    │  │ W1  │  │ W2  │  │ W3  │  │ W4  │                      │  │
│    │  └─────┘  └─────┘  └─────┘  └─────┘                      │  │
│    └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 2: Full Actor Model

Replace worker pool with Riot actors:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FULL RIOT IMPLEMENTATION                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Scheduler ──▶ [ Extractor Actor 1 ] ──▶ Crystal Process 1          │
│     │         [ Extractor Actor 2 ] ──▶ Crystal Process 2          │
│     │         [ Extractor Actor 3 ] ──▶ Crystal Process 3          │
│     │         ...                                                  │
│     │                                                             │
│     ▼                                                             │
│  Reporter ──▶ Aggregate Findings                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Riot OCaml Version Concern

Riot uses an **older OCaml version** (approximately 4.14 based on docs). This is a significant consideration:

### Version Analysis

```bash
# Check Riot's OCaml requirements
opam show riot | grep depends
# Expected output mentions OCaml version constraints

# Current catseye: OCaml 5.0+
cat catseye.opam | grep "ocaml"
```

### Potential Solutions

1. **Dual Compilation**
   - Build Riot components with older compiler
   - Build catseye with OCaml 5
   - Communicate via external protocol (files, sockets)

2. **Forks/Variants**
   - Check if there's a fork supporting OCaml 5
   - Consider building Riot from source with OCaml 5

3. **Mio (Alternative)**
   - OCaml 5 native effect-based scheduler
   - Similar to Riot but OCaml 5-first
   - See: https://github.com/robur-coop/miou

4. **Stick with Current**
   - Current architecture is functional
   - Add supervision via external process (Python/Go supervisor)
   - Use existing Domains for parallelism

---

## Recommendation

Given the constraints, here are exploration paths:

### Option A: Exploration Only (No Implementation)
Keep the current architecture but document how Riot could improve it:
- This document serves as a reference for future work
- The current system works adequately
- Riot integration would be a larger project

### Option B: Hybrid Supervision
Add Riot as an external supervisor that:
- Spawns the main catseye process
- Monitors for crashes
- Restarts with exponential backoff

### Option C: Full Rewrite (Long-term)
Replace worker pool with Riot actors:
- Requires solving OCaml version compatibility
- More significant investment
- Best fault tolerance

---

## Next Steps (Exploration)

1. [ ] Check `opam show riot` for exact OCaml requirements
2. [ ] Test a minimal Riot supervisor example
3. [ ] Benchmark current extraction throughput
4. [ ] Evaluate Miou as alternative (OCaml 5 native)
5. [ ] Consider external supervisor approach
6. [ ] Document findings in architecture decision record (ADR)

---

## References

- Riot: https://riot.ml
- Riot Supervisor Docs: https://docs.riot.ml/actor-model/supervisor/
- Miou (OCaml 5 alternative): https://github.com/robur-coop/miou
- Current worker pool: `src/ocaml/lib/catseye_engine/worker_pool.ml`
- Current parallel: `src/ocaml/lib/catseye_engine/parallel.ml`

---

## Appendix: Minimal Riot Supervisor Example

```ocaml
(* Minimal supervisor for exploration *)

open Riot

(* Child message type *)
type Message.t +=
  | Start
  | Stop

(* Child actor *)
let worker (id: int) () =
  Logs.info (fun m -> m "Worker %d started" id);
  match receive () with
  | Stop ->
    Logs.info (fun m -> m "Worker %d stopped" id);
    exit ()
  | _ -> exit ()

(* Supervisor actor *)
let supervisor () =
  let children = ref [] in
  
  (* Spawn 4 workers *)
  for i = 0 to 3 do
    let pid = spawn (worker i) in
    children := (i, pid) :: !children;
    send pid Start
  done;
  
  (* Monitor for crashes *)
  let rec loop () =
    match receive () with
    | ProcessDown { pid; exit_status } ->
      (match List.assoc_opt pid !children with
       | Some id ->
         Logs.warn (fun m -> m "Worker %d died, restarting" id);
         let new_pid = spawn (worker id) in
         children := List.map (fun (i, p) -> 
           if i = id then (i, new_pid) else (i, p)
         ) !children;
         send new_pid Start
       | None -> ());
      loop ()
    | _ -> loop ()
  in
  
  (* Cleanup on shutdown *)
  at_exit (fun () ->
    List.iter (fun (_, pid) ->
      try send pid Stop with _ -> ()
    ) !children
  );
  
  loop ()

(* Run the supervisor *)
let () =
  Logs.info (fun m -> m "Starting Catseye supervisor");
  Riot.run supervisor
```

---

**Note:** This is exploration only. Implementation would require:
- Resolving OCaml version compatibility
- Designing complete message protocol
- Migration plan from current architecture
- Testing supervisor failure modes