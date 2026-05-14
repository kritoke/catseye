# Phase 8: Persistent Cache & Crystal Worker Pool

**Phase:** 8  
**Priority:** Medium (performance, not correctness)  
**Depends on:** None (independent, can parallel with Phase 7)  
**Parent:** `planning/roadmap.md`  
**Status:** Design complete

---

## Overview

Two performance infrastructure improvements:

1. **SQLite-backed extraction cache** — persists across runs, enabling true incremental scanning
2. **Crystal Worker Pool** — persistent Crystal processes communicating via JSON, eliminating per-file process spawn overhead

Both are optimizations. The engine already works correctly without them. They unlock speed at scale (500+ files).

---

## P1: SQLite Cache Backing

### Problem

The current cache (`cache.ml`) is in-memory (`Hashtbl`). It works within a single run — if you scan 100 files, changed files are re-extracted and unchanged files are skipped. But the cache is lost when the process exits. A second identical scan re-extracts everything.

### Current State

```ocaml
(* cache.ml — current in-memory store *)
module Store = struct
  type entry = {
    path : string;
    hash : string;
    nodes : Security_node.t list;
    analyzed_at : float;
  }
  let tbl : (string, entry) Hashtbl.t = Hashtbl.create 64
end
```

### Target State

Replace `Hashtbl` with SQLite, following the same pattern as `catseye_crowsnest/cache.ml`:

```ocaml
(* cache.ml — SQLite-backed store *)

type t = {
  db : Sqlite3.db;
  dir : string;  (* cache directory path *)
}

(** Schema *)
(*
  CREATE TABLE IF NOT EXISTS extraction_cache (
    path TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    nodes_json TEXT NOT NULL,
    analyzed_at REAL NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_hash ON extraction_cache (hash);
*)
```

### Implementation

#### `open_cache`

```ocaml
let open_cache (dir : string) : t =
  let rec mkdir_p d =
    if not (Sys.file_exists d) then begin
      mkdir_p (Filename.dirname d);
      Unix.mkdir d 0o755
    end
  in
  mkdir_p dir;
  let db_path = Filename.concat dir "extraction.db" in
  let db = Sqlite3.db_open db_path in
  let _ = Sqlite3.exec db
    "CREATE TABLE IF NOT EXISTS extraction_cache (\
    \n  path TEXT PRIMARY KEY,\
    \n  hash TEXT NOT NULL,\
    \n  nodes_json TEXT NOT NULL,\
    \n  analyzed_at REAL NOT NULL)" in
  let _ = Sqlite3.exec db
    "CREATE INDEX IF NOT EXISTS idx_extraction_hash ON extraction_cache (hash)" in
  { db; dir }
```

#### `check` (cache lookup)

```ocaml
let check (cache : t option) (path : string) : Security_node.t list option =
  match cache with
  | None -> None  (* No cache available *)
  | Some c ->
    let hash = file_hash path in
    let sql = "SELECT nodes_json, hash FROM extraction_cache WHERE path = ?1" in
    let stmt = Sqlite3.prepare c.db sql in
    Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT path) |> ignore;
    let result = match Sqlite3.step stmt with
      | Sqlite3.Rc.ROW ->
        (match (Sqlite3.column stmt 0, Sqlite3.column stmt 1) with
         | Sqlite3.Data.TEXT nodes_json, Sqlite3.Data.TEXT stored_hash ->
           if stored_hash = hash then
             try Some (Security_node.decode_many (Yojson.Safe.from_string nodes_json))
             with _ -> None
           else None  (* Hash mismatch — file changed *)
         | _ -> None)
      | _ -> None  (* Not in cache *)
    in
    ignore (Sqlite3.finalize stmt);
    result
```

#### `store` (cache write)

```ocaml
let store (cache : t option) (path : string) (nodes : Security_node.t list) : unit =
  match cache with
  | None -> ()  (* No cache available *)
  | Some c ->
    let hash = file_hash path in
    let nodes_json = Yojson.Safe.to_string (Security_node.encode_many nodes) in
    let sql = "INSERT OR REPLACE INTO extraction_cache (path, hash, nodes_json, analyzed_at) \
               VALUES (?1, ?2, ?3, ?4)" in
    let stmt = Sqlite3.prepare c.db sql in
    Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT path) |> ignore;
    Sqlite3.bind stmt 2 (Sqlite3.Data.TEXT hash) |> ignore;
    Sqlite3.bind stmt 3 (Sqlite3.Data.TEXT nodes_json) |> ignore;
    Sqlite3.bind stmt 4 (Sqlite3.Data.FLOAT (Unix.time ())) |> ignore;
    let _ = Sqlite3.step stmt in
    ignore (Sqlite3.finalize stmt)
```

### Fallback Strategy

The cache must gracefully handle:
1. **SQLite not available** — fall back to in-memory `Hashtbl` (current behavior)
2. **Corrupt database** — catch `Sqlite3` exceptions, rebuild the database
3. **Permission errors** — catch `Sys_error`, disable cache silently
4. **Disk full** — catch write errors, continue without cache

```ocaml
let open_cache_safe (dir : string) : t option =
  try Some (open_cache dir)
  with exn ->
    Logs.warn (fun m -> m "Cache open failed (%s), running without cache"
      (Printexc.to_string exn));
    None
```

### Cache Invalidation

Three invalidation strategies:

| Strategy | Trigger | Implementation |
|----------|---------|---------------|
| **Content-based** | File content hash changes | Automatic — `check` compares stored hash with current hash |
| **Manual** | User runs `--clear-cache` | `DELETE FROM extraction_cache` or delete the `.db` file |
| **TTL-based** (future) | Entries older than N days | `DELETE FROM extraction_cache WHERE analyzed_at < ?` |

### Integration with Orchestrator

```ocaml
(* orchestrator.ml — modified extraction loop *)

(* Open persistent cache *)
let cache = if config.no_cache then None
  else Cache.open_cache_safe config.cache_dir in

(* Extraction with cache *)
List.iter (fun src ->
  let nodes = match Cache.check cache src.path with
    | Some cached ->
      incr cache_hits;
      Some cached
    | None ->
      match extract_with_log config src with
      | Some ns ->
        Cache.store cache src.path ns;
        Some ns
      | None -> None
  in
  ...
) sources;

(* Close cache *)
(match cache with
 | Some c -> Cache.close c
 | None -> ());
```

### Database Size Management

Each cached file stores its nodes as JSON. Estimated sizes:

| Nodes per file | JSON size | 1000 files |
|---------------|-----------|------------|
| 50 | ~5 KB | ~5 MB |
| 100 | ~10 KB | ~10 MB |
| 500 | ~50 KB | ~50 MB |

For most codebases, the cache stays under 50 MB. For very large codebases, add a `--clear-cache` command or TTL eviction.

### Files to Change

| File | Change |
|------|--------|
| `cache.ml` | Rewrite `Store` to use SQLite instead of `Hashtbl` |
| `cache.ml` | Add `open_cache`, `close`, `open_cache_safe` |
| `cache.ml` | Keep `file_hash` and `fingerprint` unchanged |
| `orchestrator.ml` | Open cache at start, pass to extraction loop, close at end |
| `config.ml` | Read `[caching]` section from TOML |
| `args.ml` | Add `--cache-dir` and `--clear-cache` flags |
| `dune` (engine) | Add `sqlite3` to libraries |

### Testing

1. **Cache hit test:** Run scan, then run again. Second run should report cache hits and finish faster.
2. **Cache invalidation:** Modify a file, run scan. Modified file should be re-extracted.
3. **Corrupt DB test:** Write garbage to the `.db` file. Scanner should handle gracefully.
4. **No SQLite test:** Build without `sqlite3`. Should fall back to in-memory cache.
5. **Performance:** Compare scan time with and without cache on 50+ files.

---

## P2: Cache CLI Flags

### New CLI Flags

```
--cache-dir <path>    Cache directory (default: .catseye)
--clear-cache         Clear cache and run full scan
--no-cache            Disable caching entirely
```

### TOML Config

```toml
[caching]
dir = ".catseye"
# no_cache = false
```

### Implementation in `args.ml`

```ocaml
| "--cache-dir" :: path :: rest ->
  go { acc with cache_dir = resolve cwd path } rest
| "--clear-cache" :: rest ->
  go { acc with clear_cache = true } rest
```

### Implementation in `orchestrator.ml`

```ocaml
(* Handle --clear-cache *)
if config.clear_cache then begin
  let db_path = Filename.concat config.cache_dir "extraction.db" in
  if Sys.file_exists db_path then Sys.remove db_path
end;
```

---

## P3: Crystal Worker Protocol

### Current State

Each Crystal file spawns a new process:

```
OCaml → system("crystal run extractor.cr -- file.cr") → parse stdout → nodes
```

Startup cost per file: ~20ms for Crystal compilation + process spawn.

### Target State

Persistent Crystal process that accepts extraction requests over stdin/stdout:

```
┌──────────────┐   NDJSON stdin    ┌──────────────────────┐
│   OCaml      │──────────────────▶│  Crystal Worker       │
│   Pool Mgr   │                   │  (persistent process) │
│              │◀──────────────────│  Loop:                │
│              │   NDJSON stdout   │   read → parse → emit │
└──────────────┘                   └──────────────────────┘
```

### Protocol Spec

All messages are newline-delimited JSON (NDJSON). One JSON object per line.

#### Request Message

```json
{
  "id": 1,
  "method": "extract",
  "file": "/abs/path/to/file.cr",
  "content": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Monotonically increasing request ID |
| `method` | string | `"extract"` \| `"ping"` \| `"shutdown"` |
| `file` | string | Absolute path to source file |
| `content` | string\|null | Pre-loaded content (null = worker reads file) |

#### Success Response

```json
{
  "id": 1,
  "status": "ok",
  "nodes": [ { ... Security Node ... } ]
}
```

#### Error Response

```json
{
  "id": 1,
  "status": "error",
  "error": "Parse error: unexpected token at line 42"
}
```

#### Control Messages

```json
{ "id": 0, "method": "ping" }     → { "id": 0, "status": "ok" }
{ "id": 0, "method": "shutdown" } → worker exits
```

### Crystal Worker Implementation

```crystal
#!/usr/bin/env crystal
# persistent_worker.cr — Crystal worker for Catseye extraction

require "compiler/crystal/syntax"
require "json"

# (Include all existing extractor code: SecurityVisitor, classify_arg, etc.)

STDERR.puts "Catseye Crystal worker started (PID: #{Process.pid})"

loop do
  line = STDIN.gets
  break if line.nil? || line.strip.empty?

  begin
    request = JSON.parse(line)
    id = request["id"].as_i

    case request["method"].as_s
    when "extract"
      file = request["file"].as_s
      unless File.file?(file)
        STDOUT.puts({id: id, status: "error", error: "File not found: #{file}"}.to_json)
        STDOUT.flush
        next
      end

      source = File.read(file)
      parser = Crystal::Parser.new(source)
      parser.filename = file
      ast = parser.parse

      visitor = SecurityVisitor.new(file)
      ast.accept(visitor)
      annotated = SecurityVisitor.annotate_timeouts(visitor.nodes)

      STDOUT.puts({id: id, status: "ok", nodes: annotated}.to_json)
      STDOUT.flush

    when "ping"
      STDOUT.puts({id: id, status: "ok"}.to_json)
      STDOUT.flush

    when "shutdown"
      break
    end

  rescue ex : Crystal::SyntaxException
    STDOUT.puts({id: id, status: "error", error: "Parse error: #{ex.message}"}.to_json)
    STDOUT.flush
  rescue ex
    STDOUT.puts({id: id, status: "error", error: ex.message.to_s}.to_json)
    STDOUT.flush
  end
end

STDERR.puts "Catseye Crystal worker shutting down"
```

---

## P4: OCaml Worker Pool Manager

### Architecture

```
                    ┌──────────────────┐
                    │   Worker Pool    │
                    │   Manager        │
                    │                  │
                    │  queue: file list│
                    │  workers: N procs│
                    │  results: map    │
                    └──┬───┬───┬───┬───┘
                       │   │   │   │
                    ┌──▼┐┌─▼─┐┌─▼─┐┌─▼──┐
                    │ W1││ W2││ W3││ W4  │  (Crystal processes)
                    └───┘└───┘└───┘└─────┘
```

### Implementation

```ocaml
(* worker_pool.ml *)

type worker = {
  id : int;
  pid : int;                    (* Unix process ID *)
  stdin_ch : out_channel;       (* Write requests *)
  stdout_ch : in_channel;       (* Read responses *)
  full_ch : Unix.file_descr * Unix.file_descr * Unix.file_descr;  (* for close *)
}

type request = {
  id : int;
  file : string;
}

type response = {
  id : int;
  status : string;
  nodes : Security_node.t list option;
  error : string option;
}

type t = {
  workers : worker array;
  next_id : int ref;
  timeout : float;  (* seconds per request *)
}

(** Spawn a single Crystal worker process. *)
let spawn_worker (extractor_path : string) (worker_id : int) : worker =
  let cmd = Printf.sprintf "crystal run %s -- --serve 2>/dev/null"
    (Filename.quote extractor_path) in
  let (stdout_ch, stdin_ch, stderr_ch) =
    Unix.open_process_full cmd (Unix.environment ()) in
  { id = worker_id;
    pid = 0 (* could parse from stderr message *);
    stdin_ch;
    stdout_ch;
    full_ch = (stdout_ch, stdin_ch, stderr_ch) }

(** Create a pool of N workers. *)
let create (extractor_path : string) (pool_size : int) : t =
  let workers = Array.init pool_size (spawn_worker extractor_path) in
  { workers; next_id = ref 0; timeout = 30.0 }

(** Send a request to a specific worker. *)
let send_request (w : worker) (req : request) : unit =
  let json = Printf.sprintf
    {|{"id":%d,"method":"extract","file":%s,"content":null}|}
    req.id (Yojson.Safe.to_string (`String req.file)) in
  output_string w.stdin_ch json;
  output_char w.stdin_ch '\n';
  flush w.stdin_ch

(** Read a response from a specific worker (with timeout). *)
let read_response (w : worker) : response =
  (* Simple line read — could add select() for timeout *)
  let line = input_line w.stdout_ch in
  let json = Yojson.Safe.from_string line in
  decode_response json

(** Extract a single file via the pool. *)
let extract (pool : t) (file : string) : Security_node.t list option =
  let req = { id = !pool.next_id; file } in
  incr pool.next_id;
  (* Round-robin: pick worker by request ID *)
  let worker = pool.workers.(req.id mod Array.length pool.workers) in
  send_request worker req;
  let resp = read_response worker in
  if resp.status = "ok" then resp.nodes
  else None

(** Shutdown all workers. *)
let shutdown (pool : t) : unit =
  Array.iter (fun w ->
    output_string w.stdin_ch {|{"id":0,"method":"shutdown"}|};
    output_char w.stdin_ch '\n';
    flush w.stdin_ch;
    ignore (Unix.close_process_full w.full_ch)
  ) pool.workers
```

### Scheduling Strategy

**Round-robin** for simplicity. Each request goes to `worker[request_id % pool_size]`. This distributes evenly without needing a shared queue.

**Future improvement:** Work-stealing with a shared `Queue.t` — workers pull the next file when idle. This handles variable extraction times better than round-robin.

---

## P5: Pool Integration

### Orchestrator Changes

```ocaml
(* orchestrator.ml *)

(* Step 2: Extract *)
let extract_crystal, cleanup_crystal =
  if config.crystal_workers > 1 then begin
    (* Use worker pool *)
    let pool = Worker_pool.create config.crystal_extractor config.crystal_workers in
    let extract src =
      Worker_pool.extract pool src.path
    in
    let cleanup () = Worker_pool.shutdown pool in
    (extract, cleanup)
  end else begin
    (* Single-process (current behavior) *)
    let extract src = extract_file config src in
    let cleanup () = () in
    (extract, cleanup)
  end
in

(* ... extraction loop using extract_crystal ... *)

cleanup_crystal ();
```

### Gating

The worker pool is activated when `config.crystal_workers > 1`. Default is 2 from TOML config, but the orchestrator only creates the pool when there are enough Crystal files to justify it (e.g., > 5 files).

### Error Recovery

If a worker crashes:
1. OCaml detects EOF on `stdout_ch` — `input_line` raises `End_of_file`
2. Catch the exception, log a warning
3. Re-spawn the worker process
4. Re-queue the failed file

```ocaml
let extract_with_recovery pool file =
  try Worker_pool.extract pool file
  with End_of_file ->
    Logs.warn (fun m -> m "Worker crashed on %s, re-spawning" file);
    Worker_pool.respawn pool;
    try Worker_pool.extract pool file
    with End_of_file -> None  (* Give up after 2nd failure *)
```

---

## Performance Expectations

| Scenario | Current | With SQLite Cache | With Worker Pool | With Both |
|----------|---------|-------------------|------------------|-----------|
| First scan, 66 files | ~2s | ~2s (same) | ~0.8s | ~0.8s |
| Second scan, 66 files (no changes) | ~2s (re-extracts all) | ~0.1s (cache hits) | ~0.8s | ~0.1s |
| First scan, 500 files | ~15s | ~15s (same) | ~5s | ~5s |
| Incremental, 500 files (10 changed) | ~15s | ~1s | ~5s | ~0.5s |

---

## Files to Change

| File | Change | Phase Task |
|------|--------|-----------|
| `cache.ml` | Rewrite to SQLite backing | P1 |
| `orchestrator.ml` | Open/close cache, pass to extraction | P1 |
| `config.ml` | Add `[caching]` TOML section | P2 |
| `args.ml` | Add `--cache-dir`, `--clear-cache` | P2 |
| New: `src/extractor/persistent_worker.cr` | Crystal worker loop | P3 |
| New: `src/ocaml/lib/catseye_engine/worker_pool.ml` | OCaml pool manager | P4 |
| `orchestrator.ml` | Use pool for Crystal extraction | P5 |
| `src/ocaml/lib/catseye_engine/dune` | Add `worker_pool` module | P4 |

---

## Exit Criteria

- [ ] SQLite cache persists across runs
- [ ] Second scan of unchanged codebase is 10x+ faster
- [ ] `--clear-cache` wipes the database
- [ ] Worker pool handles 100+ Crystal files without hanging
- [ ] Worker crash recovery works (respawn + retry)
- [ ] Graceful fallback to sequential extraction on all errors
- [ ] All existing tests pass
- [ ] No regression in analysis results
