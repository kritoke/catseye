(* lib/catseye_pipeline/process_pool.ml
   Streaming process pool for Crystal extractors using Core_unix.

   This module provides non-blocking async process management with
   persistent workers. It streams JSON bytes as Crystal emits them,
   allowing on-the-fly CFG construction before the full file is read.

   Uses OCaml 5 native Domain parallelism for concurrent processing.
*)

open Base
open Core

(* ── Worker Types ────────────────────────────────────────────────────── *)

type worker_state =
  | Idle
  | Busy of { request_id : int; file : string; }
  | Dead

type worker = {
  id : int;
  pid : int;                    (* OS process ID for monitoring *)
  mutable state : worker_state;
  stdin : Core_unix.IO.descr;    (* Core_unix async IO *)
  stdout : Core_unix.IO.descr;
  stderr : Core_unix.IO.descr;
}

type t = {
  workers : worker array;
  mutable next_id : int;
  extractor_path : string;
  pool_size : int;
  work_queue : (int * string) Queue.t;  (* request_id * file_path *)
  results : (int, string) Hashtbl.t;     (* request_id -> response_json *)
}

(* ── Core_unix Process Creation ───────────────────────────────────────── *)

(** Spawn a Crystal worker using Core_unix.
    Returns (stdin, stdout, pid) for async I/O operations. *)
let spawn_worker (extractor_path : string) (worker_id : int) 
    : (Core_unix.IO.descr * Core_unix.IO.descr * int) =
  let cmd = Printf.sprintf "%s --serve 2>/dev/null" 
    (Filename.quote extractor_path) in
  
  (* Create pipes using Core_unix *)
  let stdin_r, stdin_w = Core_unix.pipe ~cloexec:true () in
  let stdout_r, stdout_w = Core_unix.pipe ~cloexec:true () in
  let stderr_r, stderr_w = Core_unix.pipe ~cloexec:true () in
  
  match Core_unix.fork () with
  | 0 -> 
    (* Child process *)
    let (_ : Sys.signal_behavior) = Sys.signal Sys.sigpipe Sys.Signal_ignore in
    
    (* Redirect stdin/stdout/stderr *)
    Core_unix.dup2 ~src:stdin_r ~dst:Core_unix.stdin ();
    Core_unix.dup2 ~src:stdout_w ~dst:Core_unix.stdout ();
    Core_unix.dup2 ~src:stderr_w ~dst:Core_unix.stderr ();
    
    (* Close pipe ends in child *)
    Core_unix.close stdin_r; Core_unix.close stdin_w;
    Core_unix.close stdout_r; Core_unix.close stdout_w;
    Core_unix.close stderr_r; Core_unix.close stderr_w;
    
    (* Execute via shell *)
    Core_unix.execv "/bin/sh" [| "/bin/sh"; "-c"; cmd |];
    (* Never returns *)
    assert false
  | pid ->
    (* Parent process *)
    Core_unix.close stdin_r;
    Core_unix.close stdout_w;
    Core_unix.close stderr_r;
    Core_unix.close stderr_w;  (* stderr to /dev/null */
    
    (stdin_w, stdout_r, pid)

(* ── Pool Management ─────────────────────────────────────────────────── *)

let create ~(extractor_path : string) ~(pool_size : int) : t =
  let size = max 1 pool_size in
  let workers = Array.init size (fun i ->
    let stdin, stdout, pid = spawn_worker extractor_path i in
    {
      id = i;
      pid;
      state = Idle;
      stdin;
      stdout;
      stderr = Core_unix.stdout;  (* placeholder *)
    }
  ) in
  {
    workers;
    next_id = 0;
    extractor_path;
    pool_size = size;
    work_queue = Queue.create ();
    results = Hashtbl.create (module Int);
  }

(* ── Request Submission ───────────────────────────────────────────────── *)

let submit_request (pool : t) (file : string) : int =
  let req_id = pool.next_id in
  pool.next_id <- pool.next_id + 1;
  
  (* Find an idle worker (round-robin) *)
  let idx = Int.rem req_id pool.pool_size in
  let worker = pool.workers.(idx) in
  
  (* Build JSON request *)
  let json = Printf.sprintf 
    "{\"id\":%d,\"method\":\"extract\",\"file\":\"%s\",\"content\":null}\n"
    req_id file
  in
  
  (* Update worker state *)
  worker.state <- Busy { request_id = req_id; file };
  
  (* Send request asynchronously *)
  (try
    let bytes = Bytes.of_string json in
    Core_unix.write_retry pool.workers.(idx).stdin bytes
    |> ignore
  with _ -> 
    worker.state <- Dead);
  
  req_id

(* ── Response Reading ────────────────────────────────────────────────── *)

(** Read a single NDJSON line from a worker's stdout.
    Uses Core_unix.select for non-blocking IO. *)
let read_response (worker : worker) : (int * string option) =
  let buf = Bytes.create 8192 in
  let buffer = Buffer.create 8192 in
  
  let rec read_loop () =
    let ready, _, _ = Core_unix.select [worker.stdout] [] [] 5.0 in
    if List.is_empty ready then begin
      (* Timeout - return partial buffer if any *)
      let content = Buffer.contents buffer in
      if String.is_empty content then (-1, None)
      else (try parse_response content with _ -> (-1, None))
    end else begin
      let n = Core_unix.read worker.stdout buf 0 (Bytes.length buf) in
      if n = 0 then begin
        (* EOF *)
        let content = Buffer.contents buffer in
        if String.is_empty content then (-1, None)
        else (try parse_response content with _ -> (-1, None))
      end else begin
        Buffer.add_subbytes buffer buf 0 n;
        let content = Buffer.contents buffer in
        
        (* Look for newline *)
        match String.index_opt content '\n' with
        | Some pos ->
          let line = String.sub content ~pos:0 ~len:pos in
          (try parse_response line with _ -> (-1, None))
        | None -> read_loop ()
      end
    end
  and parse_response json_str =
    try
      let json = Yojson.Safe.from_string json_str in
      let dict = match json with `Assoc d -> d | _ -> [] in
      let id = match List.assoc_opt "id" dict with
        | Some (`Int i) -> i
        | _ -> -1
      in
      (id, Some json_str)
    with _ -> (-1, None)
  in
  read_loop ()

(* ── Domain-based Parallel Processing ─────────────────────────────────── *)

(** Process a batch of files using Domain parallelism.
    Each Domain processes a subset of files through the pool. *)
let process_batch 
    (pool : t) 
    (files : string list) 
    ~(num_domains : int) 
    : (int * string) list =  (* (req_id, response) pairs *)
  
  let arr = Array.of_list files in
  let n = Array.length arr in
  
  if n = 0 then []
  else if n = 1 then
    (* Single file: no domain overhead *)
    let req_id = submit_request pool arr.(0) in
    match read_response pool.workers.(0) with
    | (_, Some response) -> [req_id, response]
    | _ -> []
  else
    (* Multiple files: use Domain parallelism *)
    let results = Array.make n "" in
    let errors = Array.make n false in
    
    let domains =
      Array.init num_domains (fun d_idx ->
        let start = (n * d_idx) / num_domains in
        let end_ = (n * (d_idx + 1)) / num_domains in
        
        Domain.spawn (fun () ->
          for i = start to end_ - 1 do
            let req_id = submit_request pool arr.(i) in
            match read_response pool.workers.(d_idx) with
            | (_, Some response) -> results.(i) <- response
            | _ -> errors.(i) <- true
          done
        )
      )
    in
    
    (* Join all domains *)
    Array.iter Domain.join domains;
    
    (* Collect results *)
    let rec collect i acc =
      if i >= n then List.rev acc
      else if not errors.(i) && String.length results.(i) > 0 then
        collect (i + 1) ((i, results.(i)) :: acc)
      else
        collect (i + 1) acc
    in
    collect 0 []

(* ── Worker Health Monitoring ────────────────────────────────────────── *)

(** Check if a worker is still alive using waitpid WNOHANG. *)
let is_alive (worker : worker) : bool =
  match Core_unix.waitpid [Core_unix.WNOHANG] worker.pid with
  | (0, _) -> true   (* Still running *)
  | _ -> false       (* Died or zombie *)

(** Respawn a dead worker. *)
let respawn_worker (pool : t) (worker_id : int) : unit =
  let old = pool.workers.(worker_id) in
  
  (* Clean up old fds *)
  (try Core_unix.close old.stdin with _ -> ());
  (try Core_unix.close old.stdout with _ -> ());
  
  (* Spawn new worker *)
  let stdin, stdout, pid = spawn_worker pool.extractor_path worker_id in
  pool.workers.(worker_id) <- {
    id = worker_id;
    pid;
    state = Idle;
    stdin;
    stdout;
    stderr = Core_unix.stdout;
  }
  
(* ── Shutdown ────────────────────────────────────────────────────────── *)

(** Shutdown all workers and clean up resources. *)
let shutdown (pool : t) : unit =
  Array.iter (fun worker ->
    (try
      let json = "{\"id\":0,\"method\":\"shutdown\"}\n" in
      let bytes = Bytes.of_string json in
      Core_unix.write_retry worker.stdin bytes |> ignore
    with _ -> ());
    
    (* Close fds *)
    (try Core_unix.close worker.stdin with _ -> ());
    (try Core_unix.close worker.stdout with _ -> ());
    
    (* Wait for process *)
    (try Core_unix.waitpid [] worker.pid |> ignore with _ -> ())
  ) pool.workers

(* ── Version ──────────────────────────────────────────────────────────── *)

let version = "0.1.0"