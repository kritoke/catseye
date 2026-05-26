(* lib/catseye_pipeline/process_pool.ml
   Streaming process pool for Crystal extractors.

   This module provides async process management with
   persistent workers. It streams JSON bytes as Crystal emits them,
   allowing on-the-fly CFG construction before the full file is read.

   Uses OCaml 5 native Domain parallelism for concurrent processing.
*)

open Base

(* ── Worker Types ────────────────────────────────────────────────────── *)

type worker_state =
  | Idle
  | Busy of { request_id : int; file : string; }
  | Dead

type worker = {
  id : int;
  pid : int;
  mutable state : worker_state;
  stdin : Unix.file_descr;
  stdout : Unix.file_descr;
  stderr : Unix.file_descr;
}

type t = {
  workers : worker array;
  mutable next_id : int;
  extractor_path : string;
  pool_size : int;
  work_queue : (int * string) Queue.t;
  results : (int, string) Hashtbl.t;
}

(* ── Process Creation ───────────────────────────────────────────────── *)

let spawn_worker (extractor_path : string) (worker_id : int) 
    : (Unix.file_descr * Unix.file_descr * int) =
  let cmd = Printf.sprintf "%s --serve 2>/dev/null" 
    (Filename.quote extractor_path) in
  
  let stdin_r, stdin_w = Unix.pipe () in
  let stdout_r, stdout_w = Unix.pipe () in
  let stderr_r, stderr_w = Unix.pipe () in
  
  Unix.set_close_on_exec stdin_r;
  Unix.set_close_on_exec stdin_w;
  Unix.set_close_on_exec stdout_r;
  Unix.set_close_on_exec stdout_w;
  
  match Unix.fork () with
  | 0 -> 
    let (_ : Stdlib.Sys.signal_behavior) = Stdlib.Sys.signal Stdlib.Sys.sigpipe Stdlib.Sys.Signal_ignore in
    
    Unix.dup2 stdin_r Unix.stdin;
    Unix.dup2 stdout_w Unix.stdout;
    Unix.dup2 stderr_w Unix.stderr;
    
    Unix.close stdin_r; Unix.close stdin_w;
    Unix.close stdout_r; Unix.close stdout_w;
    Unix.close stderr_r; Unix.close stderr_w;
    
    Unix.execv "/bin/sh" [| "/bin/sh"; "-c"; cmd |];
    assert false
  | pid ->
    Unix.close stdin_r;
    Unix.close stdout_w;
    Unix.close stderr_r;
    Unix.close stderr_w;
    
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
      stderr = Unix.stdout;
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
  
  let idx = Int.rem req_id pool.pool_size in
  let worker = pool.workers.(idx) in
  
  let json = Printf.sprintf 
    "{\"id\":%d,\"method\":\"extract\",\"file\":\"%s\",\"content\":null}\n"
    req_id file
  in
  
  worker.state <- Busy { request_id = req_id; file };
  
  (try
    let bytes = Bytes.of_string json in
    ignore (Unix.write worker.stdin bytes 0 (Bytes.length bytes))
  with _ -> 
    worker.state <- Dead);
  
  req_id

(* ── Response Reading ────────────────────────────────────────────────── *)

let read_response (worker : worker) : (int * string option) =
  let buf = Bytes.create 8192 in
  let buffer = Buffer.create 8192 in
  
  let rec read_loop () =
    let ready, _, _ = Unix.select [worker.stdout] [] [] 5.0 in
    if List.is_empty ready then begin
      let content = Buffer.contents buffer in
      if String.is_empty content then (-1, None)
      else (try parse_response content with _ -> (-1, None))
    end else begin
      let n = Unix.read worker.stdout buf 0 (Bytes.length buf) in
      if n = 0 then begin
        let content = Buffer.contents buffer in
        if String.is_empty content then (-1, None)
        else (try parse_response content with _ -> (-1, None))
      end else begin
        Buffer.add_subbytes buffer buf 0 n;
        let content = Buffer.contents buffer in
        
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

let process_batch 
    (pool : t) 
    (files : string list) 
    ~(num_domains : int) 
    : (int * string) list =
  
  let arr = Array.of_list files in
  let n = Array.length arr in
  
  if n = 0 then []
  else if n = 1 then
    let req_id = submit_request pool arr.(0) in
    match read_response pool.workers.(0) with
    | (_, Some response) -> [req_id, response]
    | _ -> []
  else
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
    
    Array.iter Domain.join domains;
    
    let rec collect i acc =
      if i >= n then List.rev acc
      else if not errors.(i) && String.length results.(i) > 0 then
        collect (i + 1) ((i, results.(i)) :: acc)
      else
        collect (i + 1) acc
    in
    collect 0 []

(* ── Worker Health Monitoring ────────────────────────────────────────── *)

let is_alive (worker : worker) : bool =
  match Unix.waitpid [Unix.WNOHANG] worker.pid with
  | (0, _) -> true
  | _ -> false

let respawn_worker (pool : t) (worker_id : int) : unit =
  let old = pool.workers.(worker_id) in
  
  (try Unix.close old.stdin with _ -> ());
  (try Unix.close old.stdout with _ -> ());
  
  let stdin, stdout, pid = spawn_worker pool.extractor_path worker_id in
  pool.workers.(worker_id) <- {
    id = worker_id;
    pid;
    state = Idle;
    stdin;
    stdout;
    stderr = Unix.stdout;
  }
  
(* ── Shutdown ────────────────────────────────────────────────────────── *)

let shutdown (pool : t) : unit =
  Array.iter (fun worker ->
    (try
      let json = "{\"id\":0,\"method\":\"shutdown\"}\n" in
      let bytes = Bytes.of_string json in
      ignore (Unix.write worker.stdin bytes 0 (Bytes.length bytes))
    with _ -> ());
    
    (try Unix.close worker.stdin with _ -> ());
    (try Unix.close worker.stdout with _ -> ());
    
    (try ignore (Unix.waitpid [] worker.pid) with _ -> ())
  ) pool.workers

(* ── Version ──────────────────────────────────────────────────────────── *)

let version = "0.1.0"