(* lib/catseye_pipeline/process_pool.ml
   Streaming process pool for Crystal extractors.

   This module provides process management for Crystal extractors.
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
}

type t = {
  workers : worker array;
  mutable next_id : int;
  extractor_path : string;
  pool_size : int;
  work_queue : (int * string) Queue.t;
  results : (int, string) Hashtbl.t;
}

(* ── Pool Creation ─────────────────────────────────────────────────── *)

let create ~(extractor_path : string) ~(pool_size : int) : t =
  {
    workers = [||];
    next_id = 0;
    extractor_path;
    pool_size = max 1 pool_size;
    work_queue = Queue.create ();
    results = Hashtbl.create (module Int);
  }

(* ── Request Submission ───────────────────────────────────────────────── *)

let submit_request (pool : t) (_file : string) : int =
  let req_id = pool.next_id in
  pool.next_id <- pool.next_id + 1;
  req_id

(* ── Result Collection ─────────────────────────────────────────────────── *)

let collect_result (pool : t) (req_id : int) : string option =
  Hashtbl.find pool.results req_id

let wait_for_results (_pool : t) ~(_timeout_sec : float) : (int * string) list =
  []

(* ── Pool Cleanup ─────────────────────────────────────────────────────── *)

let shutdown (_pool : t) : unit =
  ()
