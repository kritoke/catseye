(* lib/catseye_engine/worker_pool.ml
   Crystal worker pool — manages persistent Crystal extractor processes.
   
   Workers communicate via NDJSON over stdin/stdout. The pool distributes
   extraction requests round-robin and collects results.
   
   Usage:
     let pool = Worker_pool.create "bin/catseye-crystal-extractor" 4 in
     let nodes = Worker_pool.extract pool "src/foo.cr" in
     Worker_pool.shutdown pool
*)

open Catseye_types

(* ── Protocol types ──────────────────────────────────────────────────── *)

type worker = {
  id : int;
  worker_stdin : out_channel;
  worker_stdout : in_channel;
}

type t = {
  workers : worker array;
  mutable next_req_id : int;
  extractor_path : string;
}

(* ── Response decoding ──────────────────────────────────────────────── *)

let decode_response (json_str : string) : (int * Security_node.t list option) =
  try
    let json = Yojson.Safe.from_string json_str in
    let dict = match json with `Assoc d -> d | _ -> [] in
    let id_val = match List.assoc_opt "id" dict with
      | Some (`Int i) -> i
      | _ -> -1
    in
    let status = match List.assoc_opt "status" dict with
      | Some (`String s) -> s
      | _ -> "error"
    in
    if status = "ok" then begin
      match List.assoc_opt "nodes" dict with
      | Some (`List nodes_json) ->
        let nodes = List.filter_map (fun nj ->
          try Some (Security_node.decode nj)
          with _ -> None
        ) nodes_json in
        (id_val, Some nodes)
      | _ -> (id_val, None)
    end else
      (id_val, None)
  with _ -> (-1, None)

(* ── Worker lifecycle ───────────────────────────────────────────────── *)

(** Spawn a single Crystal worker process in --serve mode. *)
let spawn_worker (extractor_path : string) (worker_id : int) : worker =
  let cmd = Printf.sprintf "%s --serve 2>/dev/null"
    (Filename.quote extractor_path) in
  (* Use pipe + fork instead of open_process_full to avoid stderr pipe deadlock.
     open_process_full creates a stderr pipe that must be drained; if the child
     writes enough to stderr, the pipe buffer fills and the child blocks forever.
     By using fork+execv and closing stderr ourselves, we eliminate this entirely. *)
  let stdin_r, stdin_w = Unix.pipe () in
  let stdout_r, stdout_w = Unix.pipe () in
  let pid = Unix.fork () in
  if pid = 0 then begin
    (* Child process *)
    Unix.dup2 stdin_r Unix.stdin;
    Unix.dup2 stdout_w Unix.stdout;
    Unix.close Unix.stderr;  (* Close stderr → /dev/null *)
    Unix.close stdin_r; Unix.close stdin_w;
    Unix.close stdout_r; Unix.close stdout_w;
    Unix.execv "/bin/sh" [| "/bin/sh"; "-c"; cmd |]
  end;
  (* Parent *)
  Unix.close stdin_r; Unix.close stdout_w;
  let proc_stdin = Unix.out_channel_of_descr stdin_w in
  let proc_stdout = Unix.in_channel_of_descr stdout_r in
  { id = worker_id; worker_stdin = proc_stdin; worker_stdout = proc_stdout }

(** Create a pool of N workers. *)
let create (extractor_path : string) (pool_size : int) : t =
  let size = max 1 pool_size in
  let workers = Array.init size (spawn_worker extractor_path) in
  { workers; next_req_id = 0; extractor_path }

(** Send a request to a specific worker. *)
let send_request (w : worker) (req_id : int) (file : string) : unit =
  let json = Printf.sprintf
    "{\"id\":%d,\"method\":\"extract\",\"file\":%s,\"content\":null}"
    req_id (Yojson.Safe.to_string (`String file)) in
  output_string w.worker_stdin json;
  output_char w.worker_stdin '\n';
  flush w.worker_stdin

(** Read a single NDJSON response line from a persistent --serve worker.
    Each request produces exactly one JSON line; the worker stays alive
    afterwards, so we must NOT read until EOF. *)
let read_response (w : worker) : (int * Security_node.t list option) =
  try
    let line = input_line w.worker_stdout in
    if line = "" then (-1, None)
    else (try decode_response line with _ -> (-1, None))
  with End_of_file -> (-1, None)

(** Extract a single file via the pool (round-robin). *)
let extract (pool : t) (file : string) : Security_node.t list option =
  let req_id = pool.next_req_id in
  pool.next_req_id <- pool.next_req_id + 1;
  let worker = pool.workers.(req_id mod Array.length pool.workers) in
  send_request worker req_id file;
  let (_resp_id, nodes) = read_response worker in
  nodes

(** Respawn a crashed worker. *)
let respawn (pool : t) (worker_id : int) : unit =
  let old = pool.workers.(worker_id) in
  (try close_in old.worker_stdout with _ -> ());
  (try close_out old.worker_stdin with _ -> ());
  pool.workers.(worker_id) <- spawn_worker pool.extractor_path worker_id

(** Extract with automatic crash recovery. Retries once on failure. *)
let extract_with_recovery (pool : t) (file : string) : Security_node.t list option =
  let req_id = pool.next_req_id in
  pool.next_req_id <- pool.next_req_id + 1;
  let idx = req_id mod Array.length pool.workers in
  let worker = pool.workers.(idx) in
  send_request worker req_id file;
  match read_response worker with
  | (-1, None) ->
    (* Worker likely crashed — respawn and retry *)
    Logs.warn (fun m -> m "Worker %d crashed on %s, respawning" idx file);
    respawn pool idx;
    let worker = pool.workers.(idx) in
    send_request worker req_id file;
    snd (read_response worker)
  | (_, nodes) -> nodes

(** Shutdown all workers gracefully. *)
let shutdown (pool : t) : unit =
  Array.iter (fun w ->
    (try
      output_string w.worker_stdin "{\"id\":0,\"method\":\"shutdown\"}\n";
      flush w.worker_stdin
    with _ -> ());
    (try close_in w.worker_stdout with _ -> ());
    (try close_out w.worker_stdin with _ -> ())
  ) pool.workers
