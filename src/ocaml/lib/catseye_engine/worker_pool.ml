(* lib/catseye_engine/worker_pool.ml
   Crystal worker pool — manages persistent Crystal extractor processes.
   
   Workers communicate via NDJSON over stdin/stdout. The pool distributes
   extraction requests round-robin and collects results.
   
   Usage:
     let pool = Worker_pool.create "bin/catseye-crystal-extractor" 4 in
     let nodes = Worker_pool.extract pool "src/foo.cr" in
     Worker_pool.shutdown pool
*)

open Base
open Catseye_types
let ( = ) = Stdlib.( = )

let string_prefix s ~prefix =
  let plen = Stdlib.String.length prefix in
  if Stdlib.String.length s < plen then false
  else Stdlib.String.sub s 0 plen = prefix

(* Read raw bytes from a file descriptor, gated by Unix.select to avoid
   OCaml 5 fast I/O race conditions where the read loop starts before
   the child process is fully registered in the OS process table. *)
let read_with_select (fd : Unix.file_descr) (buf : bytes) : int =
  let (ready, _, _) = Unix.select [fd] [] [] 5.0 in
  if List.is_empty ready then 0  (* Timeout *)
  else Unix.read fd buf 0 (Bytes.length buf)

(* ── Protocol types ──────────────────────────────────────────────────── *)

type worker = {
  id : int;
  worker_stdin : Stdlib.out_channel;
  worker_stdout : Stdlib.in_channel;
  worker_stdout_fd : Unix.file_descr;  (* Raw fd for select() *)
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
    let id_val = match Stdlib.List.assoc_opt "id" dict with
      | Some (`Int i) -> i
      | _ -> -1
    in
    let status = match Stdlib.List.assoc_opt "status" dict with
      | Some (`String s) -> s
      | _ -> "error"
    in
    if status = "ok" then begin
      match Stdlib.List.assoc_opt "nodes" dict with
      | Some (`List nodes_json) ->
        let nodes = List.filter_map ~f:(fun nj ->
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
  let cmd = Stdlib.Printf.sprintf "%s --serve 2>/dev/null"
    (Stdlib.Filename.quote extractor_path) in
  (* Use pipe + fork instead of open_process_full to avoid stderr pipe deadlock.
     open_process_full creates a stderr pipe that must be drained; if the child
     writes enough to stderr, the pipe buffer fills and the child blocks forever.
     By using fork+execv and closing stderr ourselves, we eliminate this entirely. *)
  let stdin_r, stdin_w = Unix.pipe () in
  let stdout_r, stdout_w = Unix.pipe () in
  (* CRITICAL: Set close_on_exec on ALL pipe ends before fork to prevent
     file descriptor leaks or accidental inheritance in child processes. *)
  Unix.set_close_on_exec stdin_r;
  Unix.set_close_on_exec stdin_w;
  Unix.set_close_on_exec stdout_r;
  Unix.set_close_on_exec stdout_w;
  let pid = Unix.fork () in
  if pid = 0 then begin
    (* Child process *)
    (* Ignore SIGPIPE in child so writes to closed pipe don't kill us *)
    let (_ : Stdlib.Sys.signal_behavior) = Stdlib.Sys.signal Stdlib.Sys.sigpipe Stdlib.Sys.Signal_ignore in
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
  { id = worker_id; worker_stdin = proc_stdin; worker_stdout = proc_stdout; worker_stdout_fd = stdout_r }

(** Create a pool of N workers. *)
let create (extractor_path : string) (pool_size : int) : t =
  let size = max 1 pool_size in
  let workers = Stdlib.Array.init size (spawn_worker extractor_path) in
  { workers; next_req_id = 0; extractor_path }

(* ── Request/Response protocol ───────────────────────────────────────── *)

(** Send a request to a specific worker. *)
let send_request (w : worker) (req_id : int) (file : string) : unit =
  let json = Stdlib.Printf.sprintf
    "{\"id\":%d,\"method\":\"extract\",\"file\":%s,\"content\":null}"
    req_id (Yojson.Safe.to_string (`String file)) in
  let oc = w.worker_stdin in
  (try
    Stdlib.output_string oc json;
    Stdlib.output_char oc '\n';
    Stdlib.flush oc
  with
  (* Handle EPIPE/Broken pipe — worker died mid-request *)
  | Sys_error msg when string_prefix msg ~prefix:"Broken pipe" ->
    Logs.warn (fun m -> m "Worker %d EPIPE on flush" w.id);
    raise (Stdlib.Failure "Worker EPIPE")
  | Sys_error msg when string_prefix msg ~prefix:"Write failed" ->
    Logs.warn (fun m -> m "Worker %d write failed" w.id);
    raise (Stdlib.Failure "Worker write failed")
  | exn ->
    raise exn)

(** Read a single NDJSON response line from a persistent --serve worker.
    Uses Unix.select to avoid OCaml 5 fast I/O races. *)
let read_response (w : worker) : (int * Security_node.t list option) =
  let buf = Bytes.create 8192 in
  let buffer = Stdlib.Buffer.create 8192 in
  let rec read_until_newline () =
    (* Use the stored raw fd for select() *)
    let fd = w.worker_stdout_fd in
    let n = read_with_select fd buf in
    if n = 0 then begin
      (* Timeout or EOF *)
      let content = Stdlib.Buffer.contents buffer in
      if content = "" then (-1, None)
      else (try decode_response content with _ -> (-1, None))
    end else begin
      (* Got data — append to buffer and look for newline *)
      Stdlib.Buffer.add_subbytes buffer buf 0 n;
      let content = Stdlib.Buffer.contents buffer in
      match Stdlib.String.index_opt content '\n' with
      | Some pos ->
        let line = Stdlib.String.sub content 0 pos in
        if Stdlib.String.length content > pos + 1 then begin
          (* More data after newline — keep it for next response *)
          Stdlib.Buffer.clear buffer;
          Stdlib.Buffer.add_string buffer (Stdlib.String.sub content (pos + 1) (Stdlib.String.length content - pos - 1))
        end;
        (try decode_response line with _ -> (-1, None))
      | None -> read_until_newline ()
    end
  in
  try read_until_newline ()
  with Stdlib.End_of_file -> 
    (-1, None)

(** Extract a single file via the pool (round-robin). *)
let extract (pool : t) (file : string) : Security_node.t list option =
  let req_id = pool.next_req_id in
  pool.next_req_id <- pool.next_req_id + 1;
  let idx = Int.rem req_id (Stdlib.Array.length pool.workers) in
  let worker = pool.workers.(idx) in
  send_request worker req_id file;
  let (_resp_id, nodes) = read_response worker in
  nodes

(** Respawn a crashed worker. *)
let respawn (pool : t) (worker_id : int) : unit =
  let old = pool.workers.(worker_id) in
  (try Unix.close old.worker_stdout_fd with _ -> ());
  (try Stdlib.close_in old.worker_stdout with _ -> ());
  (try Stdlib.close_out old.worker_stdin with _ -> ());
  pool.workers.(worker_id) <- spawn_worker pool.extractor_path worker_id

(* Check if an exception is a worker death signal *)
let is_worker_death (exn : exn) : bool =
  let msg = Stdlib.Printexc.to_string exn in
  msg = "Worker EPIPE" || msg = "Worker write failed" || msg = "Worker dead"

(** Extract with automatic crash recovery. Retries once on failure. *)
let extract_with_recovery (pool : t) (file : string) : Security_node.t list option =
  let req_id = pool.next_req_id in
  pool.next_req_id <- pool.next_req_id + 1;
  let idx = Int.rem req_id (Stdlib.Array.length pool.workers) in
  let worker = pool.workers.(idx) in
  (try
    send_request worker req_id file;
    match read_response worker with
    | (-1, None) ->
      Logs.warn (fun m -> m "Worker %d crashed on %s, respawning" idx file);
      respawn pool idx;
      let worker = pool.workers.(idx) in
      send_request worker req_id file;
      snd (read_response worker)
    | (_, nodes) ->
      nodes
  with exn ->
    let msg = Stdlib.Printexc.to_string exn in
    if is_worker_death exn then begin
      (* Worker died while writing - respawn and retry once *)
      Logs.warn (fun m -> m "Worker %d died (EPIPE), respawning" idx);
      respawn pool idx;
      let worker = pool.workers.(idx) in
      (try
        send_request worker req_id file;
        snd (read_response worker)
      with exn ->
        Logs.err (fun m -> m "Worker %d still dead after respawn: %s" idx (Stdlib.Printexc.to_string exn));
        None)
    end else begin
      Logs.err (fun m -> m "Worker pool extract error: %s" msg);
      None
    end)

(** Shutdown all workers gracefully. *)
let shutdown (pool : t) : unit =
  Stdlib.Array.iter (fun w ->
    (try
      Stdlib.output_string w.worker_stdin "{\"id\":0,\"method\":\"shutdown\"}\n";
      Stdlib.flush w.worker_stdin
    with _ -> ());
    (try Stdlib.close_in w.worker_stdout with _ -> ());
    (try Stdlib.close_out w.worker_stdin with _ -> ())
  ) pool.workers
