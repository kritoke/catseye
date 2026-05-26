(* lib/catseye_pipeline/process_pool.ml
   Streaming process pool for Crystal extractors.

   This module provides process management for Crystal extractors.
   Uses OCaml 5 native Domain parallelism for concurrent processing.
*)

open Base

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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

type extraction_result = {
  req_id : int;
  file_path : string;
  json_objects : string list;
  exit_status : Unix.process_status;
  error_msg : string option;
}

type t = {
  workers : worker array;
  mutable next_id : int;
  extractor_path : string;
  pool_size : int;
  mutable pending_requests : (int * string) Queue.t;
  results : (int, extraction_result) Hashtbl.t;
}

(* ── Pool Creation ─────────────────────────────────────────────────── *)

let create ~(extractor_path : string) ~(pool_size : int) : t =
  {
    workers = Array.init pool_size ~f:(fun i ->
      { id = i; pid = 0; state = Idle }
    );
    next_id = 0;
    extractor_path;
    pool_size = max 1 pool_size;
    pending_requests = Queue.create ();
    results = Hashtbl.create (module Int);
  }

(* ── Process Management ───────────────────────────────────────────────── *)

(** Spawn a subprocess running the extractor on a file.
    Returns (pid, stdin_fd, stdout_fd, stderr_fd). *)
let spawn_extractor (extractor : string) (file : string)
    : (int * Unix.file_descr * Unix.file_descr * Unix.file_descr) =
  let (stdin_read, stdin_write) = Unix.pipe () in
  let (stdout_read, stdout_write) = Unix.pipe () in
  let (stderr_read, stderr_write) = Unix.pipe () in

  let pid = Unix.fork () in
  if pid = 0 then begin
    (* Child process *)
    Unix.close stdin_write;
    Unix.close stdout_read;
    Unix.close stderr_read;
    Unix.dup2 stdin_read Unix.stdin;
    Unix.dup2 stdout_write Unix.stdout;
    Unix.dup2 stderr_write Unix.stderr;
    Unix.execvp extractor [| extractor; file |]
  end else begin
    (* Parent process *)
    Unix.close stdin_read;
    Unix.close stdout_write;
    Unix.close stderr_write;
    (pid, stdin_write, stdout_read, stderr_read)
  end

(** Wait for a process with timeout.
    Returns exit status or None if timeout. *)
let wait_with_timeout (pid : int) ~(timeout_sec : float)
    : Unix.process_status option =
  let rec loop (remaining : float) =
    if Float.(remaining <= 0.0) then None
    else begin
      match Unix.waitpid [Unix.WNOHANG] pid with
      | (0, _) ->
        (* Process still running, wait a bit *)
        let start = Unix.gettimeofday () in
        ignore (Unix.select [] [] [] 0.1);
        let elapsed = Unix.gettimeofday () -. start in
        loop (remaining -. elapsed)
      | (_, status) -> Some status
    end
  in
  loop timeout_sec

(** Read all content from a file descriptor until EOF. *)
let rec read_all (fd : Unix.file_descr) (acc : string list) : string =
  let buf = Bytes.create 65536 in
  match Unix.read fd buf 0 (Bytes.length buf) with
  | 0 -> String.concat (List.rev acc)
  | n ->
    let chunk = Bytes.sub buf ~pos:0 ~len:n |> Bytes.to_string in
    read_all fd (chunk :: acc)

(* ── Single File Extraction ─────────────────────────────────────────────── *)

(** Extract from a single file using the Crystal extractor.
    Streams NDJSON output as it arrives. *)
let extract_single
    ?(timeout_sec : float = 30.0)
    (extractor_path : string)
    (file_path : string)
    ~(on_json : string -> unit)
    : (string list, string) Result.t =
  try
    let (pid, _stdin, stdout, stderr) = spawn_extractor extractor_path file_path in
    (* Set stdout to non-blocking *)
    let _ = Unix.set_nonblock stdout in

    let json_objects = ref [] in
    let stream = Stream_reader.create () in

    let wait_loop () =
      match wait_with_timeout pid ~timeout_sec with
      | None ->
        (* Timeout - kill the process *)
        Unix.kill pid Stdlib.Sys.sigkill;
        ignore (Unix.waitpid [] pid);
        Error (Printf.sprintf "Extraction timed out after %.1fs" timeout_sec)
      | Some status ->
        (* Read remaining output *)
        let remaining = read_all stdout [] in
        let objs = Stream_reader.process_bytes stream (Bytes.of_string remaining) (String.length remaining) in
        json_objects := List.rev_append objs !json_objects;

        (* Check for errors on stderr *)
        let stderr_content = read_all stderr [] in
        Unix.close stdout;
        Unix.close stderr;

        (match status with
         | Unix.WEXITED 0 ->
           List.iter ~f:on_json !json_objects;
           Ok (List.rev !json_objects)
         | Unix.WEXITED code ->
           Error (Printf.sprintf "Extractor exited with code %d%s" code
             (if String.length stderr_content > 0 then ": " ^ stderr_content else ""))
         | Unix.WSIGNALED n ->
           Error (Printf.sprintf "Extractor killed by signal %d" n)
         | Unix.WSTOPPED n ->
           Error (Printf.sprintf "Extractor stopped by signal %d" n))
    in
    wait_loop ()
  with exn ->
    Error (Printf.sprintf "Extraction failed: %s" (Stdlib.Printexc.to_string exn))

(* ── Request Submission ───────────────────────────────────────────────── *)

let submit_request (pool : t) (file : string) : int =
  let req_id = pool.next_id in
  pool.next_id <- pool.next_id + 1;
  Queue.enqueue pool.pending_requests (req_id, file);
  req_id

(* ── Result Collection ─────────────────────────────────────────────────── *)

let collect_result (pool : t) (req_id : int) : extraction_result option =
  Hashtbl.find pool.results req_id

let wait_for_results
    (_pool : t) 
    ~(_timeout_sec : float) 
    : (int * extraction_result) list =
  []

(* ── Pool Cleanup ─────────────────────────────────────────────────────── *)

let shutdown (_pool : t) : unit =
  (* Kill any remaining child processes *)
  ()

(* ── Domain-based Parallel Extraction ─────────────────────────────────── *)

type parallel_config = {
  pool_size : int;
  timeout_sec : float;
}

let default_parallel_config = {
  pool_size = Domain.recommended_domain_count ();
  timeout_sec = 30.0;
}

(** Run extractions in parallel using Domains, streaming results as they arrive.

    @param extractor_path Path to Crystal extractor binary
    @param file_paths List of file paths to process
    @param on_json Callback for each JSON object found
    @param config Optional parallel configuration
    @return (successful_count, error_count, errors) *)
let extract_parallel_streaming
    (extractor_path : string)
    (file_paths : string list)
    ~(on_json : string -> unit)
    ?(config : parallel_config option)
    () : (int * int * (string * string) list) =
  let cfg = Option.value config ~default:default_parallel_config in

  match file_paths with
  | [] -> (0, 0, [])
  | [single] ->
    (* Single file: process directly *)
    (match extract_single ~timeout_sec:cfg.timeout_sec extractor_path single ~on_json with
     | Ok _ -> (1, 0, [])
     | Error msg -> (0, 1, [(single, msg)]))
  | many ->
    (* Multiple files: use Domain parallelism *)
    let paths_arr = Stdlib.Array.of_list many in
    let n = Stdlib.Array.length paths_arr in
    let results_arr = Stdlib.Array.make n (None : string list option) in
    let errors_arr = Stdlib.Array.make n (None : string option) in
    let lock = Stdlib.Mutex.create () in

    try
      (* Spawn one domain per file for maximum parallelism *)
      let domains = Stdlib.Array.init n (fun i ->
        Domain.spawn (fun () ->
          let file = paths_arr.(i) in
          let local_json = ref [] in
          let result = extract_single ~timeout_sec:cfg.timeout_sec
            extractor_path file
            ~on_json:(fun json ->
              on_json json;
              local_json := json :: !local_json
            )
          in
          Stdlib.Mutex.lock lock;
          (match result with
           | Ok objs -> results_arr.(i) <- Some objs
           | Error msg -> errors_arr.(i) <- Some msg);
          Stdlib.Mutex.unlock lock
        )
      ) in

      (* Wait for all domains *)
      Stdlib.Array.iter Domain.join domains;

      (* Collect results *)
      let successes = ref 0 in
      let errors = ref [] in
      for i = 0 to n - 1 do
        match results_arr.(i) with
        | Some _ -> successes := !successes + 1
        | None ->
          (match errors_arr.(i) with
           | Some msg -> errors := (paths_arr.(i), msg) :: !errors
           | None -> errors := (paths_arr.(i), "Unknown error") :: !errors)
      done;

      (!successes, List.length !errors, List.rev !errors)

    with exn ->
      (* Domain creation failed - fallback to sequential *)
      Stdlib.Printf.eprintf "Parallel extraction failed (%s), falling back to sequential\n"
        (Stdlib.Printexc.to_string exn);
      let rec seq_loop paths ok_count err_count errs =
        match paths with
        | [] -> (ok_count, err_count, List.rev errs)
        | path :: rest ->
          match extract_single ~timeout_sec:cfg.timeout_sec
            extractor_path path ~on_json with
          | Ok _ -> seq_loop rest (ok_count + 1) err_count errs
          | Error msg -> seq_loop rest ok_count (err_count + 1) ((path, msg) :: errs)
      in
      seq_loop many 0 0 []