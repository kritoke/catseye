(* lib/catseye_pipeline/stream_reader.ml
   Async byte stream reader for incremental JSON parsing.

   This module provides streaming JSON parsing for Crystal NDJSON output.
   It allows CFG construction on-the-fly as bytes stream from subprocess,
   before the full file is read.
*)

open Base

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* ── Stream State ─────────────────────────────────────────────────────── *)

type stream_state =
  | Awaiting_frame
  | In_frame
  | Newline_found
  | EOF_reached

type t = {
  buffer : Buffer.t;
  mutable state : stream_state;
  mutable depth : int;
  mutable lines_emitted : int;
  mutable bytes_read : int;
}

(* ── Initialization ─────────────────────────────────────────────────── *)

let create ?(initial_size : int = 16384) () : t =
  {
    buffer = Buffer.create initial_size;
    state = Awaiting_frame;
    depth = 0;
    lines_emitted = 0;
    bytes_read = 0;
  }

let reset (s : t) : unit =
  Buffer.clear s.buffer;
  s.state <- Awaiting_frame;
  s.depth <- 0;
  s.lines_emitted <- 0;
  s.bytes_read <- 0

(* ── Byte Processing ─────────────────────────────────────────────────── *)

(* Process a chunk of bytes into the stream.
   Returns list of complete JSON objects found. *)
let rec process_bytes (s : t) (chunk : bytes) (len : int) : string list =
  s.bytes_read <- s.bytes_read + len;
  let rec process_chars i results =
    if i >= len then results
    else begin
      let c = Bytes.get chunk i in
      let (new_results, new_state, new_depth) = 
        process_char s c s.state s.depth
      in
      s.state <- new_state;
      s.depth <- new_depth;
      process_chars (i + 1) (List.append results new_results)
    end
  in
  process_chars 0 []

and process_char (s : t) (c : char) (state : stream_state) (depth : int) 
    : (string list * stream_state * int) =
  match state with
  | Awaiting_frame ->
    (match c with
     | '{' | '[' as start ->
       Buffer.add_char s.buffer start;
       ([], In_frame, depth + 1)
     | ' ' | '\t' | '\r' ->
       ([], Awaiting_frame, depth)
     | '\n' ->
       ([], Awaiting_frame, depth)
     | _ ->
       Buffer.add_char s.buffer c;
       ([], In_frame, depth + 1))
  | In_frame ->
    (match c with
     | '{' | '[' as start ->
       Buffer.add_char s.buffer start;
       ([], In_frame, depth + 1)
     | '}' | ']' as end_char ->
       Buffer.add_char s.buffer end_char;
       let new_depth = depth - 1 in
       if new_depth = 0 then
         ([], Newline_found, 0)
       else
         ([], In_frame, new_depth)
     | '\n' when depth = 0 ->
       ([], Newline_found, 0)
     | _ ->
       Buffer.add_char s.buffer c;
       ([], In_frame, depth))
  | Newline_found ->
    let content = Buffer.contents s.buffer in
    Buffer.clear s.buffer;
    s.lines_emitted <- s.lines_emitted + 1;
    ([content], Awaiting_frame, 0)
  | EOF_reached ->
    ([], EOF_reached, 0)

(* ── Line Splitting ───────────────────────────────────────────────────── *)

let split_lines (content : string) : (string list * string) =
  let lines = String.split content ~on:'\n' in
  let rec split acc = function
    | [] -> (List.rev acc, "")
    | [last] -> (List.rev acc, last)
    | line :: rest -> split (line :: acc) rest
  in
  split [] lines

(* ── Stream from file descriptor ─────────────────────────────────────── *)

(** Read available bytes from a file descriptor (non-blocking).
    Returns empty bytes if no data available yet. *)
let read_available (fd : Unix.file_descr) (buf : bytes) : int =
  try
    Unix.read fd buf 0 (Bytes.length buf)
  with Unix.Unix_error (Unix.EAGAIN, _, _) ->
    0

(** Stream-process an NDJSON source, calling on_json for each complete object.
    Returns total bytes and objects processed. *)
let stream_from_fd 
    (fd : Unix.file_descr) 
    ~(on_json : string -> unit)
    ?(buf_size : int = 65536)
    () : (int * int) =
  let stream = create ~initial_size:buf_size () in
  let buf = Bytes.create buf_size in
  let total_bytes = ref 0 in
  let total_objects = ref 0 in
  
  let rec loop () =
    let n = read_available fd buf in
    if n > 0 then begin
      total_bytes := !total_bytes + n;
      let json_objects = process_bytes stream buf n in
      List.iter ~f:(fun json ->
        on_json json;
        total_objects := !total_objects + 1
      ) json_objects;
      loop ()
    end
  in
  
  loop ();
  (!total_bytes, !total_objects)

(* ── Stats ────────────────────────────────────────────────────────────── *)

let bytes_read (s : t) = s.bytes_read
let lines_emitted (s : t) = s.lines_emitted
let current_state (s : t) = s.state