(* lib/catseye_pipeline/stream_reader.ml
   Async byte stream reader for incremental JSON parsing.

   This module provides streaming JSON parsing for Crystal NDJSON output.
   It allows CFG construction on-the-fly as bytes stream from subprocess,
   before the full file is read.
*)

open Base

(* ── Stream State Machine ────────────────────────────────────────────── *)

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
  bytes_read : int;
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
  s.lines_emitted <- 0

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
      process_chars (i + 1) (results @ new_results)
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
    if c = '{' || c = '[' then
      (Buffer.add_char s.buffer c;
       ([content], In_frame, 1))
    else if c = '\n' || c = ' ' || c = '\t' then
      ([content], Awaiting_frame, 0)
    else
      ([content], Awaiting_frame, 0)
  | EOF_reached ->
    ([], EOF_reached, 0)

(* ── Line-based Reading ──────────────────────────────────────────────── *)

(* Read all complete lines from a file descriptor.
   Uses Unix.select for non-blocking reads. *)
let read_lines_from_fd (fd : Unix.file_descr) ~(timeout_sec : float) : string list =
  let buf = Bytes.create 8192 in
  let buffer = Buffer.create 8192 in
  let results = ref [] in
  
  let rec read_loop () =
    let ready, _, _ = Unix.select [fd] [] [] timeout_sec in
    if List.is_empty ready then begin
      let content = Buffer.contents buffer in
      if String.is_empty content then !results
      else if is_valid_json content then content :: !results
      else !results
    end else begin
      let n = Unix.read fd buf 0 (Bytes.length buf) in
      if n = 0 then begin
        let content = Buffer.contents buffer in
        if not (String.is_empty content) && is_valid_json content then
          List.rev (content :: !results)
        else
          List.rev !results
      end else begin
        Buffer.add_subbytes buffer buf 0 n;
        let content = Buffer.contents buffer in
        let (complete, remaining) = split_lines content in
        results := List.rev complete @ !results;
        Buffer.clear buffer;
        Buffer.add_string buffer remaining;
        read_loop ()
      end
    end
  in
  read_loop ()

and split_lines (content : string) : (string list * string) =
  let lines = String.split content ~on:'\n' in
  match List.rev lines with
  | [] -> ([], "")
  | last :: rest_rev ->
    let rest = List.rev rest_rev in
    (rest, last)

and is_valid_json (s : string) : bool =
  let trimmed = String.strip s in
  (String.is_prefix trimmed ~prefix:"{") ||
  (String.is_prefix trimmed ~prefix:"[")

(* ── Streaming Parser ────────────────────────────────────────────────── *)

type json_token =
  | Object_start
  | Object_end
  | Array_start
  | Array_end
  | Key of string
  | String of string
  | Number of float
  | Bool of bool
  | Null

(* Tokenize a JSON string for streaming analysis. *)
let tokenize_json (json : string) : json_token list =
  let rec tokenize i limit acc =
    if i >= limit then List.rev acc
    else begin
      let c = json.[i] in
      match c with
      | '{' -> tokenize (i + 1) limit (Object_start :: acc)
      | '}' -> tokenize (i + 1) limit (Object_end :: acc)
      | '[' -> tokenize (i + 1) limit (Array_start :: acc)
      | ']' -> tokenize (i + 1) limit (Array_end :: acc)
      | '"' ->
        (match parse_string json (i + 1) limit with
         | Some (str, j) -> tokenize j limit (String str :: acc)
         | None -> tokenize (i + 1) limit acc)
      | ' ' | '\t' | '\r' | '\n' -> tokenize (i + 1) limit acc
      | '-' | '0'..'9' ->
        (match parse_number json i limit with
         | Some (n, j) -> tokenize j limit (Number n :: acc)
         | None -> tokenize (i + 1) limit acc)
      | 't' ->
        if i + 4 <= limit && String.sub json ~pos:i ~len:4 = "true" then
          tokenize (i + 4) limit (Bool true :: acc)
        else tokenize (i + 1) limit acc
      | 'f' ->
        if i + 5 <= limit && String.sub json ~pos:i ~len:5 = "false" then
          tokenize (i + 5) limit (Bool false :: acc)
        else tokenize (i + 1) limit acc
      | 'n' ->
        if i + 4 <= limit && String.sub json ~pos:i ~len:4 = "null" then
          tokenize (i + 4) limit (Null :: acc)
        else tokenize (i + 1) limit acc
      | _ -> tokenize (i + 1) limit acc
    end
  in
  tokenize 0 (String.length json) []

and parse_string (json : string) (start : int) (limit : int) 
    : (string * int) option =
  let rec find_end i =
    if i >= limit then None
    else if json.[i] = '"' then Some i
    else if json.[i] = '\\' then find_end (i + 2)
    else find_end (i + 1)
  in
  match find_end start with
  | Some end_pos ->
    let content = String.sub json ~pos:start ~len:(end_pos - start) in
    Some (content, end_pos + 1)
  | None -> None

and parse_number (json : string) (start : int) (limit : int) 
    : (float * int) option =
  let rec find_end i =
    if i >= limit then Some i
    else match json.[i] with
      | '0'..'9' | '.' | '-' | '+' | 'e' | 'E' -> find_end (i + 1)
      | _ -> Some i
  in
  match find_end start with
  | Some end_pos ->
    (try Some (Float.of_string (String.sub json ~pos:start ~len:(end_pos - start)), end_pos)
     with _ -> None)
  | None -> None

(* ── Statistics ─────────────────────────────────────────────────────── *)

let get_stats (s : t) = {
  lines_emitted = s.lines_emitted;
  bytes_read = s.bytes_read;
  buffer_size = Buffer.length s.buffer;
  state = s.state;
}

(* ── Incremental CFG Construction ──────────────────────────────────── *)

(* Represents a partial CFG being built from streaming input *)
type partial_cfg = {
  nodes : (string, string) Hashtbl.t;
  edges : (string * string) list;
  current_function : string option;
  current_block : string option;
}

let create_partial_cfg () : partial_cfg = {
  nodes = Hashtbl.create (module String);
  edges = [];
  current_function = None;
  current_block = None;
}

(* Process a security node JSON object into the CFG.
   Returns updated CFG. *)
let process_security_node (cfg : partial_cfg) (json : string) : partial_cfg =
  try
    let obj = Yojson.Safe.from_string json in
    let dict = match obj with `Assoc d -> d | _ -> [] in
    
    (* Extract relevant fields *)
    let file = match List.assoc_opt "file" dict with
      | Some (`String s) -> s | _ -> "unknown" in
    let line = match List.assoc_opt "line" dict with
      | Some (`Int i) -> i | _ -> 0 in
    let rule = match List.assoc_opt "rule" dict with
      | Some (`String s) -> s | _ -> "unknown" in
    
    (* Add node for this finding *)
    let node_id = Printf.sprintf "%s:%d" file line in
    Hashtbl.set cfg.nodes ~key:node_id ~data:rule;
    
    cfg
  with _ -> cfg