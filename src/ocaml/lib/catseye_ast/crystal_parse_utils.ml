(* lib/catseye_ast/crystal_parse_utils.ml
   Shared utilities for Crystal AST mappers.

   Extracts the common JSON helpers, field accessors, and subprocess
   execution with timeout that were duplicated between crystal_mapper.ml
   and crystal_hierarchical_mapper.ml. *)

module PE = Error
open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

open Types

(* ── JSON helpers ──────────────────────────────────────────────────── *)

let string_of_json = function `String s -> s | _ -> ""
let int_of_json = function `Int i -> i | _ -> 0
let list_of_json = function `List l -> l | _ -> []
let assoc_of_json = function `Assoc l -> l | _ -> []

let rec find_field fields key =
  match fields with [] -> `Null | (k, v) :: _ when k = key -> v | _ :: r -> find_field r key

let get_str json key = match assoc_of_json json with
  | fields -> string_of_json (find_field fields key)

let get_int json key = match assoc_of_json json with
  | fields -> int_of_json (find_field fields key)

let get_obj json key = match assoc_of_json json with
  | fields ->
    match find_field fields key with
    | `Assoc _ as v -> Some v
    | `Null -> None
    | _ -> None

let get_list json key = match assoc_of_json json with
  | fields -> list_of_json (find_field fields key)

let get_opt_obj json key = match assoc_of_json json with
  | fields ->
    match find_field fields key with
    | `Assoc _ as v -> Some v
    | `Null | _ -> None

let get_type json = get_str json "type"

(* ── Location helpers ──────────────────────────────────────────────── *)

let zero_loc : range =
  { start = { line = 0; column = 0; byte_offset = 0 };
    end_ = { line = 0; column = 0; byte_offset = 0 } }

let make_range line col len = {
  start = { line; column = col; byte_offset = 0 };
  end_ = { line; column = col + len; byte_offset = 0 };
}

let make_loc line = make_range line 0 0

(* ── Subprocess execution with timeout ─────────────────────────────── *)

(** Run an extractor subprocess with a timeout.

    Uses Unix.pipe + create_process + select-based drain to avoid
    blocking indefinitely on hung or slow Crystal processes.

    Returns [Ok output_string] on success, [Error message] on failure. *)
let run_extractor ~timeout_sec ~extractor_cmd ~path : (string, PE.parse_error) Result.t =
  let cmd = Stdlib.Printf.sprintf "%s %s"
    (Stdlib.Filename.quote extractor_cmd)
    (Stdlib.Filename.quote path) in
  let (pipe_read, pipe_write) = Unix.pipe () in
  Unix.set_close_on_exec pipe_read;
  let pid = Unix.create_process
    "/bin/sh" [| "/bin/sh"; "-c"; cmd |]
    Unix.stdin pipe_write Unix.stderr in
  Unix.close pipe_write;
  let buffer = Stdlib.Buffer.create 8192 in
  let chunk = Stdlib.Bytes.create 4096 in
  let deadline = Unix.gettimeofday () +. timeout_sec in
  let timed_out = ref false in
  let rec drain () =
    let remaining = deadline -. Unix.gettimeofday () in
    if Stdlib.(remaining <= 0.0) then
      timed_out := true
    else begin
      let ready = Unix.select [pipe_read] [] [] remaining in
      match ready with
      | ([], _, _) -> drain ()
      | _ ->
        (match Unix.read pipe_read chunk 0 4096 with
         | 0 -> ()
         | n -> Stdlib.Buffer.add_subbytes buffer chunk 0 n; drain ())
    end
  in
  (try drain () with _ -> ());
  (try Unix.close pipe_read with _ -> ());
  let _ = try Unix.waitpid [] pid with _ -> (0, Unix.WEXITED 0) in
  if !timed_out then
    Error (PE.make_error ~file:path
      ~message:(Stdlib.Printf.sprintf "Crystal extractor timed out (%.0fs)" timeout_sec))
  else
    let output = Stdlib.Buffer.contents buffer in
    if output = "" then
      Error (PE.make_error ~file:path ~message:"Crystal extractor produced no output")
    else
      Ok output
