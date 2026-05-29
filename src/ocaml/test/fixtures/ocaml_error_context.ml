(* Test fixture: OCaml Error Context Loss *)
(* This file contains hardcoded error strings that should trigger ocaml_error_context.kdl *)

(* Simulated result types *)
type 'a processing_result =
  | Done of 'a
  | Failed of { file: string; error: string }

(* VULNERABLE: Hardcoded "unknown file" in error handler *)
let process_file_with_bad_error file_path extract_fn =
  try
    match extract_fn file_path with
    | Some result -> Done result
    | None -> Failed { file = "unknown file"; error = "Extraction returned no nodes" }
  with
  | exn ->
    Failed {
      file = "unknown file";  (* Should trigger rule *)
      error = Stdlib.Printexc.to_string exn
    }

(* VULNERABLE: Silent error swallowing *)
let silently_swallow_errors file_path =
  try
    let content = Stdlib.In_channel.read_all file_path in
    Some content
  with
  | _ -> ()  (* Silent swallow - should trigger rule *)

(* VULNERABLE: Generic "failed" error message *)
let operation_with_generic_error () =
  try
    let _ = Stdlib.Sys.command "some command" in
    Done "success"
  with
  | _ -> Failed { file = "config"; error = "operation failed" }

(* VULNERABLE: Hardcoded error context *)
let bad_error_context () =
  match Stdlib.Sys.getenv "PATH" with
  | exception Not_found ->
    Failed { file = "unknown file"; error = "missing path" }
  | _ -> Done "ok"

(* SAFE: Include actual file path in error *)
let safe_error_context file_path extract_fn =
  try
    match extract_fn file_path with
    | Some result -> Done result
    | None -> Failed { file = file_path; error = "Extraction returned no nodes" }
  with
  | exn ->
    Failed {
      file = file_path;  (* Actual path for debugging *)
      error = Stdlib.Printexc.to_string exn
    }

(* SAFE: Proper error logging *)
let safe_error_with_logging file_path =
  try
    let content = Stdlib.In_channel.read_all file_path in
    Done content
  with
  | Sys_error msg ->
    Format.eprintf "Error reading %s: %s@." file_path msg;
    Failed { file = file_path; error = msg }
  | exn ->
    Format.eprintf "Unexpected error reading %s: %s@." file_path (Printexc.to_string exn);
    Failed { file = file_path; error = Printexc.to_string exn }
