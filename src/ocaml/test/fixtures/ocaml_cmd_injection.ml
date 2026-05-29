(* Test fixture: OCaml Command Injection vulnerabilities *)
(* This file contains patterns that should trigger ocaml_command_injection.kdl *)

(* VULNERABLE: Process execution with interpolated paths *)
let vulnerable_process_in user_path =
  let cmd = Printf.sprintf "find '%s'" user_path in
  let ic = Unix.open_process_in cmd in
  let content = Stdlib.input_line ic in
  let _ = Unix.close_process_in ic in
  content

(* VULNERABLE: Full process execution with grammar path *)
let grammar_path_from_env () =
  let env_result = match Stdlib.Sys.getenv "TREE_SITTER_GRAMMAR" with
    | exception Stdlib.Not_found -> None
    | path -> Some path
  in
  match env_result with
  | Some path -> path
  | None -> "/usr/lib/default"

(* VULNERABLE: Shell command with file path interpolation *)
let extract_with_injection lib_path file_path =
  let cmd = Stdlib.Printf.sprintf
    "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>/dev/null"
    lib_path file_path in
  let (out, inp, err) = Unix.open_process_full cmd (Unix.environment ()) in
  let buf = Stdlib.Buffer.create 8192 in
  (try while true do Stdlib.Buffer.add_channel buf out 4096 done
   with Stdlib.End_of_file -> ());
  let _ = Unix.close_process_full (out, inp, err) in
  Stdlib.Buffer.contents buf

(* VULNERABLE: Sys.command with path concatenation *)
let system_with_path dir =
  let cmd = "ls -la " ^ dir in
  Stdlib.Sys.command cmd

(* SAFE: create_process with separate arguments - no shell injection *)
let safe_create_process () =
  Unix.create_process "ls" [|"ls"; "-la"|] Unix.stdin Unix.stdout Unix.stderr

(* SAFE: quoted filenames *)
let safe_process_quote path =
  let cmd = Printf.sprintf "cat %s" (Filename.quote path) in
  Unix.open_process_in cmd

(* SAFE: temp file with atomic creation *)
let safe_temp_file () =
  let (tmp_file, oc) = Filename.open_temp_file ~perms:0o600 "test-" ".out" in
  Stdlib.Buffer.add_string (Stdlib.Buffer.create 100) "content";
  oc
