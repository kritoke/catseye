(* Test fixture: OCaml Race Condition vulnerabilities *)
(* This file contains PID-based temp file patterns that should trigger ocaml_race_condition.kdl *)

(* VULNERABLE: PID-based temp file (symlink attack) *)
let bad_temp_file_usage () =
  let tmp_file = Printf.sprintf "/tmp/catseye-extract-%d.out" (Unix.getpid ()) in
  let content = Core.In_channel.read_all tmp_file in
  content

(* VULNERABLE: Another PID-based temp file pattern *)
let tmp_file_with_pid prefix =
  let tmp = Printf.sprintf "/tmp/%s-%d.tmp" prefix (Unix.getpid ()) in
  let oc = Stdlib.open_out tmp in
  Stdlib.output_string oc "data";
  Stdlib.close_out oc

(* VULNERABLE: Direct getpid in path construction *)
let unsafe_extract_output () =
  let out_file = Printf.sprintf "/tmp/extract-%d.out" (Unix.getpid ()) in
  let content = Core.In_channel.read_all out_file in
  Stdlib.print_string content

(* VULNERABLE: PID in temp directory path *)
let pid_based_dir () =
  let dir = Printf.sprintf "/tmp/myapp-%d" (Unix.getpid ()) in
  Stdlib.Sys.mkdir dir 0o755;
  dir

(* SAFE: Secure temp file with random suffix *)
let safe_temp_file () =
  let (tmp_file, oc) = Filename.open_temp_file ~perms:0o600 "catseye-" ".out" in
  Stdlib.output_string oc "safe content";
  Stdlib.close_out oc;
  tmp_file

(* SAFE: Unique file with crypto random *)
let safe_random_file () =
  let random_suffix = Core.Uuid.to_string (Core.Uuid_unix.t `Predictable) in
  let path = Printf.sprintf "/tmp/app-%s.dat" random_suffix in
  path

(* SAFE: Using mkstemp-style creation *)
let safe_mkstemp () =
  let template = "/tmp/myapp-XXXXXX" in
  let fd = Core.Unix.mkstemp template in
  fd
