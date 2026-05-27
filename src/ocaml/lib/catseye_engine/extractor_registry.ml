(* lib/catseye_engine/extractor_registry.ml
   Unified Crystal extractor resolution.

   Resolves both flat (Security_node) and hierarchical (CatseyeAST) extractors
   once at startup, using a single consistent strategy:

     1. Explicit env var value (passed from caller, already resolved)
     2. Pre-compiled binary next to the running executable
     3. Search upward from CWD for bin/<name>
     4. Global install layout (exe_dir/../lib/catseye/extractor/)
     5. crystal run on source file (slow fallback)

   Created once in args.ml, threaded through config to all consumers.
*)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(** Search upward from [dir] for <name> directly (e.g. bin/catseye-crystal-extractor).
    Also checks [dir]/bin/<name> for backward compatibility. *)
let rec search_upward (dir : string) (name : string) : string option =
  (* Check direct path first (e.g., /workspaces/catseye/bin/<name>) *)
  let direct = dir ^ "/" ^ name in
  if Stdlib.Sys.file_exists direct then Some direct
  else
    (* Check bin/ subdirectory (legacy path) *)
    let in_bin = dir ^ "/bin/" ^ name in
    if Stdlib.Sys.file_exists in_bin then Some in_bin
    else
      let parent = Stdlib.Filename.dirname dir in
      if parent = dir then None
      else search_upward parent name

(** Search for a source file relative to the executable directory. *)
let search_exe_relative (source_relative : string list) : string option =
  let exe_dir = Stdlib.Filename.dirname (Stdlib.Sys.executable_name) in
  let rec try_sources = function
    | [] -> None
    | rel :: rest ->
      let candidate = exe_dir ^ "/" ^ rel in
      if Stdlib.Sys.file_exists candidate then Some candidate
      else try_sources rest
  in
  try_sources source_relative

(** Check if a resolved command is a pre-compiled binary (vs "crystal run ..."). *)
let is_compiled_binary (cmd : string) : bool =
  String.length cmd >= 12 && Stdlib.String.sub cmd 0 12 <> "crystal run "

(** Resolve a single extractor command.
    [env_value]: already-resolved value from env var, or None.
    [exe_name]: binary name (e.g. "catseye-crystal-extractor").
    [source_relative]: relative paths to the .cr source file. *)
let resolve_one
    (env_value : string option)
    (exe_name : string)
    (source_relative : string list) : string =
  (* 1. Explicit env var override *)
  match env_value with
  | Some cmd -> cmd
  | None ->
    (* 2. Pre-compiled binary next to the running executable *)
    let exe_dir = Stdlib.Filename.dirname (Stdlib.Sys.executable_name) in
    let next_to_exe = exe_dir ^ "/" ^ exe_name in
    if Stdlib.Sys.file_exists next_to_exe then next_to_exe
    else
    (* 3. Search upward from CWD AND from executable directory *)
    let from_cwd = search_upward (Stdlib.Sys.getcwd ()) exe_name in
    let exe_dir = Stdlib.Filename.dirname (Stdlib.Sys.executable_name) in
    let from_exe = search_upward exe_dir exe_name in
    match from_cwd, from_exe with
    | Some p, _ -> p
    | None, Some p -> p
    | None, None ->
      (* 4. Global install layout *)
      let global = exe_dir ^ "/../lib/catseye/extractor/" ^ exe_name in
      if Stdlib.Sys.file_exists global then global
      else
        (* 5. Search source relative to executable *)
        (match search_exe_relative source_relative with
        | Some p -> "crystal run " ^ p ^ " --"
        | None ->
          (* 6. Search source relative to executable directory (not CWD) *)
          let exe_dir = Stdlib.Filename.dirname (Stdlib.Sys.executable_name) in
          (match source_relative with
          | [] -> "crystal run " ^ exe_dir ^ "/../src/extractor/" ^ exe_name ^ ".cr --"
          | first :: _ ->
            let source_path = exe_dir ^ "/../" ^ first in
            if Stdlib.Sys.file_exists source_path then
              "crystal run " ^ source_path ^ " --"
            else
              (* 7. Hard fallback: use exe_dir as base *)
              "crystal run " ^ exe_dir ^ "/../src/extractor/" ^ exe_name ^ ".cr --"))

(* ── Registry type ──────────────────────────────────────────────────── *)

type t = {
  flat_cmd : string;
  hier_cmd : string;
  flat_is_compiled : bool;
  hier_is_compiled : bool;
}

(** Create a registry by resolving both extractors.
    [flat_env]: already-resolved CATSEYE_CRYSTAL_EXTRACTOR value, or None.
    [hier_env]: already-resolved CATSEYE_CRYSTAL_HIERARCHICAL value, or None. *)
let create ?(flat_env = None) ?(hier_env = None) () : t =
  let flat_cmd = resolve_one flat_env
    "catseye-crystal-extractor"
    ["src/extractor/extractor.cr"]
  in
  let hier_cmd = resolve_one hier_env
    "catseye-hierarchical-extractor"
    ["src/extractor/hierarchical_extractor.cr"]
  in
  { flat_cmd; hier_cmd;
    flat_is_compiled = is_compiled_binary flat_cmd;
    hier_is_compiled = is_compiled_binary hier_cmd }

(* ── Accessors ──────────────────────────────────────────────────────── *)

let flat_cmd (r : t) = r.flat_cmd
let hier_cmd (r : t) = r.hier_cmd
let flat_is_compiled (r : t) = r.flat_is_compiled
let hier_is_compiled (r : t) = r.hier_is_compiled

(* ── Single-file extraction ─────────────────────────────────────────── *)

(** Run a command and capture stdout. *)
let run_capture (full_cmd : string) : string option =
  try
    let ic = Unix.open_process_in full_cmd in
    let buf = Stdlib.Buffer.create 8192 in
    (try while true do Stdlib.Buffer.add_channel buf ic 4096 done
     with Stdlib.End_of_file -> ());
    let status = Unix.close_process_in ic in
    match status with
    | Unix.WEXITED 0 ->
      let s = Stdlib.Buffer.contents buf in
      if s <> "" then Some s else None
    | _ -> None
  with _ -> None

(** Extract using the flat extractor. Returns raw JSON string. *)
let extract_flat (r : t) ~(path : string) : string option =
  run_capture (Stdlib.Printf.sprintf "%s '%s' 2>/dev/null" r.flat_cmd path)

(** Extract using the hierarchical extractor. Returns raw JSON string. *)
let extract_hier (r : t) ~(path : string) : string option =
  run_capture (Stdlib.Printf.sprintf "%s '%s' 2>/dev/null" r.hier_cmd path)

(* ── Pool management ────────────────────────────────────────────────── *)

(** Create a worker pool for batch flat extraction (--serve mode).
    Only works with pre-compiled binaries. *)
let create_pool (r : t) ~(num_workers : int) : Worker_pool.t =
  Worker_pool.create r.flat_cmd num_workers

(** Shutdown a previously created pool. *)
let shutdown_pool (pool : Worker_pool.t) : unit =
  Worker_pool.shutdown pool
