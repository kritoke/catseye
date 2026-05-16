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

(* ── Path resolution helpers ────────────────────────────────────────── *)

(** Search upward from [dir] for bin/<name>. *)
let rec search_upward (dir : string) (name : string) : string option =
  let candidate = dir ^ "/bin/" ^ name in
  if Sys.file_exists candidate then Some candidate
  else
    let parent = Filename.dirname dir in
    if parent = dir then None
    else search_upward parent name

(** Check if a resolved command is a pre-compiled binary (vs "crystal run ..."). *)
let is_compiled_binary (cmd : string) : bool =
  String.length cmd >= 12 && String.sub cmd 0 12 <> "crystal run "

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
    let exe_dir = Filename.dirname (Sys.executable_name) in
    let next_to_exe = exe_dir ^ "/" ^ exe_name in
    if Sys.file_exists next_to_exe then next_to_exe
    else
    (* 3. Search upward from CWD *)
    match search_upward (Sys.getcwd ()) exe_name with
    | Some p -> p
    | None ->
      (* 4. Global install layout *)
      let global = exe_dir ^ "/../lib/catseye/extractor/" ^ exe_name in
      if Sys.file_exists global then global
      else
        (* 5. crystal run on source (slow) *)
        let source = List.find_opt Sys.file_exists source_relative in
        match source with
        | Some p -> "crystal run " ^ p ^ " --"
        | None -> "crystal run src/extractor/" ^ exe_name ^ ".cr --"

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
    let buf = Buffer.create 8192 in
    (try while true do Buffer.add_channel buf ic 4096 done
     with End_of_file -> ());
    let status = Unix.close_process_in ic in
    match status with
    | Unix.WEXITED 0 ->
      let s = Buffer.contents buf in
      if s <> "" then Some s else None
    | _ -> None
  with _ -> None

(** Extract using the flat extractor. Returns raw JSON string. *)
let extract_flat (r : t) ~(path : string) : string option =
  run_capture (Printf.sprintf "%s '%s' 2>/dev/null" r.flat_cmd path)

(** Extract using the hierarchical extractor. Returns raw JSON string. *)
let extract_hier (r : t) ~(path : string) : string option =
  run_capture (Printf.sprintf "%s '%s' 2>/dev/null" r.hier_cmd path)

(* ── Pool management ────────────────────────────────────────────────── *)

(** Create a worker pool for batch flat extraction (--serve mode).
    Only works with pre-compiled binaries. *)
let create_pool (r : t) ~(num_workers : int) : Worker_pool.t =
  Worker_pool.create r.flat_cmd num_workers

(** Shutdown a previously created pool. *)
let shutdown_pool (pool : Worker_pool.t) : unit =
  Worker_pool.shutdown pool
