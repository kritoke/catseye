(* lib/catseye_engine/parallel.ml
   Parallel extraction using OCaml 5 Domains.

   Uses Domain-based parallelism for extraction. This provides good
   CPU utilization across cores for file extraction tasks.
*)

open Base

type 'a processing_result =
  | Done of 'a
  | Failed of { file : string; error : string }

let result_to_option : 'a processing_result -> 'a option = function
  | Done v -> Some v
  | Failed _ -> None

let rec filter_map_opt (f : 'a -> 'b option) (lst : 'a list) : 'b list =
  match lst with
  | [] -> []
  | x :: rest ->
    (match f x with
     | Some y -> y :: filter_map_opt f rest
     | None -> filter_map_opt f rest)

(** Run extractions in parallel, one Domain per file.
    Falls back to sequential on single-core or Domain errors. *)

let extract_parallel (extract_fn : ('a -> 'b option)) (file_list : 'a list) : 'b list =
  match file_list with
  | [] | [_] ->
    (* 0-1 files: no parallelism needed *)
    filter_map_opt extract_fn file_list
  | many ->
    let arr = Stdlib.Array.of_list many in
    let n = Stdlib.Array.length arr in
    try
      (* Spawn domains that return results directly via Domain.join *)
      let domains = Stdlib.Array.init n (fun i ->
        Domain.spawn (fun () -> extract_fn arr.(i))
      ) in
      Stdlib.Array.to_list domains
      |> List.map ~f:Domain.join
      |> filter_map_opt (function Some x -> Some x | None -> None)
    with exn ->
      (* Domain creation failed — run sequentially *)
      Stdlib.Printf.eprintf "Parallel extraction failed (%s), falling back to sequential\n"
        (Stdlib.Printexc.to_string exn);
      filter_map_opt extract_fn many

(* ── Native Parallel Workspace Scan ──────────────────────────────────── *)

(** Configuration for parallel workspace scanning *)
type scan_config = {
  max_domains : int;          (* Maximum concurrent domains *)
  chunk_size : int;           (* Files per domain batch *)
  timeout_ms : int option;    (* Optional timeout per file *)
}

let default_scan_config = {
  max_domains = Domain.recommended_domain_count ();
  chunk_size = 1;             (* One file per domain for maximum parallelism *)
  timeout_ms = None;
}

(** Process a single file inside a domain with local error handling.
    Returns a clean result that cannot crash the aggregator. *)
let process_file_domain_safe
    (extract_fn : 'a -> 'b option)
    (file : 'a)
    (file_path : string)
    : 'b processing_result =
  try
    match extract_fn file with
    | Some result -> Done result
    | None -> Failed { file = file_path; 
                      error = "Extraction returned no nodes" }
  with
  | exn ->
    Failed {
      file = file_path;
      error = Stdlib.Printexc.to_string exn
    }

(** Main parallel workspace scan function.
    
    Loops over discovered file paths, spawns a Domain for each file
    execution, and aggregates results via Domain.join.
    
    @param extract_fn Function to extract data from a file path (string)
    @param file_paths List of file paths to process
    @param config Optional scan configuration (uses defaults if None)
    @return List of successfully processed results and list of errors
*)
let parallel_workspace_scan
    ?(config : scan_config option)
    (extract_fn : string -> 'a option)
    (file_paths : string list)
    : ('a list * (string * string) list) =
  let cfg = Option.value config ~default:default_scan_config in
  let paths = Stdlib.Array.of_list file_paths in
  let n = Stdlib.Array.length paths in
  
  if n = 0 then ([], [])
  else if n = 1 then
    (* Single file: process directly without domain overhead *)
    match extract_fn paths.(0) with
    | Some result -> ([result], [])
    | None -> ([], [(paths.(0), "No result from extraction")])
  else
    (* Multiple files: use Domain parallelism *)
    let num_domains = min cfg.max_domains n in
    try
      (* Spawn domains — each processes a subset of files *)
      let domains = 
        Stdlib.Array.init num_domains (fun d_idx ->
          let start_idx = (n * d_idx) / num_domains in
          let end_idx = (n * (d_idx + 1)) / num_domains in
          Domain.spawn (fun () ->
            (* Process files in this domain's range, accumulating results locally *)
            let local_successes : 'a list ref = ref [] in
            let local_errors : (string * string) list ref = ref [] in
            for i = start_idx to end_idx - 1 do
              let file_path = paths.(i) in
              try
                match extract_fn file_path with
                | Some result -> local_successes := result :: !local_successes
                | None -> 
                  local_errors := (file_path, "Extraction returned no nodes") :: !local_errors
              with exn ->
                (* Local error catch — domain continues processing other files *)
                local_errors := (file_path, Stdlib.Printexc.to_string exn) :: !local_errors
            done;
            (!local_successes, !local_errors)
          )
        )
      in
      
      (* Aggregate results via Domain.join *)
      let all_results = Stdlib.Array.to_list domains |> List.map ~f:Domain.join in
      
      (* Combine all domain results *)
      let rec collect (results_list : ('a list * (string * string) list) list) 
                     (successes : 'a list) (errors : (string * string) list) =
        match results_list with
        | [] -> (List.rev successes, List.rev errors)
        | (s, e) :: rest -> collect rest (List.rev_append s successes) (List.rev_append e errors)
      in
      collect all_results [] []
        
    with exn ->
      (* Domain pool creation failed — fallback to sequential *)
      let success_msg = Stdlib.Printf.sprintf 
        "Parallel scan failed (%s), falling back to sequential\n"
        (Stdlib.Printexc.to_string exn) in
      Stdlib.Printf.eprintf "%s" success_msg;
      
      let rec sequential_loop paths successes errors =
        match paths with
        | [] -> (List.rev successes, List.rev errors)
        | path :: rest ->
          try
            match extract_fn path with
            | Some result -> sequential_loop rest (result :: successes) errors
            | None -> sequential_loop rest successes ((path, "No result") :: errors)
          with e ->
            sequential_loop rest successes ((path, Stdlib.Printexc.to_string e) :: errors)
      in
      sequential_loop file_paths [] []

(* ── Convenience wrapper for Security_node extraction ────────────────── *)

let extract_security_nodes_parallel
    ?config
    (extract_fn : string -> Catseye_types.Security_node.t list option)
    (file_paths : string list)
    : (Catseye_types.Security_node.t list * (string * string) list) =
  let (results, errors) = parallel_workspace_scan ?config extract_fn file_paths in
  (* Flatten all node lists into one *)
  let all_nodes = List.concat results in
  (all_nodes, errors)

(* ── Statistics helper ──────────────────────────────────────────────── *)

let scan_stats (nodes : 'a list) (errors : (string * string) list) =
  let open Stdlib.Printf in
  eprintf "  [parallel] Files processed: %d\n" 
    (List.length nodes + List.length errors);
  eprintf "  [parallel] Successful: %d\n" (List.length nodes);
  eprintf "  [parallel] Errors: %d\n" (List.length errors);
  List.iter ~f:(fun (file, err) ->
    eprintf "  [parallel]   ✗ %s: %s\n" file err
  ) errors
