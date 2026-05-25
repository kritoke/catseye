(* lib/catseye_engine/parallel.ml
   Parallel extraction using OCaml 5 Domains.

   Uses Domain-based parallelism for extraction. This provides good
   CPU utilization across cores for file extraction tasks.
*)

(** Run extractions in parallel, one Domain per file.
    Falls back to sequential on single-core or Domain errors. *)

let extract_parallel extract_fn files =
  match files with
  | [] | [_] ->
    (* 0-1 files: no parallelism needed *)
    List.filter_map extract_fn files
  | many ->
    let arr = Array.of_list many in
    let n = Array.length arr in
    let results = Array.make n None in
    try
      let domains = Array.init n (fun i ->
        Domain.spawn (fun () -> results.(i) <- extract_fn arr.(i))
      ) in
      Array.iter Domain.join domains;
      Array.to_list results
      |> List.filter_map (function Some nodes -> Some nodes | None -> None)
    with exn ->
      (* Domain creation failed — run sequentially *)
      Printf.eprintf "Parallel extraction failed (%s), falling back to sequential\n"
        (Printexc.to_string exn);
      List.filter_map extract_fn many