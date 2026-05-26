(* lib/catseye_cli/elixir_claws.ml *)
(* Claws detectors for Elixir code *)

open Base
open Catseye_types

let (=) = Stdlib.(=)
let (<>) = Stdlib.(<>)

let make_finding (file : string) (line : int) (rule : string)
    (severity : string) (message : string) : Finding.t =
  { rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = "elixir"
  ; dependency = None; reachability = None; suggestion = None
  }

(* Helper to associate lookup keeping stdlib semantics *)
let assoc key fields = List.Assoc.find ~equal:String.equal fields key

(* ── BlanketRescue ────────────────────────────────────────────────────── *)

(** Detect `rescue _` patterns which catch all exceptions including system exits.
    Elixir best practice: rescue specific exceptions or use exits/throw for control flow. *)
let check_blanket_rescue (json_data : Yojson.Safe.t list) : Finding.t list =
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          (* Look for rescue _ pattern in calls *)
          let has_blanket_rescue = List.exists ~f:(fun call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              name = "rescue" || name = "Elixir.Kernel.rescue"
            | _ -> false
          ) calls in
          if has_blanket_rescue then
            let line = match assoc "line" fn_fields with Some (`Int n) -> n | _ -> 0 in
            let finding = make_finding file line "BlanketRescue" "Medium"
              (Stdlib.Printf.sprintf "Function '%s' uses blanket rescue (rescue _). This catches all exceptions including system exits. Prefer rescuing specific exceptions or use exits/throw for control flow."
                 fn_name)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── LongFunction ───────────────────────────────────────────────────── *)

(** Detect functions with many calls (high complexity indicator in Elixir).
    Elixir functions with 20+ calls often indicate complexity that needs refactoring. *)
let check_long_functions (json_data : Yojson.Safe.t list) : Finding.t list =
  let call_threshold = 20 in
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
          let arity = match assoc "arity" fn_fields with Some (`Int n) -> n | _ -> 0 in
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          let call_count = List.length calls in
          if call_count >= call_threshold then
            let line = match assoc "line" fn_fields with Some (`Int n) -> n | _ -> 0 in
            let severity = if call_count >= call_threshold * 2 then "High" else "Medium" in
            let finding = make_finding file line "LongFunction" severity
              (Stdlib.Printf.sprintf "Function '%s/%d' has %d calls (threshold: %d). Consider splitting into smaller functions."
                 fn_name arity call_count call_threshold)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── UnusedExceptions ───────────────────────────────────────────────── *)

(** Detect functions that rescue exceptions but may not handle them properly.
    This checks for rescue without proper error handling patterns. *)
let check_unused_exceptions (json_data : Yojson.Safe.t list) : Finding.t list =
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          (* Look for raise or error calls that might not be handled *)
          let raises_count = List.fold_left ~init:0 ~f:(fun count call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              if name = "raise" || name = "Elixir.Kernel.raise" then count + 1 else count
            | _ -> count
          ) calls in
          if raises_count >= 3 then
            let line = match assoc "line" fn_fields with Some (`Int n) -> n | _ -> 0 in
            let finding = make_finding file line "UnusedExceptions" "Low"
              (Stdlib.Printf.sprintf "Function '%s' raises %d exceptions. Consider using Result/Option types instead of exceptions for control flow."
                 fn_name raises_count)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── IgnoredPermissionOp ────────────────────────────────────────────── *)

(** Detect calls to chmod/chown/chgrp without handling the return value.
    These operations return {:ok, mode} or {:error, reason} tuples that should be handled. *)
let check_ignored_permission_ops (json_data : Yojson.Safe.t list) : Finding.t list =
  let perm_ops = ["File.chmod"; "File.chmod!"; "File.chown"; "File.chown!";
                  "File.chgrp"; "File.chgrp!"] in
  let is_perm_op name =
    List.exists ~f:(fun p ->
      String.length name >= String.length p &&
      Stdlib.String.sub name (String.length name - String.length p) (String.length p) = p
    ) perm_ops
  in
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          let perm_findings = List.fold_left ~init:[] ~f:(fun pacc call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              if is_perm_op name then
                let line = match assoc "line" call_fields with Some (`Int n) -> n | _ -> 0 in
                let finding = make_finding file line "IgnoredPermissionOp" "Medium"
                  (Stdlib.Printf.sprintf "Permission operation %s returns {:ok, mode} or {:error, reason} - return value should be handled"
                     name)
                in
                finding :: pacc
              else pacc
            | _ -> pacc
          ) calls in
          perm_findings @ acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── NonAtomicFileOp ───────────────────────────────────────────────── *)

(** Detect non-atomic file operations like File.write followed by chmod.
    The create + chmod pattern has a race window between operations. *)
let check_non_atomic_file_ops (json_data : Yojson.Safe.t list) : Finding.t list =
  let perm_ops = ["File.chmod"; "File.chmod!"; "File.chown"; "File.chown!"; "File.chgrp"; "File.chgrp!"] in
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          let has_perm_op = List.exists ~f:(fun call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              List.mem perm_ops ~equal:String.equal name
            | _ -> false
          ) calls in
          if has_perm_op then
            let line = match assoc "line" fn_fields with Some (`Int n) -> n | _ -> 0 in
            let finding = make_finding file line "NonAtomicFileOp" "Hint"
              (Stdlib.Printf.sprintf "Non-atomic file operation detected in '%s': chmod/chown/chgrp creates race window - consider atomic approaches"
                 fn_name)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── UnboundedFileRead ──────────────────────────────────────────────── *)

(** Detect unbounded file reads that could cause memory issues with large files.
    Functions like File.read!/1 read entire file into memory.
    NOTE: File.stream/1 and File.stream!/1 are LAZY streams - they are the
    RECOMMENDED approach for large files and should NOT be flagged. *)
let check_unbounded_file_read (json_data : Yojson.Safe.t list) : Finding.t list =
  let unbounded_reads = ["File.read!"; "File.read"] in
  let is_unbounded_read name = List.exists ~f:(fun p ->
    String.length name >= String.length p &&
    Stdlib.String.sub name 0 (String.length p) = p
  ) unbounded_reads in
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          let call_findings = List.fold_left ~init:[] ~f:(fun pacc call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              if is_unbounded_read name then
                let line = match assoc "line" call_fields with Some (`Int n) -> n | _ -> 0 in
                let finding = make_finding file line "UnboundedFileRead" "Warning"
                  (Stdlib.Printf.sprintf "Unbounded file read: %s - reading entire file into memory could cause OOM for large files"
                     name)
                in
                finding :: pacc
              else pacc
            | _ -> pacc
          ) calls in
          call_findings @ acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── main analyzer ──────────────────────────────────────────────────── *)

let analyze (json_data : Yojson.Safe.t list) : Finding.t list =
  List.concat [
    check_blanket_rescue json_data;
    check_long_functions json_data;
    check_unused_exceptions json_data;
    check_ignored_permission_ops json_data;
    check_non_atomic_file_ops json_data;
    check_unbounded_file_read json_data;
  ]