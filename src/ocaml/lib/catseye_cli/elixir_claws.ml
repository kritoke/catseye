(* lib/catseye_cli/elixir_claws.ml *)
(* Claws detectors for Elixir code *)

open Catseye_types

let make_finding (file : string) (line : int) (rule : string)
    (severity : string) (message : string) : Finding.t =
  { rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = "elixir"
  ; dependency = None; reachability = None; suggestion = None
  }

(* ── BlanketRescue ────────────────────────────────────────────────────── *)

(** Detect `rescue _` patterns which catch all exceptions including system exits.
    Elixir best practice: rescue specific exceptions or use exits/throw for control flow. *)
let check_blanket_rescue (json_data : Yojson.Safe.t list) : Finding.t list =
  List.fold_left (fun findings json ->
    match json with
    | `Assoc fields ->
      let file = try List.assoc "file" fields |> function `String s -> s | _ -> "" with _ -> "" in
      let _module_name = try List.assoc "module" fields |> function `String s -> s | _ -> "" with _ -> "" in
      let functions = try List.assoc "functions" fields |> function `List flist -> flist | _ -> [] with _ -> [] in
      let func_findings = List.fold_left (fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = try List.assoc "name" fn_fields |> function `String s -> s | _ -> "" with _ -> "" in
          let calls = try List.assoc "calls" fn_fields |> function `List clist -> clist | _ -> [] with _ -> [] in
          (* Look for rescue _ pattern in calls *)
          let has_blanket_rescue = List.exists (fun call ->
            match call with
            | `Assoc call_fields ->
              let name = try List.assoc "name" call_fields |> function `String s -> s | _ -> "" with _ -> "" in
              name = "rescue" || name = "Elixir.Kernel.rescue"
            | _ -> false
          ) calls in
          if has_blanket_rescue then
            let line = try List.assoc "line" fn_fields |> function `Int n -> n | _ -> 0 with _ -> 0 in
            let finding = make_finding file line "BlanketRescue" "Medium"
              (Printf.sprintf "Function '%s' uses blanket rescue (rescue _). This catches all exceptions including system exits. Prefer rescuing specific exceptions or use exits/throw for control flow."
                 fn_name)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) [] functions in
      func_findings @ findings
    | _ -> findings
  ) [] json_data

(* ── LongFunction ───────────────────────────────────────────────────── *)

(** Detect functions with many calls (high complexity indicator in Elixir).
    Elixir functions with 15+ calls often indicate complexity that needs refactoring. *)
let check_long_functions (json_data : Yojson.Safe.t list) : Finding.t list =
  let call_threshold = 20 in
  List.fold_left (fun findings json ->
    match json with
    | `Assoc fields ->
      let file = try List.assoc "file" fields |> function `String s -> s | _ -> "" with _ -> "" in
      let functions = try List.assoc "functions" fields |> function `List flist -> flist | _ -> [] with _ -> [] in
      let func_findings = List.fold_left (fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = try List.assoc "name" fn_fields |> function `String s -> s | _ -> "" with _ -> "" in
          let arity = try List.assoc "arity" fn_fields |> function `Int n -> n | _ -> 0 with _ -> 0 in
          let calls = try List.assoc "calls" fn_fields |> function `List clist -> clist | _ -> [] with _ -> [] in
          let call_count = List.length calls in
          if call_count >= call_threshold then
            let line = try List.assoc "line" fn_fields |> function `Int n -> n | _ -> 0 with _ -> 0 in
            let severity = if call_count >= call_threshold * 2 then "High" else "Medium" in
            let finding = make_finding file line "LongFunction" severity
              (Printf.sprintf "Function '%s/%d' has %d calls (threshold: %d). Consider splitting into smaller functions."
                 fn_name arity call_count call_threshold)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) [] functions in
      func_findings @ findings
    | _ -> findings
  ) [] json_data

(* ── UnusedExceptions ───────────────────────────────────────────────── *)

(** Detect functions that rescue exceptions but may not handle them properly.
    This checks for rescue without proper error handling patterns. *)
let check_unused_exceptions (json_data : Yojson.Safe.t list) : Finding.t list =
  List.fold_left (fun findings json ->
    match json with
    | `Assoc fields ->
      let file = try List.assoc "file" fields |> function `String s -> s | _ -> "" with _ -> "" in
      let functions = try List.assoc "functions" fields |> function `List flist -> flist | _ -> [] with _ -> [] in
      let func_findings = List.fold_left (fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = try List.assoc "name" fn_fields |> function `String s -> s | _ -> "" with _ -> "" in
          let calls = try List.assoc "calls" fn_fields |> function `List clist -> clist | _ -> [] with _ -> [] in
          (* Look for raise or error calls that might not be handled *)
          let raises_count = List.fold_left (fun count call ->
            match call with
            | `Assoc call_fields ->
              let name = try List.assoc "name" call_fields |> function `String s -> s | _ -> "" with _ -> "" in
              if name = "raise" || name = "Elixir.Kernel.raise" then count + 1 else count
            | _ -> count
          ) 0 calls in
          if raises_count >= 3 then
            let line = try List.assoc "line" fn_fields |> function `Int n -> n | _ -> 0 with _ -> 0 in
            let finding = make_finding file line "UnusedExceptions" "Low"
              (Printf.sprintf "Function '%s' raises %d exceptions. Consider using Result/Option types instead of exceptions for control flow."
                 fn_name raises_count)
            in
            finding :: acc
          else acc
        | _ -> acc
      ) [] functions in
      func_findings @ findings
    | _ -> findings
  ) [] json_data

(* ── main analyzer ────────────────────────────────────────────────────── *)

let analyze (json_data : Yojson.Safe.t list) : Finding.t list =
  let blanket_rescue_findings = check_blanket_rescue json_data in
  let long_function_findings = check_long_functions json_data in
  let unused_exception_findings = check_unused_exceptions json_data in
  blanket_rescue_findings @ long_function_findings @ unused_exception_findings