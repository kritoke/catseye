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

(* ── SanitizerBypass ────────────────────────────────────────────────── *)

(** Detect Path.expand/Path.join used in projects that define a PathSanitizer.
    When a project has a module named *Sanitizer* or *PathSanitizer*, any
    Path.expand or Path.join call that does NOT route through the sanitizer
    is a potential validation bypass.
    From facet_pi security audit Finding 1 (High): file_edit.ex bypassed
    PathSanitizer by calling Path.expand directly. *)
let check_sanitizer_bypass (json_data : Yojson.Safe.t list) : Finding.t list =
  (* Phase 1: detect if project has a sanitizer module *)
  let has_sanitizer = List.exists ~f:(fun json ->
    match json with
    | `Assoc fields ->
      (match assoc "module" fields with
       | Some (`String s) ->
         String.is_substring ~substring:"Sanitizer" s
         || String.is_substring ~substring:"sanitizer" s
       | _ -> false)
    | _ -> false
  ) json_data in
  if not has_sanitizer then []
  else
    (* Phase 2: flag Path.expand/Path.join calls not routed through sanitizer *)
    List.fold_left ~init:[] ~f:(fun findings json ->
      match json with
      | `Assoc fields ->
        let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
        (* Skip the sanitizer module itself *)
        let is_sanitizer_mod = match assoc "module" fields with
          | Some (`String s) -> String.is_substring ~substring:"Sanitizer" s
            || String.is_substring ~substring:"sanitizer" s
          | _ -> false
        in
        if is_sanitizer_mod then findings
        else
          let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
          let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
            match fn_data with
            | `Assoc fn_fields ->
              let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
              let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
              let has_sanitizer_call = List.exists ~f:(fun call ->
                match call with
                | `Assoc call_fields ->
                  let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
                  String.is_substring ~substring:"sanitize" name
                  || String.is_substring ~substring:"Sanitize" name
                | _ -> false
              ) calls in
              let path_calls = List.filter ~f:(fun call ->
                match call with
                | `Assoc call_fields ->
                  let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
                  String.is_substring ~substring:"Path.expand" name
                  || (String.is_substring ~substring:"Path.join" name && not has_sanitizer_call)
                | _ -> false
              ) calls in
              List.fold_left ~init:acc ~f:(fun pacc call ->
                match call with
                | `Assoc call_fields ->
                  let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
                  let line = match assoc "line" call_fields with Some (`Int n) -> n | _ -> 0 in
                  let finding = make_finding file line "SanitizerBypass" "High"
                    (Stdlib.Printf.sprintf
                       "Path operation '%s' in '%s' bypasses project PathSanitizer. \
                        Other functions in this project route through the sanitizer — \
                        this call should too to prevent path traversal, symlink escaping, and null byte attacks."
                       name fn_name)
                  in
                  finding :: pacc
                | _ -> pacc
              ) path_calls
            | _ -> acc
          ) functions in
          func_findings @ findings
      | _ -> findings
    ) json_data

(* ── UnboundedRecursion ──────────────────────────────────────────────── *)

(** Detect recursive functions without depth guards.
    If a function calls itself (by name) and none of its calls include a
    depth or max_depth parameter, it risks stack overflow on deep/cyclic input.
    From facet_pi security audit Finding 3 (Low): resolve_symlink_parts/3
    recursed without a depth counter, crashing on symlink loops. *)
let check_unbounded_recursion (json_data : Yojson.Safe.t list) : Finding.t list =
  List.fold_left ~init:[] ~f:(fun findings json ->
    match json with
    | `Assoc fields ->
      let file = match assoc "file" fields with Some (`String s) -> s | _ -> "" in
      let functions = match assoc "functions" fields with Some (`List l) -> l | _ -> [] in
      let func_findings = List.fold_left ~init:[] ~f:(fun acc fn_data ->
        match fn_data with
        | `Assoc fn_fields ->
          let fn_name = match assoc "name" fn_fields with Some (`String s) -> s | _ -> "" in
          let fn_arity = match assoc "arity" fn_fields with Some (`Int n) -> n | _ -> 0 in
          let calls = match assoc "calls" fn_fields with Some (`List l) -> l | _ -> [] in
          (* Check if function calls itself *)
          let self_calls = List.filter ~f:(fun call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              name = fn_name
            | _ -> false
          ) calls in
          if self_calls <> [] then begin
            (* Check if any recursive call includes a depth/max/count guard.
               Look for args containing 'depth', 'max', 'count', 'limit' strings,
               OR check if the function params include a depth-related param. *)
            let params = match assoc "params" fn_fields with
              | Some (`List l) -> List.filter_map ~f:(function `String s -> Some s | _ -> None) l
              | _ -> [] in
            let has_depth_param = List.exists ~f:(fun p ->
              String.is_substring ~substring:"depth" p
              || String.is_substring ~substring:"max" p
              || String.is_substring ~substring:"limit" p
            ) params in
            if has_depth_param then acc
            else begin
              let has_depth_guard = List.exists ~f:(fun call ->
                match call with
                | `Assoc call_fields ->
                  let args = match assoc "args" call_fields with
                    | Some (`List l) -> l | _ -> [] in
                  List.exists ~f:(fun arg ->
                    match arg with
                    | `String s ->
                      String.is_substring ~substring:"depth" s
                      || String.is_substring ~substring:"max" s
                      || String.is_substring ~substring:"count" s
                      || String.is_substring ~substring:"limit" s
                    | _ -> false
                  ) args
                | _ -> false
              ) self_calls in
              if not has_depth_guard then begin
                let line = match assoc "line" fn_fields with Some (`Int n) -> n | _ -> 0 in
                let finding = make_finding file line "UnboundedRecursion" "Medium"
                  (Stdlib.Printf.sprintf
                     "Recursive function '%s/%d' has no depth guard. \
                      Add a depth parameter and decrement/max check to prevent stack overflow on deep or cyclic input."
                     fn_name fn_arity)
                in
                finding :: acc
              end
              else acc
            end
          end
          else acc
        | _ -> acc
      ) functions in
      func_findings @ findings
    | _ -> findings
  ) json_data

(* ── DangerousWhitelistKey ───────────────────────────────────────────── *)

(** Detect dangerous keys in allowed_update/whitelist maps.
    Maps named allowed_update_keys, permitted_fields, or similar that contain
    sensitive field names like 'messages', 'password', 'role', 'permissions'.
    From facet_pi security audit Finding 2 (Medium): @allowed_update_keys
    included 'messages' letting clients replace the entire message array. *)
let check_dangerous_whitelist_keys (json_data : Yojson.Safe.t list) : Finding.t list =
  let dangerous_keys = ["messages"; "password"; "role"; "permissions"; "admin";
                        "email"; "token"; "secret"; "api_key"; "credential"] in
  let whitelist_names = ["allowed_update_keys"; "permitted_fields"; "allowed_keys";
                        "whitelist"; "writable_fields"; "updatable_fields"] in
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
          (* Look for %{} map construction calls that might be whitelist definitions *)
          List.fold_left ~init:acc ~f:(fun pacc call ->
            match call with
            | `Assoc call_fields ->
              let name = match assoc "name" call_fields with Some (`String s) -> s | _ -> "" in
              let args = match assoc "args" call_fields with Some (`List l) -> l | _ -> [] in
              (* Check if this looks like a whitelist definition: assignment of a map
                 where the variable name matches a whitelist pattern *)
              let is_whitelist = name = "=" && List.length args >= 2 in
              if is_whitelist then begin
                let var_name = match List.hd args with
                  | Some (`String s) -> s | _ -> "" in
                let matches_whitelist_name = List.exists ~f:(fun w ->
                  String.is_substring ~substring:w var_name
                ) whitelist_names in
                if matches_whitelist_name then begin
                  (* Check args for dangerous keys *)
                  let dangerous_found = List.filter ~f:(fun arg ->
                    match arg with
                    | `String s -> List.exists ~f:(fun d ->
                      String.is_substring ~substring:d s
                    ) dangerous_keys
                    | _ -> false
                  ) args in
                  match dangerous_found with
                  | [] -> pacc
                  | _ ->
                    let line = match assoc "line" call_fields with Some (`Int n) -> n | _ -> 0 in
                    let keys_str = dangerous_found
                      |> List.map ~f:(function `String s -> s | _ -> "?")
                      |> String.concat ~sep:", " in
                    let finding = make_finding file line "DangerousWhitelistKey" "Medium"
                      (Stdlib.Printf.sprintf
                         "Whitelist map '%s' in '%s' includes sensitive key(s): %s. \
                          Allowing direct updates to these fields can bypass validation. \
                          Consider removing from allowed-update list and using a dedicated validated append function."
                         var_name fn_name keys_str)
                    in
                    finding :: pacc
                end
                else pacc
              end
              else pacc
            | _ -> pacc
          ) calls
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
    check_sanitizer_bypass json_data;
    check_unbounded_recursion json_data;
    check_dangerous_whitelist_keys json_data;
  ]