(* src/ocaml/lib/ai_linter/crystal_rules_exception_safety.ml
   Categories 14, 16, 17: Exception Safety & Control Flow

   Detects non-atomic file ops, unbounded file reads, open rescues,
   missing else branches, reassignment in conditions, and dead code
   after raise/error.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(* Rule 14.1: Non-Atomic File Operation
   Detects patterns like File.write followed by chmod on the same path. *)
let detect_non_atomic_file_op (m : t) =
  let perm_calls = ["chmod"; "chown"; "chgrp"; "File.chmod"; "File.chown"; "File.chgrp"] in
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if List.mem call_name perm_calls then
        Some (Printf.sprintf
          "Non-atomic file operation: %s should be combined with file creation or use File.atomic_write with proper permissions"
          call_name, line)
      else None
    ) (collect_app_names body)
  )

(* Rule 14.2: Unbounded File Read
   Detects File.read, File.read?, IO.copy which load entire files. *)
let detect_unbounded_file_read (m : t) =
  let unbounded_reads = ["File.read"; "File.read?"; "IO.copy"] in
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if name_starts_with_any call_name unbounded_reads then
        Some (Printf.sprintf
          "Unbounded file read: %s loads entire file into memory - OOM risk for large files"
          call_name, line)
      else None
    ) (collect_app_names body)
  )

(* Rule 16.1: Open Rescue
   Detects rescue blocks that catch all exceptions without specifying a type. *)
let detect_open_rescue (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, _) when get_full_name fn = "rescue" ->
        [("Open rescue catches all exceptions — specify the exception type (e.g. rescue ArgumentError)",
          sub.expr_location.start.line)]
      | _ -> []
    ) body
  )

(* Rule 16.2: Missing Else
   Detects if-expressions without an else branch where the result appears
   to be used (assigned to a variable or returned as last expression). *)
let detect_missing_else (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EIf (_, _, None) ->
        [("if expression without else — false branch implicitly returns nil",
          sub.expr_location.start.line)]
      | _ -> []
    ) body
  )

(* Rule 17.1: Reassignment in Condition
   Detects variable reassignment inside if/case conditions. *)
let detect_reassignment_in_condition (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EIf (cond, _, _) ->
        (match cond.expr_value with
         | EAssignment _ ->
           [("Assignment inside if condition — extract to a separate binding for clarity",
             cond.expr_location.start.line)]
         | _ -> [])
      | _ -> []
    ) body
  )

(* Rule 17.2: Unreachable Code
   Disabled for Crystal - guard clauses produce false positives. *)
let detect_unreachable_code (m : t) =
  match m.mod_lang with
  | Crystal -> []
  | _ ->
    let is_terminal (e : expr) =
      match e.expr_value with
      | EError _ -> true
      | EApp (fn, _) ->
        let name = get_full_name fn in
        name = "return" || name = "raise" || name = "fail" || name = "exit" || name = "abort"
      | _ -> false
    in
    let rec scan_block (terminal_line : int) (exprs : expr list) =
      match exprs with
      | [] | [_] -> []
      | e :: rest when is_terminal e ->
        List.map (fun dead ->
          (Printf.sprintf "Unreachable code after terminal statement on line %d"
            terminal_line, dead.expr_location.start.line)
        ) rest
      | _ :: rest -> scan_block terminal_line rest
    in
    let rec scan (e : expr) =
      match e.expr_value with
      | EBlock es ->
        let dead = (match es with
          | [] -> []
          | terminal :: _ when is_terminal terminal ->
            List.map (fun dead ->
              (Printf.sprintf "Unreachable code after terminal statement on line %d"
                terminal.expr_location.start.line, dead.expr_location.start.line)
            ) (List.tl es)
          | _ -> []) in
        dead @ List.concat_map scan es
      | ELet (_, e1, e2) -> scan e1 @ scan e2
      | EIf (_, then_, else_) -> scan then_ @ (match else_ with Some e -> scan e | None -> [])
      | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
      | EApp (fn, args) -> scan fn @ List.concat_map scan args
      | _ -> []
    in
    map_functions m (fun _name body _line -> scan body)

(* Rule 13.1: Dead Code After Error
   Disabled for Crystal - guard clauses produce false positives. *)
let detect_dead_code_after_error (m : t) =
  match m.mod_lang with
  | Crystal -> []
  | _ ->
    let rec scan_block (exprs : expr list) : (string * int) list =
      match exprs with
      | [] | [_] -> []
      | e :: rest ->
        let results = (match e.expr_value with
         | EError _ ->
           List.concat_map (fun dead ->
             [Printf.sprintf "Unreachable code after raise/error on line %d"
               e.expr_location.start.line, dead.expr_location.start.line]
           ) rest
         | EIf (_, then_, else_) ->
           let then_results = (match then_.expr_value with EError _ ->
             List.concat_map (fun dead ->
               [Printf.sprintf "Unreachable code after raise in conditional on line %d"
                 then_.expr_location.start.line, dead.expr_location.start.line]
             ) rest
           | _ -> []) in
           let else_results = (match else_ with
            | Some e2 -> (match e2.expr_value with
              | EError _ ->
                List.concat_map (fun dead ->
                  [Printf.sprintf "Unreachable code after raise in conditional on line %d"
                    e2.expr_location.start.line, dead.expr_location.start.line]
                ) rest
              | _ -> [])
            | None -> []) in
           then_results @ else_results
         | _ -> []) in
        results @ scan_block rest
    in
    map_functions m (fun _name body _line ->
      match body.expr_value with
      | EBlock exprs -> scan_block exprs
      | _ -> []
    )
