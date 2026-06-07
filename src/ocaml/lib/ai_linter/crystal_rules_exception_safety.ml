(* src/ocaml/lib/ai_linter/crystal_rules_exception_safety.ml
   Categories 14, 16, 17: Exception Safety & Control Flow

   Detects non-atomic file ops, unbounded file reads, open rescues,
   missing else branches, reassignment in conditions, and dead code
   after raise/error.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_non_atomic_file_op (m : t) =
  
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_name, _, _, body) ->
        let calls = collect_app_names body in
        let perm_calls = List.filter (fun (call_name, _) ->
          List.mem call_name ["chmod"; "chown"; "chgrp"; "File.chmod"; "File.chown"; "File.chgrp"]
        ) calls in
        List.concat_map (fun (perm_call, perm_line) ->
          [Printf.sprintf
            "Non-atomic file operation: %s should be combined with file creation or use File.atomic_write with proper permissions"
            perm_call, perm_line]
        ) perm_calls
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

(** Rule: Unbounded File Read
    Detects unbounded file reads that could cause OOM with large files.
    File.read reads entire file into memory. *)

let detect_unbounded_file_read (m : t) =
  let unbounded_reads = [
    "File.read"; "File.read?";
    "IO.copy";
  ] in
  
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_name, _, _, body) ->
        List.concat_map (fun (call_name, line) ->
          if List.exists (fun p ->
            String.length call_name >= String.length p &&
            String.sub call_name 0 (String.length p) = p
          ) unbounded_reads then
            [let msg = Printf.sprintf "Unbounded file read: %s loads entire file into memory - OOM risk for large files" call_name in (msg, line)]
          else []
        ) (collect_app_names body)
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

(** Rule: Callback Hell
    Detects 3+ levels of nested EFn (anonymous functions / blocks).
    AI often generates deeply nested callbacks instead of flat control flow. *)

let detect_open_rescue (m : t) =
  
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, args) ->
      (if get_full_name fn = "rescue" then
        [("Open rescue catches all exceptions — specify the exception type (e.g. rescue ArgumentError)", e.expr_location.start.line)]
      else []) @
      scan fn @ List.concat_map scan args
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> scan body
    | _ -> []
  ) m.mod_items

(** Rule: Missing Else
    Detects if-expressions without an else branch where the result appears
    to be used (assigned to a variable or returned as last expression).
    Missing else means nil is implicitly returned for the false branch.
    AI often forgets the else branch, causing unexpected nil values. *)

let detect_missing_else (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EIf (cond, then_, None) ->
      [("if expression without else — false branch implicitly returns nil", e.expr_location.start.line)]
      @ scan cond @ scan then_
    | EIf (cond, then_, Some else_) ->
      scan cond @ scan then_ @ scan else_
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 17: Control Flow Clarity ──────────────────────────────── *)

(** Rule: Reassignment in Condition
    Detects variable reassignment inside if/case conditions.
    AI sometimes mutates variables in conditions, leading to subtle bugs
    and hard-to-read code. *)

let detect_reassignment_in_condition (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EIf (cond, then_, else_) ->
      (match cond.expr_value with
       | EAssignment _ ->
         [("Assignment inside if condition — extract to a separate binding for clarity", cond.expr_location.start.line)]
       | _ -> []) @
      scan cond @ scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Unreachable Code
    Detects any code after return-like statements (EError, or raise-equivalents)
    in a block.
    
    NOTE: In Crystal, guard clauses are idiomatic:
    ```crystal
    def validate!(x)
      raise Error.new if invalid?  # raise is the ERROR path
      # This IS reachable - it's the NORMAL path when not invalid
    end
    ```
    The 'unreachable' code after a guard raise is actually normal continuation.
    This rule is DISABLED for Crystal as it produces false positives on guard patterns.
*)

let detect_unreachable_code (m : t) =
  (* Disabled for Crystal - guard clauses produce false positives *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let is_terminal (e : expr) =
    match e.expr_value with
    | EError _ -> true
    | EApp (fn, _) ->
        let name = get_full_name fn in
        name = "return" || name = "raise" || name = "fail" || name = "exit"
        || name = "abort"
    | _ -> false
  in
  let rec scan_block terminal_line = function
    | [] | [_] -> []
    | e :: rest when is_terminal e ->
      List.concat_map (fun dead ->
        [Printf.sprintf "Unreachable code after terminal statement on line %d"
          terminal_line, dead.expr_location.start.line]
      ) rest
    | _ :: rest -> scan_block terminal_line rest
  in
  let rec scan (e : expr) =
    match e.expr_value with
    | EBlock es ->
      let dead = (match es with
        | [] -> []
        | terminal :: _ when is_terminal terminal ->
          List.concat_map (fun dead ->
            [Printf.sprintf "Unreachable code after terminal statement on line %d"
              terminal.expr_location.start.line, dead.expr_location.start.line]
          ) (List.tl es)
        | _ -> []) in
      dead @ List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 18: Type & Network ────────────────────────────────────── *)

(** Rule: Type Checker Abuse
    Detects 3+ is_a?/as/responds_to? calls in one function.
    AI often generates manual type checking instead of using polymorphism.
    Indicates the function should be split or use method dispatch. *)

let detect_dead_code_after_error (m : t) =
  (* Disabled for Crystal - guard clauses produce false positives *)
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
           [Printf.sprintf "Unreachable code after raise/error on line %d" e.expr_location.start.line,
            dead.expr_location.start.line]
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
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      (match body.expr_value with
       | EBlock exprs -> scan_block exprs
       | _ -> [])
    | _ -> []
  ) m.mod_items

(* ── Category 14: Async & DRY ───────────────────────────────────────── *)

(** Rule: Non-Atomic File Operation
    Detects patterns like File.write followed by chmod on the same path.
    This is a non-atomic operation that creates a race window.
    Suggest using File.atomic_write or setting permissions during creation. *)