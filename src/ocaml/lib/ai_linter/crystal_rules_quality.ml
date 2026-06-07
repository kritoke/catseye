(* src/ocaml/lib/ai_linter/crystal_rules_quality.ml
   Categories 7-10: Code Quality

   Detects blanket rescues, magic strings, debug requires, empty catch
   blocks, flag arguments, long methods, infinite recursion, debug
   prints, and string interpolation in queries.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_blanket_rescue (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let bodies = List.concat_map (fun (name, line) ->
        if name = "rescue" || name = "begin" then
          [("Blanket rescue catches all exceptions — catch specific exception types instead", line)]
        else []
      ) (collect_app_names body) in
      (match bodies with [] -> None | _ -> Some bodies)
    | _ -> None
  ) m.mod_items |> List.concat

(** Rule 7.2: Duplicate Validation
    Detects the same variable being validated twice in the same function.
    
    NOTE: Disabled for Crystal - multi-layer validation is intentional defense-in-depth,
    not duplicate code. Each validation catches different attack vectors.
*)

let detect_duplicate_validation (m : t) =
  (* Disabled for Crystal - defense-in-depth validation is intentional *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let rec check_item (item : item) =
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let validation_methods = ["empty?"; "nil?"; "blank?"; "valid?"; "present?"; "includes?"] in
      List.iter (fun method_name ->
        let matching = List.filter (fun (n, _) ->
          String.length n >= String.length method_name &&
          String.sub n (String.length n - String.length method_name) (String.length method_name) = method_name
        ) calls in
        if List.length matching >= 3 then
          let line = match matching with (_, l) :: _ -> l | [] -> 0 in
          findings := (Printf.sprintf "%s called %d times — check for duplicate validation logic"
            method_name (List.length matching), line) :: !findings
      ) validation_methods
    | _ -> ()
  and findings = ref [] in
  List.iter check_item m.mod_items;
  !findings

(* ── Category 8: The Looper (Iteration Mistakes) ────────────────────── *)

(** Rule: Magic String Comparison
    Detects hardcoded string literals used in equality comparisons.
    AI often uses stringly-typed checks instead of enums or constants.
    Skips strings < 3 chars (like "", " ", "0") and common safe patterns. *)

let detect_magic_string (m : t) =
  let is_magic (s : string) =
    String.length s >= 3 &&
    not (String.length s >= 4 && String.sub s 0 4 = "http") &&
    not (String.length s >= 6 && String.sub s 0 6 = "sqlite") &&
    not (String.length s >= 10 && String.sub s 0 10 = "postgresql")
  in
  let rec collect_equality_strings (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, args) when get_full_name fn = "==" ->
      List.filter_map (fun a ->
        match a.expr_value with
        | ELiteral (LString s) when is_magic s -> Some (s, a.expr_location.start.line)
        | _ -> None
      ) args
    | EBlock es -> List.concat_map collect_equality_strings es
    | ELet (_, e1, e2) -> collect_equality_strings e1 @ collect_equality_strings e2
    | EIf (_, then_, else_) ->
      collect_equality_strings then_ @
      (match else_ with Some e -> collect_equality_strings e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := List.concat_map (fun (s, line) ->
        [Printf.sprintf "Magic string \"%s\" used in comparison — consider using a constant or enum" s, line]
      ) (collect_equality_strings body) @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Debug Require
    Detects require statements for debug/development gems that shouldn't
    be in production code. *)

let detect_debug_require (m : t) =
  let debug_requires = [
    "debug"; "pry"; "byebug"; "binding_of_caller"; "irb";
    "debugger"; "pry-byebug"; "pry-doc"; "pry-stack_explorer";
  ] in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IImport (name, _) ->
      if List.mem name debug_requires then
        [let line = item.item_location.start.line in
         (Printf.sprintf "require \"%s\" is a debug dependency — remove for production" name, line)]
      else []
    | _ -> []
  ) m.mod_items

(* ── Category 9: Code Quality ────────────────────────────────────────── *)

(** Rule: Empty Catch Block
    Detects rescue/except blocks with empty bodies — errors swallowed silently.
    AI often generates empty rescue blocks as placeholders. *)

let detect_empty_catch (m : t) =
  
  let rec has_empty_rescue (e : expr) =
    match e.expr_value with
    | EApp (fn, args) when get_full_name fn = "rescue" ->
        let has_body = List.exists (fun a ->
          match a.expr_value with
          | EBlock [] | EUnit -> false
          | _ -> true
        ) args in
        if not has_body then Some e.expr_location.start.line else None
    | EBlock es -> List.find_map has_empty_rescue es
    | ELet (_, e1, e2) ->
        (match has_empty_rescue e1 with Some l -> Some l | None -> has_empty_rescue e2)
    | EIf (_, then_, else_) ->
        (match has_empty_rescue then_ with
         | Some l -> Some l
         | None -> (match else_ with Some e -> has_empty_rescue e | None -> None))
    | _ -> None
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      (match has_empty_rescue body with
       | Some line -> [("Empty rescue block — errors are silently swallowed. Log or handle the exception.", line)]
       | None -> [])
    | _ -> []
  ) m.mod_items

(* Rule: Flag Argument
    Detects boolean-style parameters (is_X, should_X, has_X, with_X, no_X).
    AI-generated code often uses flag arguments instead of separate methods or enums. *)

let detect_flag_argument (m : t) =
  
  let is_flag_name (s : string) =
    String.length s >= 3 &&
    let prefixes = ["is_"; "should_"; "has_"; "with_"; "no_"; "use_"; "enable_"; "disable_"] in
    List.exists (fun p -> String.length s > String.length p && String.sub s 0 (String.length p) = p) prefixes
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let flag_params = List.filter_map (function
        | PVar v when is_flag_name v -> Some v
        | _ -> None
      ) patterns in
      List.concat_map (fun p ->
        [let line = item.item_location.start.line in
         (Printf.sprintf "Function '%s' has flag argument '%s' — consider splitting into separate methods or using an enum" name p, line)]
      ) flag_params
    | _ -> []
  ) m.mod_items

(** Rule: Long Method
    Detects functions with too many expression nodes in their body.
    AI often generates monolithic functions that should be decomposed. *)

let detect_long_method (m : t) =
  let max_nodes = 50 in
  let rec count_nodes (e : expr) : int =
    match e.expr_value with
    | EBlock es -> List.fold_left (fun acc e -> acc + count_nodes e) 0 es
    | ELet (_, e1, e2) -> 1 + count_nodes e1 + count_nodes e2
    | EIf (_, then_, else_) ->
        1 + count_nodes then_ +
        (match else_ with Some e -> count_nodes e | None -> 0)
    | ECase (_, branches) ->
        1 + List.fold_left (fun acc (_, e) -> acc + count_nodes e) 0 branches
    | EApp (fn, args) -> 1 + count_nodes fn + List.fold_left (fun acc e -> acc + count_nodes e) 0 args
    | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body; _ } ->
        1 + count_nodes try_body +
        List.fold_left (fun acc rc -> acc + count_nodes rc.rescue_body) 0 rescue_clauses +
        (match ensure_body with Some e -> count_nodes e | None -> 0) +
        (match else_body with Some e -> count_nodes e | None -> 0)
    | _ -> 1
  in
  
  let rec count_nodes (e : expr) : int =
    match e.expr_value with
    | EBlock es -> List.fold_left (fun acc e -> acc + count_nodes e) 0 es
    | EApp (_, args) -> 1 + List.fold_left (fun acc a -> acc + count_nodes a) 0 args
    | EIf (_, then_, else_) ->
      1 + count_nodes then_ +
      (match else_ with Some e -> count_nodes e | None -> 0)
    | ELet (_, e1, e2) -> 1 + count_nodes e1 + count_nodes e2
    | ECase (_, branches) ->
      1 + List.fold_left (fun acc (_, body) -> acc + count_nodes body) 0 branches
    | _ -> 1
  in
  let max_nodes = 80 in
  let rec collect_functions (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (name, _, _, body) ->
        let count = count_nodes body in
        if count > max_nodes then
          [let line = item.item_location.start.line in
           (Printf.sprintf "Function '%s' has %d AST nodes (max %d) — consider breaking into smaller functions" name count max_nodes, line)]
        else []
      | IModule (_, items) | IClass (_, items) ->
        collect_functions items
      | _ -> []
    ) items
  in
  collect_functions m.mod_items

(* ── Category 10: The Looper & Misc ─────────────────────────────────── *)

(** Rule: Infinite Recursion
    Detects a function that calls itself with the same argument names
    unchanged — a common AI mistake when generating recursive functions. *)

let detect_infinite_recursion (m : t) =
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (fname, params, _, body) ->
      let param_names = List.filter_map (function PVar v -> Some v | _ -> None) params in
      let calls = collect_app_names body in
      List.iter (fun (name, line) ->
        if name = fname then begin
          let is_unchanged = List.exists (fun p ->
            List.exists (fun (n, _) -> n = p) calls
          ) param_names in
          if is_unchanged then
            collected := (Printf.sprintf
              "Function '%s' calls itself with unchanged argument — possible infinite recursion" fname, line) :: !collected
        end
      ) calls
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Debug Print
    Broader than deprecated-syntax — catches print, printf, p!, pp!,
    stderr.puts, STDERR.print that are left in production code. *)

let detect_debug_print (m : t) =
  let debug_calls = [
    "print"; "printf"; "p!"; "pp!";
    "stderr.puts"; "STDERR.puts"; "STDERR.print"; "STDERR.printf";
    "debug_print"; "debug_puts"; "log.debug";
  ] in
  let is_debug (name : string) =
    List.exists (fun prefix ->
      name = prefix ||
      (String.length name > String.length prefix + 1 &&
       String.sub name (String.length name - String.length prefix - 1) (String.length prefix + 1) = "." ^ prefix)
    ) debug_calls
  in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if is_debug name then
          [(Printf.sprintf "Debug output via %s — remove or gate behind a debug flag before production" name, line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule: String Interpolation in Query
    Detects string interpolation or concatenation patterns that build
    SQL/HTML/shell commands — a classic injection vector.
    Catches calls named like concat/interpolate near DB/query methods. *)

let detect_string_interpolation_in_query (m : t) =
  let query_methods = [
    "DB.query"; "DB.exec"; "DB.query_one"; "DB.query_one?";
    "database.query"; "db.query"; "repo.query"; "repo.exec";
  ] in
  
  let is_query (name : string) =
    List.exists (fun q ->
      String.length name >= String.length q &&
      String.sub name (String.length name - String.length q) (String.length q) = q
    ) query_methods
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let has_interpolation = List.exists (fun (n, _) ->
        n = "String.interpolation" || n = "String.concat" || n = "sprintf"
      ) calls in
      let has_query = List.exists (fun (n, _) -> is_query n) calls in
      if has_interpolation && has_query then
        [let line = match List.find_opt (fun (n, _) -> is_query n) calls with
          | Some (_, l) -> l | None -> 0
        in ("String interpolation used near database query — use parameterized queries instead", line)]
      else []
    | _ -> []
  ) m.mod_items

(* ── Category 11: Structural Complexity ────────────────────────────── *)

(** Rule: Complex Conditional
    Detects boolean expressions with 4+ && / || operators.
    AI often generates monster conditions instead of extracting predicates. *)