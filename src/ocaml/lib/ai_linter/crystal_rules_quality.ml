(* src/ocaml/lib/ai_linter/crystal_rules_quality.ml
   Categories 7-10: Code Quality

   Detects blanket rescues, magic strings, debug requires, empty catch
   blocks, flag arguments, long methods, infinite recursion, debug
   prints, and string interpolation in queries.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(* Rule 7.1: Blanket Rescue
   Detects bare `rescue` or `rescue ex` without specifying an exception type. *)
let detect_blanket_rescue (m : t) =
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if call_name = "rescue" || call_name = "begin" then
        Some ("Blanket rescue catches all exceptions — catch specific exception types instead", line)
      else None
    ) (collect_app_names body)
  )

(* Rule 7.2: Duplicate Validation
   Disabled for Crystal - defense-in-depth validation is intentional. *)
let detect_duplicate_validation (m : t) =
  match m.mod_lang with
  | Crystal -> []
  | _ ->
    let validation_methods = ["empty?"; "nil?"; "blank?"; "valid?"; "present?"; "includes?"] in
    List.filter_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        let calls = collect_app_names body in
        let findings = ref [] in
        List.iter (fun method_name ->
          let matching = List.filter (fun (n, _) ->
            name_ends_with_any n [method_name]
          ) calls in
          if List.length matching >= 3 then
            let line = match matching with (_, l) :: _ -> l | [] -> 0 in
            findings := (Printf.sprintf "%s called %d times — check for duplicate validation logic"
                          method_name (List.length matching), line) :: !findings
        ) validation_methods;
        if !findings = [] then None else Some !findings
      | _ -> None
    ) m.mod_items |> List.concat

(* Rule 8.1: Magic String Comparison
   Detects hardcoded string literals used in equality comparisons. *)
let detect_magic_string (m : t) =
  let is_magic s =
    String.length s >= 3 &&
    not (String.length s >= 4 && String.sub s 0 4 = "http") &&
    not (String.length s >= 6 && String.sub s 0 6 = "sqlite") &&
    not (String.length s >= 10 && String.sub s 0 10 = "postgresql")
  in
  let collect_equality_strings (e : expr) =
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, args) when get_full_name fn = "==" ->
        List.filter_map (fun a ->
          match a.expr_value with
          | ELiteral (LString s) when is_magic s -> Some (s, a.expr_location.start.line)
          | _ -> None
        ) args
      | _ -> []
    ) e
  in
  map_functions m (fun _name body _line ->
    List.map (fun (s, line) ->
      Printf.sprintf "Magic string \"%s\" used in comparison — consider using a constant or enum" s, line
    ) (collect_equality_strings body)
  )

(* Rule 8.2: Debug Require
   Detects require statements for debug/development gems. *)
let detect_debug_require (m : t) =
  let debug_requires = [
    "debug"; "pry"; "byebug"; "binding_of_caller"; "irb";
    "debugger"; "pry-byebug"; "pry-doc"; "pry-stack_explorer";
  ] in
  List.filter_map (fun item ->
    match item.item_value with
    | IImport (name, _) when List.mem name debug_requires ->
      Some (Printf.sprintf "require \"%s\" is a debug dependency — remove for production" name,
            item.item_location.start.line)
    | _ -> None
  ) m.mod_items

(* Rule 9.1: Empty Catch Block
   Detects rescue/except blocks with empty bodies. *)
let detect_empty_catch (m : t) =
  let has_empty_rescue (e : expr) =
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, args) when get_full_name fn = "rescue" ->
        let has_body = List.exists (fun a ->
          match a.expr_value with EBlock [] | EUnit -> false | _ -> true
        ) args in
        if not has_body then [sub.expr_location.start.line] else []
      | _ -> []
    ) e
  in
  map_functions m (fun _name body _line ->
    let line = match has_empty_rescue body with l :: _ -> l | [] -> 0 in
    if line > 0 then
      [("Empty rescue block — errors are silently swallowed. Log or handle the exception.", line)]
    else []
  )

(* Rule 9.2: Flag Argument
   Detects boolean-style parameters (is_X, should_X, has_X, with_X). *)
let detect_flag_argument (m : t) =
  let is_flag_name s =
    String.length s >= 3 &&
    let prefixes = ["is_"; "should_"; "has_"; "with_"; "no_"; "use_"; "enable_"; "disable_"] in
    List.exists (fun p -> String.length s > String.length p && String.sub s 0 (String.length p) = p) prefixes
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let flag_params = List.filter_map (function PVar v when is_flag_name v -> Some v | _ -> None) patterns in
      if flag_params = [] then None
      else Some (List.map (fun p ->
        Printf.sprintf "Function '%s' has flag argument '%s' — consider splitting into separate methods or using an enum" name p,
        item.item_location.start.line
      ) flag_params)
    | _ -> None
  ) m.mod_items |> List.concat

(* Rule 9.3: Long Method
   Detects functions with too many expression nodes. *)
let detect_long_method (m : t) =
  let max_nodes = 80 in
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
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let count = count_nodes body in
      if count > max_nodes then
        Some (Printf.sprintf "Function '%s' has %d AST nodes (max %d) — consider breaking into smaller functions"
                name count max_nodes,
              item.item_location.start.line)
      else None
    | _ -> None
  ) m.mod_items

(* Rule 10.1: Infinite Recursion
   Detects a function that calls itself with the same argument names unchanged. *)
let detect_infinite_recursion (m : t) =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (fname, params, _, body) ->
      let param_names = List.filter_map (function PVar v -> Some v | _ -> None) params in
      let calls = collect_app_names body in
      let self_calls = List.filter (fun (n, _) -> n = fname) calls in
      let has_unchanged_arg = List.exists (fun (n, _) ->
        List.exists (fun p -> List.mem p [n]) param_names
      ) self_calls in
      if has_unchanged_arg then
        [Printf.sprintf "Function '%s' calls itself with unchanged argument — possible infinite recursion"
           fname, item.item_location.start.line]
      else []
    | _ -> []
  ) m.mod_items

(* Rule 10.2: Debug Print
   Broader than deprecated-syntax — catches print, printf, p!, pp!,
   stderr.puts, STDERR.print that are left in production code. *)
let detect_debug_print (m : t) =
  let debug_calls = [
    "print"; "printf"; "p!"; "pp!";
    "stderr.puts"; "STDERR.puts"; "STDERR.print"; "STDERR.printf";
    "debug_print"; "debug_puts"; "log.debug";
  ] in
  map_functions m (fun _name body _line ->
    List.filter_map (fun (call_name, line) ->
      if name_matches call_name debug_calls then
        Some (Printf.sprintf "Debug output via %s — remove or gate behind a debug flag before production"
                call_name, line)
      else None
    ) (collect_app_names body)
  )
