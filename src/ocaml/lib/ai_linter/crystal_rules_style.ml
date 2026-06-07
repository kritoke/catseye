(* src/ocaml/lib/ai_linter/crystal_rules_style.ml
   Categories 19-22: Style & Idiomatic Crystal

   Detects double-negatives (unless with else), global variables, float
   equality, sequential blocking calls, empty string comparisons,
   negated comparisons, and nilable instance variable access.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(* Rule 19.1: Unless with Else
   Detects `unless ... else ...` constructs (double negatives). *)
let detect_unless_with_else (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, args) when get_full_name fn = "unless" && List.length args >= 2 ->
        [("unless with else is a double-negative — rewrite as if/else",
          sub.expr_location.start.line)]
      | _ -> []
    ) body
  )

(* Rule 20.1: Global Variable
   Detects $-prefixed global variables in Crystal. *)
let detect_global_variable (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EVar v when String.length v > 1 && String.sub v 0 1 = "$" ->
        [Printf.sprintf "Global variable $%s — use a constant or module-level binding instead"
          (String.sub v 1 (String.length v - 1)),
          sub.expr_location.start.line]
      | _ -> []
    ) body
  )

(* Rule 20.2: Float Equality Comparison
   Detects == comparisons involving float literals or float-returning functions. *)
let detect_float_equality (m : t) =
  let is_float_expr (e : expr) =
    match e.expr_value with
    | ELiteral (LFloat _) -> true
    | ELiteral (LString s) ->
      String.length s > 0 &&
      let has_dot = String.contains s '.' in
      let is_num = List.for_all (fun c -> Char.code c >= 48 && Char.code c <= 57 || c = '.')
        (List.init (String.length s) (fun i -> s.[i])) in
      has_dot && is_num
    | _ -> false
  in
  let is_float_fn name =
    let suffixes = ["to_f"; ".floor"; ".ceil"; ".round"; ".abs"; "Float"; "rand"] in
    name_ends_with_any name suffixes
  in
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
        if is_float_expr e1 || is_float_expr e2
          || is_float_fn (get_full_name e1) || is_float_fn (get_full_name e2) then
          [("Float equality comparison is unreliable — use delta comparison (abs(a - b) < epsilon)",
            sub.expr_location.start.line)]
        else []
      | _ -> []
    ) body
  )

(* Rule 21.1: Sequential Blocking Calls
   Disabled for Crystal - validation is inherently sequential. *)
let detect_sequential_blocking (m : t) =
  match m.mod_lang with
  | Crystal -> []
  | _ ->
    let blocking_prefixes = ["HTTP::Client"; "DB."; "File."; "Process"] in
    let is_blocking name = name_starts_with_any name blocking_prefixes in
    let collect_blocking_calls (e : expr) =
      map_subexpressions (fun sub ->
        match sub.expr_value with
        | EApp (fn, _) when is_blocking (get_full_name fn) ->
          [get_full_name fn]
        | _ -> []
      ) e
    in
    map_functions m (fun fname body _line ->
      let count = List.length (collect_blocking_calls body) in
      if count >= 3 then
        [Printf.sprintf
          "Function '%s' has %d sequential blocking calls — consider parallelizing with spawn/fiber"
          fname count, 0]
      else []
    )

(* Rule 21.2: Empty String Comparison
   Detects str == "" or str != "" instead of str.empty?. *)
let detect_empty_string_comparison (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
        (match e1.expr_value, e2.expr_value with
         | ELiteral (LString ""), _ | _, ELiteral (LString "") ->
           [("Compare with empty string using .empty? instead of == \"\"",
             sub.expr_location.start.line)]
         | _ -> [])
      | _ -> []
    ) body
  )

(* Rule 21.3: Negated Comparison
   Detects not(x == y) instead of x != y. *)
let detect_negated_comparison (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, [arg]) when get_full_name fn = "not" || get_full_name fn = "!" ->
        (match arg.expr_value with
         | EBinOp (_, (("==" | "!=" | "<=" | ">=" | "<" | ">" | "===") as op), _) ->
           [Printf.sprintf "not(x %s y) is clearer written with the negated operator" op,
            sub.expr_location.start.line]
         | _ -> [])
      | _ -> []
    ) body
  )

(* Rule 21.4: String Concatenation in Loop
   Disabled for Crystal - efficiency hint, not correctness issue. *)
let detect_string_concat_loop (m : t) =
  match m.mod_lang with
  | Crystal -> []
  | _ ->
    let rec find_concat_in_iter (e : expr) : (string * int) list =
      match e.expr_value with
      | EApp (fn, [arg]) when is_iterator_method (get_full_name fn) ->
        (match arg.expr_value with
         | EFn (_, body) -> find_concat_in_iter body
         | _ -> [])
      | EApp (fn, _) when is_string_concat (get_full_name fn) ->
        [(get_full_name fn, e.expr_location.start.line)]
      | ELet (_, _, body) -> find_concat_in_iter body
      | EIf (_, then_, else_) ->
        find_concat_in_iter then_ @ (match else_ with Some x -> find_concat_in_iter x | None -> [])
      | ECase (_, branches) -> List.concat_map (fun (_, body) -> find_concat_in_iter body) branches
      | _ -> []
    and is_iterator_method (name : string) =
      List.mem name ["each"; "map"; "select"; "reject"; "transform"; "each_with_index"]
    and is_string_concat (name : string) =
      name = "String.+" || name = "+@" || name = "+"
    in
    map_functions m (fun _name body _line -> find_concat_in_iter body)

(* Rule 21.5: Nilable Instance Var Access Without Check
   Detects accesses to instance variables without defensive checks. *)
let detect_nilable_ivar_access (m : t) =
  let find_ivar_accesses (e : expr) : (string * int) list =
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EFieldAccess ({ expr_value = EVar name; _ }, field)
        when String.length name > 0 && String.sub name 0 1 = "@" ->
        if String.length name >= 2 && String.sub name 1 1 = "@" then []
        else [(name ^ "." ^ field, sub.expr_location.start.line)]
      | EVar name when String.length name > 0 && String.sub name 0 1 = "@" ->
        if String.length name >= 2 && String.sub name 1 1 = "@" then []
        else [(name, sub.expr_location.start.line)]
      | _ -> []
    ) e
  in
  let has_defensive_check (e : expr) : bool =
    List.exists ((=) true) (map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, _) ->
        let name = get_full_name fn in
        if name = "not_nil!" || name = "try" || String.ends_with name ".try" then [true]
        else []
      | _ -> []
    ) e)
  in
  map_functions m (fun _name body _line ->
    let ivar_accesses = find_ivar_accesses body in
    if not (has_defensive_check body) then
      List.map (fun (ivar, line) ->
        Printf.sprintf "Instance var '%s' access — verify nil-safety" ivar, line
      ) ivar_accesses
    else []
  )

(* Rule 22.1: Redundant Self
   Detects explicit self. method calls where implicit self would suffice. *)
let detect_redundant_self (m : t) =
  map_functions m (fun _name body _line ->
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EFieldAccess ({ expr_value = EVar "self"; _ }, field) when String.length field > 0 ->
        [Printf.sprintf "self.%s is redundant — method calls are implicitly on self" field,
          sub.expr_location.start.line]
      | _ -> []
    ) body
  )
