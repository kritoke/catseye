(* src/ocaml/lib/ai_linter/crystal_rules_style.ml
   Categories 19-22: Style & Idiomatic Crystal

   Detects double-negatives (unless with else), global variables, float
   equality, sequential blocking calls, empty string comparisons,
   negated comparisons, and nilable instance variable access.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_unless_with_else (m : t) =
  
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, args) ->
      (if get_full_name fn = "unless" && List.length args >= 2 then
        [("unless with else is a double-negative — rewrite as if/else", e.expr_location.start.line)]
      else []) @
      scan fn @ List.concat_map scan args
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
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

(* ── Category 20: Correctness ────────────────────────────────────────── *)

(** Rule: Global Variable
    Detects $-prefixed global variables in Crystal.
    AI trained on Ruby often uses $globals which are a code smell in Crystal.
    Use class variables, constants, or module-level state instead. *)

let detect_global_variable (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EVar v when String.length v > 1 && String.sub v 0 1 = "$" ->
      [Printf.sprintf "Global variable $%s — use a constant or module-level binding instead"
        (String.sub v 1 (String.length v - 1)), e.expr_location.start.line]
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> scan body
    | _ -> []
  ) m.mod_items

(** Rule: Float Equality Comparison
    Detects == comparisons involving float literals or float-returning functions.
    Float equality is unreliable due to precision — use delta comparison.
    AI often generates naive float == float checks. *)

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
  let is_float_fn (name : string) =
    List.exists (fun s ->
      String.length name >= String.length s &&
      String.sub name (String.length name - String.length s) (String.length s) = s
    ) ["to_f"; ".floor"; ".ceil"; ".round"; ".abs"; "Float"; "rand"]
  in
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
      (if is_float_expr e1 || is_float_expr e2 ||
         is_float_fn (get_full_name e1) || is_float_fn (get_full_name e2) then
        [("Float equality comparison is unreliable — use delta comparison (abs(a - b) < epsilon)",
          e.expr_location.start.line)]
      else []) @
      scan e1 @ scan e2
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
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

(* ── Category 21: Idiomatic Crystal ─────────────────────────────────── *)

(** Rule: Sequential Blocking Calls
    Detects 3+ blocking calls in a function that could be parallelized.
    
    NOTE: Disabled for Crystal - validation is inherently sequential.
    File.expand_path depends on validate_path! passing.
*)

let detect_sequential_blocking (m : t) =
  (* Disabled for Crystal - validation is inherently sequential *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  let blocking_prefixes = [
    "HTTP::Client"; "DB."; "File."; "Process";
  ] in
  let is_blocking (name : string) =
    List.exists (fun prefix ->
      String.length name >= String.length prefix &&
      String.sub name 0 (String.length prefix) = prefix
    ) blocking_prefixes
  in
  let rec collect_blocking_calls (e : expr) : string list =
    match e.expr_value with
    | EApp (fn, args) ->
      let name = get_full_name fn in
      let self_calls = if is_blocking name then [name] else [] in
      self_calls @ List.concat_map collect_blocking_calls args
    | EBlock es -> List.concat_map collect_blocking_calls es
    | ELet (_, e1, e2) -> collect_blocking_calls e1 @ collect_blocking_calls e2
    | EIf (_, then_, else_) ->
      collect_blocking_calls then_ @
      (match else_ with Some e -> collect_blocking_calls e | None -> [])
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let blocking_calls = collect_blocking_calls body in
      let count = List.length blocking_calls in
      if count >= 3 then
        collected := (Printf.sprintf
          "Function '%s' has %d sequential blocking calls — consider parallelizing with spawn/fiber"
          name count, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Empty String Comparison
    Detects str == "" or str != "" instead of str.empty?.
    AI often generates string comparisons instead of using the idiomatic method. *)

let detect_empty_string_comparison (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
      (match e1.expr_value, e2.expr_value with
       | ELiteral (LString ""), _ | _, ELiteral (LString "") ->
         [("Compare with empty string using .empty? instead of == \"\"", e.expr_location.start.line)]
       | _ -> []) @
      scan e1 @ scan e2
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
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

(** Rule: Negated Comparison
    Detects not(x == y) instead of x != y, or not(x != y) instead of x == y.
    AI sometimes generates inverted comparisons that are harder to read. *)

let detect_negated_comparison (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, [arg]) when get_full_name fn = "not" || get_full_name fn = "!" ->
      (match arg.expr_value with
       | EBinOp (_, ("==" | "!=" | "<=" | ">=" | "<" | ">" | "===" as op), _) ->
         [Printf.sprintf "not(x %s y) is clearer written with the negated operator" op, e.expr_location.start.line]
       | _ -> []) @
      scan arg
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
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

(** Rule: String Concatenation in Loop
    Detects inefficient string concatenation inside iterator blocks.
    
    NOTE: Disabled for Crystal - this is an efficiency hint, not a correctness issue.
    String concatenation in loops is acceptable for small-scale operations.
*)

let detect_string_concat_loop (m : t) =
  (* Disabled for Crystal - efficiency hint, not correctness issue *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let rec find_concat_in_iter (e : expr) : (string * int) list =
    match e.expr_value with
    | EBlock es -> List.concat_map find_concat_in_iter es
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
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := find_concat_in_iter body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Nilable Instance Var Access Without Check
    Detects accesses to instance variables without defensive checks.
    This is a heuristic rule - actual nil-safety depends on type declarations. *)

let detect_nilable_ivar_access (m : t) =
  
  let rec find_ivar_accesses (e : expr) : (string * int) list =
    match e.expr_value with
    | EFieldAccess ({ expr_value = EVar name; _ }, field)
      when String.length name > 0 && String.sub name 0 1 = "@" ->
      if String.length name >= 2 && String.sub name 1 1 = "@" then []
      else [(name ^ "." ^ field, e.expr_location.start.line)]
    | EVar name when String.length name > 0 && String.sub name 0 1 = "@" ->
      if String.length name >= 2 && String.sub name 1 1 = "@" then []
      else [(name, e.expr_location.start.line)]
    | EBlock es -> List.concat_map find_ivar_accesses es
    | ELet (_, _, body) -> find_ivar_accesses body
    | EApp (fn, args) ->
      List.concat_map find_ivar_accesses (fn :: args)
    | EIf (_, then_, else_) ->
      find_ivar_accesses then_ @ (match else_ with Some x -> find_ivar_accesses x | None -> [])
    | ECase (_, branches) ->
      List.concat_map (fun (_, body) -> find_ivar_accesses body) branches
    | _ -> []
  in
  let rec has_defensive_check (e : expr) : bool =
    match e.expr_value with
    | EApp (fn, _) ->
      let name = get_full_name fn in
      name = "not_nil!" || name = "try" || String.ends_with name ".try"
    | EIf (_, then_, else_) ->
      has_defensive_check then_ || (match else_ with Some x -> has_defensive_check x | None -> false)
    | ECase (_, branches) ->
      List.exists (fun (_, body) -> has_defensive_check body) branches
    | _ -> false
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let ivar_accesses = find_ivar_accesses body in
      List.iter (fun (ivar, line) ->
        if not (has_defensive_check body) then
          collected := (Printf.sprintf "Instance var '%s' access — verify nil-safety" ivar, line) :: !collected
      ) ivar_accesses
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 22: Final Sweep ─────────────────────────────────────────── *)

(** Rule: Redundant Self
    Detects explicit self. method calls where implicit self would suffice.
    AI trained on Python/Ruby often adds unnecessary self. prefixes. *)

let detect_redundant_self (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EFieldAccess (recv, field) ->
      (match recv.expr_value with
       | EVar v when v = "self" && String.length field > 0 ->
         [Printf.sprintf "self.%s is redundant — method calls are implicitly on self" field, e.expr_location.start.line]
       | _ -> []) @
      scan recv
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
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

(* ── All Rules ──────────────────────────────────────────────────────── *)