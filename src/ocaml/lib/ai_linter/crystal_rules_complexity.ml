(* src/ocaml/lib/ai_linter/crystal_rules_complexity.ml
   Categories 11-15: Structural Complexity

   Detects deep nesting, complex conditionals, message chains, data
   clumps, feature envy, callback hell, repeated regexes, and too
   many parameters.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_complex_conditional (m : t) =
  let max_operators = 3 in
  let rec count_bool_ops (e : expr) : int =
    match e.expr_value with
    | EApp (fn, args) ->
        let name = get_full_name fn in
        let own = if name = "&&" || name = "||" || name = "and" || name = "or" then 1 else 0 in
        own + List.fold_left (fun acc a -> acc + count_bool_ops a) 0 args
    | EBlock es -> List.fold_left (fun acc e -> acc + count_bool_ops e) 0 es
    | ELet (_, e1, e2) -> count_bool_ops e1 + count_bool_ops e2
    | EIf (_, then_, else_) ->
        count_bool_ops then_ + (match else_ with Some e -> count_bool_ops e | None -> 0)
    | _ -> 0
  in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let count = count_bool_ops body in
      if count > max_operators then
        [let line = item.item_location.start.line in
         (Printf.sprintf "Function '%s' has %d boolean operators (max %d) — extract into named predicates" name count max_operators, line)]
      else []
    | _ -> []
  ) m.mod_items

(** Rule: Message Chain (Law of Demeter)
    Detects call chains with 5+ dotted segments like `a.b.c.d.e.f`.
    AI often generates deep chains instead of using intermediate variables. *)

let detect_message_chain (m : t) =
  let max_depth = 4 in
  let rec chain_depth (e : expr) : int =
    match e.expr_value with
    | EFieldAccess (recv, _) -> 1 + chain_depth recv
    | _ -> 0
  in
  let rec find_chains (e : expr) : (int * int) list =
    match e.expr_value with
    | EApp (fn, args) ->
        let depth = chain_depth fn in
        let hits = if depth > max_depth then [(depth, e.expr_location.start.line)] else [] in
        hits @ List.concat_map find_chains args
    | EBlock es -> List.concat_map find_chains es
    | ELet (_, e1, e2) -> find_chains e1 @ find_chains e2
    | EIf (_, then_, else_) ->
        find_chains then_ @ (match else_ with Some e -> find_chains e | None -> [])
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun (depth, line) ->
        collected := (Printf.sprintf
          "Call chain has %d segments (max %d) — violates Law of Demeter, use intermediate variables"
          depth max_depth, line) :: !collected
      ) (find_chains body)
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Nested Ternary
    Detects nested ternary expressions (? :). AI sometimes generates
    deeply nested ternaries instead of case/cond. *)

let detect_nested_ternary (m : t) =
  let rec count_ternary_depth (e : expr) : int =
    match e.expr_value with
    | EIf (_, then_, else_) ->
        let then_depth = count_ternary_depth then_ in
        let else_depth = match else_ with Some e -> count_ternary_depth e | None -> 0 in
        1 + max then_depth else_depth
    | EBlock es -> List.fold_left (fun acc e -> max acc (count_ternary_depth e)) 0 es
    | ELet (_, e1, e2) -> max (count_ternary_depth e1) (count_ternary_depth e2)
    | _ -> 0
  in
  let rec find_nested_ternaries (e : expr) : int list =
    match e.expr_value with
    | EIf (_, then_, else_) when count_ternary_depth e >= 3 ->
        (* This is a nested ternary of depth 3+ *)
        e.expr_location.start.line :: List.concat_map find_nested_ternaries (
          then_ :: (match else_ with Some e -> [e] | None -> []))
    | EBlock es -> List.concat_map find_nested_ternaries es
    | ELet (_, e1, e2) -> find_nested_ternaries e1 @ find_nested_ternaries e2
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun line ->
        collected := ("Nested ternary expression (3+ levels) — use case/cond for readability", line) :: !collected
      ) (find_nested_ternaries body)
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 12: Design Smells ──────────────────────────────────────── *)

(** Rule: Data Clump
    Detects the same pair of parameters appearing together in 3+ functions.
    AI often generates repetitive parameter lists instead of grouping into a record. *)

let detect_data_clump (m : t) =
  let min_co_occurrence = 3 in
  
  
  
  
  let param_sets = List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, params, _, _) ->
      Some (List.filter_map (function PVar v -> Some v | _ -> None) params)
    | _ -> None
  ) m.mod_items in
  let pair_counts = Hashtbl.create 64 in
  List.iter (fun params ->
    let sorted = list_sort_uniq String.compare params in
    let rec count_pairs = function
      | [] | [_] -> ()
      | a :: rest ->
        List.iter (fun b ->
          let key = a ^ "," ^ b in
          let current = try Hashtbl.find pair_counts key with Stdlib.Not_found -> 0 in
          Hashtbl.replace pair_counts key (current + 1)
        ) rest;
        count_pairs rest
    in
    count_pairs sorted
  ) param_sets;
  let collected = List.concat_map (fun (key, count) ->
    if count >= min_co_occurrence then
      let pair_name = String.map (fun c -> if c = ',' then ' ' else c) key in
      let line = List.hd m.mod_items |> fun i -> i.item_location.start.line in
      [Printf.sprintf "Parameters %s appear together in %d functions — consider grouping into a record" pair_name count, line]
    else []
  ) (Hashtbl.fold (fun key count acc -> (key, count) :: acc) pair_counts []) in
  list_sort_uniq (fun (_, l1) (_, l2) -> compare l1 l2) collected

(** Rule: Feature Envy
    Detects functions that make most of their calls on a single external type.
    AI often generates functions that should be methods on the envied object. *)

let detect_feature_envy (m : t) =
  let min_calls = 5 in
  let envy_threshold = 0.7 in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let calls = collect_app_names body in
      (* Count calls by receiver prefix *)
      let receiver_counts = Hashtbl.create 16 in
      List.iter (fun (call_name, _) ->
        (match String.index_opt call_name '.' with
         | Some idx ->
             let receiver = String.sub call_name 0 idx in
             let current = try Hashtbl.find receiver_counts receiver with Stdlib.Not_found -> 0 in
             Hashtbl.replace receiver_counts receiver (current + 1)
         | None -> ());
      ) calls;
      let total_calls = List.length calls in
      if total_calls >= min_calls then
        Hashtbl.iter (fun receiver count ->
          let ratio = Float.of_int count /. Float.of_int total_calls in
          if ratio >= envy_threshold then
            collected := (Printf.sprintf
              "Function '%s' makes %d/%d calls on '%s' (%.0f%%) — consider moving to %s module"
              name count total_calls receiver (ratio *. 100.0) receiver,
              item.item_location.start.line) :: !collected
        ) receiver_counts
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 13: Dead Code ────────────────────────────────────────── *)

(** Rule: Dead Code After Error
    Detects code that appears after a raise/error expression.
    
    NOTE: In Crystal, guard clauses are idiomatic:
    ```crystal
    def validate!(x)
      raise Error.new if invalid?  # raise is the ERROR path
      # This IS reachable - it's the NORMAL path
    end
    ```
    This rule is DISABLED for Crystal as it produces false positives on guard patterns.
*)

let detect_callback_hell (m : t) =
  let max_depth = 2 in
  let rec fn_depth (e : expr) : int =
    match e.expr_value with
    | EFn (_, body) -> 1 + fn_depth body
    | EBlock es -> List.fold_left (fun acc e -> max acc (fn_depth e)) 0 es
    | ELet (_, e1, e2) -> max (fn_depth e1) (fn_depth e2)
    | EIf (_, then_, else_) ->
        max (fn_depth then_)
          (match else_ with Some e -> fn_depth e | None -> 0)
    | EApp (fn, args) -> max (fn_depth fn) (List.fold_left (fun acc a -> max acc (fn_depth a)) 0 args)
    | _ -> 0
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let depth = fn_depth body in
      if depth > max_depth then
        collected := (Printf.sprintf
          "Function '%s' has %d levels of nested closures (max %d) — flatten with named functions"
          name depth max_depth, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Repeated Regex
    Detects the same regex literal appearing in 2+ functions.
    AI often duplicates regex patterns instead of extracting to a constant. *)

let detect_repeated_regex (m : t) =
  let regex_by_func = Map.Poly.empty in
  let regex_locations = Map.Poly.empty in
  
  let rec collect_regexes (e : expr) : string list =
    match e.expr_value with
    | ELiteral (LString s) when
        String.length s >= 3 &&
        (String.length s >= 2 && String.sub s 0 1 = "/" ||
         String.length s >= 3 && String.sub s 0 2 = "r/") ->
        [s]
    | ELiteral (LString s) when
        String.length s >= 4 &&
        (String.sub s 0 1 = "^" || String.sub s (String.length s - 1) 1 = "$") &&
        List.exists (fun c -> String.contains s c) ['.'; '*'; '+'; '?'; '['; '('; '|'] ->
        [s]
    | EBlock es -> List.concat_map collect_regexes es
    | ELet (_, e1, e2) -> collect_regexes e1 @ collect_regexes e2
    | EApp (fn, args) -> collect_regexes fn @ List.concat_map collect_regexes args
    | EIf (_, then_, else_) ->
        collect_regexes then_ @ (match else_ with Some e -> collect_regexes e | None -> [])
    | _ -> []
  in
  let (regex_by_func, regex_locations) =
    List.fold_left (fun (by_func, locs) item ->
      match item.item_value with
      | IFunction (name, _, _, body) ->
        let rx_list = collect_regexes body in
        let new_by_func = List.fold_left (fun acc rx ->
          let funcs = Map.Poly.find acc rx |> Option.value ~default:[] in
          Map.Poly.set acc ~key:rx ~data:(name :: funcs)
        ) by_func rx_list in
        let new_locs = List.fold_left (fun acc rx ->
          let line = item.item_location.start.line in
          let existing = Map.Poly.find acc rx |> Option.value ~default:[] in
          Map.Poly.set acc ~key:rx ~data:((name, line) :: existing)
        ) locs rx_list in
        (new_by_func, new_locs)
      | _ -> (by_func, locs)
    ) (regex_by_func, regex_locations) m.mod_items in
  List.concat_map (fun (rx, locations) ->
    if List.length locations >= 2 then
      let funcs = String.concat ", " (List.map fst locations) in
      let _, line = List.hd locations in
      [Printf.sprintf "Regex %s duplicated in functions: %s — extract to a constant" rx funcs, line]
    else []
  ) (Map.Poly.to_alist regex_locations)

(* ── Category 15: Arity ────────────────────────────────────────────── *)

(** Rule: Too Many Parameters
    Detects functions with 7+ parameters.
    AI often generates functions with too many arguments instead of
    grouping into a configuration record/struct. *)

let detect_too_many_params (m : t) =
  let max_params = 6 in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, params, _, _) ->
      let count = List.length params in
      if count > max_params then
        collected := (Printf.sprintf
          "Function '%s' has %d parameters (max %d) — group into a configuration record"
          name count max_params, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 16: Exception Safety ─────────────────────────────────── *)

(** Rule: Open Rescue
    Detects rescue blocks that catch all exceptions without specifying a type.
    AI often generates bare 'rescue' or 'rescue ex' instead of 'rescue SpecificError'.
    Catches everything including SignalException, NoMemoryError etc. *)