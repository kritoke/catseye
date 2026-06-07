(* src/ocaml/lib/ai_linter/crystal_rules_complexity.ml
   Categories 11-15: Structural Complexity

   Detects deep nesting, complex conditionals, message chains, data
   clumps, feature envy, callback hell, repeated regexes, and too
   many parameters.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(* Rule 11.1: Complex Conditional
   Detects boolean expressions with 4+ && / || operators. *)
let detect_complex_conditional (m : t) =
  let max_operators = 3 in
  let count_bool_ops (e : expr) : int =
    let open Stdlib in
    map_subexpressions (fun sub ->
      match sub.expr_value with
      | EApp (fn, _) ->
        let name = get_full_name fn in
        if name = "&&" || name = "||" || name = "and" || name = "or" then [1] else []
      | _ -> []
    ) e
    |> List.fold_left (+) 0
  in
  map_functions m (fun fname body _line ->
    let count = count_bool_ops body in
    if count > max_operators then
      [(Printf.sprintf "Function '%s' has %d boolean operators (max %d) — extract into named predicates"
          fname count max_operators, 0)]
    else []
  )

(* Rule 11.2: Message Chain (Law of Demeter) *)
let detect_message_chain (m : t) =
  let max_depth = 4 in
  let rec chain_depth (e : expr) : int =
    match e.expr_value with
    | EFieldAccess (recv, _) -> 1 + chain_depth recv
    | _ -> 0
  in
  map_functions m (fun _name body _line ->
    List.filter_map (fun sub ->
      match sub.expr_value with
      | EApp (fn, _) ->
        let depth = chain_depth fn in
        if depth > max_depth then
          Some (Printf.sprintf
            "Call chain has %d segments (max %d) — violates Law of Demeter, use intermediate variables"
            depth max_depth, sub.expr_location.start.line)
        else None
      | _ -> None
    ) (map_subexpressions (fun e -> [e]) body)
  )

(* Rule 11.3: Nested Ternary *)
let detect_nested_ternary (m : t) =
  let rec ternary_depth (e : expr) : int =
    match e.expr_value with
    | EIf (_, then_, else_) ->
      let t = ternary_depth then_ in
      let e_depth = match else_ with Some e -> ternary_depth e | None -> 0 in
      1 + max t e_depth
    | _ -> 0
  in
  let is_nested (e : expr) =
    match e.expr_value with
    | EIf _ when ternary_depth e >= 3 -> Some ("", e.expr_location.start.line)
    | _ -> None
  in
  map_functions m (fun _name body _line ->
    List.filter_map is_nested
      (map_subexpressions (fun e -> [e]) body)
  )

(* Rule 12.1: Data Clump
   Detects the same pair of parameters appearing together in 3+ functions. *)
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
  let findings = List.concat_map (fun (key, count) ->
    if count >= min_co_occurrence then
      let pair_name = String.map (fun c -> if c = ',' then ' ' else c) key in
      let line = match m.mod_items with
        | item :: _ -> item.item_location.start.line
        | [] -> 0
      in
      [Printf.sprintf "Parameters %s appear together in %d functions — consider grouping into a record"
         pair_name count, line]
    else []
  ) (Hashtbl.fold (fun key count acc -> (key, count) :: acc) pair_counts []) in
  list_sort_uniq (fun (_, l1) (_, l2) -> compare l1 l2) findings

(* Rule 12.2: Feature Envy
   Detects functions that make most of their calls on a single external type. *)
let detect_feature_envy (m : t) =
  let min_calls = 5 in
  let envy_threshold = 0.7 in
  map_functions m (fun fname body line ->
    let calls = collect_app_names body in
    let receiver_counts = Hashtbl.create 16 in
    List.iter (fun (call_name, _) ->
      (match String.index_opt call_name '.' with
       | Some idx ->
         let receiver = String.sub call_name 0 idx in
         let current = try Hashtbl.find receiver_counts receiver with Stdlib.Not_found -> 0 in
         Hashtbl.replace receiver_counts receiver (current + 1)
       | None -> ());
    ) calls;
    let total = List.length calls in
    if total >= min_calls then
      Hashtbl.fold (fun receiver count acc ->
        let ratio = Float.of_int count /. Float.of_int total in
        if ratio >= envy_threshold then
          (Printf.sprintf
            "Function '%s' makes %d/%d calls on '%s' (%.0f%%) — consider moving to %s module"
            fname count total receiver (ratio *. 100.0) receiver, line) :: acc
        else acc
      ) receiver_counts []
    else []
  )

(* Rule 14.3: Callback Hell
   Detects 3+ levels of nested anonymous functions / blocks. *)
let detect_callback_hell (m : t) =
  let max_depth = 2 in
  let rec fn_depth (e : expr) : int =
    match e.expr_value with
    | EFn (_, body) -> 1 + fn_depth body
    | EBlock es -> List.fold_left (fun acc e -> max acc (fn_depth e)) 0 es
    | _ -> 0
  in
  map_functions m (fun fname body _line ->
    let depth = fn_depth body in
    if depth > max_depth then
      [Printf.sprintf
        "Function '%s' has %d levels of nested closures (max %d) — flatten with named functions"
        fname depth max_depth, 0]
    else []
  )

(* Rule 14.4: Repeated Regex
   Detects the same regex literal appearing in 2+ functions. *)
let detect_repeated_regex (m : t) =
  let regex_by_func = Map.Poly.empty in
  let regex_locations = Map.Poly.empty in
  List.fold_left (fun (by_func, locs) item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let regexes = map_subexpressions (fun sub ->
        match sub.expr_value with
        | ELiteral (LString s) when
            String.length s >= 3 &&
            (String.length s >= 2 && String.sub s 0 1 = "/" ||
             String.length s >= 3 && String.sub s 0 2 = "r/") ->
          [(s, sub.expr_location.start.line)]
        | _ -> []
      ) body in
      let line = item.item_location.start.line in
      let new_by_func = List.fold_left (fun acc (rx, _) ->
        let funcs = Map.Poly.find acc rx |> Option.value ~default:[] in
        Map.Poly.set acc ~key:rx ~data:(name :: funcs)
      ) by_func regexes in
      let new_locs = List.fold_left (fun acc (rx, _) ->
        let existing = Map.Poly.find acc rx |> Option.value ~default:[] in
        Map.Poly.set acc ~key:rx ~data:((name, line) :: existing)
      ) locs regexes in
      (new_by_func, new_locs)
    | _ -> (by_func, locs)
  ) (regex_by_func, regex_locations) m.mod_items
  |> snd
  |> Map.Poly.to_alist
  |> List.concat_map (fun (rx, locations) ->
    if List.length locations >= 2 then
      let funcs = String.concat ", " (List.map fst locations) in
      let _, line = List.hd locations in
      [Printf.sprintf "Regex %s duplicated in functions: %s — extract to a constant"
         rx funcs, line]
    else [])

(* Rule 15.1: Too Many Parameters
   Detects functions with 7+ parameters. *)
let detect_too_many_params (m : t) =
  let max_params = 6 in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, params, _, _) ->
      let count = List.length params in
      if count > max_params then
        Some (Printf.sprintf
          "Function '%s' has %d parameters (max %d) — group into a configuration record"
          name count max_params, item.item_location.start.line)
      else None
    | _ -> None
  ) m.mod_items
