(* lib/catseye_claws/extra_smells_ast.ml
   AST-native code smell detectors.

   Replaces the flat Security_node.t-based detectors in extra_smells.ml
   with exact tree-walking analysis on CatseyeAST.t.

   Detectors:
   - LongMethod        (count AST nodes in function body)
   - ComplexConditional(EBinOp &&/|| chain depth)
   - MessageChain      (EFieldAccess nesting depth)
   - DataClump         (param pair co-occurrence across functions)
   - FlagArgument      (is_*/should_* prefix params)
   - ComplexMatch      (ECase branch count)
   - DeadCode          (unreachable code after return/raise)
   - DataClass         (IClass with properties but no methods)
   - FeatureEnvy       (70%+ accesses on external object)
*)

open Base

(* String comparison shadows - Base remaps = and <> *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_ast.Types
open Catseye_types

(* ── Helpers ────────────────────────────────────────────────────────── *)

let make_finding (file : string) (line : int) (lang : string) (rule : string)
    (severity : string) (message : string) : Finding.t =
  { Finding.rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = lang
  ; dependency = None; reachability = None; suggestion = None
  }

(** Method names exempt from LongMethod checks.
    These naming patterns indicate idiomatic functions that tend to be
    naturally larger (query methods, data transformations, builders). *)
let is_exempt_method = Scope.is_exempt_method

let is_bench_or_example = Scope.is_benchmark_or_example

(* ── LongMethod ─────────────────────────────────────────────────────── *)

(** Count all expression nodes in a tree. *)
let rec count_nodes (e : expr) : int =
  let self = 1 in
  let children = match e.expr_value with
    | EBlock es -> Stdlib.List.fold_left (fun acc c -> acc + count_nodes c) 0 es
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> count_nodes e1 + count_nodes e2
    | EIf (cond, then_e, else_opt) ->
      count_nodes cond + count_nodes then_e +
      (match else_opt with Some e -> count_nodes e | None -> 0)
    | ECase (target, branches) ->
      count_nodes target +
      Stdlib.List.fold_left (fun acc (_, body) -> acc + count_nodes body) 0 branches
    | EAssignment (e1, e2) -> count_nodes e1 + count_nodes e2
    | EBinOp (e1, _, e2) -> count_nodes e1 + count_nodes e2
    | EUnOp (_, e) -> count_nodes e
    | EApp (fn, args) ->
      count_nodes fn + Stdlib.List.fold_left (fun acc a -> acc + count_nodes a) 0 args
    | ETuple es | EList es ->
      Stdlib.List.fold_left (fun acc c -> acc + count_nodes c) 0 es
    | ERecord fields ->
      Stdlib.List.fold_left (fun acc (_, v) -> acc + count_nodes v) 0 fields
    | ERecordUpdate (e, fields) ->
      count_nodes e + Stdlib.List.fold_left (fun acc (_, v) -> acc + count_nodes v) 0 fields
    | EFieldAccess (e, _) -> count_nodes e
    | EFn (_, body) -> count_nodes body
    | _ -> 0
  in
  self + children

let check_long_method (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let warning = config.long_method_warning in
  let critical = config.long_method_critical in
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    if is_exempt_method scope.fn_name || is_bench_or_example scope.file
    then None
    else
      let count = count_nodes scope.body in
      if count >= critical then
        Some (make_finding scope.file scope.line scope.lang "LongMethod" "High"
          (Stdlib.Printf.sprintf "Function '%s' has %d AST nodes (critical threshold: %d). Consider breaking into smaller functions."
             scope.fn_name count critical))
      else if count >= warning then
        Some (make_finding scope.file scope.line scope.lang "LongMethod" "Medium"
          (Stdlib.Printf.sprintf "Function '%s' has %d AST nodes (warning threshold: %d). Consider breaking into smaller functions."
             scope.fn_name count warning))
      else None
  ) scopes

(* ── ComplexConditional ─────────────────────────────────────────────── *)

(** Count && and || operators in an expression tree. *)
let rec count_logical_ops (e : expr) : int =
  match e.expr_value with
  | EBinOp (e1, op, e2) ->
    let base = if op = "&&" || op = "||" then 1 else 0 in
    base + count_logical_ops e1 + count_logical_ops e2
  | EIf (cond, then_e, else_opt) ->
    count_logical_ops cond + count_logical_ops then_e
    + (match else_opt with Some e -> count_logical_ops e | None -> 0)
  | ELet (_, e1, e2) -> count_logical_ops e1 + count_logical_ops e2
  | EBlock es -> Stdlib.List.fold_left (fun acc c -> acc + count_logical_ops c) 0 es
  | EUnOp (_, e) -> count_logical_ops e
  | _ -> 0

(** Find the maximum logical operator count in any single condition. *)
let rec max_conditional_complexity (e : expr) : int =
  match e.expr_value with
  | EIf (cond, then_e, else_opt) ->
    let cond_ops = count_logical_ops cond in
    let then_ops = max_conditional_complexity then_e in
    let else_ops = match else_opt with Some e -> max_conditional_complexity e | None -> 0 in
    Stdlib.max cond_ops (Stdlib.max then_ops else_ops)
  | EBlock es ->
    Stdlib.List.fold_left (fun acc c -> Stdlib.max acc (max_conditional_complexity c)) 0 es
  | ELet (_, _, e2) -> max_conditional_complexity e2
  | ECase (_, branches) ->
    Stdlib.List.fold_left (fun acc (_, body) -> Stdlib.max acc (max_conditional_complexity body)) 0 branches
  | _ -> 0

let check_complex_conditionals (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.complex_conditional_threshold in
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let max_ops = max_conditional_complexity scope.body in
    if max_ops >= threshold then
      Some (make_finding scope.file scope.line scope.lang "ComplexConditional" "Medium"
        (Stdlib.Printf.sprintf "Complex conditional with %d logical operators (threshold: %d). Consider extracting sub-expressions into named variables."
           max_ops threshold))
    else None
  ) scopes

(* ── MessageChain ───────────────────────────────────────────────────── *)

(** Compute maximum field access chain depth in an expression.
    EFieldAccess nesting = method chain depth. *)
let rec max_chain_depth (e : expr) : int =
  match e.expr_value with
  | EFieldAccess (e, _) -> 1 + max_chain_depth e
  | EApp (fn, args) ->
    let fn_depth = max_chain_depth fn in
    let arg_depth = Stdlib.List.fold_left (fun acc a -> Stdlib.max acc (max_chain_depth a)) 0 args in
    Stdlib.max fn_depth arg_depth
  | EBlock es -> Stdlib.List.fold_left (fun acc c -> Stdlib.max acc (max_chain_depth c)) 0 es
  | ELet (_, e1, e2) -> Stdlib.max (max_chain_depth e1) (max_chain_depth e2)
  | EIf (cond, then_e, else_opt) ->
    Stdlib.max (max_chain_depth cond) (Stdlib.max (max_chain_depth then_e)
      (match else_opt with Some e -> max_chain_depth e | None -> 0))
  | ECase (_, branches) ->
    Stdlib.List.fold_left (fun acc (_, body) -> Stdlib.max acc (max_chain_depth body)) 0 branches
  | EAssignment (e1, e2) -> Stdlib.max (max_chain_depth e1) (max_chain_depth e2)
  | EBinOp (e1, _, e2) -> Stdlib.max (max_chain_depth e1) (max_chain_depth e2)
  | EUnOp (_, e) -> max_chain_depth e
  | ETuple es -> Stdlib.List.fold_left (fun acc c -> Stdlib.max acc (max_chain_depth c)) 0 es
  | _ -> 0

(** Find the deepest chain and return it with location info. *)
let rec deepest_chain (e : expr) : (int * int) option =
  match e.expr_value with
  | EFieldAccess (inner, _) ->
    let depth = max_chain_depth e in
    if depth >= 4 then Some (depth, e.expr_location.start.line)
    else deepest_chain inner
  | EApp (fn, args) ->
    let best = deepest_chain fn in
    Stdlib.List.fold_left (fun acc a ->
      match (acc, deepest_chain a) with
      | Some (d1, l1), Some (d2, l2) -> if d2 > d1 then Some (d2, l2) else Some (d1, l1)
      | None, Some x -> Some x
      | Some x, None -> Some x
      | None, None -> None
    ) best args
  | EBlock es ->
    Stdlib.List.filter_map deepest_chain es
    |> Stdlib.List.sort (fun (d1, _) (d2, _) -> Int.compare d2 d1)
    |> Stdlib.List.find_opt (fun _ -> true)
  | ELet (_, e1, e2) ->
    (match deepest_chain e1 with
     | Some _ as r -> r
     | None -> deepest_chain e2)
  | _ -> None

let check_message_chains (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.message_chain_threshold in
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let depth = max_chain_depth scope.body in
    if depth >= threshold then
      Some (make_finding scope.file scope.line scope.lang "MessageChain" "Medium"
        (Stdlib.Printf.sprintf "Long method chain with %d segments (threshold: %d). Consider introducing intermediate variables (Law of Demeter)."
           depth threshold))
    else None
  ) scopes

(* ── DataClump ──────────────────────────────────────────────────────── *)

(** Extract parameter names from pattern list. *)
let rec pattern_names (p : pattern) : string list =
  match p with
  | PVar name -> [name]
  | PTuple ps -> Stdlib.List.concat_map pattern_names ps
  | PRecord fields -> Stdlib.List.concat_map (fun (_, p) -> pattern_names p) fields
  | PList ps -> Stdlib.List.concat_map pattern_names ps
  | PAlias (inner, name) -> name :: pattern_names inner
  | PType (_, inner) -> pattern_names inner
  | _ -> []

let scope_param_names (scope : Ast_scope.ast_scope) : string list =
  Stdlib.List.concat_map pattern_names scope.params

let check_data_clumps (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  if not config.data_clumps_enabled then []
  else begin
    let threshold = config.data_clumps_threshold in
    let pair_counts : (string * string, int) Stdlib.Hashtbl.t = Stdlib.Hashtbl.create 64 in
    let pair_files : (string * string, string list) Stdlib.Hashtbl.t = Stdlib.Hashtbl.create 64 in
    Stdlib.List.iter (fun (scope : Ast_scope.ast_scope) ->
      let params = scope_param_names scope in
      if Stdlib.List.length params >= 2 then
        Stdlib.List.iter (fun (p1, p2) ->
          let key = (Stdlib.min p1 p2, Stdlib.max p1 p2) in
          let current = try Stdlib.Hashtbl.find pair_counts key with Stdlib.Not_found -> 0 in
          Stdlib.Hashtbl.replace pair_counts key (current + 1);
          let files = try Stdlib.Hashtbl.find pair_files key with Stdlib.Not_found -> [] in
          if not (Stdlib.List.mem scope.file files) then
            Stdlib.Hashtbl.replace pair_files key (scope.file :: files)
        ) (Stdlib.List.concat_map (fun p1 ->
          Stdlib.List.filter_map (fun p2 ->
            if Stdlib.String.compare p1 p2 < 0 then Some (p1, p2) else None
          ) params
        ) params)
    ) scopes;
    let common_pairs = Stdlib.Hashtbl.create 16 in
    Stdlib.List.iter (fun (a, b) -> Stdlib.Hashtbl.replace common_pairs (a, b) true)
      [("config", "url"); ("key", "value"); ("message", "url"); ("body", "url")];
    Stdlib.Hashtbl.fold (fun (p1, p2) count acc ->
      if count < threshold then acc
      else begin
        let files = try Stdlib.Hashtbl.find pair_files (p1, p2) with Stdlib.Not_found -> [] in
        let is_common = Stdlib.Hashtbl.mem common_pairs (Stdlib.min p1 p2, Stdlib.max p1 p2) in
        if is_common || Stdlib.List.length files < 2 then acc
        else
          make_finding (Stdlib.List.hd (Stdlib.List.sort String.compare files)) 0 "" "DataClump" "Medium"
            (Stdlib.Printf.sprintf "Parameters '%s' and '%s' always appear together in %d functions across %d files. Consider grouping into a struct or record."
               p1 p2 count (Stdlib.List.length files))
          :: acc
      end
    ) pair_counts []
  end

(* ── FlagArgument ───────────────────────────────────────────────────── *)

let flag_prefixes = [
  "should_"; "enable_"; "disable_"; "use_"; "include_";
  "allow_"; "force_"; "skip_"; "no_"; "with_";
]
let flag_names = ["verbose"; "debug"; "dry_run"; "strict"; "quiet"]

let is_flag_arg (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  Stdlib.List.exists (fun prefix ->
    let plen = Stdlib.String.length prefix in
    Stdlib.String.length lower >= plen && Stdlib.String.sub lower 0 plen = prefix
  ) flag_prefixes
  || Stdlib.List.exists (fun n -> lower = n) flag_names

let check_flag_arguments (scopes : Ast_scope.ast_scope list) : Finding.t list =
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let params = scope_param_names scope in
    let flags = Stdlib.List.filter is_flag_arg params in
    match flags with
    | [] -> None
    | _ ->
      Some (make_finding scope.file scope.line scope.lang "FlagArgument" "Medium"
        (Stdlib.Printf.sprintf "Function '%s' has flag parameter(s): %s. Consider splitting into separate methods."
           scope.fn_name (Stdlib.String.concat ", " flags)))
  ) scopes

(* ── ComplexMatch ───────────────────────────────────────────────────── *)

(** Count ECase branches and find the deepest one. *)
let rec max_case_branches (e : expr) : int =
  match e.expr_value with
  | ECase (_, branches) ->
    let branch_count = Stdlib.List.length branches in
    let inner_max = Stdlib.List.fold_left (fun acc (_, body) ->
      Stdlib.max acc (max_case_branches body)
    ) 0 branches in
    Stdlib.max branch_count inner_max
  | EBlock es -> Stdlib.List.fold_left (fun acc c -> Stdlib.max acc (max_case_branches c)) 0 es
  | ELet (_, _, e2) -> max_case_branches e2
  | EIf (_, then_e, else_opt) ->
    Stdlib.max (max_case_branches then_e)
      (match else_opt with Some e -> max_case_branches e | None -> 0)
  | _ -> 0

let check_complex_match (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let branches = max_case_branches scope.body in
    if branches >= config.complex_match_critical then
      Some (make_finding scope.file scope.line scope.lang "ComplexMatch" "High"
        (Stdlib.Printf.sprintf "Complex case expression with %d when branches (critical threshold: %d). Consider decomposing into smaller functions or a lookup table."
           branches config.complex_match_critical))
    else if branches >= config.complex_match_warning then
      Some (make_finding scope.file scope.line scope.lang "ComplexMatch" "Medium"
        (Stdlib.Printf.sprintf "Complex case expression with %d when branches (warning threshold: %d). Consider decomposing into smaller functions or a lookup table."
           branches config.complex_match_warning))
    else None
  ) scopes

(* ── DeadCode ───────────────────────────────────────────────────────── *)

(** Check if an expression is an unconditional terminator (return/raise).
    Crystal AST maps:
    - `return` to EApp(EVar "return", ...) in crystal_hierarchical_mapper
    - `raise` to EError in crystal_hierarchical_mapper
*)
let is_terminator (e : expr) : bool =
  match e.expr_value with
  | EError _ -> true  (* Crystal's raise maps to EError *)
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EVar name -> name = "return" || name = "raise"
     | _ -> false)
  | _ -> false

(** Check if a branch ends with a terminator (return/raise).
    This detects if/else patterns where both branches return, which is NOT dead code. *)
let both_branches_return (e : expr) : bool =
  let get_last_expr = function
    | EBlock es ->
      (match Stdlib.List.rev es with [] -> None | h :: _ -> Some h.expr_value)
    | v -> Some v
  in
  match e.expr_value with
  | EIf (_, then_e, else_e) ->
    let then_returns = match get_last_expr then_e.expr_value with
      | Some v -> is_terminator { expr_value = v; expr_location = then_e.expr_location }
      | None -> false
    in
    let else_returns = match else_e with
      | Some e -> (match get_last_expr e.expr_value with
        | Some v -> is_terminator { expr_value = v; expr_location = e.expr_location }
        | None -> false)
      | None -> true  (* implicit else returns, no fall-through *)
    in
    then_returns && else_returns
  | _ -> false

(** Walk a block (expression list) looking for dead code after terminators.
    Returns the first dead code finding, if any. *)
let rec scan_block_dead = function
  | [] -> None
  | [_] -> None  (* last node — terminator at end is fine *)
  | stmt :: rest ->
    if is_terminator stmt then
      (* Find next meaningful statement AFTER the terminator's line *)
      let find_dead = function
        | [] -> None
        | dead_stmt :: _ ->
          (* Skip nodes on the same line as the terminator (Crystal can emit
             terminator + call on same line, both are part of the same statement) *)
          if dead_stmt.expr_location.start.line <= stmt.expr_location.start.line then None
          else if is_terminator dead_stmt then None  (* another terminator *)
          else
            Some (dead_stmt.expr_location.start.line,
                  dead_stmt.expr_location.start.line,
                  stmt.expr_location.start.line)
      in
      find_dead rest
    else if both_branches_return stmt then
      (* If/else where BOTH branches end with return/raise:
         This is NOT dead code - both branches are mutually exclusive returns. *)
      None
    else
      (* Recurse into nested structures *)
      let nested = match stmt.expr_value with
        | EBlock es -> scan_block_dead es
        | ELet (_, _, e2) ->
          (match e2.expr_value with EBlock es -> scan_block_dead es | _ -> None)
        | EIf (_, then_e, Some else_e) ->
          (match then_e.expr_value with EBlock es -> scan_block_dead es | _ -> None)
          |> (fun r -> match r with Some _ -> r
              | None -> match else_e.expr_value with EBlock es -> scan_block_dead es | _ -> None)
        | _ -> None
      in
      match nested with Some _ as r -> r | None -> scan_block_dead rest

let check_dead_code (scopes : Ast_scope.ast_scope list) : Finding.t list =
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let body_exprs = match scope.body.expr_value with
      | EBlock es -> es
      | _ -> [scope.body]
    in
    match scan_block_dead body_exprs with
    | Some (dead_line, _end, term_line) ->
      Some (make_finding scope.file dead_line scope.lang "DeadCode" "High"
        (Stdlib.Printf.sprintf "Unreachable code after unconditional return/raise at line %d in '%s'. This code will never execute."
           term_line scope.fn_name))
    | None -> None
  ) scopes

(* ── DataClass ──────────────────────────────────────────────────────── *)

(** Check if an IClass has only property declarations + initialize (no behavior). *)
let check_data_class_item (item : item) (file : string) (lang : string)
    : Finding.t option =
  match item.item_value with
  | IClass (name, children) ->
    let has_method = Stdlib.List.exists (fun (c : item) ->
      match c.item_value with
      | IFunction (fn_name, _, _, _) -> fn_name <> "initialize"
      | _ -> false
    ) children in
    let property_count = Stdlib.List.filter_map (fun (c : item) ->
      match c.item_value with
      | IFunction ("initialize", params, _, _) ->
        Some (Stdlib.List.length params)
      | _ -> None
    ) children |> Stdlib.List.fold_left (+ ) 0 in
    let _has_include = Stdlib.List.exists (fun (c : item) ->
      match c.item_value with
      | IFunction _ -> false
      | _ -> true  (* imports, includes, etc. *)
    ) children in
    (* DataClass: has properties, no non-initialize methods *)
    if property_count >= 2 && not has_method then
      let is_dto_file =
        let lower = Stdlib.String.lowercase_ascii file in
        Stdlib.List.exists (fun pat ->
          let rec contains s i =
            i + Stdlib.String.length pat <= Stdlib.String.length s &&
            (Stdlib.String.sub s i (Stdlib.String.length pat) = pat || contains s (i + 1))
          in contains lower 0
        ) ["/dtos/"; "/dto/"; "/types/"; "/entities/"; "/models/"]
      in
      if is_dto_file then None
      else
        Some (make_finding file item.item_location.start.line lang "DataClass" "Medium"
          (Stdlib.Printf.sprintf "Class '%s' has %d properties but no behavior methods (only initialize). Consider using a Crystal struct or record instead."
             name property_count))
    else None
  | _ -> None

let rec check_data_classes_in_items (items : item list) (file : string) (lang : string)
    : Finding.t list =
  Stdlib.List.concat_map (fun (item : item) ->
    match check_data_class_item item file lang with
    | Some f -> [f]
    | None ->
      (* Recurse into nested classes/modules *)
      match item.item_value with
      | IClass (_, children) | IModule (_, children) ->
        check_data_classes_in_items children file lang
      | _ -> []
  ) items

let check_data_classes (modules : Catseye_ast.Types.t list) : Finding.t list =
  Stdlib.List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | Rust -> "rust" | JavaScript -> "javascript"
    | OCaml -> "ocaml" | Elixir -> "elixir"
    | FSharp -> "fsharp" | Other s -> s in
    check_data_classes_in_items mod_.mod_items mod_.mod_path lang
  ) modules

(* ── FeatureEnvy ────────────────────────────────────────────────────── *)

(** Count field accesses on named objects in an expression.
    Returns (target_name, access_count) list. *)
let rec count_accesses (e : expr) : (string * int) list =
  match e.expr_value with
  | EFieldAccess (inner, _field) ->
    let target = match inner.expr_value with
      | EVar name -> Some name
      | _ -> None
    in
    let inner_accesses = count_accesses inner in
    (match target with
     | Some name -> (name, 1) :: inner_accesses
     | None -> inner_accesses)
  | EApp (fn, args) ->
    count_accesses fn @ Stdlib.List.concat_map count_accesses args
  | EBlock es -> Stdlib.List.concat_map count_accesses es
  | ELet (_, e1, e2) -> count_accesses e1 @ count_accesses e2
  | EIf (cond, then_e, else_opt) ->
    count_accesses cond @ count_accesses then_e
    @ (match else_opt with Some e -> count_accesses e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> count_accesses body) branches
  | EAssignment (e1, e2) -> count_accesses e1 @ count_accesses e2
  | EBinOp (e1, _, e2) -> count_accesses e1 @ count_accesses e2
  | ETuple es | EList es -> Stdlib.List.concat_map count_accesses es
  | ERecord fields -> Stdlib.List.concat_map (fun (_, v) -> count_accesses v) fields
  | _ -> []

let is_generic_target (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  Stdlib.List.exists (fun prefix ->
    let plen = Stdlib.String.length prefix in
    Stdlib.String.length lower >= plen && Stdlib.String.sub lower 0 plen = prefix
  ) ["rows"; "row"; "result"; "data"; "response"; "hash"; "arr";
     "item"; "entry"; "elem"; "val"; "value"; "key"; "field";
     "conn"; "client"; "node"; "child"; "ex"; "err"; "site"; "ctx";
     "opts"; "options"; "config"; "params"]

let is_converter_method (name : string) : bool =
  Stdlib.List.exists (fun prefix ->
    let plen = Stdlib.String.length prefix in
    Stdlib.String.length name >= plen && Stdlib.String.sub name 0 plen = prefix
  ) ["from_"; "to_"; "build_"; "map_"; "parse_"; "convert_"; "format_"]

let check_feature_envy (scopes : Ast_scope.ast_scope list) : Finding.t list =
  Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    if is_converter_method scope.fn_name then None
    else begin
      let params = scope_param_names scope in
      let accesses = count_accesses scope.body in
      (* Aggregate counts per target *)
      let counts : (string, int) Stdlib.Hashtbl.t = Stdlib.Hashtbl.create 8 in
      Stdlib.List.iter (fun (name, c) ->
        if not (Stdlib.List.mem name params) && not (is_generic_target name)
           && Stdlib.String.length name > 0 && name.[0] <> '@'
        then
          let current = try Stdlib.Hashtbl.find counts name with Stdlib.Not_found -> 0 in
          Stdlib.Hashtbl.replace counts name (current + c)
      ) accesses;
      let total = Stdlib.Hashtbl.fold (fun _ c acc -> acc + c) counts 0 in
      if total >= 5 then begin
        let best_obj = Stdlib.ref "" in
        let best_count = Stdlib.ref 0 in
        Stdlib.Hashtbl.iter (fun obj count ->
          if count > !best_count then (best_obj := obj; best_count := count)
        ) counts;
        let ratio = Stdlib.Float.of_int !best_count /. Stdlib.Float.of_int total in
        if Stdlib.Float.compare ratio 0.7 >= 0 then
          Some (make_finding scope.file scope.line scope.lang "FeatureEnvy" "Medium"
            (Stdlib.Printf.sprintf "Method '%s' accesses '%s' %d/%d non-parameter accesses (%d%%). Consider moving this logic to the '%s' class."
               scope.fn_name !best_obj !best_count total (Stdlib.int_of_float (ratio *. 100.0)) !best_obj))
        else None
      end else None
    end
  ) scopes

(* ── MagicNumber ─────────────────────────────────────────────────────── *)

(** Strip Rust integer type suffixes from numeric literals.
    Rust uses suffixes like 1i64, 0usize, 100u32, -1isize, etc.
    Without stripping, these don't match the known-literal set. *)
let strip_rust_int_suffix (n : string) : string =
  let suffixes = ["i8"; "i16"; "i32"; "i64"; "i128"; "isize";
                "u8"; "u16"; "u32"; "u64"; "u128"; "usize";
                "f32"; "f64"] in
  let stripped = Stdlib.ref n in
  Stdlib.List.iter (fun sfx ->
    let sfx_len = Stdlib.String.length sfx in
    if Stdlib.String.length !stripped > sfx_len &&
       Stdlib.String.sub !stripped (Stdlib.String.length !stripped - sfx_len) sfx_len = sfx
    then
      stripped := Stdlib.String.sub !stripped 0 (Stdlib.String.length !stripped - sfx_len)
  ) suffixes;
  !stripped

(** Numbers that are not considered "magic" — well-known constants or common patterns. *)
let is_known_literal (n : string) : bool =
  let base = strip_rust_int_suffix n in
  base = "0" || base = "1" || base = "-1" || base = "2" || base = "10" || base = "100"
  || base = "1000" || base = "0x0" || base = "0x1" || base = "0b0" || base = "0b1"
  || base = "0o0" || base = "0o1" || base = "0.0" || base = "1.0" || base = "0.5"
  || base = "2.0" || base = "-1.0"
  (* Domain-specific constants commonly used as literals *)
  || Stdlib.List.mem base ["4"; "5"; "6"; "60"; "120"; "-1"]
  (* HTTP status codes *)
  || Stdlib.List.mem base [
    "200"; "201"; "202"; "204";
    "301"; "302"; "304"; "307"; "308";
    "400"; "401"; "403"; "404"; "405"; "406"; "408"; "409"; "410"; "411"; "413"; "415"; "418"; "422"; "425"; "426"; "428"; "429"; "431"; "451";
    "500"; "501"; "502"; "503"; "504"; "505"; "506"; "507"; "508"; "511";
  ]

(** Contexts where a numeric literal is acceptable and not "magic" *)
let is_constant_item (items : item list) (line : int) : bool =
  Stdlib.List.exists (fun (item : item) ->
    (match item.item_value with
     | IConstant _ -> true
     | _ -> false)
    && item.item_location.start.line = line
  ) items

(** Recursively walk an expression looking for integer/float literals *)
let rec collect_magic_numbers (e : expr) : (string * int) list =
  match e.expr_value with
  | ELiteral (LInt n) when not (is_known_literal n) ->
    [(n, e.expr_location.start.line)]
  | ELiteral (LFloat n) when not (is_known_literal n) ->
    [(n, e.expr_location.start.line)]
  | EApp (fn, args) ->
    collect_magic_numbers fn @ Stdlib.List.concat_map collect_magic_numbers args
  | EBlock es -> Stdlib.List.concat_map collect_magic_numbers es
  | ELet (_, e1, e2) -> collect_magic_numbers e1 @ collect_magic_numbers e2
  | EIf (cond, then_, else_) ->
    collect_magic_numbers cond @ collect_magic_numbers then_
    @ (match else_ with Some e -> collect_magic_numbers e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> collect_magic_numbers body) branches
  | EAssignment (e1, e2) -> collect_magic_numbers e1 @ collect_magic_numbers e2
  | EBinOp (e1, _, e2) -> collect_magic_numbers e1 @ collect_magic_numbers e2
  | EUnOp (_, e) -> collect_magic_numbers e
  | ETuple es | EList es -> Stdlib.List.concat_map collect_magic_numbers es
  | ERecord fields -> Stdlib.List.concat_map (fun (_, v) -> collect_magic_numbers v) fields
  | ERecordUpdate (e, fields) ->
    collect_magic_numbers e @ Stdlib.List.concat_map (fun (_, v) -> collect_magic_numbers v) fields
  | EFieldAccess (inner, _) -> collect_magic_numbers inner
  | EFn (_, body) -> collect_magic_numbers body
  | _ -> []

let check_magic_numbers (modules : Catseye_ast.Types.t list)
    : Finding.t list =
  Stdlib.List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | Rust -> "rust" | JavaScript -> "javascript"
    | OCaml -> "ocaml" | Elixir -> "elixir"
    | FSharp -> "fsharp" | Other s -> s in
    let scopes = Ast_scope.build [mod_] in
    Stdlib.List.concat_map (fun (scope : Ast_scope.ast_scope) ->
      let nums = collect_magic_numbers scope.body in
      Stdlib.List.filter_map (fun (n, line) ->
        if is_constant_item mod_.mod_items line then None
        else
          Some (make_finding scope.file line lang "MagicNumber" "Medium"
            (Stdlib.Printf.sprintf "Magic number %s in '%s' — extract to a named constant for clarity"
               n scope.fn_name))
      ) nums
    ) scopes
  ) modules

(* ── EmptyCatch ──────────────────────────────────────────────────────── *)

(** Check if a rescue/catch body is empty (EUnit, empty block, or just a variable binding). *)
let is_empty_body (e : expr) : bool =
  match e.expr_value with
  | EUnit -> true
  | EBlock [] -> true
  | EBlock [e] -> (match e.expr_value with EUnit | EVar _ -> true | _ -> false)
  | _ -> false

(** Find ETryCatchFinally with empty rescue bodies. *)
let rec find_empty_catches (e : expr) : (string option * int) list =
  match e.expr_value with
  | ETryCatchFinally { rescue_clauses; _ } ->
    let empty = Stdlib.List.filter_map (fun (clause : Catseye_ast.Types.rescue_clause) ->
      if is_empty_body clause.rescue_body then
        Some (clause.exception_var, clause.rescue_body.expr_location.start.line)
      else None
    ) rescue_clauses in
    empty
  | EApp (fn, args) ->
    find_empty_catches fn @ Stdlib.List.concat_map find_empty_catches args
  | EBlock es -> Stdlib.List.concat_map find_empty_catches es
  | ELet (_, e1, e2) -> find_empty_catches e1 @ find_empty_catches e2
  | EIf (cond, then_, else_) ->
    find_empty_catches cond @ find_empty_catches then_
    @ (match else_ with Some e -> find_empty_catches e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> find_empty_catches body) branches
  | EAssignment (e1, e2) -> find_empty_catches e1 @ find_empty_catches e2
  | EBinOp (e1, _, e2) -> find_empty_catches e1 @ find_empty_catches e2
  | EFn (_, body) -> find_empty_catches body
  | _ -> []

let check_empty_catch (modules : Catseye_ast.Types.t list)
    : Finding.t list =
  Stdlib.List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | Rust -> "rust" | JavaScript -> "javascript"
    | OCaml -> "ocaml" | Elixir -> "elixir"
    | FSharp -> "fsharp" | Other s -> s in
    let scopes = Ast_scope.build [mod_] in
    Stdlib.List.concat_map (fun (scope : Ast_scope.ast_scope) ->
      let empties = find_empty_catches scope.body in
      Stdlib.List.map (fun (var, line) ->
        let var_desc = match var with Some v -> Stdlib.Printf.sprintf " '%s'" v | None -> "" in
        make_finding scope.file line lang "EmptyCatch" "High"
          (Stdlib.Printf.sprintf "Empty catch%s in '%s' silently swallows errors — at minimum, log the exception"
             var_desc scope.fn_name)
      ) empties
    ) scopes
  ) modules

(* ── ReturnFromFinally ────────────────────────────────────────────────── *)

(** Check if an expression is a return statement. *)
let is_return_expr (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, _) ->
    (match fn.expr_value with EVar "return" -> true | _ -> false)
  | EVar "return" -> true
  | _ -> false

(** Recursively find return/raise inside an expression. *)
let rec has_return_or_raise (e : expr) : int option =
  match e.expr_value with
  | EApp (fn, args) ->
    (match fn.expr_value with
     | EVar "return" | EVar "raise" -> Some e.expr_location.start.line
     | _ -> None)
    |> (fun r -> match r with
        | Some _ as r -> r
        | None ->
          match has_return_or_raise fn with
          | Some _ as r -> r
          | None -> Stdlib.List.find_map has_return_or_raise args)
  | EBlock es -> Stdlib.List.find_map has_return_or_raise es
  | ELet (_, e1, e2) ->
    (match has_return_or_raise e1 with Some _ as r -> r | None -> has_return_or_raise e2)
  | EIf (_, then_, else_) ->
    (match has_return_or_raise then_ with
     | Some _ as r -> r
     | None -> match else_ with Some e -> has_return_or_raise e | None -> None)
  | ECase (_, branches) ->
    Stdlib.List.find_map (fun (_, body) -> has_return_or_raise body) branches
  | _ -> None

(** Find ETryCatchFinally where ensure_body contains a return/raise. *)
let rec find_return_in_finally (e : expr) : int option =
  match e.expr_value with
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
    (match ensure_body with
     | Some body -> has_return_or_raise body
     | None -> None)
    |> (fun r -> match r with
        | Some _ as r -> r
        | None ->
          match has_return_or_raise try_body with
          | Some _ as r -> r
          | None ->
            Stdlib.List.find_map (fun (clause : Catseye_ast.Types.rescue_clause) ->
              find_return_in_finally clause.rescue_body
            ) rescue_clauses)
  | EApp (fn, args) ->
    (match find_return_in_finally fn with Some _ as r -> r | None ->
     Stdlib.List.find_map find_return_in_finally args)
  | EBlock es -> Stdlib.List.find_map find_return_in_finally es
  | ELet (_, e1, e2) ->
    (match find_return_in_finally e1 with Some _ as r -> r | None -> find_return_in_finally e2)
  | EIf (_, then_, else_) ->
    (match find_return_in_finally then_ with
     | Some _ as r -> r
     | None -> (match else_ with Some e -> find_return_in_finally e | None -> None))
  | EFn (_, body) -> find_return_in_finally body
  | _ -> None

let check_return_from_finally (modules : Catseye_ast.Types.t list)
    : Finding.t list =
  Stdlib.List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | Rust -> "rust" | JavaScript -> "javascript"
    | OCaml -> "ocaml" | Elixir -> "elixir"
    | FSharp -> "fsharp" | Other s -> s in
    let scopes = Ast_scope.build [mod_] in
    Stdlib.List.filter_map (fun (scope : Ast_scope.ast_scope) ->
      match find_return_in_finally scope.body with
      | Some line ->
        Some (make_finding scope.file line lang "ReturnFromFinally" "High"
          (Stdlib.Printf.sprintf "return/raise inside finally block in '%s' masks exceptions from try/catch"
             scope.fn_name))
      | None -> None
    ) scopes
  ) modules

(* ── FloatEquality ──────────────────────────────────────────────────── *)

(** Detect exact float equality comparisons (== or === with float literals). *)
let rec find_float_equality (e : expr) : (string * int) list =
  match e.expr_value with
  | EBinOp (e1, op, e2) when op = "==" || op = "===" || op = "!=" || op = "!==" ->
    let is_float (x : expr) =
      match x.expr_value with
      | ELiteral (LFloat _) -> true
      | ELiteral (LString s) ->
        Stdlib.String.length s > 0 && Stdlib.String.contains s '.'
      | _ -> false
    in
    if is_float e1 || is_float e2 then
      [(op, e.expr_location.start.line)]
    else
      find_float_equality e1 @ find_float_equality e2
  | EBinOp (e1, _, e2) ->
    find_float_equality e1 @ find_float_equality e2
  | EApp (fn, args) ->
    find_float_equality fn @ Stdlib.List.concat_map find_float_equality args
  | EBlock es -> Stdlib.List.concat_map find_float_equality es
  | ELet (_, e1, e2) -> find_float_equality e1 @ find_float_equality e2
  | EIf (cond, then_, else_) ->
    find_float_equality cond @ find_float_equality then_
    @ (match else_ with Some e -> find_float_equality e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> find_float_equality body) branches
  | _ -> []

let check_float_equality (modules : Catseye_ast.Types.t list)
    : Finding.t list =
  Stdlib.List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | Rust -> "rust" | JavaScript -> "javascript"
    | OCaml -> "ocaml" | Elixir -> "elixir"
    | FSharp -> "fsharp" | Other s -> s in
    let scopes = Ast_scope.build [mod_] in
    Stdlib.List.concat_map (fun (scope : Ast_scope.ast_scope) ->
      let floats = find_float_equality scope.body in
      Stdlib.List.map (fun (op, line) ->
        make_finding scope.file line lang "FloatEquality" "Warning"
          (Stdlib.Printf.sprintf "Float equality via '%s' in '%s' is unreliable due to floating-point precision — use epsilon comparison"
             op scope.fn_name)
      ) floats
    ) scopes
  ) modules

(* ── Combined analysis ──────────────────────────────────────────────── *)

let analyze (modules : Catseye_ast.Types.t list)
    (config : Types.claws_config) : Finding.t list =
  let scopes = Ast_scope.build modules in
  check_long_method scopes config
  @ check_complex_conditionals scopes config
  @ check_message_chains scopes config
  @ check_data_clumps scopes config
  @ check_flag_arguments scopes
  @ check_complex_match scopes config
  @ check_dead_code scopes
  @ check_data_classes modules
  @ check_feature_envy scopes
  @ check_magic_numbers modules
  @ check_empty_catch modules
  @ check_return_from_finally modules
  @ check_float_equality modules