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

(** Method names exempt from LongMethod checks (from anatomy_ast.ml). *)
let is_exempt_method (name : string) : bool =
  name = "initialize" || name = "new"
  || String.length name >= 5 && String.sub name 0 5 = "from_"
  || String.length name >= 6 && (let p = String.sub name 0 6 in p = "decode" || p = "parse_")
  || String.length name >= 5 && (let p = String.sub name 0 5 in p = "build" || p = "creat")
  || String.length name >= 7 && String.sub name 0 7 = "handle_"
  || String.length name >= 4 && String.sub name 0 4 = "test"

let is_bench_or_example (file : string) : bool =
  let lower = String.lowercase_ascii file in
  List.exists (fun pat ->
    let rec contains s i =
      i + String.length pat <= String.length s &&
      (String.sub s i (String.length pat) = pat || contains s (i + 1))
    in contains lower 0
  ) ["/bench/"; "/benchmark/"; "/example/"; "/examples/"; "/spec/"; "/test/"]

(* ── LongMethod ─────────────────────────────────────────────────────── *)

(** Count all expression nodes in a tree. *)
let rec count_nodes (e : expr) : int =
  let self = 1 in
  let children = match e.expr_value with
    | EBlock es -> List.fold_left (fun acc c -> acc + count_nodes c) 0 es
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> count_nodes e1 + count_nodes e2
    | EIf (cond, then_e, else_opt) ->
      count_nodes cond + count_nodes then_e +
      (match else_opt with Some e -> count_nodes e | None -> 0)
    | ECase (target, branches) ->
      count_nodes target +
      List.fold_left (fun acc (_, body) -> acc + count_nodes body) 0 branches
    | EAssignment (e1, e2) -> count_nodes e1 + count_nodes e2
    | EBinOp (e1, _, e2) -> count_nodes e1 + count_nodes e2
    | EUnOp (_, e) -> count_nodes e
    | EApp (fn, args) ->
      count_nodes fn + List.fold_left (fun acc a -> acc + count_nodes a) 0 args
    | ETuple es | EList es ->
      List.fold_left (fun acc c -> acc + count_nodes c) 0 es
    | ERecord fields ->
      List.fold_left (fun acc (_, v) -> acc + count_nodes v) 0 fields
    | ERecordUpdate (e, fields) ->
      count_nodes e + List.fold_left (fun acc (_, v) -> acc + count_nodes v) 0 fields
    | EFieldAccess (e, _) -> count_nodes e
    | EFn (_, body) -> count_nodes body
    | _ -> 0
  in
  self + children

let check_long_method (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let warning = config.long_method_warning in
  let critical = config.long_method_critical in
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    if is_exempt_method scope.fn_name || is_bench_or_example scope.file
    then None
    else
      let count = count_nodes scope.body in
      if count >= critical then
        Some (make_finding scope.file scope.line scope.lang "LongMethod" "High"
          (Printf.sprintf "Function '%s' has %d AST nodes (critical threshold: %d). Consider breaking into smaller functions."
             scope.fn_name count critical))
      else if count >= warning then
        Some (make_finding scope.file scope.line scope.lang "LongMethod" "Medium"
          (Printf.sprintf "Function '%s' has %d AST nodes (warning threshold: %d). Consider breaking into smaller functions."
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
  | EBlock es -> List.fold_left (fun acc c -> acc + count_logical_ops c) 0 es
  | EUnOp (_, e) -> count_logical_ops e
  | _ -> 0

(** Find the maximum logical operator count in any single condition. *)
let rec max_conditional_complexity (e : expr) : int =
  match e.expr_value with
  | EIf (cond, then_e, else_opt) ->
    let cond_ops = count_logical_ops cond in
    let then_ops = max_conditional_complexity then_e in
    let else_ops = match else_opt with Some e -> max_conditional_complexity e | None -> 0 in
    max cond_ops (max then_ops else_ops)
  | EBlock es ->
    List.fold_left (fun acc c -> max acc (max_conditional_complexity c)) 0 es
  | ELet (_, _, e2) -> max_conditional_complexity e2
  | ECase (_, branches) ->
    List.fold_left (fun acc (_, body) -> max acc (max_conditional_complexity body)) 0 branches
  | _ -> 0

let check_complex_conditionals (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.complex_conditional_threshold in
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let max_ops = max_conditional_complexity scope.body in
    if max_ops >= threshold then
      Some (make_finding scope.file scope.line scope.lang "ComplexConditional" "Medium"
        (Printf.sprintf "Complex conditional with %d logical operators (threshold: %d). Consider extracting sub-expressions into named variables."
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
    let arg_depth = List.fold_left (fun acc a -> max acc (max_chain_depth a)) 0 args in
    max fn_depth arg_depth
  | EBlock es -> List.fold_left (fun acc c -> max acc (max_chain_depth c)) 0 es
  | ELet (_, e1, e2) -> max (max_chain_depth e1) (max_chain_depth e2)
  | EIf (cond, then_e, else_opt) ->
    max (max_chain_depth cond) (max (max_chain_depth then_e)
      (match else_opt with Some e -> max_chain_depth e | None -> 0))
  | ECase (_, branches) ->
    List.fold_left (fun acc (_, body) -> max acc (max_chain_depth body)) 0 branches
  | EAssignment (e1, e2) -> max (max_chain_depth e1) (max_chain_depth e2)
  | EBinOp (e1, _, e2) -> max (max_chain_depth e1) (max_chain_depth e2)
  | EUnOp (_, e) -> max_chain_depth e
  | ETuple es -> List.fold_left (fun acc c -> max acc (max_chain_depth c)) 0 es
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
    List.fold_left (fun acc a ->
      match (acc, deepest_chain a) with
      | Some (d1, l1), Some (d2, l2) -> if d2 > d1 then Some (d2, l2) else Some (d1, l1)
      | None, Some x -> Some x
      | Some x, None -> Some x
      | None, None -> None
    ) best args
  | EBlock es ->
    List.filter_map deepest_chain es
    |> List.sort (fun (d1, _) (d2, _) -> compare d2 d1)
    |> List.find_opt (fun _ -> true)
  | ELet (_, e1, e2) ->
    (match deepest_chain e1 with
     | Some _ as r -> r
     | None -> deepest_chain e2)
  | _ -> None

let check_message_chains (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.message_chain_threshold in
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let depth = max_chain_depth scope.body in
    if depth >= threshold then
      Some (make_finding scope.file scope.line scope.lang "MessageChain" "Medium"
        (Printf.sprintf "Long method chain with %d segments (threshold: %d). Consider introducing intermediate variables (Law of Demeter)."
           depth threshold))
    else None
  ) scopes

(* ── DataClump ──────────────────────────────────────────────────────── *)

(** Extract parameter names from pattern list. *)
let rec pattern_names (p : pattern) : string list =
  match p with
  | PVar name -> [name]
  | PTuple ps -> List.concat_map pattern_names ps
  | PRecord fields -> List.concat_map (fun (_, p) -> pattern_names p) fields
  | PList ps -> List.concat_map pattern_names ps
  | PAlias (inner, name) -> name :: pattern_names inner
  | PType (_, inner) -> pattern_names inner
  | _ -> []

let scope_param_names (scope : Ast_scope.ast_scope) : string list =
  List.concat_map pattern_names scope.params

let check_data_clumps (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  if not config.data_clumps_enabled then []
  else begin
    let threshold = config.data_clumps_threshold in
    let pair_counts : (string * string, int) Hashtbl.t = Hashtbl.create 64 in
    let pair_files : (string * string, string list) Hashtbl.t = Hashtbl.create 64 in
    List.iter (fun (scope : Ast_scope.ast_scope) ->
      let params = scope_param_names scope in
      if List.length params >= 2 then
        List.iter (fun (p1, p2) ->
          let key = (min p1 p2, max p1 p2) in
          let current = try Hashtbl.find pair_counts key with Not_found -> 0 in
          Hashtbl.replace pair_counts key (current + 1);
          let files = try Hashtbl.find pair_files key with Not_found -> [] in
          if not (List.mem scope.file files) then
            Hashtbl.replace pair_files key (scope.file :: files)
        ) (List.concat_map (fun p1 ->
          List.filter_map (fun p2 ->
            if p1 < p2 then Some (p1, p2) else None
          ) params
        ) params)
    ) scopes;
    let common_pairs = Hashtbl.create 16 in
    List.iter (fun (a, b) -> Hashtbl.replace common_pairs (a, b) true)
      [("config", "url"); ("key", "value"); ("message", "url"); ("body", "url")];
    Hashtbl.fold (fun (p1, p2) count acc ->
      if count < threshold then acc
      else begin
        let files = try Hashtbl.find pair_files (p1, p2) with Not_found -> [] in
        let is_common = Hashtbl.mem common_pairs (min p1 p2, max p1 p2) in
        if is_common || List.length files < 2 then acc
        else
          make_finding (List.hd (List.sort String.compare files)) 0 "" "DataClump" "Medium"
            (Printf.sprintf "Parameters '%s' and '%s' always appear together in %d functions across %d files. Consider grouping into a struct or record."
               p1 p2 count (List.length files))
          :: acc
      end
    ) pair_counts []
  end

(* ── FlagArgument ───────────────────────────────────────────────────── *)

let flag_prefixes = [
  "is_"; "should_"; "enable_"; "disable_"; "use_"; "include_";
  "has_"; "allow_"; "force_"; "skip_"; "no_"; "with_";
]
let flag_names = ["verbose"; "debug"; "dry_run"; "strict"; "quiet"]

let is_flag_arg (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length lower >= plen && String.sub lower 0 plen = prefix
  ) flag_prefixes
  || List.exists (fun n -> lower = n) flag_names

let check_flag_arguments (scopes : Ast_scope.ast_scope list) : Finding.t list =
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let params = scope_param_names scope in
    let flags = List.filter is_flag_arg params in
    match flags with
    | [] -> None
    | _ ->
      Some (make_finding scope.file scope.line scope.lang "FlagArgument" "Medium"
        (Printf.sprintf "Function '%s' has flag parameter(s): %s. Consider splitting into separate methods."
           scope.fn_name (String.concat ", " flags)))
  ) scopes

(* ── ComplexMatch ───────────────────────────────────────────────────── *)

(** Count ECase branches and find the deepest one. *)
let rec max_case_branches (e : expr) : int =
  match e.expr_value with
  | ECase (_, branches) ->
    let branch_count = List.length branches in
    let inner_max = List.fold_left (fun acc (_, body) ->
      max acc (max_case_branches body)
    ) 0 branches in
    max branch_count inner_max
  | EBlock es -> List.fold_left (fun acc c -> max acc (max_case_branches c)) 0 es
  | ELet (_, _, e2) -> max_case_branches e2
  | EIf (_, then_e, else_opt) ->
    max (max_case_branches then_e)
      (match else_opt with Some e -> max_case_branches e | None -> 0)
  | _ -> 0

let check_complex_match (scopes : Ast_scope.ast_scope list)
    (config : Types.claws_config) : Finding.t list =
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let branches = max_case_branches scope.body in
    if branches >= config.complex_match_critical then
      Some (make_finding scope.file scope.line scope.lang "ComplexMatch" "High"
        (Printf.sprintf "Complex case expression with %d when branches (critical threshold: %d). Consider decomposing into smaller functions or a lookup table."
           branches config.complex_match_critical))
    else if branches >= config.complex_match_warning then
      Some (make_finding scope.file scope.line scope.lang "ComplexMatch" "Medium"
        (Printf.sprintf "Complex case expression with %d when branches (warning threshold: %d). Consider decomposing into smaller functions or a lookup table."
           branches config.complex_match_warning))
    else None
  ) scopes

(* ── DeadCode ───────────────────────────────────────────────────────── *)

(** Check if an expression is an unconditional terminator (return/raise). *)
let is_terminator (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EVar name -> name = "return" || name = "raise"
     | _ -> false)
  | _ -> false

(** Walk a block (expression list) looking for dead code after terminators.
    Returns the first dead code finding, if any. *)
let rec scan_block_dead = function
  | [] -> None
  | [_] -> None  (* last node — terminator at end is fine *)
  | stmt :: rest ->
    if is_terminator stmt then
      (* Find next meaningful statement *)
      let find_dead = function
        | [] -> None
        | dead_stmt :: _ ->
          if is_terminator dead_stmt then None  (* another terminator *)
          else
            Some (dead_stmt.expr_location.start.line,
                  dead_stmt.expr_location.start.line,
                  stmt.expr_location.start.line)
      in
      find_dead rest
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
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    let body_exprs = match scope.body.expr_value with
      | EBlock es -> es
      | _ -> [scope.body]
    in
    match scan_block_dead body_exprs with
    | Some (dead_line, _end, term_line) ->
      Some (make_finding scope.file dead_line scope.lang "DeadCode" "High"
        (Printf.sprintf "Unreachable code after unconditional return/raise at line %d in '%s'. This code will never execute."
           term_line scope.fn_name))
    | None -> None
  ) scopes

(* ── DataClass ──────────────────────────────────────────────────────── *)

(** Check if an IClass has only property declarations + initialize (no behavior). *)
let check_data_class_item (item : item) (file : string) (lang : string)
    : Finding.t option =
  match item.item_value with
  | IClass (name, children) ->
    let has_method = List.exists (fun (c : item) ->
      match c.item_value with
      | IFunction (fn_name, _, _, _) -> fn_name <> "initialize"
      | _ -> false
    ) children in
    let property_count = List.filter_map (fun (c : item) ->
      match c.item_value with
      | IFunction ("initialize", params, _, _) ->
        Some (List.length params)
      | _ -> None
    ) children |> List.fold_left (+) 0 in
    let _has_include = List.exists (fun (c : item) ->
      match c.item_value with
      | IFunction _ -> false
      | _ -> true  (* imports, includes, etc. *)
    ) children in
    (* DataClass: has properties, no non-initialize methods *)
    if property_count >= 2 && not has_method then
      let is_dto_file =
        let lower = String.lowercase_ascii file in
        List.exists (fun pat ->
          let rec contains s i =
            i + String.length pat <= String.length s &&
            (String.sub s i (String.length pat) = pat || contains s (i + 1))
          in contains lower 0
        ) ["/dtos/"; "/dto/"; "/types/"; "/entities/"; "/models/"]
      in
      if is_dto_file then None
      else
        Some (make_finding file item.item_location.start.line lang "DataClass" "Medium"
          (Printf.sprintf "Class '%s' has %d properties but no behavior methods (only initialize). Consider using a Crystal struct or record instead."
             name property_count))
    else None
  | _ -> None

let rec check_data_classes_in_items (items : item list) (file : string) (lang : string)
    : Finding.t list =
  List.concat_map (fun (item : item) ->
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
  List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" in
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
    count_accesses fn @ List.concat_map count_accesses args
  | EBlock es -> List.concat_map count_accesses es
  | ELet (_, e1, e2) -> count_accesses e1 @ count_accesses e2
  | EIf (cond, then_e, else_opt) ->
    count_accesses cond @ count_accesses then_e
    @ (match else_opt with Some e -> count_accesses e | None -> [])
  | ECase (_, branches) ->
    List.concat_map (fun (_, body) -> count_accesses body) branches
  | EAssignment (e1, e2) -> count_accesses e1 @ count_accesses e2
  | EBinOp (e1, _, e2) -> count_accesses e1 @ count_accesses e2
  | ETuple es | EList es -> List.concat_map count_accesses es
  | ERecord fields -> List.concat_map (fun (_, v) -> count_accesses v) fields
  | _ -> []

let is_generic_target (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length lower >= plen && String.sub lower 0 plen = prefix
  ) ["rows"; "row"; "result"; "data"; "response"; "hash"; "arr";
     "item"; "entry"; "elem"; "val"; "value"; "key"; "field";
     "conn"; "client"; "node"; "child"; "ex"; "err"; "site"; "ctx";
     "opts"; "options"; "config"; "params"]

let is_converter_method (name : string) : bool =
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length name >= plen && String.sub name 0 plen = prefix
  ) ["from_"; "to_"; "build_"; "map_"; "parse_"; "convert_"; "format_"]

let check_feature_envy (scopes : Ast_scope.ast_scope list) : Finding.t list =
  List.filter_map (fun (scope : Ast_scope.ast_scope) ->
    if is_converter_method scope.fn_name then None
    else begin
      let params = scope_param_names scope in
      let accesses = count_accesses scope.body in
      (* Aggregate counts per target *)
      let counts : (string, int) Hashtbl.t = Hashtbl.create 8 in
      List.iter (fun (name, c) ->
        if not (List.mem name params) && not (is_generic_target name)
           && String.length name > 0 && name.[0] <> '@'
        then
          let current = try Hashtbl.find counts name with Not_found -> 0 in
          Hashtbl.replace counts name (current + c)
      ) accesses;
      let total = Hashtbl.fold (fun _ c acc -> acc + c) counts 0 in
      if total >= 5 then begin
        let best_obj = ref "" in
        let best_count = ref 0 in
        Hashtbl.iter (fun obj count ->
          if count > !best_count then (best_obj := obj; best_count := count)
        ) counts;
        let ratio = float_of_int !best_count /. float_of_int total in
        if ratio >= 0.7 then
          Some (make_finding scope.file scope.line scope.lang "FeatureEnvy" "Medium"
            (Printf.sprintf "Method '%s' accesses '%s' %d/%d non-parameter accesses (%d%%). Consider moving this logic to the '%s' class."
               scope.fn_name !best_obj !best_count total (int_of_float (ratio *. 100.0)) !best_obj))
        else None
      end else None
    end
  ) scopes

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
