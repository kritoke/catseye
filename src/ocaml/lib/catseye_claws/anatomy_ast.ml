(* lib/catseye_claws/anatomy_ast.ml
   AST-native structural smell detection.

   Three checks using CatseyeAST.t directly:
   - Long parameter lists  (IFunction pattern lists — exact count)
   - Deep nesting          (walk EIf/ECase nesting depth — exact, not heuristic)
   - God objects           (IClass/IModule boundaries — exact scope, not per-file)

   Replaces the heuristic substring-matching approach in anatomy.ml which
   pattern-matches node names like "if", "unless", "case" on Security_node.t.
*)

open Base
open Catseye_ast.Types
open Catseye_types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )

(* ── Helpers ────────────────────────────────────────────────────────── *)

(** Method names that are inherently multi-parameter and should be exempt
    from LongParameterList checks. These are patterns where many params
    are structurally required by the domain. *)
let is_exempt_method (name : string) : bool =
  name = "initialize" ||
  name = "new" ||
  (* from_* — factory/constructor methods like from_entity, from_string, from_json *)
  Stdlib.String.length name >= 5 &&
  Stdlib.String.sub name 0 5 = "from_" ||
  Stdlib.String.length name >= 6 &&
  (let prefix = Stdlib.String.sub name 0 6 in
   prefix = "decode" || prefix = "parse_" || prefix = "to_json" || prefix = "to_hash") ||
  (Stdlib.String.length name >= 5 &&
   let suffix = Stdlib.String.sub name (Stdlib.String.length name - 5) 5 in
   suffix = "_core") ||
  (Stdlib.String.length name >= 5 &&
   let prefix = Stdlib.String.sub name 0 5 in
   prefix = "build" || prefix = "creat") ||
  (* handle_* — event/action handlers with domain context *)
  Stdlib.String.length name >= 7 &&
  Stdlib.String.sub name 0 7 = "handle_" ||
  Stdlib.String.length name >= 9 &&
  (let prefix = Stdlib.String.sub name 0 9 in
   prefix = "benchmark") ||
  Stdlib.String.length name >= 4 &&
  (let prefix = Stdlib.String.sub name 0 4 in
   prefix = "test")

(** File paths that should be exempt from certain checks. *)
let is_benchmark_or_example (file : string) : bool =
  let lower = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun pat ->
    let plen = Stdlib.String.length pat in
    Stdlib.String.length lower >= plen &&
    Stdlib.String.sub lower (Stdlib.String.length lower - plen) plen = pat
  ) ["/bench/"; "/benchmark/"; "/example/"; "/examples/"; "/spec/"; "/test/"; "/tests/"]

let is_constants_file (file : string) : bool =
  let lower = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun pat ->
    let plen = Stdlib.String.length pat in
    Stdlib.String.length lower >= plen &&
    Stdlib.String.sub lower (Stdlib.String.length lower - plen) plen = pat
  ) ["constants.cr"; "consts.cr"; "constants.gl"; "enums.cr"; "enums.gl"]

let make_finding (file : string) (line : int) (lang : string) (rule : string)
    (severity : string) (message : string) : Finding.t =
  { Finding.rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = lang
  ; dependency = None; reachability = None; suggestion = None
  }

(* ── C3a: Long parameter lists ──────────────────────────────────────── *)

(** Check parameter counts directly from IFunction pattern lists.
    Unlike the flat engine which reads Security_node.args (already parsed),
    this reads the AST pattern list directly — same data, but part of the
    unified AST path so it doesn't need Security_node.t at all. *)
let check_params_ast (scopes : Ast_scope.ast_scope list) (config : Types.claws_config)
    : Finding.t list =
  scopes
  |> List.filter ~f:(fun (scope : Ast_scope.ast_scope) -> not (is_exempt_method scope.fn_name))
  |> List.filter ~f:(fun (scope : Ast_scope.ast_scope) -> not (is_benchmark_or_example scope.file))
  |> List.filter_map ~f:(fun (scope : Ast_scope.ast_scope) ->
    let count = Stdlib.List.length scope.params in
    if count >= config.max_params_critical then
      Some (make_finding scope.file scope.line scope.lang "LongParameterList" "High"
        (Stdlib.Printf.sprintf "Function '%s' has %d parameters (critical threshold: %d)"
          scope.fn_name count config.max_params_critical))
    else if count >= config.max_params then
      Some (make_finding scope.file scope.line scope.lang "LongParameterList" "Medium"
        (Stdlib.Printf.sprintf "Function '%s' has %d parameters (warning threshold: %d)"
          scope.fn_name count config.max_params))
    else None
  )

(* ── C3b: Deep nesting (exact AST walk) ─────────────────────────────── *)

(** Compute the maximum nesting depth of control-flow expressions.
    Walks EIf and ECase recursively, tracking the maximum depth.

    Unlike the flat engine which counts scope-creating keywords via substring
    matching (overcounting sequential ifs as nesting), this walks the actual
    tree structure for exact nesting measurement. *)
let rec nesting_depth (expr : expr) : int =
  match expr.expr_value with
  | EUnit | ELiteral _ | EVar _ ->
    0
  | EFieldAccess (recv, _) ->
    nesting_depth recv
  | ETuple es | EList es ->
    List.fold_left ~init:0 ~f:(fun acc e -> Int.max acc (nesting_depth e)) es
  | ERecord fields ->
    List.fold_left ~init:0 ~f:(fun acc (_, e) -> Int.max acc (nesting_depth e)) fields
  | ERecordUpdate (e, fields) ->
    Int.max (nesting_depth e)
      (List.fold_left ~init:0 ~f:(fun acc (_, e) -> Int.max acc (nesting_depth e)) fields)
  | EApp (fn, args) ->
    Int.max (nesting_depth fn)
      (List.fold_left ~init:0 ~f:(fun acc a -> Int.max acc (nesting_depth a)) args)
  | EFn (_, body) ->
    nesting_depth body
  (* Control-flow: these create nesting *)
  | EIf (_cond, then_, else_) ->
    let then_depth = 1 + nesting_depth then_ in
    let else_depth = match else_ with
      | Some e -> 1 + nesting_depth e
      | None -> 0
    in
    Int.max then_depth else_depth
  | ECase (_target, branches) ->
    let branch_depth = List.fold_left ~init:0 ~f:(fun acc (_, body) ->
      Int.max acc (1 + nesting_depth body)
    ) branches in
    (* Also check the target expression *)
    Int.max branch_depth 0
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
    Int.max (nesting_depth e1) (nesting_depth e2)
  | EAssignment (e1, e2) ->
    Int.max (nesting_depth e1) (nesting_depth e2)
  | EBinOp (e1, _, e2) ->
    Int.max (nesting_depth e1) (nesting_depth e2)
  | EUnOp (_, e1) ->
    nesting_depth e1
  | EBlock es ->
    List.fold_left ~init:0 ~f:(fun acc e -> Int.max acc (nesting_depth e)) es
  | EError _ | EUnknown _ | ETryCatchFinally _ | EUse _ ->
    0

(** Check nesting depth for each function scope. *)
let check_nesting_ast (scopes : Ast_scope.ast_scope list) (config : Types.claws_config)
    : Finding.t list =
  scopes
  |> List.filter ~f:(fun (scope : Ast_scope.ast_scope) -> not (is_benchmark_or_example scope.file))
  |> List.filter_map ~f:(fun (scope : Ast_scope.ast_scope) ->
    let depth = nesting_depth scope.body in
    if depth >= config.max_nesting_critical then
      Some (make_finding scope.file scope.line scope.lang "DeepNesting" "High"
        (Stdlib.Printf.sprintf "Function '%s' has nesting depth of %d (critical threshold: %d)"
          scope.fn_name depth config.max_nesting_critical))
    else if depth >= config.max_nesting then
      Some (make_finding scope.file scope.line scope.lang "DeepNesting" "Medium"
        (Stdlib.Printf.sprintf "Function '%s' has nesting depth of %d (warning threshold: %d)"
          scope.fn_name depth config.max_nesting))
    else None
  )

(* ── C3c: God objects (exact class/module boundaries) ────────────────── *)

(** File patterns that legitimately have many methods. *)
let is_exempt_god_object (file : string) (method_names : string list) : bool =
  is_benchmark_or_example file ||
  is_constants_file file ||
  let lower = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun pat ->
    let plen = Stdlib.String.length pat in
    Stdlib.String.length lower >= plen &&
    Stdlib.String.sub lower (Stdlib.String.length lower - plen) plen = pat
  ) ["parser.cr"; "extractor.cr"; "decoder.cr"; "serializer.cr";
     "parser.gl"; "extractor.gl"; "decoder.gl"; "serializer.gl"] ||
  let total = Stdlib.List.length method_names in
  total > 0 &&
  let format_methods = List.filter ~f:(fun name ->
    Stdlib.String.length name >= 4 &&
    (let prefix = Stdlib.String.sub name 0 4 in
     prefix = "deco" || prefix = "pars" || prefix = "to_r" || prefix = "to_" || prefix = "from") ||
    Stdlib.String.length name >= 5 &&
    (let prefix = Stdlib.String.sub name 0 5 in
     prefix = "write" || prefix = "encod")
  ) method_names in
  Stdlib.List.length format_methods * 100 / total >= 40

(** Check god objects using exact IClass/IModule boundaries via ast_scope.
    Unlike the flat engine which groups defs by container line ranges
    (heuristic scope resolution), this uses the AST's actual parent field
    and counts methods per class/module directly. *)
let check_god_objects_ast (modules : Catseye_ast.Types.t list)
    (config : Types.claws_config) : Finding.t list =
  let parent_counts = Ast_scope.count_methods_in_parent modules in
  List.filter_map ~f:(fun (name, file, count) ->
    (* We don't have method_names easily here, but we can still exempt by file *)
    if count >= config.max_methods_per_file
       && not (is_benchmark_or_example file)
       && not (is_constants_file file)
    then
      Some (make_finding file 0 "" "GodObject" "Medium"
        (Stdlib.Printf.sprintf "%s has %d method definitions (threshold: %d). Consider splitting."
          name count config.max_methods_per_file))
    else None
  ) parent_counts

(* ── Combined AST anatomy analysis ──────────────────────────────────── *)

(** Run all anatomy checks on AST-native input and return merged findings. *)
let analyze (modules : Catseye_ast.Types.t list) (config : Types.claws_config)
    : Finding.t list =
  let scopes = Ast_scope.build modules in
  check_params_ast scopes config
  @ check_nesting_ast scopes config
  @ check_god_objects_ast modules config
