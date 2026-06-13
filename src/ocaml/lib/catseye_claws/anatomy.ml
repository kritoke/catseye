(* lib/catseye_claws/anatomy.ml *)

(** Structural smell detector.

    Three checks on Security_node.t lists:
    - Long parameter lists  (Def nodes with many args)
    - Deep nesting          (heuristic: count scope-creating patterns)
    - God objects           (files with too many Def nodes)
*)

open Base
open Catseye_types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )

(* ── Helpers ────────────────────────────────────────────────────────── *)

let make_finding (def : Security_node.t) (rule : string) (severity : string)
    (message : string) : Finding.t =
  { Finding.rule; severity
  ; file = def.Security_node.file
  ; line = def.Security_node.line
  ; message
  ; flow = [ {
      Finding.file = def.Security_node.file
      ; line = def.Security_node.line
      ; message = Stdlib.Printf.sprintf "Definition of '%s'" def.Security_node.name
    } ]
  ; language = def.Security_node.language
  ; dependency = None
  ; reachability = None
  ; suggestion = None
  }

(** Method names that are inherently multi-parameter and should be exempt
    from LongParameterList checks. These are patterns where many params
    are structurally required by the domain. *)
let is_exempt_method = Scope.is_exempt_method

(* is_benchmark_or_example inherited from Scope *)
let is_benchmark_or_example = Scope.is_benchmark_or_example

let is_constants_file (file : string) : bool =
  let lower = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun pat ->
    let plen = Stdlib.String.length pat in
    Stdlib.String.length lower >= plen &&
    Stdlib.String.sub lower (Stdlib.String.length lower - plen) plen = pat
  ) ["constants.cr"; "consts.cr"; "constants.gl"; "enums.cr"; "enums.gl"]

(* ── C3a: Long parameter lists ──────────────────────────────────────── *)

let check_params (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  nodes
  |> List.filter ~f:(fun n -> n.Security_node.node_type = Security_node.Def)
  (* Skip exempt methods *)
  |> List.filter ~f:(fun def -> not (is_exempt_method def.Security_node.name))
  (* Skip benchmarks/examples *)
  |> List.filter ~f:(fun def -> not (is_benchmark_or_example def.Security_node.file))
  |> List.filter_map ~f:(fun (def : Security_node.t) ->
    let count = Stdlib.List.length def.Security_node.args in
    if count >= config.max_params_critical then
      Some (make_finding def "LongParameterList" "High"
        (Stdlib.Printf.sprintf "Function '%s' has %d parameters (critical threshold: %d)"
          def.Security_node.name count config.max_params_critical))
    else if count >= config.max_params then
      Some (make_finding def "LongParameterList" "Medium"
        (Stdlib.Printf.sprintf "Function '%s' has %d parameters (warning threshold: %d)"
          def.Security_node.name count config.max_params))
    else None
  )

(* ── C3b: Deep nesting (heuristic) ──────────────────────────────────── *)

(** Patterns that create nesting scope.
    Without full AST, we approximate by counting these in function bodies.
    Note: sequential if/unless at the same level should NOT count as nesting.
    We overcount by nature — the thresholds compensate.*)
let scope_creators =
  [ "if"; "unless"; "case"; "do"; "begin"; "try"; "loop"; "while"; "each" ]
  (* Note: "when" and "select" are NOT included here. In Crystal/Ruby,
     `when` clauses in a `case` statement are mutually exclusive pattern
     matches — they don't represent nested control flow. A `case` with
     15 `when` branches is a flat decision tree, not depth 15. *)

(** Check if a node name contains a scope-creating pattern. *)
let is_scope_creator (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  List.exists ~f:(fun pat ->
    let idx = Scope.find_substring lower pat in
    if idx < 0 then false
    else begin
      let before_ok = idx = 0 || let c = lower.[idx - 1] in c = ' ' || c = '.' || c = '_' in
      let after_idx = idx + Stdlib.String.length pat in
      let after_ok = after_idx >= Stdlib.String.length lower
        || let c = lower.[after_idx] in c = ' ' || c = '.' || c = '_' || c = '('
      in
      before_ok && after_ok
    end
  ) scope_creators

(** Approximate nesting depth for a function body.
    This overcounts — sequential if statements count as nesting.
    The thresholds (4/6) absorb this.
*)
let approx_nesting_depth (body : Security_node.t list) : int =
  List.fold_left ~init:0 ~f:(fun acc (n : Security_node.t) ->
    if is_scope_creator n.Security_node.name then acc + 1
    else acc
  ) body

(** Build function scopes (same heuristic as complexity.ml). *)
type scope = { def : Security_node.t; body : Security_node.t list }

let build_scopes (nodes : Security_node.t list) : scope list =
  let by_file = Stdlib.Hashtbl.create 16 in
  List.iter ~f:(fun (n : Security_node.t) ->
    let existing = try Stdlib.Hashtbl.find by_file n.Security_node.file with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  let scopes = ref [] in
  Stdlib.Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort ~compare:(fun (a : Security_node.t) (b : Security_node.t) ->
      Int.compare a.Security_node.line b.Security_node.line
    ) file_nodes in
    let defs = List.filter ~f:(fun (n : Security_node.t) ->
      n.Security_node.node_type = Security_node.Def
    ) sorted in
    List.iteri ~f:(fun i (def : Security_node.t) ->
      let start_line = def.Security_node.line in
      let end_line =
        if i + 1 < Stdlib.List.length defs then
          (match List.nth defs (i + 1) with
           | Some next_def -> next_def.Security_node.line
           | None -> Stdlib.Int.max_int)
        else Stdlib.Int.max_int
      in
      let body = List.filter ~f:(fun (n : Security_node.t) ->
        n.Security_node.node_type <> Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in
      scopes := { def; body } :: !scopes
    ) defs
  ) by_file;
  List.rev !scopes

let check_nesting (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let scopes = build_scopes nodes in
  List.filter_map ~f:(fun ({ def; body } : scope) ->
    (* Skip benchmarks/examples — nesting in harness code is acceptable *)
    if is_benchmark_or_example def.Security_node.file then None
    else begin
      let depth = approx_nesting_depth body in
      if depth >= config.max_nesting_critical then
        Some (make_finding def "DeepNesting" "High"
          (Stdlib.Printf.sprintf "Function '%s' has nesting depth of %d (critical threshold: %d)"
            def.Security_node.name depth config.max_nesting_critical))
      else if depth >= config.max_nesting then
        Some (make_finding def "DeepNesting" "Medium"
          (Stdlib.Printf.sprintf "Function '%s' has nesting depth of %d (warning threshold: %d)"
            def.Security_node.name depth config.max_nesting))
      else None
    end
  ) scopes

(* ── C3c: God objects ───────────────────────────────────────────────── *)

(** File patterns that legitimately have many methods.
    Format parsers, API modules, and coordinator classes need many methods
    by their nature. *)
let is_exempt_god_object (file : string) (method_names : string list) : bool =
  (* Benchmarks/examples *)
  is_benchmark_or_example file ||
  (* Constants/enum files *)
  is_constants_file file ||
  (* Binary format parsers — many methods for different format aspects *)
  let lower = Stdlib.String.lowercase_ascii file in
  List.exists ~f:(fun pat ->
    let plen = Stdlib.String.length pat in
    Stdlib.String.length lower >= plen &&
    Stdlib.String.sub lower (Stdlib.String.length lower - plen) plen = pat
  ) ["parser.cr"; "extractor.cr"; "decoder.cr"; "serializer.cr";
     "parser.gl"; "extractor.gl"; "decoder.gl"; "serializer.gl"] ||
  (* If > 40% of methods start with decode_/parse_/to_/from_, it's a format module *)
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

(** Group Def nodes by class/module scope and flag scopes exceeding the threshold.
    Uses Class/Module node line ranges to determine which defs belong to which scope.
    If no class/module is found, falls back to per-file counting. *)
let check_god_objects (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let defs = List.filter ~f:(fun (n : Security_node.t) ->
    n.Security_node.node_type = Security_node.Def
    && n.Security_node.name <> "initialize"
  ) nodes in
  let containers = List.filter ~f:(fun (n : Security_node.t) ->
    n.Security_node.node_type = Security_node.Class
    || n.Security_node.node_type = Security_node.Module
  ) nodes in
  (* Build sorted list of (line, file, container_name) for scope resolution *)
  let containers_sorted = List.sort ~compare:(fun a b ->
    let c = String.compare a.Security_node.file b.Security_node.file in
    if c <> 0 then c else Int.compare a.Security_node.line b.Security_node.line
  ) containers in
  (* For each def, find which container (class/module) it belongs to *)
  let scope_of_def (d : Security_node.t) : string =
    let file = d.Security_node.file in
    let line = d.Security_node.line in
    (* Find the last container in the same file with line <= def line *)
    let best = ref "" in
    List.iter ~f:(fun (c : Security_node.t) ->
      if c.Security_node.file = file && c.Security_node.line <= line then
        best := c.Security_node.name
    ) containers_sorted;
    !best
  in
  (* Group defs by (file, scope) *)
  let by_scope = Stdlib.Hashtbl.create 32 in
  List.iter ~f:(fun (d : Security_node.t) ->
    let file = d.Security_node.file in
    let scope = scope_of_def d in
    let key = file ^ "::" ^ scope in
    let existing = try Stdlib.Hashtbl.find by_scope key with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_scope key (d :: existing)
  ) defs;
  (* Check each scope *)
  Stdlib.Hashtbl.fold (fun key file_defs acc ->
    let count = Stdlib.List.length file_defs in
    let file = match Stdlib.String.index_opt key ':' with
      | Some i -> Stdlib.String.sub key 0 i
      | None -> key
    in
    let method_names = List.map ~f:(fun (d : Security_node.t) -> d.Security_node.name) file_defs in
    if count >= config.max_methods_per_file
       && not (is_exempt_god_object file method_names)
    then begin
      let first_def = Stdlib.List.hd (List.sort ~compare:(fun (a : Security_node.t) (b : Security_node.t) ->
        Int.compare a.Security_node.line b.Security_node.line
      ) file_defs) in
      (* Extract scope name from key *)
      let scope_name = match Stdlib.String.index_opt key ':' with
        | Some i ->
            let rest = Stdlib.String.sub key (i + 2) (Stdlib.String.length key - i - 2) in
            if rest = "" then "(top-level)" else rest
        | None -> "(top-level)"
      in
      { Finding.rule = "GodObject"
      ; severity = "Medium"
      ; file
      ; line = first_def.Security_node.line
      ; message = Stdlib.Printf.sprintf
          "%s has %d method definitions (threshold: %d). Consider splitting."
          scope_name count config.max_methods_per_file
      ; flow = [{
          Finding.file; line = first_def.Security_node.line
          ; message = Stdlib.Printf.sprintf "First definition of %d in %s" count scope_name
        }]
      ; language = first_def.Security_node.language
      ; dependency = None
      ; reachability = None
      ; suggestion = None
      } :: acc
    end else acc
  ) by_scope []

(* ── Combined anatomy analysis ──────────────────────────────────────── *)

(** Run all anatomy checks and return merged findings. *)
let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  check_params nodes config
  @ check_nesting nodes config
  @ check_god_objects nodes config
