(* lib/catseye_claws/anatomy.ml *)

(** Structural smell detector.

    Three checks on Security_node.t lists:
    - Long parameter lists  (Def nodes with many args)
    - Deep nesting          (heuristic: count scope-creating patterns)
    - God objects           (files with too many Def nodes)
*)

open Catseye_types

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
      ; message = Printf.sprintf "Definition of '%s'" def.Security_node.name
    } ]
  ; language = def.Security_node.language
  ; dependency = None
  ; reachability = None
  }

(** Method names that are inherently multi-parameter and should be exempt
    from LongParameterList checks. These are patterns where many params
    are structurally required by the domain. *)
let is_exempt_method (name : string) : bool =
  (* Constructors *)
  name = "initialize" ||
  name = "new" ||
  name = "from_" ||
  (* Binary format parsers — params map to format fields *)
  String.length name >= 6 &&
  (let prefix = String.sub name 0 6 in
   prefix = "decode" || prefix = "parse_") ||
  (* Private helpers — extracted for dedup, params are required *)
  (String.length name >= 5 &&
   let suffix = String.sub name (String.length name - 5) 5 in
   suffix = "_core") ||
  (* Factory/builder patterns *)
  (String.length name >= 5 &&
   let prefix = String.sub name 0 5 in
   prefix = "build" || prefix = "creat") ||
  (* Benchmark methods — self-contained harnesses *)
  String.length name >= 9 &&
  (let prefix = String.sub name 0 9 in
   prefix = "benchmark") ||
  (* Test methods *)
  String.length name >= 4 &&
  (let prefix = String.sub name 0 4 in
   prefix = "test")

(** File paths that should be exempt from certain checks. *)
let is_benchmark_or_example (file : string) : bool =
  let lower = String.lowercase_ascii file in
  List.exists (fun pat ->
    let plen = String.length pat in
    String.length lower >= plen &&
    String.sub lower (String.length lower - plen) plen = pat
  ) ["/bench/"; "/benchmark/"; "/example/"; "/examples/"; "/spec/"; "/test/"; "/tests/"]

let is_constants_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  List.exists (fun pat ->
    let plen = String.length pat in
    String.length lower >= plen &&
    String.sub lower (String.length lower - plen) plen = pat
  ) ["constants.cr"; "consts.cr"; "constants.gl"; "enums.cr"; "enums.gl"]

(* ── C3a: Long parameter lists ──────────────────────────────────────── *)

let check_params (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  nodes
  |> List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  (* Skip exempt methods *)
  |> List.filter (fun def -> not (is_exempt_method def.Security_node.name))
  (* Skip benchmarks/examples *)
  |> List.filter (fun def -> not (is_benchmark_or_example def.Security_node.file))
  |> List.filter_map (fun (def : Security_node.t) ->
    let count = List.length def.Security_node.args in
    if count >= config.max_params_critical then
      Some (make_finding def "LongParameterList" "High"
        (Printf.sprintf "Function '%s' has %d parameters (critical threshold: %d)"
          def.Security_node.name count config.max_params_critical))
    else if count >= config.max_params then
      Some (make_finding def "LongParameterList" "Medium"
        (Printf.sprintf "Function '%s' has %d parameters (warning threshold: %d)"
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

(** Find substring [needle] in [haystack], returning start index or -1. *)
let find_substring (haystack : string) (needle : string) : int =
  let hlen = String.length haystack in
  let nlen = String.length needle in
  if nlen > hlen then -1
  else begin
    let result = ref (-1) in
    (try
      for i = 0 to hlen - nlen do
        if String.sub haystack i nlen = needle then begin
          result := i;
          raise Exit
        end
      done
    with Exit -> ());
    !result
  end

(** Check if a node name contains a scope-creating pattern. *)
let is_scope_creator (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun pat ->
    let idx = find_substring lower pat in
    if idx < 0 then false
    else begin
      let before_ok = idx = 0 || let c = lower.[idx - 1] in c = ' ' || c = '.' || c = '_' in
      let after_idx = idx + String.length pat in
      let after_ok = after_idx >= String.length lower
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
  List.fold_left (fun acc (n : Security_node.t) ->
    if is_scope_creator n.Security_node.name then acc + 1
    else acc
  ) 0 body

(** Build function scopes (same heuristic as complexity.ml). *)
type scope = { def : Security_node.t; body : Security_node.t list }

let build_scopes (nodes : Security_node.t list) : scope list =
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  let scopes = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun (a : Security_node.t) (b : Security_node.t) ->
      compare a.Security_node.line b.Security_node.line
    ) file_nodes in
    let defs = List.filter (fun (n : Security_node.t) ->
      n.Security_node.node_type = Security_node.Def
    ) sorted in
    List.iteri (fun i (def : Security_node.t) ->
      let start_line = def.Security_node.line in
      let end_line =
        if i + 1 < List.length defs then
          (List.nth defs (i + 1)).Security_node.line
        else max_int
      in
      let body = List.filter (fun (n : Security_node.t) ->
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
  List.filter_map (fun ({ def; body } : scope) ->
    (* Skip benchmarks/examples — nesting in harness code is acceptable *)
    if is_benchmark_or_example def.Security_node.file then None
    else begin
      let depth = approx_nesting_depth body in
      if depth >= config.max_nesting_critical then
        Some (make_finding def "DeepNesting" "High"
          (Printf.sprintf "Function '%s' has nesting depth of %d (critical threshold: %d)"
            def.Security_node.name depth config.max_nesting_critical))
      else if depth >= config.max_nesting then
        Some (make_finding def "DeepNesting" "Medium"
          (Printf.sprintf "Function '%s' has nesting depth of %d (warning threshold: %d)"
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
  let lower = String.lowercase_ascii file in
  List.exists (fun pat ->
    let plen = String.length pat in
    String.length lower >= plen &&
    String.sub lower (String.length lower - plen) plen = pat
  ) ["parser.cr"; "extractor.cr"; "decoder.cr"; "serializer.cr";
     "parser.gl"; "extractor.gl"; "decoder.gl"; "serializer.gl"] ||
  (* If > 40% of methods start with decode_/parse_/to_/from_, it's a format module *)
  let total = List.length method_names in
  total > 0 &&
  let format_methods = List.filter (fun name ->
    String.length name >= 4 &&
    (let prefix = String.sub name 0 4 in
     prefix = "deco" || prefix = "pars" || prefix = "to_r" || prefix = "to_" || prefix = "from") ||
    String.length name >= 5 &&
    (let prefix = String.sub name 0 5 in
     prefix = "write" || prefix = "encod")
  ) method_names in
  List.length format_methods * 100 / total >= 40

(** Group Def nodes by file and flag files exceeding the threshold. *)
let check_god_objects (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let defs = List.filter (fun (n : Security_node.t) ->
    n.Security_node.node_type = Security_node.Def
    && n.Security_node.name <> "initialize"  (* Exclude constructors *)
  ) nodes in
  let by_file = Hashtbl.create 16 in
  List.iter (fun (d : Security_node.t) ->
    let existing = try Hashtbl.find by_file d.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file d.Security_node.file (d :: existing)
  ) defs;
  Hashtbl.fold (fun file file_defs acc ->
    let count = List.length file_defs in
    let method_names = List.map (fun (d : Security_node.t) -> d.Security_node.name) file_defs in
    if count >= config.max_methods_per_file
       && not (is_exempt_god_object file method_names)
    then begin
      let first_def = List.hd (List.sort (fun (a : Security_node.t) (b : Security_node.t) ->
        compare a.Security_node.line b.Security_node.line
      ) file_defs) in
      { Finding.rule = "GodObject"
      ; severity = "Medium"
      ; file
      ; line = first_def.Security_node.line
      ; message = Printf.sprintf
          "File has %d method definitions (threshold: %d). Consider splitting."
          count config.max_methods_per_file
      ; flow = [ {
          Finding.file; line = first_def.Security_node.line
          ; message = Printf.sprintf "First definition of %d in this file" count
        } ]
      ; language = first_def.Security_node.language
      ; dependency = None
      ; reachability = None
      } :: acc
    end else acc
  ) by_file []

(* ── Combined anatomy analysis ──────────────────────────────────────── *)

(** Run all anatomy checks and return merged findings. *)
let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  check_params nodes config
  @ check_nesting nodes config
  @ check_god_objects nodes config
