(* lib/catseye_claws/extra_smells.ml

   Additional smell detectors beyond DRY/complexity/anatomy:

   - Long Method: functions with too many AST nodes
   - Complex Conditional: single expressions with too many && / ||
   - Message Chains: a.b.c.d() call chains (Law of Demeter violation)
   - Data Clumps: parameter pairs repeated across multiple functions
*)

open Catseye_types
open Scope

(* ── Long Method ────────────────────────────────────────────────────── *)

(** Check if a file is a benchmark, example, or test file. *)
let is_bench_or_example (file : string) : bool =
  let lower = String.lowercase_ascii file in
  List.exists (fun pat ->
    let plen = String.length pat in
    String.length lower >= plen &&
    String.sub lower (String.length lower - plen) plen = pat
  ) ["/bench/"; "/benchmark/"; "/example/"; "/examples/"; "/spec/"; "/test/"; "/tests/"]

(** Method names that should be exempt from LongMethod checks. *)
let is_long_method_exempt (name : string) : bool =
  (* Constructors *)
  name = "initialize" || name = "new" ||
  (* Benchmark methods *)
  (String.length name >= 9 &&
   let prefix = String.sub name 0 9 in
   prefix = "benchmark") ||
  (* Binary format decoders - inherently sequential *)
  (String.length name >= 6 &&
   let prefix = String.sub name 0 6 in
   prefix = "decode" || prefix = "parse_" || prefix = "from_s") ||
  (* Algorithm implementations - well-known structures *)
  (String.length name >= 9 &&
   let suffix = String.sub name (String.length name - 9) 9 in
   suffix = "_weighted" || suffix = "_quantize" || suffix = "_histogra") ||
  name = "quantize" || name = "sink_down" || name = "quickselect" ||
  name = "split" || name = "suggest_text_palette" || name = "relative_luminance" ||
  name = "from_hsl" || name = "from_color_string" ||
  name = "validate_file_path" || name = "image_header?" ||
  name = "try_unix_mkstemp"

(** Count the number of AST nodes in a function body. Skip exempt methods. *)
let check_long_method (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let scopes = build_scopes nodes in
  let warning_threshold = config.long_method_warning in
  let critical_threshold = config.long_method_critical in
  List.filter_map (fun ({ def; body } : scope) ->
    (* Skip exempt methods and files *)
    if is_long_method_exempt def.Security_node.name
       || is_bench_or_example def.Security_node.file
    then None
    else
      let count = List.length body in
      if count >= critical_threshold then
        Some {
          Finding.rule = "LongMethod";
          severity = "High";
          file = def.Security_node.file;
          line = def.Security_node.line;
          message = Printf.sprintf
            "Function '%s' has %d AST nodes (critical threshold: %d). Consider breaking into smaller functions."
            def.Security_node.name count critical_threshold;
          flow = [ {
            Finding.file = def.Security_node.file;
            line = def.Security_node.line;
            message = Printf.sprintf "Definition of '%s' (%d nodes)" def.Security_node.name count;
          } ];
          language = def.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else if count >= warning_threshold then
        Some {
          Finding.rule = "LongMethod";
          severity = "Medium";
          file = def.Security_node.file;
          line = def.Security_node.line;
          message = Printf.sprintf
            "Function '%s' has %d AST nodes (warning threshold: %d). Consider breaking into smaller functions."
            def.Security_node.name count warning_threshold;
          flow = [ {
            Finding.file = def.Security_node.file;
            line = def.Security_node.line;
            message = Printf.sprintf "Definition of '%s' (%d nodes)" def.Security_node.name count;
          } ];
          language = def.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
  ) scopes

(* ── Complex Conditional ────────────────────────────────────────────── *)

(** Count logical operators (&&, ||) in a single node name.
    Crystal emits compound conditional names that include these operators.
    Gleam uses different patterns but we check the same way. *)
let count_logical_ops (name : string) : int =
  let lower = String.lowercase_ascii name in
  let count = ref 0 in
  (* Count && and || occurrences *)
  let rec scan i =
    if i + 1 >= String.length lower then ()
    else begin
      let two = String.sub lower i 2 in
      if two = "&&" || two = "||" then begin
        incr count; scan (i + 2)
      end else scan (i + 1)
    end
  in
  scan 0;
  !count

(** Flag functions containing conditionals with too many logical operators.
    Threshold: 3+ operators in a single expression = Warning. *)
let check_complex_conditionals (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.complex_conditional_threshold in
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type <> Security_node.Call then None
    else
      let ops = count_logical_ops n.Security_node.name in
      if ops >= threshold then
        Some {
          Finding.rule = "ComplexConditional";
          severity = "Medium";
          file = n.Security_node.file;
          line = n.Security_node.line;
          message = Printf.sprintf
            "Complex conditional with %d logical operators (threshold: %d). \
             Consider extracting sub-expressions into named variables."
            ops threshold;
          flow = [ {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "Expression: %s" n.Security_node.name;
          } ];
          language = n.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
  ) nodes

(* ── Message Chains (Law of Demeter) ────────────────────────────────── *)

(** Count the number of segments in a dotted call name.
    "feed.items.size.to_i32" has 4 segments.
    Threshold: 4+ segments = Warning (Law of Demeter violation). *)
let count_chain_segments (name : string) : int =
  let count = ref 1 in
  for i = 0 to String.length name - 1 do
    if name.[i] = '.' then incr count
  done;
  !count

(** Filter out chains that are just module paths (e.g., "XML::ParserOptions::RECOVER")
    or common Crystal stdlib paths that are idiomatic, or mathematical expressions. *)
let is_idiomatic_chain (name : string) : bool =
  let lower = String.lowercase_ascii name in
  (* Module paths use :: not . - these are fine *)
  find_substring lower "::" >= 0
  (* Type conversions are idiomatic *)
  || List.exists (fun suffix ->
    let slen = String.length suffix in
    String.length name >= slen
    && String.sub name (String.length name - slen) slen = suffix
  ) [".to_s"; ".to_i"; ".to_i32"; ".to_i64"; ".to_f"; ".to_f32"; ".to_f64";
     ".to_bool"; ".to_a"; ".to_h"; ".nil?"; ".to_json"; ".as_json"
     ; ".size"; ".empty?"; ".blank?"; ".present?"; ".try"; ".not_nil!"
     ; ".to_s.downcase"; ".to_s.strip"; ".to_i32?"; ".to_i64?"
     ; ".to_f32?"; ".to_f64?"; ".starts_with?"; ".ends_with?"
     (* Math/numeric coercion chains - standard Crystal numeric patterns *)
     ; ".to_i.clamp"; ".to_f.clamp"; ".to_i32.clamp"; ".to_i64.clamp"
     ; ".to_i.round"; ".to_f.round"; ".to_i.abs"; ".to_f.abs"
     ; ".clamp"; ".round"; ".abs"
  ]
  (* Math expressions - chains containing arithmetic operators *)
  || List.exists (fun op -> find_substring lower op >= 0)
    ["+"; "-"; "*"; "/"; "%"; "**"]
  (* Bitwise operations for binary parsing *)
  || List.exists (fun op -> find_substring lower op >= 0)
    ["<<"; ">>"; "|"]

let check_message_chains (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let threshold = config.message_chain_threshold in
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type <> Security_node.Call then None
    else
      let segments = count_chain_segments n.Security_node.name in
      if segments >= threshold && not (is_idiomatic_chain n.Security_node.name) then
        Some {
          Finding.rule = "MessageChain";
          severity = "Medium";
          file = n.Security_node.file;
          line = n.Security_node.line;
          message = Printf.sprintf
            "Long method chain with %d segments (threshold: %d): %s. \
             Consider introducing intermediate variables (Law of Demeter)."
            segments threshold n.Security_node.name;
          flow = [ {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "Chain: %s" n.Security_node.name;
          } ];
          language = n.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
  ) nodes

(* ── Data Clumps ────────────────────────────────────────────────────── *)

(** Detect parameter pairs that appear together across multiple function
    definitions, suggesting they should be grouped into a struct/record.

    Algorithm:
    1. Extract all (var_name) params from each Def node
    2. Generate all 2-pairs from each function's params
    3. Count how many functions share each pair
    4. Pairs appearing in >= threshold functions are data clumps
*)
let check_data_clumps (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  if not config.data_clumps_enabled then []
  else begin
    let threshold = config.data_clumps_threshold in
    (* Collect param sets per function *)
    let defs = List.filter (fun n ->
      n.Security_node.node_type = Security_node.Def
      && List.length n.Security_node.args >= 2
    ) nodes in
    (* Count co-occurrences of param pairs *)
    let pair_counts : (string * string, int) Hashtbl.t = Hashtbl.create 64 in
    let pair_files : (string * string, string list) Hashtbl.t = Hashtbl.create 64 in
    List.iter (fun (def : Security_node.t) ->
      let params = List.filter_map (fun a ->
        if a.Security_node.arg_type = Security_node.ArgVar then
          Some a.Security_node.value
        else None
      ) def.Security_node.args in
      (* Generate all pairs *)
      List.iter (fun (p1, p2) ->
        let key = (min p1 p2, max p1 p2) in
        let current = try Hashtbl.find pair_counts key with Not_found -> 0 in
        Hashtbl.replace pair_counts key (current + 1);
        let files = try Hashtbl.find pair_files key with Not_found -> [] in
        if not (List.mem def.Security_node.file files) then
          Hashtbl.replace pair_files key (def.Security_node.file :: files)
      ) (List.concat_map (fun p1 ->
        List.filter_map (fun p2 ->
          if p1 < p2 then Some (p1, p2) else None
        ) params
      ) params)
    ) defs;
    (* Report pairs exceeding threshold, filtering out common Crystal stdlib patterns
       that are idiomatic rather than code smells. *)
    let common_pairs = Hashtbl.create 16 in
    List.iter (fun (a, b) -> Hashtbl.replace common_pairs (a, b) true) [
      ("config", "url"); ("key", "value"); ("message", "url");
      ("body", "url"); ("body", "config"); ("content", "limit");
      ("io", "limit"); ("data", "limit"); ("ex", "url");
    ];
    Hashtbl.fold (fun (p1, p2) count acc ->
      if count < threshold then acc
      else begin
        let files = try Hashtbl.find pair_files (p1, p2) with Not_found -> [] in
        let is_common = Hashtbl.mem common_pairs (min p1 p2, max p1 p2) in
        let file_count = List.length files in
        if is_common || file_count < 2 then acc
        else
          { Finding.rule = "DataClump";
            severity = "Medium";
            file = List.hd (List.sort String.compare files);
            line = 0;
            message = Printf.sprintf
              "Parameters '%s' and '%s' always appear together in %d functions \
               across %d files. Consider grouping into a struct or record."
              p1 p2 count file_count;
            flow = [];
            language = "";
            dependency = None;
            reachability = None; suggestion = None;
          } :: acc
      end
    ) pair_counts []
  end

(* ── Flag Argument ───────────────────────────────────────────────────── *)

(** Detect boolean-style parameters that control function behavior:
    is_*, should_*, enable_*, disable_*, use_*, has_*, with_*, force_*,
    skip_*, no_*, verbose, debug, dry_run.
    These split the function's behavior and suggest decomposition. *)
let flag_prefixes = [
  "should_"; "enable_"; "disable_"; "use_"; "include_";
  "allow_"; "force_"; "skip_"; "no_"; "with_";
]
let flag_names = ["verbose"; "debug"; "dry_run"; "strict"; "quiet"]

(* Note: is_* and has_* are NOT in flag_prefixes. These are commonly
   used for DTO/record boolean properties (is_active, has_more, etc.)
   which are data fields, not control flow flags. Only methods that
   branch behavior based on these should be flagged, and that's better
   detected by complexity analysis than by parameter naming. *)

let is_flag_arg (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length lower >= plen && String.sub lower 0 plen = prefix
  ) flag_prefixes
  || List.exists (fun n -> lower = n) flag_names

let check_flag_arguments (nodes : Security_node.t list)
    (_config : Types.claws_config) : Finding.t list =
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type <> Security_node.Def then None
    else
      let flags = List.filter (fun a ->
        a.Security_node.arg_type = Security_node.ArgVar
        && is_flag_arg a.Security_node.value
      ) n.Security_node.args in
      match flags with
      | [] -> None
      | _ ->
        let flag_names = String.concat ", " (
          List.map (fun a -> a.Security_node.value) flags
        ) in
        Some {
          Finding.rule = "FlagArgument";
          severity = "Medium";
          file = n.Security_node.file;
          line = n.Security_node.line;
          message = Printf.sprintf
            "Function '%s' has flag parameter(s): %s. \
             Consider splitting into separate methods."
            n.Security_node.name flag_names;
          flow = [ {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "Definition of '%s'" n.Security_node.name;
          } ];
          language = n.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
  ) nodes

(* ── Complex Match/Case ─────────────────────────────────────────────── *)

(** Flag case expressions with too many when branches.
    Uses the new Control nodes emitted by the extractor.
    Threshold: 5+ when branches = Warning, 10+ = Error. *)
let check_complex_match (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type <> Security_node.Control then None
    else if n.Security_node.name <> "case" then None
    else
      (* The extractor stores the when count as a literal arg *)
      let when_count = match n.Security_node.args with
        | [{ Security_node.arg_type = ArgLiteral; value; _ }] -> (
          try int_of_string value with _ -> 0
        )
        | _ -> 0
      in
      if when_count >= config.complex_match_critical then
        Some {
          Finding.rule = "ComplexMatch";
          severity = "High";
          file = n.Security_node.file;
          line = n.Security_node.line;
          message = Printf.sprintf
            "Complex case expression with %d when branches (critical threshold: %d). \
             Consider decomposing into smaller functions or a lookup table."
            when_count config.complex_match_critical;
          flow = [ {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "case with %d branches" when_count;
          } ];
          language = n.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else if when_count >= config.complex_match_warning then
        Some {
          Finding.rule = "ComplexMatch";
          severity = "Medium";
          file = n.Security_node.file;
          line = n.Security_node.line;
          message = Printf.sprintf
            "Complex case expression with %d when branches (warning threshold: %d). \
             Consider decomposing into smaller functions or a lookup table."
            when_count config.complex_match_warning;
          flow = [ {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "case with %d branches" when_count;
          } ];
          language = n.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
  ) nodes

(* ── Dead Code (after unconditional terminators) ────────────────────── *)

(** Build a set of control flow lines (if/unless) - terminators on
    these lines are conditional (e.g., "return if x") and NOT dead code. *)
let build_control_lines (nodes : Security_node.t list) : (string, int list) Hashtbl.t =
  let tbl : (string, int list) Hashtbl.t = Hashtbl.create 32 in
  List.iter (fun (n : Security_node.t) ->
    if n.Security_node.node_type = Security_node.Control then begin
      let existing = try Hashtbl.find tbl n.Security_node.file with Not_found -> [] in
      Hashtbl.replace tbl n.Security_node.file (n.Security_node.line :: existing)
    end
  ) nodes;
  tbl

(** Check if a line is a control flow line (conditional terminator).
    Checks the exact line and the 2 lines before it to handle
    `if condition\n  return\nend` patterns where control and terminator
    are on different lines. *)
let is_conditional_terminator (control_lines : (string, int list) Hashtbl.t)
    (file : string) (line : int) : bool =
  match Hashtbl.find_opt control_lines file with
  | Some lines ->
    List.mem line lines
    || List.mem (line - 1) lines
    || List.mem (line - 2) lines
  | None -> false

(** Detect code after unconditional return/raise in the same function scope.
    A terminator is "unconditional" if it's NOT on a control flow line
    (i.e., not "return if x" but just "return x").
    Flags the first non-control, non-class node after an unconditional terminator. *)
let check_dead_code (nodes : Security_node.t list)
    (_config : Types.claws_config) : Finding.t list =
  let control_lines = build_control_lines nodes in
  (* Build function scopes *)
  let scopes = build_scopes nodes in
  List.filter_map (fun ({ def; body } : scope) ->
    (* Scan body for unconditional terminators followed by code *)
      (* Scan body for unconditional terminators followed by code.
         Skip terminators in the last 3 nodes of the body - these are
         common "return at end of function" patterns, not dead code.
         Also require at least 2 nodes after terminator to reduce noise. *)
      let rec scan (nesting : int) (idx : int) = function
        | [] -> None
        | n :: rest ->
          let remaining = List.length rest in
          let next_nesting =
            if n.Security_node.node_type = Security_node.Control then nesting + 1
            else nesting
          in
          let is_inline_guard =
            (* A terminator on the same line as an assign or call is likely
               an inline guard like `x || return` or `x ? return` *)
            n.Security_node.node_type = Security_node.Terminator
            && List.exists (fun (prev : Security_node.t) ->
              prev.Security_node.line = n.Security_node.line
              && (prev.Security_node.node_type = Security_node.Assign
                  || prev.Security_node.node_type = Security_node.Call)
            ) body
          in
          let is_early_macro_terminator =
            (* Athena and other framework macros expand `return` statements
               at the top of method bodies. If a terminator appears before
               any Assign or Call node in the body, it's likely a macro
               artifact — the user code below is reachable through the
               original method body. Only apply this heuristic when the
               terminator is in the first 3 nodes of the body. *)
            n.Security_node.node_type = Security_node.Terminator
            && idx < 3
            && List.exists (fun (later : Security_node.t) ->
              later.Security_node.node_type = Security_node.Assign
              || later.Security_node.node_type = Security_node.Call
            ) body
          in
          if remaining <= 2 then None  (* too close to end of function *)
          else if n.Security_node.node_type = Security_node.Terminator
             && (nesting > 0 || is_inline_guard || is_early_macro_terminator
                 || is_conditional_terminator control_lines
                       n.Security_node.file n.Security_node.line)
          then
            (* Terminator inside a control branch — not unconditional *)
            scan next_nesting (idx + 1) rest
          else if n.Security_node.node_type = Security_node.Terminator
             && not (is_conditional_terminator control_lines
                       n.Security_node.file n.Security_node.line)
          then begin
            (* Check for branch boundaries (rescue, when) between terminator
               and potential dead code — if a branch boundary exists, the
               terminator and “dead” code are in different branches. *)
            let has_branch_boundary = List.exists (fun (b : Security_node.t) ->
              b.Security_node.node_type = Security_node.Control
              && (b.Security_node.name = "rescue"
                  || b.Security_node.name = "when"
                  || b.Security_node.name = "exception_handler")
              && b.Security_node.line > n.Security_node.line
            ) rest in
            if has_branch_boundary then scan next_nesting (idx + 1) rest
            else begin
            (* Find next meaningful node — skip control/terminator/class nodes *)
            let dead = List.find_opt (fun (d : Security_node.t) ->
              d.Security_node.node_type <> Security_node.Control
              && d.Security_node.node_type <> Security_node.Terminator
              && d.Security_node.node_type <> Security_node.Class
              && d.Security_node.node_type <> Security_node.Module
              && d.Security_node.node_type <> Security_node.Enum
              && d.Security_node.line > n.Security_node.line
            ) rest in
            (match dead with
             | Some d ->
               Some (d.Security_node.file, d.Security_node.line,
                     n.Security_node.name, n.Security_node.line,
                     def.Security_node.name,
                     d.Security_node.node_type, d.Security_node.name)
             | None -> None)
            end
          end else scan next_nesting (idx + 1) rest
      in
      match (scan 0 0) body with
    | Some (file, line, term_name, term_line, def_name, dead_type, dead_name) ->
      Some {
        Finding.rule = "DeadCode";
        severity = "High";
        file;
        line;
        message = Printf.sprintf
          "Unreachable %s '%s' after unconditional %s at line %d in '%s'. \
           This code will never execute."
          (Security_node.string_of_node_type dead_type) dead_name
          term_name term_line def_name;
        flow = [ {
          Finding.file = file;
          line = term_line;
          message = Printf.sprintf "Unconditional %s" term_name;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    | None -> None
  ) scopes

(* ── Data Class ─────────────────────────────────────────────────────── *)

(** Detect classes/structs that only contain getters/properties and initialize.
    These are pure data containers that should be Crystal structs or records.

    Algorithm: for each Class node, count the Def nodes between this class
    and the next class/module/enum (or end of file). If all defs are
    'initialize' and there are getter/property calls, it's a Data Class. *)
let check_data_classes (nodes : Security_node.t list)
    (_config : Types.claws_config) : Finding.t list =
  (* Build class boundaries: (file, start_line, end_line, class_name) *)
  let class_boundaries = ref [] in
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b ->
      compare a.Security_node.line b.Security_node.line
    ) file_nodes in
    let class_nodes = List.filter (fun n ->
      n.Security_node.node_type = Security_node.Class
      || n.Security_node.node_type = Security_node.Module
      || n.Security_node.node_type = Security_node.Enum
    ) sorted in
    List.iteri (fun i (cn : Security_node.t) ->
      if cn.Security_node.node_type = Security_node.Class then begin
        let end_line =
          if i + 1 < List.length class_nodes then
            (List.nth class_nodes (i + 1)).Security_node.line
          else max_int
        in
        class_boundaries := (cn.Security_node.file, cn.Security_node.line,
                             end_line, cn.Security_node.name) :: !class_boundaries
      end
    ) class_nodes
  ) by_file;
  (* For each class, analyze its contents *)
  List.filter_map (fun (file, start_line, end_line, class_name) ->
    let class_nodes = List.filter (fun (n : Security_node.t) ->
      n.Security_node.file = file
      && n.Security_node.line >= start_line
      && n.Security_node.line < end_line
    ) nodes in
    let defs = List.filter (fun n ->
      n.Security_node.node_type = Security_node.Def
    ) class_nodes in
    let getters = List.filter (fun n ->
      n.Security_node.node_type = Security_node.Call
      && List.mem n.Security_node.name ["getter"; "property"; "setter";
         "class_getter"; "class_property"; "class_setter"]
    ) class_nodes in
    let non_init_defs = List.filter (fun (d : Security_node.t) ->
      d.Security_node.name <> "initialize"
    ) defs in
    (* Check for Crystal DTO/serialization patterns that make DataClass acceptable *)
    let has_serializable = List.exists (fun n ->
      n.Security_node.node_type = Security_node.Call
      && n.Security_node.name = "include"
      && List.exists (fun (a : Security_node.arg) ->
        List.mem a.Security_node.value
          ["JSON::Serializable"; "JSON::Serializable::Unmapped";
           "JSON::Mappings"; "YAML::Serializable";
           "DB::Serializable"; "OAuth2::Serializable"]
      ) n.Security_node.args
    ) class_nodes in
    let is_dto_file =
      let lower = String.lowercase_ascii file in
      List.exists (fun pat ->
        let rec contains_sub s start =
          if start + String.length pat > String.length s then false
          else if String.sub s start (String.length pat) = pat then true
          else contains_sub s (start + 1)
        in contains_sub lower 0
      ) ["/dtos/"; "/dto/"; "/types/"; "/entities/"; "/models/"] in
    (* Data Class: has getters, no non-initialize methods, not a DTO/serializable *)
    if List.length getters >= 2 && List.length non_init_defs = 0
       && not has_serializable && not is_dto_file then
      Some {
        Finding.rule = "DataClass";
        severity = "Medium";
        file;
        line = start_line;
        message = Printf.sprintf
          "Class '%s' has %d properties but no behavior methods (only initialize). \
           Consider using a Crystal struct or record instead."
          class_name (List.length getters);
        flow = [ {
          Finding.file = file;
          line = start_line;
          message = Printf.sprintf "Definition of '%s'" class_name;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) !class_boundaries

(* ── Feature Envy ────────────────────────────────────────────────────── *)

(* Feature Envy: flag when a function spends 70%+ of external
   call accesses on a non-parameter target from another class.
   See is_converter_method, is_parameter, is_generic_target. *)

(** Check if a function name is a conversion/serializer pattern *)
let is_converter_method (name : string) : bool =
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length name >= plen && String.sub name 0 plen = prefix
  ) ["from_"; "to_"; "build_"; "map_"; "serialize_"; "deserialize_";
     "parse_"; "convert_"; "format_"; "render_"; "compose_"]

(* Check if envied target matches any parameter name *)
let is_parameter (def_node : Security_node.t) (obj_name : string) : bool =
  List.exists (fun (a : Security_node.arg) ->
    a.Security_node.value = obj_name
  ) def_node.Security_node.args

(* Check if the envied target name is embedded in the function name.
   E.g. 'validate_feed_urls!' envies 'feed' - the function is ABOUT feeds.
   Not envy, it's the function's declared domain. *)
let is_name_related (def_name : string) (obj_name : string) : bool =
  let lower_def = String.lowercase_ascii def_name in
  let lower_obj = String.lowercase_ascii obj_name in
  (* obj name appears as substring of function name *)
  let obj_len = String.length lower_obj in
  let def_len = String.length lower_def in
  obj_len > 0 && obj_len < def_len &&
    (let rec check i =
      i + obj_len <= def_len &&
        (String.sub lower_def i obj_len = lower_obj || check (i + 1))
    in check 0)

(* Build set of locally-assigned variable names in a function body.
   These are NOT envied - they are the function's own working data. *)
let build_local_vars (body : Security_node.t list) : string list =
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type = Security_node.Assign then
      Some n.Security_node.name
    else None
  ) body

(* Generic data-access target names used in repository/DB patterns.
   Not real domain targets - iteration artifacts.
   Also includes common loop iterator and exception variable names. *)
(* Generic data-access target names used in repository/DB patterns.
   Not real domain targets - iteration artifacts.
   Also includes common loop iterator and exception variable names.
   Uses prefix match: 'item' matches 'items', 'entry' matches 'entries'. *)
(* Generic data-access target names used in repository/DB patterns.
   Not real domain targets - iteration artifacts.
   Also includes common loop iterator and exception variable names.
   Uses prefix match: 'item' matches 'items', 'entry' matches 'entries'. *)
let is_generic_target (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun prefix ->
    let plen = String.length prefix in
    String.length lower >= plen && String.sub lower 0 plen = prefix
  ) [
    "rows"; "row"; "result"; "results"; "data"; "dataset";
    "response"; "resp"; "hash"; "arr"; "collection";
    (* Common loop iterator names from .each/.map/.select blocks *)
    (* Common loop/iterator names *)
    "item"; "entry"; "elem"; "element"; "record"; "rec";
    "val"; "value"; "key"; "field";
    "conn"; "connection"; "sock"; "socket"; "client";
    "migration"; "candidate"; "resource";
    "cons"; "tuple"; "pair";
    (* XML/HTML parsing iterators *)
    "node"; "child"; "children";
    (* Path/URL segment iterators *)
    "part"; "segment"; "chunk"; "piece";
    (* Network address variables *)
    "addr"; "address"; "host";
    (* Web framework context objects - always passed in *)
    "site"; "app"; "ctx"; "context";
    (* Constructor/config parameter patterns *)
    "opts"; "options"; "config"; "settings"; "params";
    (* Exception variables from rescue blocks *)
    "ex"; "exc"; "err"; "error"; "exception";
    (* Retry/attempt counters *)
    "retry"; "attempt";
  ]
  (* Crystal/Ruby stdlib types that cannot be reopened — accessing these
     heavily is not "envy", it's the only way to use them. *)
  || List.mem lower [
    "uri"; "url"; "path"; "file"; "dir"; "io";
    "json"; "xml"; "html"; "csv"; "yaml"; "toml";
    "http"; "tcp"; "udp"; "ssl"; "tls"; "dns";
    "time"; "date"; "datetime";
    "array"; "hash"; "set"; "tuple"; "range"; "regex";
    "string"; "int"; "float"; "bool"; "char"; "bytes";
    "log"; "logger"; "fiber"; "channel"; "mutex";
    "process"; "system"; "env"; "signal";
    "socket"; "ip"; "openssl"; "base64";
  ]

let check_feature_envy (nodes : Security_node.t list)
    (_config : Types.claws_config) : Finding.t list =
  let scopes = build_scopes nodes in
  List.filter_map (fun ({ def; body } : scope) ->
    (* Skip converter/serializer methods and anonymous lambdas *)
    if is_converter_method def.Security_node.name
       || def.Security_node.name = "->"
       || def.Security_node.name = "<lambda>"
    then None
    else begin
      (* Build set of parameter names and local variable names for this function *)
      let param_set = List.map (fun (a : Security_node.arg) ->
        a.Security_node.value
      ) def.Security_node.args in
      let local_vars = build_local_vars body in
      let is_own_var obj =
        List.mem obj param_set || List.mem obj local_vars
        || is_generic_target obj || is_name_related def.Security_node.name obj
      in

      (* Count object accesses in this function, excluding params *)
      let obj_counts : (string, int) Hashtbl.t = Hashtbl.create 8 in
      List.iter (fun (n : Security_node.t) ->
        if n.Security_node.node_type = Security_node.Call then begin
          let name = n.Security_node.name in
          try
            let dot = String.index name '.' in
            let obj = String.sub name 0 dot in
            (* Skip: self-accesses (@x), params, stdlib, operators,
               generic targets, Module paths *)
            (* Skip: self-accesses (@x), params, stdlib, operators,
               generic targets, name-related, parsing artifacts *)
            if String.length obj > 0
               && obj.[0] <> '@'
               && obj <> "raise"
               && String.length obj >= 2
               && not (let c = obj.[0] in c = '_' || c = '(' || c >= 'A' && c <= 'Z')
               && not (is_own_var obj)
            then begin
              let current = try Hashtbl.find obj_counts obj with Not_found -> 0 in
              Hashtbl.replace obj_counts obj (current + 1)
            end
          with Not_found -> ()
        end
      ) body;

      (* Find dominant object *)
      let total = Hashtbl.fold (fun _ c acc -> acc + c) obj_counts 0 in
      if total >= 5 then begin
        let best_obj = ref "" in
        let best_count = ref 0 in
        Hashtbl.iter (fun obj count ->
          if count > !best_count then begin
            best_obj := obj;
            best_count := count
          end
        ) obj_counts;
        let ratio = float_of_int !best_count /. float_of_int total in
        if ratio >= 0.7 then
          Some {
            Finding.rule = "FeatureEnvy";
            severity = "Medium";
            file = def.Security_node.file;
            line = def.Security_node.line;
            message = Printf.sprintf
              "Method '%s' accesses '%s' %d/%d non-parameter accesses (%d%%). \
               Consider moving this logic to the '%s' class."
              def.Security_node.name !best_obj !best_count total
              (int_of_float (ratio *. 100.0)) !best_obj;
            flow = [ {
              Finding.file = def.Security_node.file;
              line = def.Security_node.line;
              message = Printf.sprintf "Definition of '%s'" def.Security_node.name;
            } ];
            language = def.Security_node.language;
            dependency = None;
            reachability = None; suggestion = None;
          }
        else None
      end else None
    end
  ) scopes

(* ── Combined extra smells analysis ─────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  check_long_method nodes config
  @ check_complex_conditionals nodes config
  @ check_message_chains nodes config
  @ check_data_clumps nodes config
  @ check_flag_arguments nodes config
  @ check_complex_match nodes config
  @ check_dead_code nodes config
  @ check_data_classes nodes config
  @ check_feature_envy nodes config
