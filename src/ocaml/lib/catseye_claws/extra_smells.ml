(* lib/catseye_claws/extra_smells.ml

   Additional smell detectors beyond DRY/complexity/anatomy:

   - Long Method: functions with too many AST nodes
   - Complex Conditional: single expressions with too many && / ||
   - Message Chains: a.b.c.d() call chains (Law of Demeter violation)
   - Data Clumps: parameter pairs repeated across multiple functions
*)

open Catseye_types

(* ── Helpers ────────────────────────────────────────────────────────── *)

let find_substring (haystack : string) (needle : string) : int =
  let hlen = String.length haystack in
  let nlen = String.length needle in
  if nlen > hlen then -1
  else begin
    let result = ref (-1) in
    (try
      for i = 0 to hlen - nlen do
        if String.sub haystack i nlen = needle then begin
          result := i; raise Exit
        end
      done
    with Exit -> ());
    !result
  end

(* ── Scope building (shared pattern) ────────────────────────────────── *)

type scope = {
  def : Security_node.t;
  body : Security_node.t list;
}

let build_scopes (nodes : Security_node.t list) : scope list =
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  let scopes = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b ->
      compare a.Security_node.line b.Security_node.line
    ) file_nodes in
    let defs = List.filter (fun n ->
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

(* ── Long Method ────────────────────────────────────────────────────── *)

(** Count the number of AST nodes in a function body. Skip initialize
    methods since Crystal DTOs legitimately have large constructors. *)
let check_long_method (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let scopes = build_scopes nodes in
  let warning_threshold = config.long_method_warning in
  let critical_threshold = config.long_method_critical in
  List.filter_map (fun ({ def; body } : scope) ->
    (* Skip initialize — large constructors are normal for DTOs *)
    if def.Security_node.name = "initialize" then None
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
          reachability = None;
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
          reachability = None;
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
    Threshold: 3+ operators in a single expression = Meow. *)
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
          reachability = None;
        }
      else None
  ) nodes

(* ── Message Chains (Law of Demeter) ────────────────────────────────── *)

(** Count the number of segments in a dotted call name.
    "feed.items.size.to_i32" has 4 segments.
    Threshold: 4+ segments = Meow (Law of Demeter violation). *)
let count_chain_segments (name : string) : int =
  let count = ref 1 in
  for i = 0 to String.length name - 1 do
    if name.[i] = '.' then incr count
  done;
  !count

(** Filter out chains that are just module paths (e.g., "XML::ParserOptions::RECOVER")
    or common Crystal stdlib paths that are idiomatic. *)
let is_idiomatic_chain (name : string) : bool =
  let lower = String.lowercase_ascii name in
  (* Module paths use :: not . — these are fine *)
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
     ; ".to_f32?"; ".to_f64?"; ".starts_with?"; ".ends_with?"]

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
          reachability = None;
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
    (* Report pairs exceeding threshold *)
    Hashtbl.fold (fun (p1, p2) count acc ->
      if count >= threshold then begin
        let files = try Hashtbl.find pair_files (p1, p2) with Not_found -> [] in
        { Finding.rule = "DataClump";
          severity = "Medium";
          file = List.hd (List.sort String.compare files);
          line = 0;
          message = Printf.sprintf
            "Parameters '%s' and '%s' always appear together in %d functions \
             across %d files. Consider grouping into a struct or record."
            p1 p2 count (List.length files);
          flow = [];
          language = "";
          dependency = None;
          reachability = None;
        } :: acc
      end else acc
    ) pair_counts []
  end

(* ── Combined extra smells analysis ─────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  check_long_method nodes config
  @ check_complex_conditionals nodes config
  @ check_message_chains nodes config
  @ check_data_clumps nodes config
