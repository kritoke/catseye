(* lib/catseye_claws/complexity.ml *)

(** Cyclomatic complexity detector.

    Approximates McCabe complexity by counting decision points in a
    function's flat Security_node list:

        M = 1 + (count of decision patterns)

    This is a heuristic — without full AST structure we cannot distinguish
    nested from sequential control flow. The thresholds (10/20) are generous
    enough to absorb minor overcounting.
*)

open Catseye_types

(* ── Decision patterns ──────────────────────────────────────────────── *)

(** Strings that indicate a decision point when they appear in a node name. *)
let decision_patterns =
  [ "if"; "unless"; "case"; "select"; "when"
  ; "&&"; "||"; "and "; "or "
  ; "loop"; "while"; "for "; "each"
  ; "exception_handler"
  ]

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

(** Check if a node name contains a decision pattern.

    Uses substring matching because Crystal extractor emits compound names
    like "if_expression" or "each_line" — we want to catch these.
    Requires word boundaries around the pattern.
*)
let is_decision (name : string) : bool =
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
  ) decision_patterns

(* ── Scope building ─────────────────────────────────────────────────── *)

(** A function scope: the Def node + all nodes in its body.

    We use a line-range heuristic: a Def's body extends from its line
    to the next Def's line (or end of file) in the same file.

    This is the same approach as reachability.ml — duplicated here
    to avoid coupling catseye_claws → catseye_engine.
*)
type scope = {
  def : Security_node.t;
  body : Security_node.t list;
}

(** Build function scopes from a flat node list, grouped by file. *)
let build_scopes (nodes : Security_node.t list) : scope list =
  (* Group by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.file with Not_found -> [] in
    Hashtbl.replace by_file n.file (n :: existing)
  ) nodes;
  (* For each file, find Def nodes and their bodies *)
  let scopes = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    let defs = List.filter (fun n -> n.Security_node.node_type = Security_node.Def) sorted in
    let non_def_sorted = sorted in
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
      ) non_def_sorted in
      scopes := { def; body } :: !scopes
    ) defs
  ) by_file;
  List.rev !scopes

(* ── Complexity computation ─────────────────────────────────────────── *)

(** Compute cyclomatic complexity for a function body. *)
let compute_complexity (body : Security_node.t list) : int =
  1 + List.fold_left (fun acc (n : Security_node.t) ->
    if is_decision n.Security_node.name then acc + 1
    else acc
  ) 0 body

(* ── Analysis ───────────────────────────────────────────────────────── *)

(** Run complexity analysis on all nodes, returning findings. *)
let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let scopes = build_scopes nodes in
  List.filter_map (fun ({ def; body } : scope) ->
    let complexity = compute_complexity body in
    let severity, threshold =
      if complexity >= config.complexity_critical then
        ("High", config.complexity_critical)
      else if complexity >= config.complexity_warning then
        ("Medium", config.complexity_warning)
      else ("", 0)
    in
    if severity = "" then None
    else Some {
      Finding.rule = "HighComplexity";
      severity;
      file = def.Security_node.file;
      line = def.Security_node.line;
      message = Printf.sprintf
        "Function '%s' has cyclomatic complexity of %d (threshold: %d)"
        def.Security_node.name complexity threshold;
      flow = [ {
        Finding.file = def.Security_node.file;
        line = def.Security_node.line;
        message = Printf.sprintf "Definition of '%s' (complexity: %d)"
          def.Security_node.name complexity;
      } ];
      language = def.Security_node.language;
      dependency = None;
      reachability = None; suggestion = None;
    }
  ) scopes
