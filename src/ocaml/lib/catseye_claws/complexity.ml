(* lib/catseye_claws/complexity.ml *)

(** Cyclomatic complexity detector.

    Approximates McCabe complexity by counting decision points in a
    function's flat Security_node list:

        M = 1 + (count of decision patterns)

    This is a heuristic — without full AST structure we cannot distinguish
    nested from sequential control flow. The thresholds (10/20) are generous
    enough to absorb minor overcounting.
*)

open Base
open Catseye_types
open Scope

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )

(* Alias for using old List API temporarily *)
module OldList = struct
  let exists = Stdlib.List.exists
  let fold_left = Stdlib.List.fold_left
  let filter_map = Stdlib.List.filter_map
end

(* ── Decision patterns ──────────────────────────────────────────────── *)

(** Strings that indicate a decision point when they appear in a node name. *)
let decision_patterns =
  [ "if"; "unless"; "case"; "select"
  ; "&&"; "||"; "and "; "or "
  ; "loop"; "while"; "for "; "each"
  ; "exception_handler"
  ]
  (* Note: "when" is NOT a decision point. In Crystal/Ruby, `when`
     clauses in a `case` are mutually exclusive — they don't add
     independent decision paths. Only `case` itself counts as +1. *)

(** Find substring [needle] in [haystack], returning start index or -1. *)
let find_substring (haystack : string) (needle : string) : int =
  let hlen = Stdlib.String.length haystack in
  let nlen = Stdlib.String.length needle in
  if nlen > hlen then -1
  else begin
    let result = ref (-1) in
    (try
      for i = 0 to hlen - nlen do
        if Stdlib.String.sub haystack i nlen = needle then begin
          result := i;
          raise Stdlib.Exit
        end
      done
    with Stdlib.Exit -> ());
    !result
  end

(** Check if a node name contains a decision pattern.

    Uses substring matching because Crystal extractor emits compound names
    like "if_expression" or "each_line" — we want to catch these.
    Requires word boundaries around the pattern.
*)
let is_decision (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  OldList.exists (fun pat ->
    let idx = find_substring lower pat in
    if idx < 0 then false
    else begin
      let before_ok = idx = 0 || let c = lower.[idx - 1] in c = ' ' || c = '.' || c = '_' in
      let after_idx = idx + Stdlib.String.length pat in
      let after_ok = after_idx >= Stdlib.String.length lower
        || let c = lower.[after_idx] in c = ' ' || c = '.' || c = '_' || c = '('
      in
      before_ok && after_ok
    end
  ) decision_patterns

(* ── Complexity computation ─────────────────────────────────────────── *)

(** Compute cyclomatic complexity for a function body. *)
let compute_complexity (body : Security_node.t list) : int =
  1 + OldList.fold_left (fun acc (n : Security_node.t) ->
    if is_decision n.Security_node.name then acc + 1
    else acc
  ) 0 body

(* ── Analysis ───────────────────────────────────────────────────────── *)

(** Run complexity analysis on all nodes, returning findings. *)
let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let scopes = build_scopes nodes in
  OldList.filter_map (fun ({ def; body } : scope) ->
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
      message = Stdlib.Printf.sprintf
        "Function '%s' has cyclomatic complexity of %d (threshold: %d)"
        def.Security_node.name complexity threshold;
      flow = [ {
        Finding.file = def.Security_node.file;
        line = def.Security_node.line;
        message = Stdlib.Printf.sprintf "Definition of '%s' (complexity: %d)"
          def.Security_node.name complexity;
      } ];
      language = def.Security_node.language;
      dependency = None;
      reachability = None; suggestion = None;
    }
  ) scopes
