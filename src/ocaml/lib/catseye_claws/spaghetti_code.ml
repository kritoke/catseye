(* lib/catseye_claws/spaghetti_code.ml *)

(** SpaghettiCode detector.

    Spaghetti code is code where control flow is tangled and hard to follow.
    Uses body node count as proxy for complexity.
    
    https://martinfowler.com/bliki/SpaghettiCode.html
*)

open Base

open Catseye_types

(* ── Thresholds ────────────────────────────────────────────────────── *)

let warning_threshold = 60
let error_threshold = 100

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let scopes = Scope.build_scopes nodes in
  Stdlib.List.filter_map (fun (s : Scope.scope) ->
    let method_name = s.def.Security_node.name in
    let branch_count = Stdlib.List.length s.body in

    if branch_count >= error_threshold then
      Some {
        Finding.rule = "SpaghettiCode";
        severity = "Critical";
        file = s.def.Security_node.file;
        line = s.def.Security_node.line;
        message = Stdlib.Printf.sprintf
          "Method '%s' has %d body nodes - extremely tangled control flow. \
           Strongly consider breaking into smaller functions."
          method_name branch_count;
        flow = [ {
          Finding.file = s.def.Security_node.file;
          line = s.def.Security_node.line;
          message = Stdlib.Printf.sprintf "Definition of '%s' (%d body nodes)"
            method_name branch_count;
        } ];
        language = s.def.Security_node.language;
        dependency = None;
        reachability = None; suggestion = None;
      }
    else if branch_count >= warning_threshold then
      Some {
        Finding.rule = "SpaghettiCode";
        severity = "Medium";
        file = s.def.Security_node.file;
        line = s.def.Security_node.line;
        message = Stdlib.Printf.sprintf
          "Method '%s' has %d body nodes - large tangled control flow. \
           Consider breaking into smaller functions."
          method_name branch_count;
        flow = [ {
          Finding.file = s.def.Security_node.file;
          line = s.def.Security_node.line;
          message = Stdlib.Printf.sprintf "Definition of '%s' (%d body nodes)"
            method_name branch_count;
        } ];
        language = s.def.Security_node.language;
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) scopes