(* lib/catseye_claws/spaghetti_code.ml *)

(** SpaghettiCode detector.

    Spaghetti code is code where control flow is tangled and hard to follow.
    Heuristic: methods with many decision points (high cyclomatic complexity).

    https://martinfowler.com/bliki/SpaghettiCode.html
*)

open Catseye_types

(* ── Thresholds ────────────────────────────────────────────────────── *)

let decision_threshold = 40   (* Very large method bodies only *)

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let scopes = Scope.build_scopes nodes in
  List.filter_map (fun (s : Scope.scope) ->
    let method_name = s.def.Security_node.name in
    let branch_count = List.length s.body in  (* Use body size as proxy *)

    (* Spaghetti code: very long method bodies indicate tangled logic *)
    if branch_count >= decision_threshold then
      Some {
        Finding.rule = "SpaghettiCode";
        severity = "Medium";
        file = s.def.Security_node.file;
        line = s.def.Security_node.line;
        message = Printf.sprintf
          "Method '%s' has %d body nodes - large tangled control flow. \
           Consider breaking into smaller functions."
          method_name branch_count;
        flow = [ {
          Finding.file = s.def.Security_node.file;
          line = s.def.Security_node.line;
          message = Printf.sprintf "Definition of '%s' (%d body nodes)"
            method_name branch_count;
        } ];
        language = s.def.Security_node.language;
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) scopes