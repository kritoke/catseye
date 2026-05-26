(* lib/catseye_claws/large_class.ml *)

(** LargeClass detector.

    A class with too many lines of code is a Large Class smell.
    This is the LOC-based version complementing the AST-node-based
    LongMethod detector.

    https://martinfowler.com/bliki/LargeClass.html
*)

open Base

(* String comparison shadow *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.large_class_enabled then [] else
    let warn_threshold = config.large_class_loc_warning in
    let crit_threshold = config.large_class_loc_critical in
    let class_scopes = Scope.build_class_scopes nodes in
    Stdlib.List.filter_map (fun (cs : Scope.class_scope) ->
      let loc = cs.loc in
      if loc >= crit_threshold then
        Some {
          Finding.rule = "LargeClass";
          severity = "High";
          file = cs.class_node.Security_node.file;
          line = cs.class_node.Security_node.line;
          message = Stdlib.Printf.sprintf
            "Class '%s' is %d lines (critical threshold: %d). \
             Consider splitting into smaller, focused classes."
            cs.class_node.Security_node.name loc crit_threshold;
          flow = [ {
            Finding.file = cs.class_node.Security_node.file;
            line = cs.class_node.Security_node.line;
            message = Stdlib.Printf.sprintf "Definition of '%s' (%d lines)"
              cs.class_node.Security_node.name loc;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else if loc >= warn_threshold then
        Some {
          Finding.rule = "LargeClass";
          severity = "Medium";
          file = cs.class_node.Security_node.file;
          line = cs.class_node.Security_node.line;
          message = Stdlib.Printf.sprintf
            "Class '%s' is %d lines (warning threshold: %d). \
             Consider splitting into smaller, focused classes."
            cs.class_node.Security_node.name loc warn_threshold;
          flow = [ {
            Finding.file = cs.class_node.Security_node.file;
            line = cs.class_node.Security_node.line;
            message = Stdlib.Printf.sprintf "Definition of '%s' (%d lines)"
              cs.class_node.Security_node.name loc;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
    ) class_scopes