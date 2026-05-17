(* lib/catseye_claws/lazy_class.ml *)

(** LazyClass detector.

    A class or module with fewer than 3 methods is likely a Lazy Class —
    it isn't doing enough to warrant its own type. Fowler's smell.

    https://martinfowler.com/bliki/LazyClass.html
*)

open Catseye_types

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.lazy_class_enabled then [] else
    let threshold = config.lazy_class_method_threshold in
    let class_scopes = Scope.build_class_scopes nodes in
    List.filter_map (fun (cs : Scope.class_scope) ->
      let method_count = List.length cs.methods in
      if method_count > 0 && method_count < threshold then
        Some {
          Finding.rule = "LazyClass";
          severity = "Medium";
          file = cs.class_node.Security_node.file;
          line = cs.class_node.Security_node.line;
          message = Printf.sprintf
            "Class '%s' has only %d method(s) (threshold: %d). \
             Consider whether it deserves its own type or can be absorbed elsewhere."
            cs.class_node.Security_node.name method_count threshold;
          flow = [ {
            Finding.file = cs.class_node.Security_node.file;
            line = cs.class_node.Security_node.line;
            message = Printf.sprintf "Definition of '%s' (%d methods)"
              cs.class_node.Security_node.name method_count;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
    ) class_scopes