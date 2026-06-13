(* lib/catseye_claws/blob.ml *)

(** Blob detector (simplified).

    A God Object / Blob is a class that tries to do too much.
    Simplified heuristic: a class with many methods AND high LOC.

    https://martinfowler.com/bliki/Blob.html
*)

open Base
open Catseye_types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )

(* Alias for using old List API temporarily *)
module OldList = struct
  let length = Stdlib.List.length
  let filter_map = Stdlib.List.filter_map
end

(* ── Config thresholds ─────────────────────────────────────────────── *)

let default_method_count_warning = 15
let default_method_count_critical = 25

(* ── Helpers ───────────────────────────────────────────────────────── *)

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.large_class_enabled then [] else
    let class_scopes = Scope.build_class_scopes nodes in
    (* Filter to real blob candidates: large + many methods *)
    OldList.filter_map (fun (cs : Scope.class_scope) ->
      let method_count = OldList.length cs.methods in
      let loc = cs.loc in
      let file = cs.class_node.Security_node.file in
      let name = cs.class_node.Security_node.name in

      (* Heuristic: blob if either critical threshold met, or both warning thresholds *)
      let is_critical = method_count >= default_method_count_critical && loc >= 300 in
      let is_warning = method_count >= default_method_count_warning && loc >= 200 in

      if is_critical then
        Some {
          Finding.rule = "Blob";
          severity = "High";
          file;
          line = cs.class_node.Security_node.line;
          message = Stdlib.Printf.sprintf
            "Class '%s' appears to be a Blob (God Object): %d methods, %d LOC. \
             This class has too many responsibilities. Consider splitting by feature."
            name method_count loc;
          flow = [ {
            Finding.file;
            line = cs.class_node.Security_node.line;
            message = Stdlib.Printf.sprintf "Definition of '%s' (%d methods, %d LOC)"
              name method_count loc;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else if is_warning then
        Some {
          Finding.rule = "Blob";
          severity = "Medium";
          file;
          line = cs.class_node.Security_node.line;
          message = Stdlib.Printf.sprintf
            "Class '%s' may be a Blob: %d methods, %d LOC. \
             Consider if it has multiple responsibilities that could be separated."
            name method_count loc;
          flow = [ {
            Finding.file;
            line = cs.class_node.Security_node.line;
            message = Stdlib.Printf.sprintf "Definition of '%s' (%d methods, %d LOC)"
              name method_count loc;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
    ) class_scopes