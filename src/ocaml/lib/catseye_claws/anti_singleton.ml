(* lib/catseye_claws/anti_singleton.ml *)

(** AntiSingleton detector.

    A class that provides mutable class variables (e.g. @@counter = 0)
    which could be used as global variables. This is a Fowler code smell.

    https://martinfowler.com/bliki/AntiSingleton.html
*)

open Catseye_types

(* ── Detection ─────────────────────────────────────────────────────── *)

(** Check if a class has mutable class variables.
    Class variables are detected by Assign nodes with names starting with @@.
*)
let check_anti_singleton (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  (* Group nodes by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;

  let findings = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    (* Find class/module boundaries *)
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    let class_nodes = List.filter (fun n ->
      List.mem n.Security_node.node_type [Security_node.Class; Security_node.Module]
    ) sorted in

    List.iteri (fun i (cn : Security_node.t) ->
      let start_line = cn.Security_node.line in
      let end_line =
        if i + 1 < List.length class_nodes then
          (List.nth class_nodes (i + 1)).Security_node.line
        else max_int
      in

      (* Find class variable assignments within this class *)
      let class_var_assigns = List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Assign
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
        && String.length n.Security_node.name >= 2
        && n.Security_node.name.[0] = '@'
        && n.Security_node.name.[1] = '@'
      ) sorted in

      if List.length class_var_assigns > 0 then
        let class_vars = List.map (fun n -> n.Security_node.name) class_var_assigns in
        let msg = String.concat ", " class_vars in
        findings := {
          Finding.rule = "AntiSingleton";
          severity = "Medium";
          file = cn.Security_node.file;
          line = cn.Security_node.line;
          message = Printf.sprintf
            "Class '%s' has mutable class variables: %s. \
             Class variables can be used as global state. Consider using instance variables or dependency injection."
            cn.Security_node.name msg;
          flow = List.map (fun n -> {
            Finding.file = n.Security_node.file;
            line = n.Security_node.line;
            message = Printf.sprintf "Mutable class variable: %s" n.Security_node.name;
          }) class_var_assigns;
          language = cn.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        } :: !findings
    ) class_nodes
  ) by_file;
  List.rev !findings

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.anti_singleton_enabled then [] else
    check_anti_singleton nodes config