(* lib/catseye_claws/hierarchy_smells.ml *)

(** Inheritance-based smell detectors.

    These smells require understanding class hierarchies:
    - BaseClassShouldBeAbstract: concrete classes with ≥3 children
    - SpeculativeGenerality: abstract classes with <2 children
    - RefusedParentBequest: empty overrides of parent methods
    - BaseClassKnowsDerivedClass: base class references its subclasses
    - TraditionBreaker: small child of large parent
*)

open Catseye_types

(* ── Config ─────────────────────────────────────────────────────────── *)

let base_class_subclass_threshold = 3
let speculative_generality_child_threshold = 2
let tradition_breaker_parent_loc_threshold = 500

(* ── Helper ───────────────────────────────────────────────────────── *)

(** Check if a string contains a substring *)
let contains (str : string) (sub : string) : bool =
  let slen = String.length str in
  let slen_sub = String.length sub in
  if slen_sub > slen then false
  else
    let rec check i =
      if i > slen - slen_sub then false
      else if String.sub str i slen_sub = sub then true
      else check (i + 1)
    in
    check 0

(** Check if a class name suggests it's abstract (Crystal convention) *)
let is_abstract_class (name : string) : bool =
  let lower = String.lowercase_ascii name in
  contains lower "abstract"

(* ── Class Registry Building ────────────────────────────────────────── *)

(** Build inheritance registry from Security_node list.

    Returns (class_infos, parent_to_children) where:
    - class_infos: list of class_info records
    - parent_to_children: map from parent name to child names
*)
let build_registry (nodes : Security_node.t list) :
    (Class_graph.class_info list * string list Class_graph.StringMap.t) =
  (* Group nodes by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;

  let class_infos = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    
    (* Find class boundaries *)
    let class_nodes = List.filter (fun n ->
      n.Security_node.node_type = Security_node.Class
    ) sorted in

    List.iteri (fun i (cn : Security_node.t) ->
      let start_line = cn.Security_node.line in
      let end_line =
        if i + 1 < List.length class_nodes then
          (List.nth class_nodes (i + 1)).Security_node.line
        else 1000000
      in

      (* Find Def nodes within this class *)
      let methods_in_class = List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in

      let method_names = List.map (fun n -> n.Security_node.name) methods_in_class in
      let parent = Security_node.get_metadata cn "parent" in
      let loc = end_line - start_line in
      let name = cn.Security_node.name in
      let is_abstract = is_abstract_class name in

      class_infos := {
        Class_graph.name = name;
        Class_graph.file = cn.Security_node.file;
        Class_graph.line = cn.Security_node.line;
        Class_graph.parent = parent;
        Class_graph.methods = method_names;
        Class_graph.loc = loc;
        Class_graph.is_abstract = is_abstract;
      } :: !class_infos
    ) class_nodes
  ) by_file;

  let infos = List.rev !class_infos in

  (* Build parent -> children map *)
  let parent_to_children = List.fold_left (fun acc info ->
    match info.Class_graph.parent with
    | Some parent ->
        let children = try Class_graph.StringMap.find parent acc with Not_found -> [] in
        Class_graph.StringMap.add parent (info.Class_graph.name :: children) acc
    | None -> acc
  ) Class_graph.StringMap.empty infos in

  (infos, parent_to_children)

(* ── Smell Detectors ────────────────────────────────────────────────── *)

(** 1. BaseClassShouldBeAbstract
    A concrete class with many subclasses should be abstract. *)
let detect_base_class_not_abstract
    (infos : Class_graph.class_info list)
    (parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  List.filter_map (fun (info : Class_graph.class_info) ->
    let children = try Class_graph.StringMap.find info.Class_graph.name parent_to_children
                  with Not_found -> [] in
    let child_count = List.length children in
    if not info.Class_graph.is_abstract && child_count >= base_class_subclass_threshold then
      Some {
        Finding.rule = "BaseClassShouldBeAbstract";
        severity = "Medium";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Printf.sprintf
          "Class '%s' is concrete but has %d subclasses. Consider making it abstract."
          info.Class_graph.name child_count;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Printf.sprintf "Definition of '%s' (%d children)"
            info.Class_graph.name child_count;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

(** 2. SpeculativeGenerality
    An abstract class with few or no children. *)
let detect_speculative_generality
    (infos : Class_graph.class_info list)
    (parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  List.filter_map (fun (info : Class_graph.class_info) ->
    let children = try Class_graph.StringMap.find info.Class_graph.name parent_to_children
                  with Not_found -> [] in
    let child_count = List.length children in
    if info.Class_graph.is_abstract && child_count < speculative_generality_child_threshold then
      Some {
        Finding.rule = "SpeculativeGenerality";
        severity = "Low";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Printf.sprintf
          "Class '%s' is abstract but has only %d child(ren). Consider removing the abstract modifier."
          info.Class_graph.name child_count;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Printf.sprintf "Definition of '%s' (abstract, %d children)"
            info.Class_graph.name child_count;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

(* ── Main Analyzer ───────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let infos, parent_to_children = build_registry nodes in
  
  let base_class_findings = detect_base_class_not_abstract infos parent_to_children in
  let speculative_findings = detect_speculative_generality infos parent_to_children in
  
  base_class_findings @ speculative_findings