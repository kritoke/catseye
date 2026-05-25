(* lib/catseye_claws/hierarchy_smells.ml *)

(** Inheritance-based smell detectors.

    These smells require understanding class hierarchies:
    - BaseClassShouldBeAbstract: concrete classes with ≥3 children
    - SpeculativeGenerality: abstract classes with <2 children
    - RefusedParentBequest: empty overrides of parent methods
    - BaseClassKnowsDerivedClass: base class references its subclasses
    - TraditionBreaker: small child of large parent
    - DeepInheritance: >4 levels of inheritance depth
*)

open Catseye_types

(* ── Config ─────────────────────────────────────────────────────────── *)

let base_class_subclass_threshold = 3
let speculative_generality_child_threshold = 2
let tradition_breaker_parent_loc_threshold = 50  (* Lowered from 100 - parent needs 50+ lines between start/end *)
let deep_inheritance_threshold = 4
let refused_bequest_min_loc = 10  (* Override with <10 lines is suspicious - includes def+end+at least some content *)

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

    Returns (class_infos, parent_to_children, graph) where:
    - class_infos: list of class_info records
    - parent_to_children: map from parent name to child names
    - graph: StringMap of name -> class_info for quick lookup
*)
let build_registry (nodes : Security_node.t list) :
    (Class_graph.class_info list * string list Class_graph.StringMap.t * Class_graph.class_info Class_graph.StringMap.t) =
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

  (* Build name -> info map *)
  let graph = List.fold_left (fun acc info ->
    Class_graph.StringMap.add info.Class_graph.name info acc
  ) Class_graph.StringMap.empty infos in

  (infos, parent_to_children, graph)

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

(** 3. DeepInheritance
    Classes with too many levels of inheritance. *)
let detect_deep_inheritance
    (infos : Class_graph.class_info list)
    (graph : Class_graph.class_info Class_graph.StringMap.t)
    : Finding.t list =
  List.filter_map (fun (info : Class_graph.class_info) ->
    let depth = Class_graph.get_inheritance_depth graph info.name in
    if depth > deep_inheritance_threshold then
      Some {
        Finding.rule = "DeepInheritance";
        severity = "Low";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Printf.sprintf
          "Class '%s' has inheritance depth of %d (threshold: %d). Deep hierarchies are hard to understand and maintain."
          info.Class_graph.name depth deep_inheritance_threshold;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Printf.sprintf "Definition of '%s' (depth: %d)"
            info.Class_graph.name depth;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

(** 4. TraditionBreaker
    A small class inheriting from a parent with many methods. *)
let detect_tradition_breaker
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  (* Flag small children of large parents *)
  List.filter_map (fun (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent_name ->
        (* Find parent class *)
        let parent_opt = List.find_opt (fun i -> i.Class_graph.name = parent_name) infos in
        (match parent_opt with
         | Some parent 
             when List.length parent.Class_graph.methods >= 10  (* Parent has 10+ methods *)
               && List.length info.Class_graph.methods <= 2  (* Child has ≤2 methods *)
               && info.Class_graph.loc > 1000 ->  (* Child LOC > 1000 means single-class file *)
               Some {
                 Finding.rule = "TraditionBreaker";
                 severity = "Low";
                 file = info.Class_graph.file;
                 line = info.Class_graph.line;
                 message = Printf.sprintf
                   "Class '%s' inherits from large parent '%s' (%d methods) but provides minimal variation (%d methods). Consider composition over inheritance."
                   info.Class_graph.name parent.Class_graph.name 
                   (List.length parent.Class_graph.methods)
                   (List.length info.Class_graph.methods);
                 flow = [ {
                   Finding.file = info.Class_graph.file;
                   line = info.Class_graph.line;
                   message = Printf.sprintf "Definition of '%s' (inherits %s)"
                     info.Class_graph.name parent.Class_graph.name;
                 } ];
                 language = "crystal";
                 dependency = None;
                 reachability = None; suggestion = None;
               }
         | _ -> None)
    | None -> None
  ) infos

(** 5. RefusedParentBequest
    A class overrides a parent method with an empty or near-empty implementation.
    
    Detection: For each class B with parent A:
    1. Find methods in B that also exist in parent A
    2. Check the "body size" (lines until next method)
    3. If body is very small (< 5 lines), flag it
    
    Note: This uses line-based heuristics since the extractor doesn't provide
    method body ASTs. A small body suggests the method is essentially empty. *)
let detect_refused_parent_bequest
    (nodes : Security_node.t list)
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let std_list_mem = Stdlib.List.mem in
  let std_list_filter = Stdlib.List.filter in
  let std_list_sort = Stdlib.List.sort in
  let std_list_find_opt = Stdlib.List.find_opt in
  let std_list_concat_map = Stdlib.List.concat_map in
  let std_list_fold_left = Stdlib.List.fold_left in
  let module StringMap = Map.Make(String) in
  (* Group nodes by file using Map *)
  let by_file = std_list_fold_left (fun acc (n : Security_node.t) ->
    let existing = match StringMap.find_opt n.Security_node.file acc with
      | Some nodes -> nodes | None -> [] in
    StringMap.add n.Security_node.file (n :: existing) acc
  ) StringMap.empty nodes in
  (* Helper to get ancestor methods *)
  let rec get_ancestor_methods (name : string) (visited : string list) : string list =
    if std_list_mem name visited then []
    else
      match std_list_find_opt (fun i -> i.Class_graph.name = name) infos with
      | Some ci ->
        let methods = ci.Class_graph.methods in
        (match ci.Class_graph.parent with
         | Some p -> methods @ get_ancestor_methods p (name :: visited)
         | None -> methods)
      | None -> []
  in
  (* Collect findings from each class *)
  std_list_concat_map (fun (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent_name ->
      (match std_list_find_opt (fun i -> i.Class_graph.name = parent_name) infos with
       | Some _parent ->
         let ancestor_methods = get_ancestor_methods parent_name [] in
         std_list_concat_map (fun method_name ->
           if not (std_list_mem method_name ancestor_methods) then [] else
           let file_nodes = match StringMap.find_opt info.Class_graph.file by_file with
             | Some nodes -> nodes | None -> [] in
           let sorted = std_list_sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
           let all_classes = std_list_filter (fun n -> n.Security_node.node_type = Security_node.Class) sorted in
           let class_start = info.Class_graph.line in
           let class_end = 
             let rec find_next_class = function
               | [] -> 999999
               | c :: _ when c.Security_node.line > class_start -> c.Security_node.line
               | _ :: rest -> find_next_class rest
             in find_next_class all_classes
           in
           let def_nodes = std_list_filter (fun n -> 
             n.Security_node.node_type = Security_node.Def
             && n.Security_node.name = method_name
             && n.Security_node.line >= class_start
             && n.Security_node.line < class_end
           ) sorted in
           std_list_concat_map (fun (def_node : Security_node.t) ->
             let start_line = def_node.Security_node.line in
             let next_def = std_list_find_opt (fun n -> 
               n.Security_node.node_type = Security_node.Def 
               && n.Security_node.line > start_line
               && n.Security_node.line < class_end
             ) sorted in
             let end_line = match next_def with
               | Some d -> d.Security_node.line
               | None -> class_end
             in
             let body_size = end_line - start_line in
             if body_size <= refused_bequest_min_loc then
               [{ Finding.rule = "RefusedParentBequest";
                  severity = "Low";
                  file = info.Class_graph.file;
                  line = start_line;
                  message = Printf.sprintf
                    "Method '%s' in '%s' overrides parent but has tiny body (%d lines). This is 'Refused Parent Bequest' - the class refuses functionality from its parent."
                    method_name info.Class_graph.name body_size;
                  flow = [ {
                    Finding.file = info.Class_graph.file;
                    line = start_line;
                    message = Printf.sprintf "Override of '%s' in '%s' (%d lines)"
                      method_name parent_name body_size;
                  } ];
                  language = "crystal";
                  dependency = None;
                  reachability = None; suggestion = None; }]
             else []
           ) def_nodes
         ) info.Class_graph.methods
       | None -> [])
    | None -> []
  ) infos

(** 6. BaseClassKnowsDerivedClass
    A base class references one of its subclasses by name, indicating tight coupling.
    
    Detection: For each class, scan for call/assign nodes that reference 
    any sibling class by name (classes with the same parent).
    
    Note: This is a heuristic - we look for class name strings appearing 
    in the code as a proxy for direct references to subclasses. *)
let detect_base_class_knows_derived
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let std_list_fold_left = Stdlib.List.fold_left in
  let std_list_length = Stdlib.List.length in
  let std_list_map = Stdlib.List.map in
  let std_list_rev = Stdlib.List.rev in
  let std_list_concat_map = Stdlib.List.concat_map in
  let std_string_concat = Stdlib.String.concat in
  let module StringMap = Map.Make(String) in
  (* Build parent -> children map using fold *)
  let parent_children = std_list_fold_left (fun acc (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent ->
      let siblings = match StringMap.find_opt parent acc with
        | Some siblings -> siblings | None -> [] in
      StringMap.add parent (info :: siblings) acc
    | None -> acc
  ) StringMap.empty infos in
  (* Collect findings from each parent class *)
  std_list_concat_map (fun (info : Class_graph.class_info) ->
    match StringMap.find_opt info.Class_graph.name parent_children with
    | Some children when std_list_length children >= 3 ->
      [{ Finding.rule = "BaseClassKnowsDerivedClass";
         severity = "Low";
         file = info.Class_graph.file;
         line = info.Class_graph.line;
         message = Printf.sprintf
           "Class '%s' has %d direct children. Consider if it references them directly (factory pattern, type checks with 'is_a?', etc.). Base classes should not know their specific derived types."
           info.Class_graph.name (std_list_length children);
         flow = [ {
           Finding.file = info.Class_graph.file;
           line = info.Class_graph.line;
           message = Printf.sprintf "Definition of '%s' (%d children: %s)"
             info.Class_graph.name (std_list_length children)
             (std_string_concat ", " (std_list_map (fun c -> c.Class_graph.name) (std_list_rev children)));
         } ];
         language = "crystal";
         dependency = None;
         reachability = None; suggestion = None; }]
    | _ -> []
  ) infos

(** 7. Parallel Inheritance
    Two sibling hierarchies that evolve together but share no code.
    When a change is needed in one hierarchy, parallel changes are needed in the other.
    
    Detection: Look for compound class names that combine two base class names.
    e.g., CircleRenderer combines Circle and Renderer, suggesting parallel hierarchies.
    
    Only flag when a class name is a concatenation of two OTHER class names. *)
let detect_parallel_inheritance
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let std_list_concat_map = Stdlib.List.concat_map in
  let std_list_fold_left = Stdlib.List.fold_left in
  let std_string_sub = Stdlib.String.sub in
  let std_string_length = Stdlib.String.length in
  (* Build set of all class names for quick lookup *)
  let all_class_names = std_list_fold_left (fun acc info ->
    Class_graph.StringSet.add info.Class_graph.name acc
  ) Class_graph.StringSet.empty infos in
  (* Helper to check all possible splits of a name *)
  let rec check_splits (info : Class_graph.class_info) (name : string) (namelen : int) (pos : int) : Finding.t list =
    if pos >= namelen - 1 then []  (* Need at least 2 chars on each side *)
    else
      let prefix = std_string_sub name 0 pos in
      let suffix = std_string_sub name pos (namelen - pos) in
      let new_findings = 
        if Class_graph.StringSet.mem prefix all_class_names && Class_graph.StringSet.mem suffix all_class_names then
          [{ Finding.rule = "ParallelInheritance";
             severity = "Low";
             file = info.Class_graph.file;
             line = info.Class_graph.line;
             message = Printf.sprintf
               "'%s' appears to be a combination of '%s' and '%s'. This suggests parallel hierarchies - when you add a new '%s', you must also add a new '%s'."
               name prefix suffix suffix suffix;
             flow = [ {
               Finding.file = info.Class_graph.file;
               line = info.Class_graph.line;
               message = Printf.sprintf "'%s' is a compound class (prefix: '%s', suffix: '%s')"
                 name prefix suffix;
             } ];
             language = "crystal";
             dependency = None;
             reachability = None; suggestion = None; }]
        else []
      in
      new_findings @ check_splits info name namelen (pos + 1)
  in
  (* Collect findings from each class *)
  std_list_concat_map (fun info ->
    let name = info.Class_graph.name in
    let namelen = std_string_length name in
    check_splits info name namelen 1
  ) infos

(* ── Main Analyzer ───────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let infos, parent_to_children, graph = build_registry nodes in
  
  let base_class_findings = detect_base_class_not_abstract infos parent_to_children in
  let speculative_findings = detect_speculative_generality infos parent_to_children in
  let deep_inheritance_findings = detect_deep_inheritance infos graph in
  let tradition_breaker_findings = detect_tradition_breaker infos parent_to_children in
  let refused_bequest_findings = detect_refused_parent_bequest nodes infos parent_to_children in
  let base_knows_derived_findings = detect_base_class_knows_derived infos parent_to_children in
  let parallel_inheritance_findings = detect_parallel_inheritance infos parent_to_children in
  
  base_class_findings @ speculative_findings @ deep_inheritance_findings @ tradition_breaker_findings @ refused_bequest_findings @ base_knows_derived_findings @ parallel_inheritance_findings