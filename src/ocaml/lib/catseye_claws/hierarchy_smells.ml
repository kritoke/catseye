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

open Base

(* Comparison shadows *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Config ─────────────────────────────────────────────────────────── *)

let base_class_subclass_threshold = 3
let speculative_generality_child_threshold = 2
let tradition_breaker_parent_loc_threshold = 50
let deep_inheritance_threshold = 4
let refused_bequest_min_loc = 10

(* ── Helper ───────────────────────────────────────────────────────── *)

(** Check if a string contains a substring *)
let contains (str : string) (sub : string) : bool =
  let slen = Stdlib.String.length str in
  let slen_sub = Stdlib.String.length sub in
  if slen_sub > slen then false
  else
    let rec check i =
      if i > slen - slen_sub then false
      else if Stdlib.String.sub str i slen_sub = sub then true
      else check (i + 1)
    in
    check 0

(** Check if a class name suggests it's abstract (Crystal convention) *)
let is_abstract_class (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  contains lower "abstract"

(* ── Class Registry Building ────────────────────────────────────────── *)

let build_registry (nodes : Security_node.t list) :
    (Class_graph.class_info list * string list Class_graph.StringMap.t * Class_graph.class_info Class_graph.StringMap.t) =
  let by_file = Stdlib.Hashtbl.create 16 in
  Stdlib.List.iter (fun (n : Security_node.t) ->
    let existing = try Stdlib.Hashtbl.find by_file n.Security_node.file with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;

  let class_infos = Stdlib.ref [] in
  Stdlib.Hashtbl.iter (fun _file file_nodes ->
    let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    
    let class_nodes = Stdlib.List.filter (fun n ->
      n.Security_node.node_type = Security_node.Class
    ) sorted in

    Stdlib.List.iteri (fun i (cn : Security_node.t) ->
      let start_line = cn.Security_node.line in
      let end_line =
        if i + 1 < Stdlib.List.length class_nodes then
          (Stdlib.List.nth class_nodes (i + 1)).Security_node.line
        else 1000000
      in

      let methods_in_class = Stdlib.List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in

      let method_names = Stdlib.List.map (fun n -> n.Security_node.name) methods_in_class in
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

  let infos = Stdlib.List.rev !class_infos in

  let parent_to_children = Stdlib.List.fold_left (fun acc info ->
    match info.Class_graph.parent with
    | Some parent ->
        let children = try Class_graph.StringMap.find parent acc with Stdlib.Not_found -> [] in
        Class_graph.StringMap.add parent (info.Class_graph.name :: children) acc
    | None -> acc
  ) Class_graph.StringMap.empty infos in

  let graph = Stdlib.List.fold_left (fun acc info ->
    Class_graph.StringMap.add info.Class_graph.name info acc
  ) Class_graph.StringMap.empty infos in

  (infos, parent_to_children, graph)

(* ── Smell Detectors ────────────────────────────────────────────────── *)

let detect_base_class_not_abstract
    (infos : Class_graph.class_info list)
    (parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  Stdlib.List.filter_map (fun (info : Class_graph.class_info) ->
    let children = try Class_graph.StringMap.find info.Class_graph.name parent_to_children
                  with Stdlib.Not_found -> [] in
    let child_count = Stdlib.List.length children in
    if not info.Class_graph.is_abstract && child_count >= base_class_subclass_threshold then
      Some {
        Finding.rule = "BaseClassShouldBeAbstract";
        severity = "Medium";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Stdlib.Printf.sprintf
          "Class '%s' is concrete but has %d subclasses. Consider making it abstract."
          info.Class_graph.name child_count;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Stdlib.Printf.sprintf "Definition of '%s' (%d children)"
            info.Class_graph.name child_count;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

let detect_speculative_generality
    (infos : Class_graph.class_info list)
    (parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  Stdlib.List.filter_map (fun (info : Class_graph.class_info) ->
    let children = try Class_graph.StringMap.find info.Class_graph.name parent_to_children
                  with Stdlib.Not_found -> [] in
    let child_count = Stdlib.List.length children in
    if info.Class_graph.is_abstract && child_count < speculative_generality_child_threshold then
      Some {
        Finding.rule = "SpeculativeGenerality";
        severity = "Low";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Stdlib.Printf.sprintf
          "Class '%s' is abstract but has only %d child(ren). Consider removing the abstract modifier."
          info.Class_graph.name child_count;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Stdlib.Printf.sprintf "Definition of '%s' (abstract, %d children)"
            info.Class_graph.name child_count;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

let detect_deep_inheritance
    (infos : Class_graph.class_info list)
    (graph : Class_graph.class_info Class_graph.StringMap.t)
    : Finding.t list =
  Stdlib.List.filter_map (fun (info : Class_graph.class_info) ->
    let depth = Class_graph.get_inheritance_depth graph info.name in
    if depth > deep_inheritance_threshold then
      Some {
        Finding.rule = "DeepInheritance";
        severity = "Low";
        file = info.Class_graph.file;
        line = info.Class_graph.line;
        message = Stdlib.Printf.sprintf
          "Class '%s' has inheritance depth of %d (threshold: %d). Deep hierarchies are hard to understand and maintain."
          info.Class_graph.name depth deep_inheritance_threshold;
        flow = [ {
          Finding.file = info.Class_graph.file;
          line = info.Class_graph.line;
          message = Stdlib.Printf.sprintf "Definition of '%s' (depth: %d)"
            info.Class_graph.name depth;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    else None
  ) infos

let detect_tradition_breaker
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  Stdlib.List.filter_map (fun (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent_name ->
        let parent_opt = Stdlib.List.find_opt (fun i -> i.Class_graph.name = parent_name) infos in
        (match parent_opt with
         | Some parent 
             when Stdlib.List.length parent.Class_graph.methods >= 10
               && Stdlib.List.length info.Class_graph.methods <= 2
               && info.Class_graph.loc > 1000 ->
               Some {
                 Finding.rule = "TraditionBreaker";
                 severity = "Low";
                 file = info.Class_graph.file;
                 line = info.Class_graph.line;
                 message = Stdlib.Printf.sprintf
                   "Class '%s' inherits from large parent '%s' (%d methods) but provides minimal variation (%d methods). Consider composition over inheritance."
                   info.Class_graph.name parent.Class_graph.name 
                   (Stdlib.List.length parent.Class_graph.methods)
                   (Stdlib.List.length info.Class_graph.methods);
                 flow = [ {
                   Finding.file = info.Class_graph.file;
                   line = info.Class_graph.line;
                   message = Stdlib.Printf.sprintf "Definition of '%s' (inherits %s)"
                     info.Class_graph.name parent.Class_graph.name;
                 } ];
                 language = "crystal";
                 dependency = None;
                 reachability = None; suggestion = None;
               }
         | _ -> None)
    | None -> None
  ) infos

let detect_refused_parent_bequest
    (nodes : Security_node.t list)
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let module StringMap = Stdlib.Map.Make(Stdlib.String) in
  let by_file = Stdlib.List.fold_left (fun acc (n : Security_node.t) ->
    let existing = match StringMap.find_opt n.Security_node.file acc with
      | Some nodes -> nodes | None -> [] in
    StringMap.add n.Security_node.file (n :: existing) acc
  ) StringMap.empty nodes in
  
  let rec get_ancestor_methods name visited =
    if Stdlib.List.mem name visited then []
    else
      match Stdlib.List.find_opt (fun i -> i.Class_graph.name = name) infos with
      | Some ci ->
        let methods = ci.Class_graph.methods in
        (match ci.Class_graph.parent with
         | Some p -> methods @ get_ancestor_methods p (name :: visited)
         | None -> methods)
      | None -> []
  in
  
  Stdlib.List.concat_map (fun (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent_name ->
      (match Stdlib.List.find_opt (fun i -> i.Class_graph.name = parent_name) infos with
       | Some _parent ->
         let ancestor_methods = get_ancestor_methods parent_name [] in
         Stdlib.List.concat_map (fun method_name ->
           if not (Stdlib.List.mem method_name ancestor_methods) then [] else
           let file_nodes = match StringMap.find_opt info.Class_graph.file by_file with
             | Some nodes -> nodes | None -> [] in
           let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
           let all_classes = Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Class) sorted in
           let class_start = info.Class_graph.line in
           let class_end = 
             let rec find_next_class = function
               | [] -> 999999
               | c :: _ when c.Security_node.line > class_start -> c.Security_node.line
               | _ :: rest -> find_next_class rest
             in find_next_class all_classes
           in
           let def_nodes = Stdlib.List.filter (fun n -> 
             n.Security_node.node_type = Security_node.Def
             && n.Security_node.name = method_name
             && n.Security_node.line >= class_start
             && n.Security_node.line < class_end
           ) sorted in
           Stdlib.List.concat_map (fun (def_node : Security_node.t) ->
             let start_line = def_node.Security_node.line in
             let next_def = Stdlib.List.find_opt (fun n -> 
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
                  message = Stdlib.Printf.sprintf
                    "Method '%s' in '%s' overrides parent but has tiny body (%d lines). This is 'Refused Parent Bequest' - the class refuses functionality from its parent."
                    method_name info.Class_graph.name body_size;
                  flow = [ {
                    Finding.file = info.Class_graph.file;
                    line = start_line;
                    message = Stdlib.Printf.sprintf "Override of '%s' in '%s' (%d lines)"
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

let detect_base_class_knows_derived
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let module StringMap = Stdlib.Map.Make(Stdlib.String) in
  let parent_children = Stdlib.List.fold_left (fun acc (info : Class_graph.class_info) ->
    match info.Class_graph.parent with
    | Some parent ->
      let siblings = match StringMap.find_opt parent acc with
        | Some siblings -> siblings | None -> [] in
      StringMap.add parent (info :: siblings) acc
    | None -> acc
  ) StringMap.empty infos in
  Stdlib.List.concat_map (fun (info : Class_graph.class_info) ->
    match StringMap.find_opt info.Class_graph.name parent_children with
    | Some children when Stdlib.List.length children >= 3 ->
      [{ Finding.rule = "BaseClassKnowsDerivedClass";
         severity = "Low";
         file = info.Class_graph.file;
         line = info.Class_graph.line;
         message = Stdlib.Printf.sprintf
           "Class '%s' has %d direct children. Consider if it references them directly (factory pattern, type checks with 'is_a?', etc.). Base classes should not know their specific derived types."
           info.Class_graph.name (Stdlib.List.length children);
         flow = [ {
           Finding.file = info.Class_graph.file;
           line = info.Class_graph.line;
           message = Stdlib.Printf.sprintf "Definition of '%s' (%d children: %s)"
             info.Class_graph.name (Stdlib.List.length children)
             (Stdlib.String.concat ", " (Stdlib.List.map (fun c -> c.Class_graph.name) (Stdlib.List.rev children)));
         } ];
         language = "crystal";
         dependency = None;
         reachability = None; suggestion = None; }]
    | _ -> []
  ) infos

let detect_parallel_inheritance
    (infos : Class_graph.class_info list)
    (_parent_to_children : string list Class_graph.StringMap.t)
    : Finding.t list =
  let all_class_names = Stdlib.List.fold_left (fun acc info ->
    Class_graph.StringSet.add info.Class_graph.name acc
  ) Class_graph.StringSet.empty infos in
  let rec check_splits (info : Class_graph.class_info) (name : string) (namelen : int) (pos : int) : Finding.t list =
    if pos >= namelen - 1 then []
    else
      let prefix = Stdlib.String.sub name 0 pos in
      let suffix = Stdlib.String.sub name pos (namelen - pos) in
      let new_findings = 
        if Class_graph.StringSet.mem prefix all_class_names && Class_graph.StringSet.mem suffix all_class_names then
          [{ Finding.rule = "ParallelInheritance";
             severity = "Low";
             file = info.Class_graph.file;
             line = info.Class_graph.line;
             message = Stdlib.Printf.sprintf
               "'%s' appears to be a combination of '%s' and '%s'. This suggests parallel hierarchies - when you add a new '%s', you must also add a new '%s'."
               name prefix suffix suffix suffix;
             flow = [ {
               Finding.file = info.Class_graph.file;
               line = info.Class_graph.line;
               message = Stdlib.Printf.sprintf "'%s' is a compound class (prefix: '%s', suffix: '%s')"
                 name prefix suffix;
             } ];
             language = "crystal";
             dependency = None;
             reachability = None; suggestion = None; }]
        else []
      in
      new_findings @ check_splits info name namelen (pos + 1)
  in
  Stdlib.List.concat_map (fun info ->
    let name = info.Class_graph.name in
    let namelen = Stdlib.String.length name in
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