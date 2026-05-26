(* lib/catseye_claws/hierarchy/class_graph.ml *)

(** Class hierarchy graph builder.

    Builds an inheritance graph from extracted Security_node.t list.
    Maps class names to their parent, children, methods, and metadata.
*)

open Base
open Catseye_types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )

(* Alias for using old List API temporarily *)
module OldList = struct
  let iter = Stdlib.List.iter
  let iteri = Stdlib.List.iteri
  let filter = Stdlib.List.filter
  let map = Stdlib.List.map
  let length = Stdlib.List.length
  let nth = Stdlib.List.nth
  let sort = Stdlib.List.sort
  let fold_left = Stdlib.List.fold_left
  let rev = Stdlib.List.rev
  let mem = Stdlib.List.mem
  let exists = Stdlib.List.exists
end

(* ── Types ──────────────────────────────────────────────────────────── *)

type class_info = {
  name : string;          (** Class name *)
  file : string;          (** File where defined *)
  line : int;            (** Line number of class definition *)
  parent : string option; (** Parent class name if any *)
  methods : string list; (** Method names defined in this class *)
  loc : int;             (** Lines of code (end - start) *)
  is_abstract : bool;    (** Whether class is abstract *)
}

(* ── Helpers ───────────────────────────────────────────────────────── *)

(** Extract parent name from class node metadata *)
let get_parent (node : Security_node.t) : string option =
  Security_node.get_metadata node "parent"

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

(* ── Class Graph Building ───────────────────────────────────────────── *)

(** Build a class graph from a flat node list.

    Groups Class nodes and their Def children into class_info records.
*)
let build_class_graph (nodes : Security_node.t list) : (string, class_info) Map.Poly.t =
  (* Group nodes by file *)
  let by_file = Stdlib.Hashtbl.create 16 in
  OldList.iter (fun (n : Security_node.t) ->
    let existing = try Stdlib.Hashtbl.find by_file n.Security_node.file with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;

  let class_infos = ref [] in
  Stdlib.Hashtbl.iter (fun _file file_nodes ->
    let sorted = OldList.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    
    (* Find class boundaries *)
    let class_nodes = OldList.filter (fun n ->
      n.Security_node.node_type = Security_node.Class
    ) sorted in

    OldList.iteri (fun i (cn : Security_node.t) ->
      let start_line = cn.Security_node.line in
      let end_line =
        if i + 1 < OldList.length class_nodes then
          (OldList.nth class_nodes (i + 1)).Security_node.line
        else 1000000
      in

      (* Find Def nodes within this class *)
      let methods_in_class = OldList.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in

      let method_names = OldList.map (fun n -> n.Security_node.name) methods_in_class in
      let parent = get_parent cn in
      let loc = end_line - start_line in
      let is_abstract = is_abstract_class cn.Security_node.name in

      class_infos := {
        name = cn.Security_node.name;
        file = cn.Security_node.file;
        line = cn.Security_node.line;
        parent;
        methods = method_names;
        loc;
        is_abstract;
      } :: !class_infos
    ) class_nodes
  ) by_file;

  (* Build map from class name to info *)
  let graph = Map.Poly.empty in
  OldList.fold_left (fun map ci ->
    Map.Poly.set map ~key:ci.name ~data:ci
  ) graph (OldList.rev !class_infos)

(* ── Graph Queries ──────────────────────────────────────────────────── *)

(** Get direct children of a class *)
let get_children (graph : (string, class_info) Map.Poly.t) (class_name : string) : class_info list =
  Map.Poly.fold graph ~init:[] ~f:(fun ~key:_ ~data:info acc ->
    match info.parent with
    | Some p when p = class_name -> info :: acc
    | _ -> acc
  )

(** Get ancestor chain (parent, grandparent, etc.) *)
let get_ancestors (graph : (string, class_info) Map.Poly.t) (class_name : string) : class_info list =
  let rec collect (name : string) (visited : string list) : class_info list =
    if OldList.mem name visited then []  (* Prevent cycles *)
    else
      match Map.Poly.find graph name with
      | Some info ->
        let new_visited = name :: visited in
        (match info.parent with
         | Some p -> info :: collect p new_visited
         | None -> [info])
      | None -> []
  in
  collect class_name []

(** Get inheritance depth (how many ancestors) *)
let get_inheritance_depth (graph : (string, class_info) Map.Poly.t) (class_name : string) : int =
  let ancestors = get_ancestors graph class_name in
  OldList.length ancestors

(** Check if class B inherits from class A (directly or indirectly) *)
let inherits_from (graph : (string, class_info) Map.Poly.t) (child : string) (ancestor : string) : bool =
  let ancestors = get_ancestors graph child in
  OldList.exists (fun a -> a.name = ancestor) ancestors

(** Get all methods in a class and its ancestors *)
let get_all_methods (graph : (string, class_info) Map.Poly.t) (class_name : string) : string list =
  let ancestors = get_ancestors graph class_name in
  OldList.fold_left (fun methods a -> a.methods @ methods) [] ancestors

(** Check if a class overrides a method from a parent *)
let overrides_method (graph : (string, class_info) Map.Poly.t) (class_name : string) (method_name : string) : bool =
  match Map.Poly.find graph class_name with
  | Some info -> OldList.mem method_name info.methods
  | None -> false