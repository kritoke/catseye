(* lib/catseye_engine/returns.ml
   Track functions whose body produces tainted data.
   Optimized: precompute file-grouped nodes for O(n) total instead of O(n²). *)

open Base
open Catseye_types
open Db

module StringMap = Stdlib.Map.Make(String)

(** Group nodes by file, sorted by line within each group. *)
let group_by_file (nodes : Security_node.t list)
    : (string * Security_node.t list) list =
  let map = Stdlib.List.fold_left (fun m n ->
    let key = n.Security_node.file in
    let existing = match StringMap.find_opt key m with Some l -> l | None -> [] in
    StringMap.add key (n :: existing) m
  ) StringMap.empty nodes in
  StringMap.bindings map
  |> List.map ~f:(fun (file, ns) -> (file, List.sort ~compare:(fun a b -> Int.compare a.Security_node.line b.Security_node.line) ns))

(* Find the next def line in the same file after a given line.
   Uses pre-sorted node list for efficiency. *)
let next_def_line (sorted_nodes : Security_node.t list) (line : int) : int option =
  let rec go = function
    | [] -> None
    | n :: rest ->
      if n.Security_node.node_type = Security_node.Def
         && n.Security_node.line > line
      then Some n.Security_node.line
      else go rest
  in
  go sorted_nodes

(* Track functions whose body produces tainted data *)
let track_return_taint (nodes : Security_node.t list) (db : Db.t) : Db.t =
  (* Precompute: group nodes by file, sorted by line *)
  let file_groups = group_by_file nodes in
  let file_map = Stdlib.List.fold_left (fun m (f, ns) -> StringMap.add f ns m) StringMap.empty file_groups in

  (* Iterate over Def nodes only *)
  let defs =
    nodes
    |> Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  in
  Stdlib.List.fold_left (fun acc def ->
    let sorted_nodes = match StringMap.find_opt def.Security_node.file file_map with
      | Some ns -> ns
      | None -> []
    in
    let ndl = next_def_line sorted_nodes def.Security_node.line in
    (* Filter assigns within this function's body using the pre-sorted list *)
    let fn_assigns =
      Stdlib.List.filter (fun n ->
        n.Security_node.node_type = Security_node.Assign
        && n.Security_node.line > def.Security_node.line
        && match ndl with
           | Some next_line -> n.Security_node.line < next_line
           | None -> true
      ) sorted_nodes
    in
    let fn_tainted =
      Stdlib.List.exists (fun n ->
        Db.has_record acc n.Security_node.name || n.Security_node.taint
      ) fn_assigns
    in
    if fn_tainted && not (Db.has_record acc def.Security_node.name) then
      Db.add_record acc {
        var_name = def.Security_node.name
      ; file = def.Security_node.file
      ; line = def.Security_node.line
      ; description = def.Security_node.name ^ " returns tainted data"
      ; source_var = ""
      ; field = None
      ; status = Tainted { source = def.Security_node.name
                          ; field = None
                          ; origin = From_var def.Security_node.name }
      }
    else acc
  ) db defs
