(* lib/catseye_engine/propagate.ml *)

open Catseye_types
open Db

(* File-scoped propagation: assignment in file X picks up taint from vars in X *)
let do_propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else match Db.check_assignment_taint node acc with
      | Some source_var ->
        Db.add_record acc {
          var_name = node.Security_node.name
        ; file = node.Security_node.file
        ; line = node.Security_node.line
        ; description = node.Security_node.name
            ^ " assigned from tainted: " ^ source_var
        ; source_var
        ; field = None
        ; status = Tainted { source = source_var
                            ; field = None
                            ; origin = From_var source_var }
        }
      | None -> acc
  ) db nodes

(* Fixed-point: propagate until no new tainted vars found (max 100 iterations) *)
let propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let rec loop db count =
    if count >= 100 then db
    else
      let size_before = Db.db_size db in
      let db' = do_propagate nodes db in
      let size_after = Db.db_size db' in
      if size_after > size_before then loop db' (count + 1)
      else db'
  in
  loop db 0