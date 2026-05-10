(* lib/catseye_engine/propagate.ml *)

open Catseye_types
open Db

(** Check if an assignment node picks up taint from any of its args.
    Returns the source variable name if taint is found. *)
let check_assignment_taint (node : Security_node.t) (acc : Db.t) : string option =
  let is_sanitized =
    List.exists (fun a ->
      a.Security_node.arg_type = Security_node.ArgCall
      && Seed.is_sanitizer a.Security_node.value
    ) node.Security_node.args
  in
  if is_sanitized then None
  else
    List.find_opt (fun a ->
      a.Security_node.arg_type = Security_node.ArgVar
      && (Db.is_tainted_in_file acc a.Security_node.value node.Security_node.file
          || Db.is_tainted acc a.Security_node.value)
    ) node.Security_node.args
    |> Option.map (fun a -> a.Security_node.value)

(* File-scoped propagation: assignment in file X picks up taint from vars in X *)
let do_propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else match check_assignment_taint node acc with
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

(* Fixed-point: propagate until no new tainted vars found *)
let rec propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let size_before = Db.db_size db in
  let db' = do_propagate nodes db in
  let size_after = Db.db_size db' in
  if size_after > size_before then propagate nodes db'
  else db'
