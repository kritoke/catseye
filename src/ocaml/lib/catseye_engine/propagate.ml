(* lib/catseye_engine/propagate.ml *)

open Catseye_types
open Db

let is_sanitizer_call (name : string) : bool =
  Seed.is_sanitizer name

(* File-scoped propagation: assignment in file X picks up taint from vars in X *)
let do_propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else begin
      (* Check if RHS is sanitized *)
      let is_sanitized = List.exists (fun a ->
        a.Security_node.arg_type = Security_node.ArgCall
        && is_sanitizer_call a.Security_node.value
      ) node.Security_node.args in
      if is_sanitized then acc
      else begin
        (* Find first tainted var arg in same file *)
        let tainted_arg =
          node.Security_node.args
          |> List.find_opt (fun a ->
            a.Security_node.arg_type = Security_node.ArgVar
            && Db.is_tainted_in_file acc a.Security_node.value node.Security_node.file
          )
        in
        match tainted_arg with
        | Some a ->
          Db.add_record acc {
            var_name = node.Security_node.name
          ; file = node.Security_node.file
          ; line = node.Security_node.line
          ; description = node.Security_node.name
              ^ " assigned from tainted: " ^ a.Security_node.value
          ; source_var = a.Security_node.value
          ; field = None
          ; status = Tainted { source = a.Security_node.value
                              ; field = None
                              ; origin = From_var a.Security_node.value }
          }
        | None -> acc
      end
    end
  ) db nodes

(* Fixed-point: propagate until no new tainted vars found *)
let rec propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let size_before = Db.db_size db in
  let db' = do_propagate nodes db in
  let size_after = Db.db_size db' in
  if size_after > size_before then propagate nodes db'
  else db'
