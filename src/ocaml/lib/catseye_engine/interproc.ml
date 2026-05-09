(* lib/catseye_engine/interproc.ml *)

open Catseye_types
open Db

(* Inter-procedural propagation: if x = tainted_fn(args) and tainted_fn is tainted, x is tainted *)
let propagate_interprocedural (nodes : Security_node.t list) (db : Db.t) : Db.t =
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else begin
      (* Check if any arg is a call to a tainted function *)
      let tainted_call =
        node.Security_node.args
        |> List.find_opt (fun a ->
          a.Security_node.arg_type = Security_node.ArgCall
          && Db.has_record acc a.Security_node.value
        )
      in
      match tainted_call with
      | Some a ->
        Db.add_record acc {
          var_name = node.Security_node.name
        ; file = node.Security_node.file
        ; line = node.Security_node.line
        ; description = node.Security_node.name
            ^ " assigned from tainted call: " ^ a.Security_node.value
        ; source_var = a.Security_node.value
        ; field = None
        ; status = Tainted { source = a.Security_node.value
                            ; field = None
                            ; origin = From_var a.Security_node.value }
        }
      | None ->
        (* Fallback: check if any var arg is tainted *)
        let tainted_var =
          node.Security_node.args
          |> List.find_opt (fun a ->
            a.Security_node.arg_type = Security_node.ArgVar
            && Db.has_record acc a.Security_node.value
          )
        in
        match tainted_var with
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
  ) db nodes
