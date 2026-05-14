(* lib/catseye_engine/propagate.ml *)

open Catseye_types
open Db

(* File-scoped propagation: assignment in file X picks up taint from vars in X.
   Handles two patterns:
   1. Direct var-to-var: x = y  (y is tainted → x becomes tainted)
   2. Call return: x = f(y)  (call f has tainted arg y → x becomes tainted)
   The assign node has args=[call:"f"], but the call node has args=[var:"y"].
   We need to resolve through the call node to find the actual tainted source. *)
let do_propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  (* Build a lookup: (file, line) → call nodes for resolving call args *)
  let call_at = Hashtbl.create 128 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then
      let key = n.Security_node.file ^ ":" ^ string_of_int n.Security_node.line in
      Hashtbl.replace call_at key n
  ) nodes;
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.is_tainted_in_file acc node.Security_node.name node.Security_node.file then acc
    else
      (* Pattern 1: direct var arg in the assign node *)
      let direct_hit = Db.check_assignment_taint node acc in
      match direct_hit with
      | Some _ -> Db.add_record acc {
          var_name = node.Security_node.name
        ; file = node.Security_node.file
        ; line = node.Security_node.line
        ; description = node.Security_node.name
            ^ " assigned from tainted: " ^ (Option.get direct_hit)
        ; source_var = Option.get direct_hit
        ; field = None
        ; status = Tainted { source = Option.get direct_hit
                            ; field = None
                            ; origin = From_var (Option.get direct_hit) }
        }
      | None ->
          (* Pattern 2: call args — look at the RHS call nodes *)
          let call_hits =
            List.filter_map (fun a ->
              if a.Security_node.arg_type <> Security_node.ArgCall then None
              else
                (* Find the actual call node to check its args *)
                let key = node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line in
                match Hashtbl.find_opt call_at key with
                | Some call_node ->
                    (* Check if any arg to the call is tainted *)
                    let hit = List.find_opt (fun ca ->
                      ca.Security_node.arg_type = Security_node.ArgVar
                      && Db.is_tainted_in_file acc ca.Security_node.value node.Security_node.file
                    ) call_node.Security_node.args in
                    (match hit with
                     | Some ca ->
                         Some ca.Security_node.value
                     | None -> None)
                | None -> None
            ) node.Security_node.args
          in
          (match call_hits with
           | source_var :: _ ->
               Db.add_record acc {
                 var_name = node.Security_node.name
               ; file = node.Security_node.file
               ; line = node.Security_node.line
               ; description = node.Security_node.name
                   ^ " assigned from tainted call arg: " ^ source_var
               ; source_var
               ; field = None
               ; status = Tainted { source = source_var
                                   ; field = None
                                   ; origin = From_var source_var }
               }
           | [] -> acc)
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