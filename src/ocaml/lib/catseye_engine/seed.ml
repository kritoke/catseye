(* lib/catseye_engine/seed.ml *)

open Catseye_types
open Db

(* Alias from constants — deduped source of truth. *)
let is_source ?(extra = []) name = Constants.is_source ~extra name
let is_sanitizer ?(extra = []) name = Constants.is_sanitizer ~extra name

(* Seed from function parameters named like taint sources.
   Only seed params in functions where the extractor detected at least
   one tainted assignment — this avoids seeding in helper functions
   where params have source-like names (e.g. `path`) but receive safe data. *)
let seed_from_params (nodes : Security_node.t list) (extra_sources : string list)
    (db : Db.t) : Db.t =
  (* Build set of (file, def_line) for functions with tainted assigns *)
  let has_tainted_assign = Hashtbl.create 32 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Assign && n.Security_node.taint then
      (* Find the enclosing def by looking for the nearest Def before this line *)
      let def_node =
        List.filter (fun d ->
          d.Security_node.node_type = Security_node.Def
          && d.Security_node.file = n.Security_node.file
          && d.Security_node.line < n.Security_node.line
        ) nodes
        |> List.sort (fun a b -> compare b.Security_node.line a.Security_node.line)
        |> List.find_opt (fun _ -> true)
      in
      match def_node with
      | Some d ->
        Hashtbl.replace has_tainted_assign
          (d.Security_node.file, d.Security_node.line) true
      | None -> ()
    (* Also consider calls with taint=true — they indicate user data flow *)
    else if n.Security_node.node_type = Security_node.Call && n.Security_node.taint then
      let def_node =
        List.filter (fun d ->
          d.Security_node.node_type = Security_node.Def
          && d.Security_node.file = n.Security_node.file
          && d.Security_node.line < n.Security_node.line
        ) nodes
        |> List.sort (fun a b -> compare b.Security_node.line a.Security_node.line)
        |> List.find_opt (fun _ -> true)
      in
      match def_node with
      | Some d ->
        Hashtbl.replace has_tainted_assign
          (d.Security_node.file, d.Security_node.line) true
      | None -> ()
  ) nodes;
  nodes
  |> List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  |> List.filter (fun def ->
    (* Only seed params in functions where extractor found tainted assigns *)
    Hashtbl.mem has_tainted_assign (def.Security_node.file, def.Security_node.line)
  )
  |> List.concat_map (fun def ->
    def.Security_node.args
    |> List.filter (fun a -> is_source ~extra:extra_sources a.Security_node.value)
    |> List.map (fun a ->
      { var_name = a.Security_node.value
      ; file = def.Security_node.file
      ; line = def.Security_node.line
      ; description = a.Security_node.value ^ " is a taint source (parameter)"
      ; source_var = ""
      ; field = (if a.Security_node.field <> "" then Some a.Security_node.field else None)
      ; status = Tainted { source = a.Security_node.value
                          ; field = None
                          ; origin = Known_source a.Security_node.value }
      }
    )
  )
  |> List.fold_left (fun acc record -> Db.add_record acc record) db

(* Seed from extractor-flagged assignments (taint=true) *)
let seed_from_taint_flags (nodes : Security_node.t list) (db : Db.t) : Db.t =
  nodes
  |> List.filter (fun n ->
    n.Security_node.node_type = Security_node.Assign && n.Security_node.taint
  )
  |> List.filter (fun n ->
    (* Skip if RHS is a sanitizer call *)
    match n.Security_node.args with
    | [{ Security_node.arg_type = ArgCall; value; _ }] ->
      not (is_sanitizer value)
    | _ -> true
  )
  |> List.map (fun n ->
    let from_var =
      n.Security_node.args
      |> List.find_opt (fun a -> a.Security_node.arg_type = Security_node.ArgVar)
      |> Option.map (fun a -> a.Security_node.value)
      |> Option.value ~default:""
    in
    let field =
      n.Security_node.args
      |> List.find_opt (fun a -> a.Security_node.field <> "")
      |> Option.map (fun a -> Some a.Security_node.field)
      |> Option.value ~default:None
    in
    { var_name = n.Security_node.name
    ; file = n.Security_node.file
    ; line = n.Security_node.line
    ; description = if from_var <> ""
      then n.Security_node.name ^ " assigned from tainted: " ^ from_var
      else n.Security_node.name ^ " tainted via source"
    ; source_var = from_var
    ; field
    ; status = Tainted { source = from_var
                        ; field
                        ; origin = Known_source from_var }
    }
  )
  |> List.fold_left (fun acc record -> Db.add_record acc record) db

let seed_sources ?(extra_sources = []) (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let db' = seed_from_params nodes extra_sources db in
  let db'' = seed_from_taint_flags nodes db' in
  (* Seed from scent metadata: assignments carrying scent=true are also tainted *)
  nodes
  |> List.filter (fun n ->
    n.Security_node.node_type = Security_node.Assign
    && Security_node.has_metadata_flag n "scent"
  )
  |> List.filter (fun n ->
    (* Don't double-seed: if already tainted, skip *)
    not n.Security_node.taint
  )
  |> List.map (fun n ->
    let from_var =
      n.Security_node.args
      |> List.find_opt (fun a -> a.Security_node.arg_type = Security_node.ArgVar)
      |> Option.map (fun a -> a.Security_node.value)
      |> Option.value ~default:""
    in
    { var_name = n.Security_node.name
    ; file = n.Security_node.file
    ; line = n.Security_node.line
    ; description = n.Security_node.name ^ " carries sensitive data (scent source)"
    ; source_var = from_var
    ; field = None
    ; status = Tainted { source = from_var
                        ; field = None
                        ; origin = Known_source ("scent:" ^ n.Security_node.name) }
    }
  )
  |> List.fold_left (fun acc record -> Db.add_record acc record) db''