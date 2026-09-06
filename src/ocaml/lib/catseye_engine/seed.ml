(* lib/catseye_engine/seed.ml *)

open Base
open Catseye_types
open Db

(* Shadow string equality/comparison - Base makes these polymorphic *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

(* Alias from constants — deduped source of truth. *)
let is_source ?(extra = []) name = Constants.is_source ~extra name
let is_sanitizer ?(extra = []) name = Constants.is_sanitizer ~extra name

(* Seed from function parameters named like taint sources.
   Always seed params that match known sources (they're likely primary taint sources).
   Also seed other params in functions where the extractor detected at least
   one tainted assignment — this avoids seeding in helper functions
   where params have source-like names (e.g. `path`) but receive safe data. *)
let seed_from_params (nodes : Security_node.t list) (extra_sources : string list)
    (db : Db.t) : Db.t =
  (* Build set of (file, def_line) for functions with tainted assigns *)
  let has_tainted_assign = Stdlib.Hashtbl.create 32 in
  Stdlib.List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Assign && n.Security_node.taint then
      let def_node =
        Stdlib.List.filter (fun d ->
          d.Security_node.node_type = Security_node.Def
          && d.Security_node.file = n.Security_node.file
          && Stdlib.(<) d.Security_node.line n.Security_node.line
        ) nodes
        |> Stdlib.List.sort (fun a b -> Int.compare b.Security_node.line a.Security_node.line)
        |> Stdlib.List.find_opt (fun _ -> true)
      in
      (match def_node with
       | Some d ->
           Stdlib.Hashtbl.replace has_tainted_assign
             (d.Security_node.file, d.Security_node.line) true
       | None -> ())
else if n.Security_node.node_type = Security_node.Call && n.Security_node.taint then
      let def_node =
        Stdlib.List.filter (fun d ->
          d.Security_node.node_type = Security_node.Def
          && d.Security_node.file = n.Security_node.file
          && Stdlib.(<) d.Security_node.line n.Security_node.line
        ) nodes
        |> Stdlib.List.sort (fun a b -> Int.compare b.Security_node.line a.Security_node.line)
        |> Stdlib.List.find_opt (fun _ -> true)
      in
      (match def_node with
       | Some d ->
           Stdlib.Hashtbl.replace has_tainted_assign
             (d.Security_node.file, d.Security_node.line) true
       | None -> ())
  ) nodes;
  nodes
  |> Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  |> Stdlib.List.filter (fun def ->
    let has_source_param = Stdlib.List.exists (fun a -> 
      is_source ~extra:extra_sources a.Security_node.value
    ) def.Security_node.args in
    let has_tainted = Stdlib.Hashtbl.mem has_tainted_assign (def.Security_node.file, def.Security_node.line) in
    (* For Elixir files, treat all function params as potential taint sources
       since we can't know at extraction time which ones are user-controlled *)
    let is_elixir =
      let len = String.length def.Security_node.file in
      len > 3 && (Stdlib.String.sub def.Security_node.file (len - 3) 3 = ".ex"
                  || Stdlib.String.sub def.Security_node.file (len - 4) 4 = ".exs")
    in
    has_source_param || has_tainted || is_elixir
  )
  |> Stdlib.List.concat_map (fun def ->
    def.Security_node.args
    |> Stdlib.List.filter (fun a ->
      is_source ~extra:extra_sources a.Security_node.value
      || (let len = String.length def.Security_node.file in
          len > 3 && (Stdlib.String.sub def.Security_node.file (len - 3) 3 = ".ex"
                      || Stdlib.String.sub def.Security_node.file (len - 4) 4 = ".exs"))
    )
    |> Stdlib.List.map (fun a ->
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
  |> Stdlib.List.fold_left (fun acc record -> Db.add_record acc record) db

(* Seed from source-call results: when a variable is assigned the result
   of a known source call (e.g. `let x = os.getEnv(...)` or `let body = request(...)`),
   the target variable is tainted. This matters for AST-bridge languages
   (Gleam, OCaml, JS, Rust, Nim) whose extractors don't pre-flag taint on
   individual nodes the way Crystal's does. The assign node carries the
   call name as an ArgCall, so we seed the target when that call is a source. *)
let seed_from_source_calls ?(extra_sources = []) (nodes : Security_node.t list)
    (db : Db.t) : Db.t =
  nodes
  |> Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Assign)
  |> Stdlib.List.filter (fun n ->
    Stdlib.List.exists (fun a ->
      a.Security_node.arg_type = Security_node.ArgCall
      && is_source ~extra:extra_sources a.Security_node.value
      && not (is_sanitizer ~extra:[] a.Security_node.value)
    ) n.Security_node.args
  )
  |> Stdlib.List.filter (fun n ->
    not (Db.is_tainted_in_file db n.Security_node.name n.Security_node.file)
  )
  |> Stdlib.List.map (fun n ->
    let source_call =
      n.Security_node.args
      |> Stdlib.List.find (fun a ->
        a.Security_node.arg_type = Security_node.ArgCall
        && is_source ~extra:extra_sources a.Security_node.value)
      |> fun a -> a.Security_node.value
    in
    { Db.var_name = n.Security_node.name
    ; file = n.Security_node.file
    ; line = n.Security_node.line
    ; description = n.Security_node.name ^ " assigned from source call: " ^ source_call
    ; source_var = source_call
    ; field = None
    ; status = Db.Tainted { source = source_call
                           ; field = None
                           ; origin = Db.Known_source source_call }
    }
  )
  |> Stdlib.List.fold_left (fun acc record -> Db.add_record acc record) db

(* Seed from extractor-flagged assignments (taint=true) *)
let seed_from_taint_flags (nodes : Security_node.t list) (db : Db.t) : Db.t =
  nodes
  |> Stdlib.List.filter (fun n ->
    n.Security_node.node_type = Security_node.Assign && n.Security_node.taint
  )
  |> Stdlib.List.filter (fun n ->
    (match n.Security_node.args with
     | [{ Security_node.arg_type = ArgCall; value; _ }] ->
       not (is_sanitizer value)
     | _ -> true)
  )
  |> Stdlib.List.map (fun n ->
    let from_var =
      n.Security_node.args
      |> Stdlib.List.find_opt (fun a -> a.Security_node.arg_type = ArgVar)
      |> Option.map ~f:(fun a -> a.Security_node.value)
      |> Option.value ~default:""
    in
    let field =
      n.Security_node.args
      |> Stdlib.List.find_opt (fun a -> a.Security_node.field <> "")
      |> Option.map ~f:(fun a -> Some a.Security_node.field)
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
  |> Stdlib.List.fold_left (fun acc record -> Db.add_record acc record) db

(* Seed Elixir module attributes (@name) as taint sources.
   Module attributes can hold user-configured values (API keys, URLs, etc.)
   so they should be treated as potential taint sources. *)
let seed_elixir_module_attrs (nodes : Security_node.t list) (db : Db.t) : Db.t =
  nodes
  |> Stdlib.List.filter (fun n ->
    n.Security_node.node_type = Security_node.Assign
    && String.length n.Security_node.name > 0
    && n.Security_node.name.[0] = '@'
    && (let len = String.length n.Security_node.file in
        len > 3 && (Stdlib.String.sub n.Security_node.file (len - 3) 3 = ".ex"
                    || Stdlib.String.sub n.Security_node.file (len - 4) 4 = ".exs"))
  )
  |> Stdlib.List.map (fun n ->
    { Db.var_name = n.Security_node.name
    ; Db.file = n.Security_node.file
    ; Db.line = n.Security_node.line
    ; Db.description = n.Security_node.name ^ " is a module attribute (potential config value)"
    ; Db.source_var = ""
    ; Db.field = None
    ; Db.status = Db.Tainted { source = ""
                              ; field = None
                              ; origin = Db.Known_source n.Security_node.name }
    }
  )
  |> Stdlib.List.fold_left (fun acc record -> Db.add_record acc record) db

let seed_sources ?(extra_sources = []) (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let db' = seed_from_params nodes extra_sources db in
  let db'' = seed_from_taint_flags nodes db' in
  let db''' = seed_from_source_calls ~extra_sources nodes db'' in
  let db'''' = seed_elixir_module_attrs nodes db''' in
  (* Seed from scent metadata: assignments carrying scent=true are also tainted *)
  nodes
  |> Stdlib.List.filter (fun n ->
    n.Security_node.node_type = Security_node.Assign
    && Security_node.has_metadata_flag n "scent"
  )
  |> Stdlib.List.filter (fun n ->
    not n.Security_node.taint
  )
  |> Stdlib.List.map (fun n ->
    let from_var =
      n.Security_node.args
      |> Stdlib.List.find_opt (fun a -> a.Security_node.arg_type = ArgVar)
      |> Option.map ~f:(fun a -> a.Security_node.value)
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
  |> Stdlib.List.fold_left (fun acc record -> Db.add_record acc record) db''''
