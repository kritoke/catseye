(* lib/catseye_engine/interproc.ml
   Inter-procedural taint propagation.
   Two strategies:
   1. Return-value: if fn_name is in the taint DB (marked by returns.ml),
      propagate its taint to any variable assigned from the call.
   2. Call-arg: if a call receives tainted args, its return value is tainted
      (covers external functions we can't analyze). *)

open Catseye_types
open Db

module StringMap = Map.Make(String)

let is_sanitizer_call (name : string) : bool =
  Constants.is_sanitizer name

(** Check if any arg of a call is tainted. *)
let call_has_tainted_args (args : Security_node.arg list) (db : Db.t) (file : string) =
  List.exists (fun a ->
    match a.Security_node.arg_type with
    | Security_node.ArgVar ->
      Db.is_tainted_in_file db a.Security_node.value file
    | Security_node.ArgCall ->
      (* Nested call — check if the function itself returns tainted data *)
      Db.has_record db a.Security_node.value
    | _ -> false
  ) args

(** Extract a human-readable taint source name from a call node's args. *)
let taint_source_of_call (call : Security_node.t) (db : Db.t) : string =
  List.find_opt (fun a ->
    a.Security_node.arg_type = Security_node.ArgVar
    && Db.is_tainted_in_file db a.Security_node.value call.Security_node.file
  ) call.Security_node.args
  |> Option.map (fun a -> a.Security_node.value)
  |> Option.value ~default:call.Security_node.name

(** Build a (file,line) → Call node map for O(1) lookup. *)
let build_call_map (nodes : Security_node.t list) : Security_node.t StringMap.t =
  List.fold_left (fun m n ->
    if n.Security_node.node_type = Security_node.Call then
      StringMap.add
        (n.Security_node.file ^ ":" ^ string_of_int n.Security_node.line) n m
    else m
  ) StringMap.empty nodes

let propagate_interprocedural (nodes : Security_node.t list) (db : Db.t) : Db.t =
  (* Precompute call lookup map — O(n) instead of O(n²) *)
  let call_map = build_call_map nodes in
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.has_record acc node.Security_node.name then acc
    else begin
      (* Strategy 1: RHS is a call to a function marked as returning tainted data *)
      let tainted_call =
        node.Security_node.args
        |> List.find_opt (fun a ->
          a.Security_node.arg_type = Security_node.ArgCall
          && Db.has_record acc a.Security_node.value
        )
      in
      match tainted_call with
      | Some a ->
        (* Check if the tainted call is actually a sanitizer — if so, result is clean *)
        let call_node =
          StringMap.find_opt
            (node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line)
            call_map
        in
        (match call_node with
         | Some cn when is_sanitizer_call cn.Security_node.name ->
           acc  (* Sanitizer overrides return-value taint *)
         | _ ->
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
        })
      | None ->
        (* Strategy 2: A call arg is tainted → return is tainted.
           Use precomputed call_map for O(1) lookup instead of scanning all nodes. *)
        let call_node =
          StringMap.find_opt
            (node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line)
            call_map
        in
        (match call_node with
         | Some cn when is_sanitizer_call cn.Security_node.name ->
           (* Sanitizer call — result is clean *)
           acc
         | Some cn when call_has_tainted_args cn.Security_node.args acc cn.Security_node.file ->
           let src = taint_source_of_call cn acc in
           Db.add_record acc {
             var_name = node.Security_node.name
           ; file = node.Security_node.file
           ; line = node.Security_node.line
           ; description = node.Security_node.name
               ^ " receives tainted data via " ^ cn.Security_node.name
           ; source_var = src
           ; field = None
           ; status = Tainted { source = src
                               ; field = None
                               ; origin = From_var src }
           }
         | _ ->
           (* Fallback: use shared taint-check helper (handles same-file
              and global taint, sanitizer calls, and ArgVar matching) *)
           match Db.check_assignment_taint node acc with
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
           | None -> acc)
    end
  ) db nodes
