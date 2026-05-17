(* lib/catseye_engine/propagate.ml *)

open Catseye_types
open Db

(** Build a lookup: (file, line) → call nodes.
   Built once and reused across all propagate iterations. *)
let build_call_lookup (nodes : Security_node.t list) : (string, Security_node.t) Hashtbl.t =
  let call_at = Hashtbl.create 128 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then
      let key = n.Security_node.file ^ ":" ^ string_of_int n.Security_node.line in
      Hashtbl.replace call_at key n
  ) nodes;
  call_at

(* File-scoped propagation: assignment in file X picks up taint from vars in X.
   Handles two patterns:
   1. Direct var-to-var: x = y  (y is tainted → x becomes tainted)
   2. Call return: x = f(y)  (call f has tainted arg y → x becomes tainted)
   The assign node has args=[call:"f"], but the call node has args=[var:"y"].
   We need to resolve through the call node to find the actual tainted source.
   Sanitizer calls (File.expand_path, URI.encode, etc.) cleanse taint —
   if the RHS is a sanitizer, the assign target is NOT tainted, even if the
   call's args are tainted.

   Performance: call_at is built once by the caller and reused across all
   propagate iterations to avoid O(n) hashtable rebuild on every fixed-point pass. *)
let do_propagate (nodes : Security_node.t list) (db : Db.t)
    ~(call_at : (string, Security_node.t) Hashtbl.t) : Db.t =
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
                    (* Sanitizer check: if the call is a known sanitizer, skip taint
                       propagation and remove any existing taint on the target var.
                       e.g. absolute_path = File.expand_path(path) → clean *)
                    if Constants.is_sanitizer call_node.Security_node.name then None
                    else
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

(* Sanitizer cleansing pass: when a variable is assigned the result of a
   sanitizer call (File.expand_path, URI.encode, etc.), remove it from the
   taint DB. This handles cases where a previous propagation pass tainted
   the var, but a later pass discovers it was actually sanitized.
   e.g. path = validate_and_resolve_path!(path) → path is now clean *)
let cleanse_sanitized_assigns (nodes : Security_node.t list) (db : Db.t)
    ~(call_at : (string, Security_node.t) Hashtbl.t) : Db.t =
  List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else
      (* Check if any arg to this assign is a sanitizer call *)
      let has_sanitizer_arg =
        List.exists (fun a ->
          a.Security_node.arg_type = Security_node.ArgCall
          && Constants.is_sanitizer a.Security_node.value
        ) node.Security_node.args
      in
      (* Also check via call_at: the same-line call might be a sanitizer *)
      let has_sanitizer_call =
        let key = node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line in
        match Hashtbl.find_opt call_at key with
        | Some cn -> Constants.is_sanitizer cn.Security_node.name
        | None -> false
      in
      if has_sanitizer_arg || has_sanitizer_call then
        Db.remove_record acc node.Security_node.name node.Security_node.file
      else acc
  ) db nodes

(* Fixed-point: propagate until no new tainted vars found (max 100 iterations).
   After each propagation pass, cleanse sanitized assigns to remove taint
   that was incorrectly propagated through sanitizer calls.

   Performance: call_at is built ONCE before the loop and reused across all
   iterations. Previously, do_propagate created a new Hashtbl on every call
   (~100 hashtables per propagate call), and cleanse_sanitized_assigns built
   another one inline on each invocation. *)
let propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let call_at = build_call_lookup nodes in
  let rec loop db count =
    if count >= 100 then db
    else
      let size_before = Db.db_size db in
      let db' = cleanse_sanitized_assigns nodes db ~call_at
                |> fun d -> do_propagate nodes d ~call_at
      in
      let size_after = Db.db_size db' in
      if size_after > size_before then loop db' (count + 1)
      else db'
  in
  loop db 0