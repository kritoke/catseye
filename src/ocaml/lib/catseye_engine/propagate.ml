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
                let key = node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line in
                match Hashtbl.find_opt call_at key with
                | Some call_node ->
                    if Constants.is_sanitizer call_node.Security_node.name then None
                    else
                      let hit = List.find_opt (fun ca ->
                        ca.Security_node.arg_type = Security_node.ArgVar
                        && Db.is_tainted_in_file acc ca.Security_node.value node.Security_node.file
                      ) call_node.Security_node.args in
                      (match hit with
                       | Some ca -> Some ca.Security_node.value
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
      let has_sanitizer_arg =
        List.exists (fun a ->
          a.Security_node.arg_type = Security_node.ArgCall
          && Constants.is_sanitizer a.Security_node.value
        ) node.Security_node.args
      in
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

(* ── Property Taint Propagation ────────────────────────────────────────

   When URI.parse(tainted_var) is called, the resulting URI object's
   properties (host, request_target, etc.) inherit the taint.

   Also handles aliases:
     uri = URI.parse(url)
     other = uri  # alias - should also inherit tainted properties
*)

let uri_constructors = [
  "URI.parse";
  "URI.new";
  "URL.parse";
  "URL.new";
]

let uri_tainted_properties = [
  "host";
  "request_target";
  "path";
  "query";
  "full_path";
  "scheme";
]

let is_uri_constructor (call_name : string) : bool =
  List.exists (fun c -> 
    call_name = c || call_name = c ^ "."
  ) uri_constructors

(* Propagate URI constructor property taint *)
let propagate_uri_properties (nodes : Security_node.t list) (db : Db.t)
    ~(call_at : (string, Security_node.t) Hashtbl.t) : Db.t =
  let db_ref = ref db in
  let uri_found = ref 0 in
  let tainted_found = ref 0 in
  List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      let key = node.Security_node.file ^ ":" ^ string_of_int node.Security_node.line in
      match Hashtbl.find_opt call_at key with
      | Some cn when is_uri_constructor cn.Security_node.name ->
          uri_found := !uri_found + 1;
          let tainted_arg = List.find_opt (fun a ->
            a.Security_node.arg_type = Security_node.ArgVar
            && Db.is_tainted_in_file !db_ref a.Security_node.value node.Security_node.file
          ) cn.Security_node.args in
          (match tainted_arg with
           | Some arg ->
               tainted_found := !tainted_found + 1;
               let var_name = node.Security_node.name in
               let file = node.Security_node.file in
               List.iter (fun prop ->
                 let record = {
                   Db.var_name = var_name;
                   Db.file = file;
                   Db.line = node.Security_node.line;
                   Db.description = var_name ^ "." ^ prop ^ " tainted from " ^ arg.Security_node.value;
                   Db.source_var = arg.Security_node.value;
                   Db.field = Some prop;
                   Db.status = Db.Tainted {
                     source = arg.Security_node.value;
                     field = Some prop;
                     origin = Db.From_var arg.Security_node.value
                   }
                 } in
                 db_ref := Db.add_record !db_ref record
               ) uri_tainted_properties
           | None -> ())
      | _ -> ()
  ) nodes;
  (if !uri_found > 0 || !tainted_found > 0 then
     Printf.eprintf "[propagate_uri_properties] URI calls: %d, tainted: %d\n" !uri_found !tainted_found
  );
  !db_ref

(* Propagate aliases *)
let propagate_aliases (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let db_ref = ref db in
  List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      match node.Security_node.args with
      | [{ arg_type = Security_node.ArgVar; value = rhs_var; field = "" }] ->
          if Db.is_tainted_in_file !db_ref rhs_var node.Security_node.file then
            let var_name = node.Security_node.name in
            let file = node.Security_node.file in
            List.iter (fun prop ->
              let record = {
                Db.var_name = var_name;
                Db.file = file;
                Db.line = node.Security_node.line;
                Db.description = var_name ^ "." ^ prop ^ " tainted via alias of " ^ rhs_var;
                Db.source_var = rhs_var;
                Db.field = Some prop;
                Db.status = Db.Tainted {
                  source = rhs_var;
                  field = Some prop;
                  origin = Db.From_var rhs_var
                }
              } in
              db_ref := Db.add_record !db_ref record
            ) uri_tainted_properties
      | _ -> ()
  ) nodes;
  !db_ref

(* Fixed-point: propagate until no new tainted vars found (max 100 iterations). *)
let propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let call_at = build_call_lookup nodes in
  
  let rec loop_uri db count =
    if count >= 100 then db
    else
      let size_before = Db.db_size db in
      let db1 = cleanse_sanitized_assigns nodes db ~call_at in
      let db2 = do_propagate nodes db1 ~call_at in
      let db3 = propagate_uri_properties nodes db2 ~call_at in
      let size_after = Db.db_size db3 in
      if size_after > size_before then loop_uri db3 (count + 1)
      else db3
  in
  
  let rec loop_alias db count =
    if count >= 100 then db
    else
      let size_before = Db.db_size db in
      let db1 = propagate_aliases nodes db in
      let size_after = Db.db_size db1 in
      if size_after > size_before then loop_alias db1 (count + 1)
      else db1
  in
  
  let after_uri = loop_uri db 0 in
  let after_alias = loop_alias after_uri 0 in
  after_alias
