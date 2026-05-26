(* lib/catseye_engine/propagate.ml *)

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

(** Build a lookup: (file, line) → call nodes.
   Built once and reused across all propagate iterations. *)
let build_call_lookup (nodes : Security_node.t list) : (string, Security_node.t) Stdlib.Hashtbl.t =
  let call_at = Stdlib.Hashtbl.create 128 in
  Stdlib.List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then
      let key = n.Security_node.file ^ ":" ^ Int.to_string n.Security_node.line in
      Stdlib.Hashtbl.replace call_at key n
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
    ~(call_at : (string, Security_node.t) Stdlib.Hashtbl.t) : Db.t =
  Stdlib.List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else if Db.is_tainted_in_file acc node.Security_node.name node.Security_node.file then acc
    else
      (* Pattern 1: direct var arg in the assign node *)
      let direct_hit = Db.check_assignment_taint node acc in
      match direct_hit with
      | Some source -> Db.add_record acc {
          var_name = node.Security_node.name
        ; file = node.Security_node.file
        ; line = node.Security_node.line
        ; description = node.Security_node.name
            ^ " assigned from tainted: " ^ source
        ; source_var = source
        ; field = None
        ; status = Tainted { source
                            ; field = None
                            ; origin = From_var source }
        }
      | None ->
          (* Pattern 2: call args — look at the RHS call nodes *)
          let call_hits =
            Stdlib.List.filter_map (fun a ->
              if a.Security_node.arg_type <> Security_node.ArgCall then None
              else
                let key = node.Security_node.file ^ ":" ^ Int.to_string node.Security_node.line in
                match Stdlib.Hashtbl.find_opt call_at key with
                | Some call_node ->
if Constants.is_sanitizer call_node.Security_node.name then None
                      else
                        let hit = Stdlib.List.find_opt (fun ca ->
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
    ~(call_at : (string, Security_node.t) Stdlib.Hashtbl.t) : Db.t =
  Stdlib.List.fold_left (fun acc node ->
    if node.Security_node.node_type <> Security_node.Assign then acc
    else
      let has_sanitizer_arg =
        Stdlib.List.exists (fun a ->
          a.Security_node.arg_type = Security_node.ArgCall
          && Constants.is_sanitizer a.Security_node.value
        ) node.Security_node.args
      in
      let has_sanitizer_call =
        let key = node.Security_node.file ^ ":" ^ Int.to_string node.Security_node.line in
        match Stdlib.Hashtbl.find_opt call_at key with
        | Some cn -> Constants.is_sanitizer cn.Security_node.name
        | None -> false
      in
      if has_sanitizer_arg || has_sanitizer_call then
        Db.remove_record acc node.Security_node.name node.Security_node.file
      else acc
  ) db nodes

(* ── String Operation Taint Propagation ───────────────────────────────

   When a tainted string is used in string operations, the result inherits taint:
   - Method chains: result = tainted.upcase, result = tainted.split(",")
   - Interpolations: result = "#{tainted} suffix"
   - Gsub/replace: result = tainted.gsub("a", "b")

   For method chains, we look for assignments where:
   - The RHS is a method call on a tainted variable (receiver is tainted)
   - The assign target inherits the tainted receiver's properties
*)

(* String methods that preserve/propagate taint when called on a tainted string *)
let string_taint_methods = [
  "upcase"; "downcase"; "capitalize"; "strip"; "lstrip"; "rstrip";
  "reverse"; "chomp"; "chop"; "squeeze"; "squeeze!";
  "gsub"; "gsub!"; "sub"; "sub!"; "replace";
  "split"; "lines"; "chars"; "bytes";
  "strip_margin"; "indent";
  "tr"; "tr!"; "delete"; "delete!";
  "prepend"; "concat";
  "encode"; "decode";
]

let is_string_taint_method (method_name : string) : bool =
  Stdlib.List.exists (fun m -> method_name = m || method_name = m ^ "!") string_taint_methods

(* Extract method name from "receiver.method" format *)
let extract_method_name (full_name : string) : string option =
  match Stdlib.String.rindex_opt full_name '.' with
  | Some idx -> Some (Stdlib.String.sub full_name (idx + 1) (String.length full_name - idx - 1))
  | None -> None

(* Get the receiver variable from a call node *)
let get_call_receiver (call_node : Security_node.t) : string option =
  let name = call_node.Security_node.name in
  match Stdlib.String.index_opt name '.' with
  | Some idx -> Some (Stdlib.String.sub name 0 idx)
  | None -> None

(* ── Cross-File Taint Propagation ─────────────────────────────────────

   When a variable is tainted in one file, propagate that taint to
   assignments in other files that reference the same variable name.

   Example:
     # file_a.cr
     url = params["url"]  # ← Taint source

     # file_b.cr (different file)
     target = fetch_url(url)  # url is tainted in file_a, should propagate
     HTTP::Client.get(target)  # ← Should be flagged
*)

(* Propagate taint across file boundaries.
   When a variable is tainted in one file (file A), and it's assigned
   to another variable in a different file (file B), the new variable
   in file B should inherit the taint. *)
let propagate_cross_file (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let taint_db_ref = ref db in
  (* For each assign node, check if the source variable is tainted in ANY file *)
  Stdlib.List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      (* Check direct var args *)
      Stdlib.List.iter (fun arg ->
        if arg.Security_node.arg_type = Security_node.ArgVar then
          let source_var = arg.Security_node.value in
          let target_file = node.Security_node.file in
          (* Check if source is tainted in any OTHER file *)
          let is_cross_file = Db.is_tainted_anywhere !taint_db_ref source_var in
          if is_cross_file then
            (* Check if target is not already tainted in target file *)
            if not (Db.is_tainted_in_file !taint_db_ref node.Security_node.name target_file) then
              let record = {
                Db.var_name = node.Security_node.name;
                Db.file = target_file;
                Db.line = node.Security_node.line;
                Db.description = node.Security_node.name ^ " tainted via cross-file assignment from " ^ source_var;
                Db.source_var = source_var;
                Db.field = None;
                Db.status = Db.Tainted {
                  source = source_var;
                  field = None;
                  origin = Db.From_var source_var
                }
              } in
              taint_db_ref := Db.add_record !taint_db_ref record
      ) node.Security_node.args
  ) nodes;
  !taint_db_ref

(* ── URI Constructor Taint Propagation ────────────────────────────────

   When URI.parse(tainted_var) is called, the resulting URI object's
   properties (host, request_target, etc.) inherit the taint.
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
  Stdlib.List.exists (fun c -> 
    call_name = c || call_name = c ^ "."
  ) uri_constructors

(* Propagate URI constructor property taint *)
let propagate_uri_properties (nodes : Security_node.t list) (db : Db.t)
    ~(call_at : (string, Security_node.t) Stdlib.Hashtbl.t) : Db.t =
  let taint_db_ref = ref db in
  let uri_found = ref 0 in
  let tainted_found = ref 0 in
  Stdlib.List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      let key = node.Security_node.file ^ ":" ^ Int.to_string node.Security_node.line in
      match Stdlib.Hashtbl.find_opt call_at key with
      | Some cn when is_uri_constructor cn.Security_node.name ->
          uri_found := !uri_found + 1;
          let tainted_arg = Stdlib.List.find_opt (fun a ->
            a.Security_node.arg_type = Security_node.ArgVar
            && Db.is_tainted_in_file !taint_db_ref a.Security_node.value node.Security_node.file
          ) cn.Security_node.args in
          (match tainted_arg with
           | Some arg ->
               tainted_found := !tainted_found + 1;
               let var_name = node.Security_node.name in
               let file = node.Security_node.file in
               Stdlib.List.iter (fun prop ->
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
                 taint_db_ref := Db.add_record !taint_db_ref record
               ) uri_tainted_properties
           | None -> ())
      | _ -> ()
  ) nodes;
  !taint_db_ref

(* Propagate aliases *)
let propagate_aliases (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let taint_db_ref = ref db in
  Stdlib.List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      match node.Security_node.args with
      | [{ arg_type = Security_node.ArgVar; value = rhs_var; field = "" }] ->
          if Db.is_tainted_in_file !taint_db_ref rhs_var node.Security_node.file then
            let var_name = node.Security_node.name in
            let file = node.Security_node.file in
            let source_taints = Db.get_tainted_records !taint_db_ref rhs_var file in
            Stdlib.List.iter (fun record ->
              match record.Db.field with
              | Some fld ->
                  let new_record = {
                    Db.var_name = var_name;
                    Db.file = file;
                    Db.line = node.Security_node.line;
                    Db.description = var_name ^ "." ^ fld ^ " tainted via alias of " ^ rhs_var;
                    Db.source_var = rhs_var;
                    Db.field = Some fld;
                    Db.status = Db.Tainted {
                      source = rhs_var;
                      field = Some fld;
                      origin = Db.From_var rhs_var
                    }
                  } in
                  taint_db_ref := Db.add_record !taint_db_ref new_record
              | None -> ()
            ) source_taints
      | [{ arg_type = Security_node.ArgCall; value = _; field = "" }] ->
          let _key = node.Security_node.file ^ ":" ^ Int.to_string node.Security_node.line in
          (match Stdlib.List.find_opt (fun n ->
             n.Security_node.node_type = Security_node.Call
             && n.Security_node.file = node.Security_node.file
             && n.Security_node.line = node.Security_node.line
           ) nodes with
           | Some call_node ->
               let receiver_opt = get_call_receiver call_node in
               (match receiver_opt with
                | Some receiver when Db.is_tainted_in_file !taint_db_ref receiver node.Security_node.file ->
                    let var_name = node.Security_node.name in
                    let file = node.Security_node.file in
                    let source_taints = Db.get_tainted_records !taint_db_ref receiver file in
                    Stdlib.List.iter (fun record ->
                      match record.Db.field with
                      | Some fld ->
                          let new_record = {
                            Db.var_name = var_name;
                            Db.file = file;
                            Db.line = node.Security_node.line;
                            Db.description = var_name ^ "." ^ fld ^ " tainted via method call";
                            Db.source_var = receiver;
                            Db.field = Some fld;
                            Db.status = Db.Tainted {
                              source = receiver;
                              field = Some fld;
                              origin = Db.From_var receiver
                            }
                          } in
                          taint_db_ref := Db.add_record !taint_db_ref new_record
                      | None -> ()
                    ) source_taints
                | _ -> ())
           | None -> ())
      | _ -> ()
  ) nodes;
  !taint_db_ref

(* Propagate taint through string operations.
   When x = tainted_string.upcase, mark x as tainted (variable-level).
   When x = tainted_string.split(","), mark x as tainted.
   This handles both variable-level and field-level taint propagation. *)
let propagate_string_ops (nodes : Security_node.t list) (db : Db.t)
    ~(call_at : (string, Security_node.t) Stdlib.Hashtbl.t) : Db.t =
  let taint_db_ref = ref db in
  Stdlib.List.iter (fun node ->
    if node.Security_node.node_type = Security_node.Assign then
      (* Check if this is a method call on a variable *)
      match node.Security_node.args with
      | [{ arg_type = Security_node.ArgCall; value = _; field = "" }] ->
          (* Look up the call node to get the full method name *)
          let key = node.Security_node.file ^ ":" ^ Int.to_string node.Security_node.line in
          (match Stdlib.Hashtbl.find_opt call_at key with
           | Some call_node ->
               let receiver_opt = get_call_receiver call_node in
               let method_opt = extract_method_name call_node.Security_node.name in
               (match receiver_opt, method_opt with
                | Some receiver, Some method_name when is_string_taint_method method_name ->
                    (* Check if receiver is tainted at variable level *)
                    let is_tainted = Db.is_tainted_in_file !taint_db_ref receiver node.Security_node.file in
                    if is_tainted then
                      let var_name = node.Security_node.name in
                      let file = node.Security_node.file in
                      (* Mark the assign target as tainted *)
                      let record = {
                        Db.var_name = var_name;
                        Db.file = file;
                        Db.line = node.Security_node.line;
                        Db.description = var_name ^ " tainted via string operation on " ^ receiver;
                        Db.source_var = receiver;
                        Db.field = None;
                        Db.status = Db.Tainted {
                          source = receiver;
                          field = None;
                          origin = Db.From_var receiver
                        }
                      } in
                      taint_db_ref := Db.add_record !taint_db_ref record;
                      (* Also mark all string property fields as tainted *)
                      Stdlib.List.iter (fun prop ->
                        let prop_record = {
                          Db.var_name = var_name;
                          Db.file = file;
                          Db.line = node.Security_node.line;
                          Db.description = var_name ^ "." ^ prop ^ " tainted via " ^ method_name;
                          Db.source_var = receiver;
                          Db.field = Some prop;
                          Db.status = Db.Tainted {
                            source = receiver;
                            field = Some prop;
                            origin = Db.From_var receiver
                          }
                        } in
                        taint_db_ref := Db.add_record !taint_db_ref prop_record
                      ) ["length"; "size"; "empty"; "bytesize"]
                | _ -> ())
           | None -> ())
      | _ -> ()
  ) nodes;
  !taint_db_ref

let max_propagation_iterations = 100

(* Fixed-point: propagate until no new tainted vars found. *)
let propagate (nodes : Security_node.t list) (db : Db.t) : Db.t =
  let call_at = build_call_lookup nodes in
  
  let rec loop_string_ops db count =
    if count >= max_propagation_iterations then db
    else
      let size_before = Db.db_size db in
      let db1 = cleanse_sanitized_assigns nodes db ~call_at in
      let db2 = do_propagate nodes db1 ~call_at in
      let db3 = propagate_string_ops nodes db2 ~call_at in
      let size_after = Db.db_size db3 in
      if size_after > size_before then loop_string_ops db3 (count + 1)
      else db3
  in
  
  let rec loop_uri db count =
    if count >= max_propagation_iterations then db
    else
      let size_before = Db.db_size db in
      let db1 = cleanse_sanitized_assigns nodes db ~call_at in
      let db2 = propagate_uri_properties nodes db1 ~call_at in
      let size_after = Db.db_size db2 in
      if size_after > size_before then loop_uri db2 (count + 1)
      else db2
  in
  
  let rec loop_alias db count =
    if count >= max_propagation_iterations then db
    else
      let size_before = Db.db_size db in
      let db1 = propagate_aliases nodes db in
      let size_after = Db.db_size db1 in
      if size_after > size_before then loop_alias db1 (count + 1)
      else db1
  in
  
  let rec loop_cross_file db count =
    if count >= max_propagation_iterations then db
    else
      let size_before = Db.db_size db in
      let db1 = propagate_cross_file nodes db in
      let size_after = Db.db_size db1 in
      if size_after > size_before then loop_cross_file db1 (count + 1)
      else db1
  in
  
  let after_string = loop_string_ops db 0 in
  let after_uri = loop_uri after_string 0 in
  let after_alias = loop_alias after_uri 0 in
  let after_cross = loop_cross_file after_alias 0 in
  after_cross
