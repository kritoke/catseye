(* lib/catseye_engine/db.ml *)

open Catseye_types

module StringMap = Map.Make(String)

(** Named constants for Hashtbl initial sizes *)
let taint_dedup_size = 64

type taint_source =
  | Known_source of string       (* standard source name *)
  | From_var of string           (* propagated from another tainted var *)

type taint_status =
  | Clean
  | Tainted of { source : string; field : string option; origin : taint_source }
  | Sanitized of { by : string }
  | Guarded of { at_line : int }  (** Validated by a guard at this line; clean for sinks after it *)

type taint_record = {
  var_name : string;
  file : string;
  line : int;
  description : string;
  source_var : string;
  field : string option;
  status : taint_status;
}

type t = taint_record list StringMap.t
(** Map from file path → list of taint records for that file *)

let empty : t = StringMap.empty

let is_tainted (db : t) (var : string) : bool =
  StringMap.exists (fun _ records ->
    List.exists (fun r -> r.var_name = var) records
  ) db

let is_tainted_in_file (db : t) (var : string) (file : string) : bool =
  match StringMap.find_opt file db with
  | Some records -> List.exists (fun r -> r.var_name = var) records
  | None -> false

let get_tainted_vars (db : t) : string list =
  let std_list_mem = Stdlib.List.mem in
  let std_list_fold = Stdlib.List.fold_left in
  StringMap.fold (fun _ records acc ->
    std_list_fold (fun acc r -> 
      if std_list_mem r.var_name acc then acc 
      else r.var_name :: acc
    ) acc records
  ) db [] |> List.rev

let get_tainted_vars_in_file (db : t) (file : string) : string list =
  match StringMap.find_opt file db with
  | Some records ->
    List.filter_map (fun r ->
      match r.status with
      | Tainted _ -> Some r.var_name
      | Clean | Sanitized _ | Guarded _ -> None
    ) records
  | None -> []

let add_record (db : t) (record : taint_record) : t =
  let file = record.file in
  let records = match StringMap.find_opt file db with
    | Some rs -> rs
    | None -> []
  in
  (* Don't add duplicate entries for same (var, field) in same file *)
  if List.exists (fun r -> r.var_name = record.var_name && r.field = record.field) records then db
  else StringMap.add file (record :: records) db

let find_record (db : t) (var : string) : taint_record option =
  StringMap.fold (fun _ records acc ->
    match acc with
    | Some _ -> acc
    | None -> List.find_opt (fun r -> r.var_name = var) records
  ) db None

let has_record (db : t) (var : string) : bool =
  is_tainted db var

(** Check if a specific variable is tainted in a specific file. *)
let has_record_in_file (db : t) (var : string) (file : string) : bool =
  is_tainted_in_file db var file

let db_size (db : t) : int =
  StringMap.fold (fun _ records acc -> acc + List.length records) db 0

(** Get all taint records for a variable in a specific file. *)
let get_tainted_records (db : t) (var : string) (file : string) : taint_record list =
  match StringMap.find_opt file db with
  | Some records -> List.filter (fun r -> r.var_name = var) records
  | None -> []

(** Check if a variable is tainted in ANY file (cross-file taint propagation). *)
let is_tainted_anywhere (db : t) (var : string) : bool =
  StringMap.exists (fun _ records ->
    List.exists (fun r -> r.var_name = var) records
  ) db

(** Get all taint records for a variable across ALL files (for cross-file propagation). *)
let get_tainted_records_global (db : t) (var : string) : taint_record list =
  StringMap.fold (fun _ records acc ->
    let filtered = List.filter (fun r -> r.var_name = var) records in
    filtered :: acc
  ) db [] |> List.concat

(** Remove a tainted var from a specific file. Used for guard processing:
    when a guard node validates a variable, it should no longer be tainted
    for sinks at lines after the guard. *)
let remove_record (db : t) (var : string) (file : string) : t =
  match StringMap.find_opt file db with
  | Some records ->
    let filtered = List.filter (fun r -> r.var_name <> var) records in
    if filtered = [] then StringMap.remove file db
    else StringMap.add file filtered db
  | None -> db

(** Remove a tainted var from a specific file for sinks at lines >= guard_line.
    Changes the taint status from Tainted to Guarded, preserving the record for
    sinks at lines before the guard. This allows the record to remain in the DB
    for cross-file analysis while still suppressing findings on post-guard sinks. *)
let apply_guard (db : t) (var : string) (file : string) (guard_line : int) : t =
  match StringMap.find_opt file db with
  | Some records ->
    let updated = List.map (fun r ->
      if r.var_name = var then
        match r.status with
        | Tainted _ -> { r with status = Guarded { at_line = guard_line } }
        | _ -> r
      else r
    ) records in
    StringMap.add file updated db
  | None -> db

(** Shared taint-check: given an Assign node, return the source var name if
    any ArgVar arg is tainted (same-file or global) and none of the args is a
    sanitizer call. *)
let check_assignment_taint (node : Security_node.t) (acc : t) : string option =
  let is_sanitized =
    List.exists (fun a ->
      a.Security_node.arg_type = Security_node.ArgCall
      && Constants.is_sanitizer a.Security_node.value
    ) node.Security_node.args
  in
  if is_sanitized then None
  else
    List.find_opt (fun a ->
      a.Security_node.arg_type = Security_node.ArgVar
      && is_tainted_in_file acc a.Security_node.value node.Security_node.file
    ) node.Security_node.args
    |> Option.map (fun a -> a.Security_node.value)
