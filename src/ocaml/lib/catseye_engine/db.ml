(* lib/catseye_engine/db.ml *)

open Base
open Catseye_types
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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

(* Use Map.Poly.t for polymorphic maps (uses physical comparison based on =) *)
type t = (string, taint_record list) Map.Poly.t
(** Map from file path → list of taint records for that file *)

let empty : t = Map.Poly.empty

let is_tainted (db : t) (var : string) : bool =
  Map.Poly.exists db ~f:(fun records ->
    List.exists ~f:(fun r -> r.var_name = var) records
  )

let is_tainted_in_file (db : t) (var : string) (file : string) : bool =
  match Map.Poly.find db file with
  | Some records -> List.exists ~f:(fun r -> r.var_name = var) records
  | None -> false

let get_tainted_vars (db : t) : string list =
  Map.Poly.fold db ~init:[] ~f:(fun ~key:_ ~data:records acc ->
    List.fold_left ~init:acc ~f:(fun acc r ->
      if List.mem acc ~equal:String.equal r.var_name then acc
      else r.var_name :: acc
    ) records
  ) |> List.rev

let get_tainted_vars_in_file (db : t) (file : string) : string list =
  match Map.Poly.find db file with
  | Some records ->
    List.filter_map ~f:(fun r ->
      match r.status with
      | Tainted _ -> Some r.var_name
      | Clean | Sanitized _ | Guarded _ -> None
    ) records
  | None -> []

let add_record (db : t) (record : taint_record) : t =
  let file = record.file in
  let records = match Map.Poly.find db file with
    | Some rs -> rs
    | None -> []
  in
  (* Don't add duplicate entries for same (var, field) in same file *)
  if List.exists ~f:(fun r -> r.var_name = record.var_name && r.field = record.field) records then db
  else Map.Poly.set db ~key:file ~data:(record :: records)

let find_record (db : t) (var : string) : taint_record option =
  Map.Poly.fold db ~init:None ~f:(fun ~key:_ ~data:records acc ->
    match acc with
    | Some _ -> acc
    | None -> List.find ~f:(fun r -> r.var_name = var) records
  )

let has_record (db : t) (var : string) : bool =
  is_tainted db var

(** Check if a specific variable is tainted in a specific file. *)
let has_record_in_file (db : t) (var : string) (file : string) : bool =
  is_tainted_in_file db var file

let db_size (db : t) : int =
  Map.Poly.fold db ~init:0 ~f:(fun ~key:_ ~data:records acc -> acc + List.length records)

(** Get all taint records for a variable in a specific file. *)
let get_tainted_records (db : t) (var : string) (file : string) : taint_record list =
  match Map.Poly.find db file with
  | Some records -> List.filter ~f:(fun r -> r.var_name = var) records
  | None -> []

(** Check if a variable is tainted in ANY file (cross-file taint propagation). *)
let is_tainted_anywhere = is_tainted

(** Get all taint records for a variable across ALL files (for cross-file propagation). *)
let get_tainted_records_global (db : t) (var : string) : taint_record list =
  Map.Poly.fold db ~init:[] ~f:(fun ~key:_ ~data:records acc ->
    let filtered = List.filter ~f:(fun r -> r.var_name = var) records in
    filtered :: acc
  ) |> List.concat

(** Remove a tainted var from a specific file. Used for guard processing:
    when a guard node validates a variable, it should no longer be tainted
    for sinks at lines after the guard. *)
let remove_record (db : t) (var : string) (file : string) : t =
  match Map.Poly.find db file with
  | Some records ->
    let filtered = List.filter ~f:(fun r -> r.var_name <> var) records in
    if filtered = [] then Map.Poly.remove db file
    else Map.Poly.set db ~key:file ~data:filtered
  | None -> db

(** Remove a tainted var from a specific file for sinks at lines >= guard_line.
    Changes the taint status from Tainted to Guarded, preserving the record for
    sinks at lines before the guard. This allows the record to remain in the DB
    for cross-file analysis while still suppressing findings on post-guard sinks. *)
let apply_guard (db : t) (var : string) (file : string) (guard_line : int) : t =
  match Map.Poly.find db file with
  | Some records ->
    let updated = List.map ~f:(fun r ->
      if r.var_name = var then
        match r.status with
        | Tainted _ -> { r with status = Guarded { at_line = guard_line } }
        | _ -> r
      else r
    ) records in
    Map.Poly.set db ~key:file ~data:updated
  | None -> db

(** Shared taint-check: given an Assign node, return the source var name if
    any ArgVar arg is tainted (same-file or global) and none of the args is a
    sanitizer call. *)
let check_assignment_taint (node : Security_node.t) (acc : t) : string option =
  let is_sanitized =
    List.exists ~f:(fun a ->
      a.Security_node.arg_type = Security_node.ArgCall
      && Constants.is_sanitizer a.Security_node.value
    ) node.Security_node.args
  in
  if is_sanitized then None
  else
    List.find ~f:(fun a ->
      a.Security_node.arg_type = Security_node.ArgVar
      && is_tainted_in_file acc a.Security_node.value node.Security_node.file
    ) node.Security_node.args
    |> Option.map ~f:(fun a -> a.Security_node.value)