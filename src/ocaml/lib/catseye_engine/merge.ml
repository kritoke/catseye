(* lib/catseye_engine/merge.ml *)

open Base
open Db

(* Shadow string equality - Base makes = polymorphic *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(* Merge two TaintDBs: union of records per file *)
let merge_db (a : Db.t) (b : Db.t) : Db.t =
  Db.StringMap.fold (fun file records_b acc ->
    let records_a = match Db.StringMap.find_opt file acc with
      | Some rs -> rs
      | None -> []
    in
    (* Add records from b that don't already exist in a *)
    let new_records = Stdlib.List.filter (fun rb ->
      not (Stdlib.List.exists (fun ra -> ra.var_name = rb.var_name) records_a)
    ) records_b in
    Db.StringMap.add file (new_records @ records_a) acc
  ) b a
