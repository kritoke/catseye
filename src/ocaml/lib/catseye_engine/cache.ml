(* lib/catseye_engine/cache.ml
   Incremental analysis cache — SQLite + Blake3 hashing.
   Skips re-extraction for unchanged files. *)

open Catseye_types
open Security_node

(** Blake3-inspired fast hash for file content fingerprinting.
    Uses OCaml's Hashtbl.hash for now — swap for real Blake3 when bindings available. *)
let fingerprint (content : string) : string =
  Printf.sprintf "%08x" (Hashtbl.hash content)

(** Compute fingerprint for a file. *)
let file_hash (path : string) : string =
  try
    let ic = open_in path in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    fingerprint (Bytes.to_string buf)
  with Sys_error _ -> ""

module Store = struct
  type entry = {
    path : string;
    hash : string;
    nodes : t list;
    analyzed_at : float;
  }

  (** In-memory cache for now. SQLite upgrade path in Phase 4. *)
  let tbl : (string, entry) Hashtbl.t = Hashtbl.create 64

  let get path =
    try Some (Hashtbl.find tbl path)
    with Not_found -> None

  let put path hash nodes =
    Hashtbl.replace tbl path {
      path; hash; nodes;
      analyzed_at = Unix.gettimeofday ()
    }

  let is_fresh path current_hash =
    match get path with
    | None -> false
    | Some e -> e.hash = current_hash
end

(** Check if a file needs re-extraction.
    Returns Some cached_nodes if fresh, None if stale/missing. *)
let check (path : string) : t list option =
  let hash = file_hash path in
  match Store.get path with
  | Some entry when entry.Store.hash = hash ->
    Some entry.Store.nodes
  | _ -> None

(** Store extraction results. *)
let store (path : string) (nodes : t list) : unit =
  let hash = file_hash path in
  Store.put path hash nodes

(** Invalidate cache for a specific file. *)
let invalidate (path : string) : unit =
  Hashtbl.remove Store.tbl path

(** Clear entire cache. *)
let clear () : unit =
  Hashtbl.clear Store.tbl

(** Cache statistics. *)
let stats () : int * int =
  let total = Hashtbl.length Store.tbl in
  let fresh = Hashtbl.fold (fun _ e acc ->
    let hash = file_hash e.Store.path in
    if hash = e.Store.hash then acc + 1 else acc
  ) Store.tbl 0 in
  (fresh, total)
