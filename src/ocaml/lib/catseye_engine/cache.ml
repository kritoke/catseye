(* lib/catseye_engine/cache.ml
   Persistent extraction cache — SQLite-backed.
   Skips re-extraction for unchanged files across runs.
   Falls back to in-memory Hashtbl if SQLite is unavailable. *)

open Base
open Catseye_types
open Security_node
let ( = ) = Stdlib.( = )

(* Cache schema version. Bump when extraction output semantics change:
   new metadata fields (e.g. abstract, has_timeout_config), changed field
   meanings, or JSON schema changes. This invalidates the on-disk cache so
   an upgraded extractor never returns stale nodes from a previous version.
   Version 1 = pre-versioning (bare content hash, no prefix). *)
let cache_schema_version = 2

(** Blake3-inspired fast hash for file content fingerprinting.
    Uses OCaml's Hashtbl.hash — swap for real Blake3 when bindings available.
    Prefixes the schema version so bumping it invalidates stale entries. *)
let fingerprint (content : string) : string =
  Stdlib.Printf.sprintf "v%d:%08x" cache_schema_version (Hashtbl.hash content)

(** Compute fingerprint for a file. *)
let file_hash (path : string) : string =
  try
    let ic = Stdlib.open_in path in
    Stdlib.Fun.protect
      ~finally:(fun () -> Stdlib.close_in ic)
      (fun () ->
         let content = Stdio.In_channel.input_all ic in
         fingerprint content)
  with Sys_error _ -> ""

(* ── SQLite-backed persistent cache ─────────────────────────────────── *)

type db_cache = {
  db : Sqlite3.db;
  dir : string;
}

type t =
  | Sqlite of db_cache
  | Memory of (string, string * Security_node.t list) Stdlib.Hashtbl.t
  | Disabled

(** Create parent directories recursively. *)
let rec mkdir_p d =
    if not (Stdlib.Sys.file_exists d) then begin
    mkdir_p (Stdlib.Filename.dirname d);
    Unix.mkdir d 0o755
  end

(** Open a SQLite-backed cache. Creates the database and schema if needed. *)
let open_sqlite (dir : string) : db_cache =
  mkdir_p dir;
  let db_path = Stdlib.Filename.concat dir "extraction.db" in
  let db = Sqlite3.db_open db_path in
  let _ = Sqlite3.exec db
    "CREATE TABLE IF NOT EXISTS extraction_cache (\
    \n  path TEXT PRIMARY KEY,\
    \n  hash TEXT NOT NULL,\
    \n  nodes_json TEXT NOT NULL,\
    \n  analyzed_at REAL NOT NULL)" in
  let _ = Sqlite3.exec db
    "CREATE INDEX IF NOT EXISTS idx_extraction_hash ON extraction_cache (hash)" in
  { db; dir }

(** Open a cache of the appropriate type.
    - If no_cache is true → Disabled
    - If SQLite opens successfully → Sqlite
    - Otherwise → Memory (fallback)
*)
let open_cache ~no_cache ~cache_dir : t =
  if no_cache then Disabled
  else
    try Sqlite (open_sqlite cache_dir)
    with exn ->
      Logs.warn (fun m -> m "SQLite cache open failed (%s), using in-memory fallback"
        (Stdlib.Printexc.to_string exn));
      Memory (Stdlib.Hashtbl.create 64)

(** Close the cache (flushes SQLite). *)
let close = function
  | Sqlite c -> ignore (Sqlite3.db_close c.db)
  | Memory _ | Disabled -> ()

(** Clear all cached entries. *)
let clear = function
  | Sqlite c ->
    let _ = Sqlite3.exec c.db "DELETE FROM extraction_cache" in
    ()
  | Memory tbl -> Stdlib.Hashtbl.clear tbl
  | Disabled -> ()

(** Delete the cache database file entirely. *)
let delete_cache (cache_dir : string) : unit =
  let db_path = Stdlib.Filename.concat cache_dir "extraction.db" in
  if Stdlib.Sys.file_exists db_path then
    try Stdlib.Sys.remove db_path
    with Sys_error _ -> ()

(* ── Check (cache lookup) ───────────────────────────────────────────── *)

let check_sqlite (c : db_cache) (path : string) : Security_node.t list option =
  let hash = file_hash path in
  let sql = "SELECT nodes_json, hash FROM extraction_cache WHERE path = ?1" in
  let stmt = Sqlite3.prepare c.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT path) |> ignore;
  let result = match Sqlite3.step stmt with
    | Sqlite3.Rc.ROW ->
      (match (Sqlite3.column stmt 0, Sqlite3.column stmt 1) with
       | Sqlite3.Data.TEXT nodes_json, Sqlite3.Data.TEXT stored_hash ->
         if stored_hash = hash then
           try Some (decode_many (Yojson.Safe.from_string nodes_json))
           with _ -> None
         else None
       | _ -> None)
    | _ -> None
  in
  ignore (Sqlite3.finalize stmt);
  result

let check_memory (tbl : (string, string * Security_node.t list) Stdlib.Hashtbl.t) (path : string) : Security_node.t list option =
  let hash = file_hash path in
  match Stdlib.Hashtbl.find_opt tbl path with
  | Some (stored_hash, nodes) when stored_hash = hash -> Some nodes
  | _ -> None

(** Check if a file has a fresh cache entry. Returns cached nodes or None. *)
let check (cache : t) (path : string) : Security_node.t list option =
  match cache with
  | Sqlite c -> check_sqlite c path
  | Memory tbl -> check_memory tbl path
  | Disabled -> None

(* ── Store (cache write) ────────────────────────────────────────────── *)

let store_sqlite (c : db_cache) (path : string) (nodes : Security_node.t list) : unit =
  let hash = file_hash path in
  let nodes_json = Yojson.Safe.to_string (encode_many nodes) in
  let sql = "INSERT OR REPLACE INTO extraction_cache (path, hash, nodes_json, analyzed_at) VALUES (?1, ?2, ?3, ?4)" in
  let stmt = Sqlite3.prepare c.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT path) |> ignore;
  Sqlite3.bind stmt 2 (Sqlite3.Data.TEXT hash) |> ignore;
  Sqlite3.bind stmt 3 (Sqlite3.Data.TEXT nodes_json) |> ignore;
  Sqlite3.bind stmt 4 (Sqlite3.Data.FLOAT (Unix.gettimeofday ())) |> ignore;
  let _ = Sqlite3.step stmt in
  ignore (Sqlite3.finalize stmt)

let store_memory (tbl : (string, string * Security_node.t list) Stdlib.Hashtbl.t) (path : string) (nodes : Security_node.t list) : unit =
  let hash = file_hash path in
  Stdlib.Hashtbl.replace tbl path (hash, nodes)

(** Store extraction results in the cache. *)
let store (cache : t) (path : string) (nodes : Security_node.t list) : unit =
  match cache with
  | Sqlite c -> store_sqlite c path nodes
  | Memory tbl -> store_memory tbl path nodes
  | Disabled -> ()

(* ── Stats ──────────────────────────────────────────────────────────── *)

(** Return (cached_entries, total_db_size_kb) for SQLite, (entries, 0) otherwise. *)
let stats = function
  | Sqlite c ->
    let stmt = Sqlite3.prepare c.db "SELECT COUNT(*) FROM extraction_cache" in
    let count = match Sqlite3.step stmt with
      | Sqlite3.Rc.ROW ->
        (match Sqlite3.column stmt 0 with
         | Sqlite3.Data.INT n -> Option.value (Int64.to_int n) ~default:0
         | _ -> 0)
      | _ -> 0
    in
    ignore (Sqlite3.finalize stmt);
    let db_path = Stdlib.Filename.concat c.dir "extraction.db" in
    let size_kb =
      try (Unix.stat db_path).Unix.st_size / 1024
      with _ -> 0
    in
    (count, size_kb)
  | Memory tbl -> (Stdlib.Hashtbl.length tbl, 0)
  | Disabled -> (0, 0)
