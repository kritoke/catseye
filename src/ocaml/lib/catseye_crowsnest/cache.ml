(* lib/catseye_crowsnest/cache.ml
   SQLite-backed cache for OSV query results and staleness data.
   Stores results keyed by ecosystem:package:version with a TTL. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

type t = {
  db : Sqlite3.db;
  ttl : float;  (* seconds *)
}

let default_ttl = 86400.0 (* 24 hours *)

let open_db ?(ttl = default_ttl) (path : string) : t =
  (* Ensure parent directory exists *)
  let dir = Stdlib.Filename.dirname path in
  let rec mkdir_p d =
    if not (Stdlib.Sys.file_exists d) then begin
      mkdir_p (Stdlib.Filename.dirname d);
      Unix.mkdir d 0o755
    end
  in
  mkdir_p dir;
  let db = Sqlite3.db_open path in
  (* Create tables if they don't exist *)
  let _ = Sqlite3.exec db "CREATE TABLE IF NOT EXISTS osv_cache (\
    \n  key TEXT PRIMARY KEY,\
    \n  response_json TEXT NOT NULL,\
    \n  queried_at REAL NOT NULL)" in
  let _ = Sqlite3.exec db "CREATE TABLE IF NOT EXISTS staleness_cache (\
    \n  key TEXT PRIMARY KEY,\
    \n  score INT NOT NULL,\
    \n  signals_json TEXT NOT NULL,\
    \n  level TEXT NOT NULL,\
    \n  queried_at REAL NOT NULL)" in
  { db; ttl }

let close (t : t) = ignore (Sqlite3.db_close t.db)

(* ── Helpers ────────────────────────────────────────────────────────── *)

let exec_bind stmt params =
  List.iteri ~f:(fun i p ->
    Sqlite3.bind stmt (i + 1) p |> ignore
  ) params;
  let _ = Sqlite3.step stmt in
  ignore (Sqlite3.finalize stmt)

(* ── OSV cache ──────────────────────────────────────────────────────── *)

let osv_key (ecosystem : string) (package : string) (version : string) : string =
  Printf.sprintf "%s:%s:%s" ecosystem package version

let lookup_osv (t : t) (ecosystem : string) (package : string) (version : string)
    : string option =
  let key = osv_key ecosystem package version in
  let sql = "SELECT response_json, queried_at FROM osv_cache WHERE key = ?1" in
  let stmt = Sqlite3.prepare t.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT key) |> ignore;
  let result = match Sqlite3.step stmt with
    | Sqlite3.Rc.ROW ->
      (match (Sqlite3.column stmt 0, Sqlite3.column stmt 1) with
       | Sqlite3.Data.TEXT json, Sqlite3.Data.FLOAT queried_at ->
         let age = Unix.time () -. queried_at in
         if age < t.ttl then Some json
         else None
       | _ -> None)
    | _ -> None
  in
  ignore (Sqlite3.finalize stmt);
  result

let store_osv (t : t) (ecosystem : string) (package : string) (version : string)
    (response_json : string) : unit =
  let key = osv_key ecosystem package version in
  let sql = "INSERT OR REPLACE INTO osv_cache (key, response_json, queried_at) VALUES (?1, ?2, ?3)" in
  let stmt = Sqlite3.prepare t.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT key) |> ignore;
  Sqlite3.bind stmt 2 (Sqlite3.Data.TEXT response_json) |> ignore;
  Sqlite3.bind stmt 3 (Sqlite3.Data.FLOAT (Unix.time ())) |> ignore;
  let _ = Sqlite3.step stmt in
  ignore (Sqlite3.finalize stmt)

(* ── Staleness cache ────────────────────────────────────────────────── *)

let staleness_key (source : string) (package : string) : string =
  Printf.sprintf "staleness:%s:%s" source package

let lookup_staleness (t : t) (source : string) (package : string)
    : (int * string list * string) option =
  let key = staleness_key source package in
  let sql = "SELECT score, signals_json, level, queried_at FROM staleness_cache WHERE key = ?1" in
  let stmt = Sqlite3.prepare t.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT key) |> ignore;
  let result = match Sqlite3.step stmt with
    | Sqlite3.Rc.ROW ->
      (match (Sqlite3.column stmt 0, Sqlite3.column stmt 1,
              Sqlite3.column stmt 2, Sqlite3.column stmt 3) with
       | Sqlite3.Data.INT score, Sqlite3.Data.TEXT signals_json,
         Sqlite3.Data.TEXT level, Sqlite3.Data.FLOAT queried_at ->
         let age = Unix.time () -. queried_at in
         if age < t.ttl then begin
           let signals =
             try
let json = Yojson.Safe.from_string signals_json in
                Yojson.Safe.Util.to_list json
                |> List.map ~f:Yojson.Safe.Util.to_string
             with _ -> []
           in
           Some (Stdlib.Int64.to_int score, signals, level)
         end
         else None
       | _ -> None)
    | _ -> None
  in
  ignore (Sqlite3.finalize stmt);
  result

let store_staleness (t : t) (source : string) (package : string)
    (score : int) (signals : string list) (level : string) : unit =
  let key = staleness_key source package in
  let signals_json = Yojson.Safe.to_string
    (`List (List.map ~f:(fun s -> `String s) signals))
  in
  let sql = "INSERT OR REPLACE INTO staleness_cache (key, score, signals_json, level, queried_at) VALUES (?1, ?2, ?3, ?4, ?5)" in
  let stmt = Sqlite3.prepare t.db sql in
  Sqlite3.bind stmt 1 (Sqlite3.Data.TEXT key) |> ignore;
  Sqlite3.bind stmt 2 (Sqlite3.Data.INT (Int64.of_int score)) |> ignore;
  Sqlite3.bind stmt 3 (Sqlite3.Data.TEXT signals_json) |> ignore;
  Sqlite3.bind stmt 4 (Sqlite3.Data.TEXT level) |> ignore;
  Sqlite3.bind stmt 5 (Sqlite3.Data.FLOAT (Unix.time ())) |> ignore;
  let _ = Sqlite3.step stmt in
  ignore (Sqlite3.finalize stmt)
