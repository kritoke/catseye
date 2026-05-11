(* lib/catseye_crowsnest/aggregator.ml
   Merges OSV results + staleness scores into per-dependency audit results.
   This is the main entry point for the Crow's Nest analysis. *)

open Manifest
open Osv
open Staleness

type dep_result = {
  name : string;
  version : string option;
  ecosystem : string;
  source_file : string;         (* which manifest declared this dep *)
  osv : osv_result;
  staleness : staleness option;
  level : [ `Hiss | `Meow | `Purr ];
}

let level_of_osv = function
  | Vulnerabilities vulns ->
    if List.exists (fun v ->
      match v.severity with
      | Some s when
          String.length s >= 4 &&
          (String.sub s 0 4 = "CRIT" || String.sub s 0 4 = "HIGH")
        -> true
      | Some s when
          String.length s >= 4 &&
          String.sub s 0 4 = "MOD" || s = "HIGH" || s = "CRITICAL"
        -> true
      | _ -> false
    ) vulns then `Hiss
    else `Meow
  | No_known_cves -> `Purr
  | Query_failed _ -> `Purr  (* don't penalize for network failures *)

(* Merge OSV level and staleness level — take the worse one *)
let merge_levels (osv_level : [> `Hiss | `Meow | `Purr ])
    (staleness_level : [> `Hiss | `Meow | `Purr ] option)
    : [ `Hiss | `Meow | `Purr ] =
  match staleness_level with
  | None -> osv_level
  | Some sl ->
    match (osv_level, sl) with
    | (`Hiss, _) | (_, `Hiss) -> `Hiss
    | (`Meow, _) | (_, `Meow) -> `Meow
    | (`Purr, `Purr) -> `Purr

(** Run the full Crow's Nest analysis on discovered manifests.
    Returns per-dependency results sorted by severity (worst first). *)
let audit (manifests : manifest list) ?(cache : Cache.t option) ()
    : dep_result list =
  let results = ref [] in

  List.iter (fun m ->
    match m with
    | Shard_yml (path, deps) ->
      List.iter (fun (dep : Manifest.shard_dep) ->
        let version = match dep.version with
          | Some v -> v
          | None -> "*"
        in
        (* Check cache *)
        let cached_osv = match cache with
          | Some c -> Cache.lookup_osv c "crystal-shards" dep.name version
          | None -> None
        in
        let osv_result = match cached_osv with
          | Some json -> Osv.parse_osv_response json
          | None ->
            let r = Osv.query "crystal-shards" dep.name version in
            (* Cache the raw response *)
            (match cache, r with
             | Some c, (Vulnerabilities _ | No_known_cves) ->
               (* Store a synthetic response for caching *)
               let json = Printf.sprintf
                 {|{"_osv_status":"%s"}|}
                 (match r with
                  | No_known_cves -> "clean"
                  | Vulnerabilities _ -> "has_vulns"
                  | Query_failed _ -> "failed")
               in
               Cache.store_osv c "crystal-shards" dep.name version json
             | _ -> ());
            r
        in

        (* Staleness check via GitHub *)
        let staleness_result = match dep.github with
          | Some repo ->
            let cached = match cache with
              | Some c -> Cache.lookup_staleness c "github" dep.name
              | None -> None
            in
            (match cached with
             | Some (score, signals, level) ->
               Some { Staleness.score; signals; level = (match level with
                 | "hiss" -> `Hiss | "meow" -> `Meow | _ -> `Purr) }
             | None ->
               let repo_activity = Staleness.query_github repo in
               let s = Staleness.compute_staleness
                 ?repo:repo_activity () in
               (match cache with
                | Some c ->
                  let level_str = match s.level with
                    | `Hiss -> "hiss" | `Meow -> "meow" | `Purr -> "purr"
                  in
                  Cache.store_staleness c "github" dep.name
                    s.score s.signals level_str
                | None -> ());
               Some s)
          | None -> None
        in

        let osv_level = level_of_osv osv_result in
        let level = merge_levels osv_level (Option.map (fun s -> s.Staleness.level) staleness_result) in
        results := {
          name = dep.name;
          version = dep.version;
          ecosystem = "crystal-shards";
          source_file = path;
          osv = osv_result;
          staleness = staleness_result;
          level;
        } :: !results
      ) deps

    | Gleam_toml (path, deps) ->
      List.iter (fun (dep : Manifest.hex_dep) ->
        let version = match dep.version with
          | Some v -> v
          | None -> "*"
        in
        let cached_osv = match cache with
          | Some c -> Cache.lookup_osv c "hex" dep.name version
          | None -> None
        in
        let osv_result = match cached_osv with
          | Some json -> Osv.parse_osv_response json
          | None ->
            let r = Osv.query "hex" dep.name version in
            (match cache with
             | Some _c -> ()
             | None -> ());
            r
        in

        (* Staleness check via Hex API *)
        let hex_info = Staleness.query_hex dep.name in
        let staleness_result = Some (Staleness.compute_staleness
          ?hex:hex_info ()) in

        let osv_level = level_of_osv osv_result in
        let level = merge_levels osv_level (Option.map (fun s -> s.Staleness.level) staleness_result) in
        results := {
          name = dep.name;
          version = dep.version;
          ecosystem = "hex";
          source_file = path;
          osv = osv_result;
          staleness = staleness_result;
          level;
        } :: !results
      ) deps
  ) manifests;

  (* Sort: Hiss first, then Meow, then Purr *)
  let level_rank = function `Hiss -> 0 | `Meow -> 1 | `Purr -> 2 in
  List.sort (fun a b -> compare (level_rank a.level) (level_rank b.level)) !results
