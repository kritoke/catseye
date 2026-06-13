(* lib/catseye_claws/anti_singleton.ml *)

(** AntiSingleton detector.

    A class that provides mutable class variables (e.g. @@counter = 0)
    which could be used as global variables. This is a Fowler code smell.

    https://martinfowler.com/bliki/AntiSingleton.html

    exemptions:
    - Patterns like @@cache, @@instance_cache, @@_cache (Crystal caching idiom)
    - Files in /config/ or ending in _config.cr (configuration classes)
    - Class variables named @@instance or @@initialized (common Crystal patterns)
*)

open Base
open Catseye_types

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )

(* Alias for using old (non-labeled) List API temporarily *)
module OldList = struct
  let exists = Stdlib.List.exists
  let filter = Stdlib.List.filter
  let map = Stdlib.List.map
  let mapi = Stdlib.List.mapi
  let length = Stdlib.List.length
  let nth = Stdlib.List.nth
  let sort = Stdlib.List.sort
  let fold_left = Stdlib.List.fold_left
  let concat_map = Stdlib.List.concat_map
end

module OldString = struct
  let concat = Stdlib.String.concat
  let length = Stdlib.String.length
end

(* ── Exemptions ──────────────────────────────────────────────────── *)

(** Class variable names that are common Crystal idioms and not true anti-patterns *)
let exempt_class_var_names = [
  "instance";           (* @@instance = something *)
  "initialized";       (* @@initialized = false *)
  "cache";             (* @@cache = Hash.new *)
  "instance_cache";    (* @@instance_cache = {} *)
  "mutex";             (* @@mutex = Mutex.new *)
  "lock";              (* @@lock = Mutex.new *)
]

(** Class names where class variables are idiomatic — application-wide
    singletons that must share state across all instances (connection
    pools, caches, registries, rate limiters). *)
let is_singleton_class (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  List.exists ~f:(fun suffix ->
    let slen = Stdlib.String.length suffix in
    Stdlib.String.length lower >= slen
    && Stdlib.String.sub lower (Stdlib.String.length lower - slen) slen = suffix
  ) [
    "manager";       (* SocketManager, ConnectionManager *)
    "registry";      (* HandlerRegistry *)
    "cache";         (* FaviconCache *)
    "store";         (* StateStore, CleanupStore *)
    "pool";          (* ConnectionPool *)
    "limiter";       (* RateLimiter *)
    "tracker";       (* RequestTracker *)
    "monitor";       (* HealthMonitor *)
    "counter";       (* RequestCounter *)
    "provider";      (* ConfigProvider *)
    "service";       (* FeedService, ContentService — app-wide services *)
    "fetcher";       (* FeedFetcher — singleton workers *)
  ]

(** Check if a class variable name is exempt from AntiSingleton detection *)
let is_exempt_class_var (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  List.exists ~f:(fun exempt ->
    (* Exact match *)
    exempt = lower ||
    (* Ends with _cache or has _cache suffix (e.g., @@user_cache, @@_cache) *)
    (Stdlib.String.length exempt < Stdlib.String.length lower &&
     let suffix = Stdlib.String.sub lower (Stdlib.String.length lower - Stdlib.String.length exempt) (Stdlib.String.length exempt) in
     suffix = exempt)
  ) exempt_class_var_names

(** Check if a file is a configuration file (exempt from AntiSingleton) *)
let is_config_file (file : string) : bool =
  let lower = Stdlib.String.lowercase_ascii file in
  Scope.contains lower "/config/" ||
  Scope.contains lower "_config.cr" ||
  Scope.contains lower "/settings/" ||
  Scope.contains lower ".cr.settings"

(** Check if a class is a configuration or settings class *)
let is_config_class (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  Scope.contains lower "config" ||
  Scope.contains lower "settings" ||
  Scope.contains lower "constants" ||
  Scope.contains lower "defaults"

(* ── Detection ────────────────────────────────────────────────────── *)

let check_anti_singleton (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  (* Group nodes by file using Map.Poly *)
  let by_file = OldList.fold_left (fun acc (n : Security_node.t) ->
    let existing = Map.Poly.find acc n.Security_node.file |> Option.value ~default:[] in
    Map.Poly.set acc ~key:n.Security_node.file ~data:(n :: existing)
  ) Map.Poly.empty nodes in
  (* Collect findings from each file's class nodes *)
  OldList.concat_map (fun (file, file_nodes) ->
    if is_config_file file then [] else
    let sorted = OldList.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    let class_nodes = OldList.filter (fun n ->
      OldList.exists (fun nt -> nt = n.Security_node.node_type) [Security_node.Class; Security_node.Module]
    ) sorted in
    let indexed_class_nodes = OldList.mapi (fun i cn -> (i, cn)) class_nodes in
    OldList.concat_map (fun (i, cn : int * Security_node.t) ->
      if is_singleton_class cn.Security_node.name then [] else
      let start_line = cn.Security_node.line in
      let end_line =
        if i + 1 < OldList.length class_nodes then
          (OldList.nth class_nodes (i + 1)).Security_node.line
        else Stdlib.Int.max_int
      in
      let class_var_assigns = OldList.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Assign
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
        && OldString.length n.Security_node.name >= 2
        && n.Security_node.name.[0] = '@'
        && n.Security_node.name.[1] = '@'
      ) sorted in
      let non_exempt_vars = OldList.filter (fun n ->
        not (is_exempt_class_var n.Security_node.name)
      ) class_var_assigns in
      if OldList.length non_exempt_vars > 0 then
        let class_vars = OldList.map (fun n -> n.Security_node.name) non_exempt_vars in
        let msg = OldString.concat ", " class_vars in
        [{ Finding.rule = "AntiSingleton";
           severity = "Medium";
           file = cn.Security_node.file;
           line = cn.Security_node.line;
           message = Stdlib.Printf.sprintf
             "Class '%s' has mutable class variables: %s. \
             Class variables can be used as global state. Consider using instance variables or dependency injection."
             cn.Security_node.name msg;
           flow = OldList.map (fun n -> {
             Finding.file = n.Security_node.file;
             line = n.Security_node.line;
             message = Stdlib.Printf.sprintf "Mutable class variable: %s" n.Security_node.name;
           }) non_exempt_vars;
           language = cn.Security_node.language;
           dependency = None;
           reachability = None; suggestion = None; }]
      else []
    ) indexed_class_nodes
  ) (Map.Poly.to_alist by_file)

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.anti_singleton_enabled then [] else
    check_anti_singleton nodes config