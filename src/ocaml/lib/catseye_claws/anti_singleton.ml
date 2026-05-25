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

open Catseye_types

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
  let lower = String.lowercase name in
  List.exists (fun suffix ->
    let slen = String.length suffix in
    String.length lower >= slen
    let suffix = String.sub lower ~pos:(String.length lower - slen) ~len:slen in
    suffix = suffix
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
  let lower = String.lowercase name in
  List.exists (fun exempt ->
    (* Exact match *)
    exempt = lower ||
    (* Ends with _cache or has _cache suffix (e.g., @@user_cache, @@_cache) *)
    (String.length exempt < String.length lower &&
     let suffix = String.sub lower ~pos:(String.length lower - String.length exempt) ~len:(String.length exempt) in
     suffix = exempt)
  ) exempt_class_var_names

(** Check if a string contains a substring *)
let contains (str : string) (sub : string) : bool =
  let slen = String.length str in
  let slen_sub = String.length sub in
  if slen_sub > slen then false
  else
    let rec check i =
      if i > slen - slen_sub then false
      else if String.equal (String.sub str ~pos:i ~len:slen_sub) sub then true
      else check (i + 1)
    in
    check 0

(** Check if a file is a configuration file (exempt from AntiSingleton) *)
let is_config_file (file : string) : bool =
  let lower = String.lowercase file in
  contains lower "/config/" ||
  contains lower "_config.cr" ||
  contains lower "/settings/" ||
  contains lower ".cr.settings"

(** Check if a class is a configuration or settings class *)
let is_config_class (name : string) : bool =
  let lower = String.lowercase name in
  contains lower "config" ||
  contains lower "settings" ||
  contains lower "constants" ||
  contains lower "defaults"

(* ── Detection ────────────────────────────────────────────────────── *)

let check_anti_singleton (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let module StringMap = Map.Make(String) in
  (* Group nodes by file using Map *)
  let by_file = List.fold_left nodes ~init:StringMap.empty ~f:(fun acc (n : Security_node.t) ->
    let existing = match StringMap.find_opt n.Security_node.file acc with
      | Some nodes -> nodes | None -> [] in
    StringMap.add n.Security_node.file (n :: existing) acc
  ) in
  (* Collect findings from each file's class nodes *)
  List.concat_map (StringMap.bindings by_file) ~f:(fun (file, file_nodes) ->
    if is_config_file file then [] else
    let sorted = List.sort file_nodes ~compare:(fun a b -> Int.compare a.Security_node.line b.Security_node.line) in
    let class_nodes = List.filter sorted ~f:(fun n ->
      List.exists [Security_node.Class; Security_node.Module] ~f:(fun nt -> nt = n.Security_node.node_type)
    ) in
    List.concat_map class_nodes ~f:(fun (cn : Security_node.t) ->
      if is_singleton_class cn.Security_node.name then [] else
      let start_line = cn.Security_node.line in
      let end_line = match List.nth class_nodes (List.length class_nodes) with
        | _ when List.length class_nodes = 1 -> max_int
        | _ -> (try (Option.value_exn (List.nth class_nodes 1)).Security_node.line with _ -> max_int)
      in
      let class_var_assigns = List.filter sorted ~f:(fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Assign
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
        && String.length n.Security_node.name >= 2
        && n.Security_node.name.[0] = '@'
        && n.Security_node.name.[1] = '@'
      ) in
      let non_exempt_vars = List.filter class_var_assigns ~f:(fun n ->
        not (is_exempt_class_var n.Security_node.name)
      ) in
      if List.length non_exempt_vars > 0 then
        let class_vars = List.map non_exempt_vars ~f:(fun n -> n.Security_node.name) in
        let msg = String.concat ", " class_vars in
        [{ Finding.rule = "AntiSingleton";
           severity = "Medium";
           file = cn.Security_node.file;
           line = cn.Security_node.line;
           message = Printf.sprintf
             "Class '%s' has mutable class variables: %s. \
             Class variables can be used as global state. Consider using instance variables or dependency injection."
             cn.Security_node.name msg;
           flow = List.map non_exempt_vars ~f:(fun n -> {
             Finding.file = n.Security_node.file;
             line = n.Security_node.line;
             message = Printf.sprintf "Mutable class variable: %s" n.Security_node.name;
           });
           language = cn.Security_node.language;
           dependency = None;
           reachability = None; suggestion = None; }]
      else []
    )
  )

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.anti_singleton_enabled then [] else
    check_anti_singleton nodes config