(* lib/catseye_claws/shotgun_surgery.ml *)

(** Shotgun Surgery detector.

    Shotgun Surgery is a code smell where a single change requires modifying
    many different classes, indicating poor responsibility encapsulation.
    
    Detection heuristic:
    - Feature Envy: Classes that heavily use methods from specific other classes
    - Tracks calls like Config.get, Logger.info, @logger.info (Class.method or @var.method)
    - If a file makes 5+ calls to the same receiver, it may have behavior
      that should be moved into that class
    
    https://martinfowler.com/bliki/ShotgunSurgery.html
*)

open Catseye_types

(* ── Config thresholds ─────────────────────────────────────────────── *)

let default_envy_threshold = 5   (* 5+ calls to same class = potential envy *)

(* Exempt patterns for helper/facade classes and logging APIs *)
let exempt_class_patterns = [
  "Dispatcher";
  "Router";
  "Facade";
  "Adapter";
  "Proxy";
  "Builder";
  "Log";      (* Logging API — calling Log.info/Log.error frequently is correct *)
  "Logger";   (* Same for Logger variants *)
  "Time";     (* Time is core stdlib — scheduling/expiry/rate-limiting naturally uses it heavily *)
  "StateStore"; (* Central app state — controllers/services naturally read/write frequently *)
]

(* ── Helpers ───────────────────────────────────────────────────────── *)

let contains (str : string) (sub : string) : bool =
  let rec loop i =
    if i > String.length str - String.length sub then false
    else if String.sub str i (String.length sub) = sub then true
    else loop (i + 1)
  in
  loop 0

let is_exempt_class (class_name : string) : bool =
  List.exists (fun pattern -> contains class_name pattern) exempt_class_patterns

(* Extract class name from a call like "Config.get" -> "Config" or "@logger.info" -> "Logger" *)
(* Only extracts if it looks like a class name (PascalCase) *)
let rec extract_class_name (call_name : string) : string option =
  if contains call_name "." then
    (try
      let receiver = String.sub call_name 0 (String.index call_name '.') in
      let class_name = 
        if String.length receiver > 0 && receiver.[0] = '@' then
          String.sub receiver 1 (String.length receiver - 1)
        else
          receiver
      in
      (* Skip special variables *)
      if String.length class_name > 0 && class_name.[0] = '$' then None
      (* Skip common local variable names (camelCase/snake_case) - check FIRST! *)
      else if is_common_local_var class_name then None
      (* Only return if it looks like a class name (PascalCase, 3+ chars) *)
      else if String.length class_name >= 3 && class_name.[0] >= 'A' && class_name.[0] <= 'Z' && not (contains class_name "_") then Some class_name
      else None
    with Not_found -> None)
  else
    None

(* Check if name looks like a class name (PascalCase, not camelCase or snake_case) *)
and looks_like_class_name (name : string) : bool =
  if String.length name < 3 then false
  else
    let first_char = name.[0] in
    (* Must start with uppercase letter to be a class *)
    if not (first_char >= 'A' && first_char <= 'Z') then false
    else
      (* Must not have underscores (snake_case is variable, not class) *)
      not (contains name "_")

(* Skip common local variable names that are NOT class names *)
(* These are typically camelCase or snake_case local/instance variables *)
and is_common_local_var (name : string) : bool =
  let lower = String.lowercase_ascii name in
  List.exists (fun p -> lower = p) [
    (* Local variables *)
    "response"; "result"; "data"; "value"; "item"; "node"; "map";
    "cmd"; "request"; "hash"; "array"; "list"; "set"; "uri"; "url";
    "err"; "error"; "entries"; "links"; "parser"; "builder";
    (* Instance variables (typically lowercase) *)
    "logger"; "config"; "client"; "store"; "validator"; "reader"; "writer"; "factory";
    "cache"; "connection"; "session"; "user"; "message"; "event"; "handler";
    "service"; "repo"; "repository"; "adapter"; "resolver"; "fetcher";
    (* Methods/properties that are often local *)
    "success"; "failure"; "content"; "body"; "header"; "headers";
    "title"; "author"; "url"; "categories"; "attachments";
  ]

(* ── Feature Envy Detection ───────────────────────────────────────── *)

type envy_target = {
  receiver : string;
  call_count : int;
  locations : (string * int) list;
}

(* Detect classes that heavily use methods from specific other classes *)
let detect_feature_envy (nodes : Security_node.t list) : envy_target list =
  let receiver_calls = Hashtbl.create 16 in
  
  (* Track calls by file and receiver *)
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then
      let name = n.Security_node.name in
      let extracted = extract_class_name name in
      (match extracted with
       | Some r ->
           if String.length r >= 3 then
             (try
               let _ = String.index name '.' in
               let key = n.Security_node.file ^ "|" ^ r in
               let existing = try Hashtbl.find receiver_calls key with Not_found -> ([], 0) in
               let (locs, count) = existing in
               let new_locs = (n.Security_node.file, n.Security_node.line) :: locs in
               Hashtbl.replace receiver_calls key (new_locs, count + 1)
             with Not_found -> ())
       | None -> ())
  ) nodes;
  
  Printf.eprintf "[Shotgun] Total entries in table: %d\n" (Hashtbl.length receiver_calls);
  
  (* Filter to only high-call receivers that are within a class *)
  let result = ref [] in
  Hashtbl.iter (fun key (locs, count) ->
    if count >= default_envy_threshold then
      match String.split_on_char '|' key with
      | [file; receiver] ->
          (* Check if this file contains a class definition *)
          let has_class = List.exists (fun n ->
            n.Security_node.node_type = Security_node.Class 
            && n.Security_node.file = file
          ) nodes in
          if has_class && not (is_exempt_class receiver) then
            result := { receiver; call_count = count; locations = locs } :: !result
      | _ -> ()
  ) receiver_calls;
  
  !result

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.large_class_enabled then [] else
    let feature_envy = detect_feature_envy nodes in
    List.filter_map (fun target ->
      let file = 
        match target.locations with
        | [] -> ""
        | (f, _) :: _ -> f
      in
      let line = 
        match target.locations with
        | [] -> 1
        | (_, l) :: _ -> l
      in
      Some {
        Finding.rule = "ShotgunSurgery";
        severity = "Medium";
        file;
        line;
        message = Printf.sprintf
          "Feature Envy: '%s' calls '%s' %d times. This behavior may belong in '%s', not here. Consider moving these methods or using composition/refactoring."
          file target.receiver target.call_count target.receiver;
        flow = [ {
          Finding.file;
          line;
          message = Printf.sprintf "File '%s' makes %d calls to '%s'" file target.call_count target.receiver;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    ) feature_envy