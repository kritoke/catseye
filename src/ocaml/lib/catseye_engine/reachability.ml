(* lib/catseye_engine/reachability.ml
   Predator Vision — lightweight reachability analysis.

   Builds a call adjacency map from Security_node Def/Call scopes,
   detects entry points (HTTP handlers, CLI mains), then BFS from
   each entry point to determine which functions are reachable.

   Findings in reachable functions are "Live", others are "Dormant". *)

open Catseye_types

module StringMap = Map.Make(String)
module StringSet = Set.Make(String)

(* ── Types ──────────────────────────────────────────────────────────── *)

type entry_point_kind =
  | Http
  | Cli
  | Test
  | Custom

type entry_point = {
  function_name : string;
  file : string;
  line : int;
  kind : entry_point_kind;
}

(** Call adjacency: function_name → [(called_name, file, line)] *)
type call_adjacency = (string * string * int) list StringMap.t

(** Function scope: maps a function name to its file and line *)
type func_scope = {
  file : string;
  line : int;
}

(** Reachability result for a single finding *)
type reachability = {
  status : [ `Live | `Dormant | `Safe ];
  entry_point : string option;
  entry_function : string option;
  path_length : int;
  path : (string * int) list;  (* [(file, line), ...] *)
}

(* ── Known entry point patterns ─────────────────────────────────────── *)

let http_param_patterns = [
  "params"; "request"; "req"; "context"; "ctx"; "conn";
  "HTTP::Request"; "HTTP::Server::Context"; "HTTP::Params";
  "get_body"; "query";
]

let http_function_patterns = [
  "handle_"; "get_"; "post_"; "put_"; "delete_"; "patch_";
  "index"; "show"; "create"; "update"; "destroy";
]

let cli_function_names = [
  "main"; "run"; "cli"; "execute";
]

let cli_param_patterns = [
  "ARGV"; "STDIN"; "gets"; "args"; "env";
]

(* ── Scope detection ────────────────────────────────────────────────── *)

(** Build a map from function name → scope info, and group nodes by
    their enclosing function scope. Uses line-range heuristic:
    a Def at line L owns all subsequent nodes until the next Def in the
    same file. *)
type scope_info = {
  func_name : string;
  file : string;
  start_line : int;
  end_line : int;  (* exclusive: start_line of next Def, or max_int *)
}

(** Build scope list per file, then map each node to its enclosing scope. *)
let build_scopes (nodes : Security_node.t list) : scope_info list =
  let file_defs = Hashtbl.create 16 in
  (* Collect Def nodes grouped by file *)
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Def then begin
      let file = n.Security_node.file in
      let defs = try Hashtbl.find file_defs file with Not_found -> [] in
      Hashtbl.replace file_defs file
        ({ func_name = n.Security_node.name; file; start_line = n.Security_node.line; end_line = max_int } :: defs)
    end
  ) nodes;
  (* Sort each file's defs by line, set end_line to next def's start_line *)
  let all_scopes = ref [] in
  Hashtbl.iter (fun _file defs ->
    let sorted = List.sort (fun a b -> compare a.start_line b.start_line) defs in
    let rec set_ends prev = function
      | [] -> ()
      | [last] ->
        all_scopes := { last with end_line = max_int } :: !all_scopes
      | cur :: ((next :: _) as rest) ->
        all_scopes := { cur with end_line = next.start_line } :: !all_scopes;
        set_ends (Some cur) rest
    in
    set_ends None sorted
  ) file_defs;
  !all_scopes

(** Find which function scope contains a given file:line *)
let find_scope (scopes : scope_info list) (file : string) (line : int)
    : scope_info option =
  List.find_opt (fun s ->
    s.file = file && line >= s.start_line && line < s.end_line
  ) scopes

(* ── Call adjacency ─────────────────────────────────────────────────── *)

(** Build call adjacency: for each Call node, add an edge from its
    enclosing function to the called function. *)
let build_call_adjacency (nodes : Security_node.t list)
    (scopes : scope_info list) : call_adjacency =
  let adj = ref StringMap.empty in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then begin
      match find_scope scopes n.Security_node.file n.Security_node.line with
      | Some scope ->
        let key = scope.func_name in
        let edges = try StringMap.find key !adj with Not_found -> [] in
        let edge = (n.Security_node.name, n.Security_node.file, n.Security_node.line) in
        (* Avoid duplicate edges *)
        if not (List.exists (fun (name, _, _) -> name = n.Security_node.name) edges) then
          adj := StringMap.add key (edge :: edges) !adj
      | None -> ()
    end
  ) nodes;
  !adj

(* ── Entry point detection ──────────────────────────────────────────── *)

(** Detect entry points from Def nodes and their arguments. *)
let detect_entry_points (nodes : Security_node.t list)
    (custom_patterns : string list) : entry_point list =
  let results = ref [] in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Def then begin
      let name = n.Security_node.name in
      let args = n.Security_node.args in
      let file = n.Security_node.file in
      let line = n.Security_node.line in

      (* Check HTTP handler patterns *)
      let is_http =
        List.exists (fun a ->
          List.exists (fun p ->
            String.length a.Security_node.value >= String.length p
            && String.sub a.Security_node.value 0 (String.length p) = p
          ) http_param_patterns
        ) args
        || List.exists (fun p ->
          String.length name >= String.length p
          && String.sub name 0 (String.length p) = p
        ) http_function_patterns
      in

      (* Check CLI patterns *)
      let is_cli =
        List.mem name cli_function_names
        || List.exists (fun a ->
          List.exists (fun p -> a.Security_node.value = p) cli_param_patterns
        ) args
      in

      (* Check custom patterns *)
      let is_custom =
        List.exists (fun p ->
          String.length name >= String.length p
          && String.sub name 0 (String.length p) = p
        ) custom_patterns
      in

      let kind =
        if is_http then (Some Http)
        else if is_cli then (Some Cli)
        else if is_custom then (Some Custom)
        else None
      in

      match kind with
      | Some k ->
        results := { function_name = name; file; line; kind = k } :: !results
      | None -> ()
    end
  ) nodes;
  List.rev !results

(* ── BFS reachability ───────────────────────────────────────────────── *)

(** BFS from entry points through call adjacency.
    Returns set of reachable function names. *)
let reachable_from (entries : entry_point list) (adj : call_adjacency)
    : StringSet.t =
  let visited = ref StringSet.empty in
  let queue = Queue.create () in
  List.iter (fun e ->
    if not (StringSet.mem e.function_name !visited) then begin
      StringSet.add e.function_name !visited |> ( := ) visited;
      Queue.push e.function_name queue
    end
  ) entries;
  while not (Queue.is_empty queue) do
    let current = Queue.pop queue in
    (match StringMap.find_opt current adj with
     | Some edges ->
       List.iter (fun (called, _, _) ->
         if not (StringSet.mem called !visited) then begin
           StringSet.add called !visited |> ( := ) visited;
           Queue.push called queue
         end
       ) edges
     | None -> ())
  done;
  !visited

(* ── Path tracing ───────────────────────────────────────────────────── *)

(** Trace the shortest call path from an entry point to a target function.
    Returns the path as [(file, line), ...] or [] if unreachable. *)
let trace_path (entries : entry_point list) (adj : call_adjacency)
    (target : string) : (entry_point * (string * int) list) option =
  (* BFS with parent tracking *)
  let parent = Hashtbl.create 32 in
  let visited = Hashtbl.create 32 in
  let queue = Queue.create () in
  List.iter (fun e ->
    if not (Hashtbl.mem visited e.function_name) then begin
      Hashtbl.replace visited e.function_name true;
      Hashtbl.add parent e.function_name None;
      Queue.push e.function_name queue
    end
  ) entries;
  let found = ref None in
  while not (Queue.is_empty queue) && !found = None do
    let current = Queue.pop queue in
    if current = target then
      found := Some current
    else
      (match StringMap.find_opt current adj with
       | Some edges ->
         List.iter (fun (called, _f, _l) ->
           if not (Hashtbl.mem visited called) then begin
             Hashtbl.replace visited called true;
             Hashtbl.add parent called (Some (current, called));
             Queue.push called queue
           end
         ) edges
       | None -> ())
  done;
  match !found with
  | None -> None
  | Some _target ->
    (* Reconstruct path *)
    let path = ref [] in
    let rec walk name =
      match Hashtbl.find_opt parent name with
      | None -> () (* entry point reached *)
      | Some None -> ()
      | Some (Some (parent_name, _child)) ->
        (* Find the edge for file/line info *)
        (match StringMap.find_opt parent_name adj with
         | Some edges ->
           (match List.find_opt (fun (n, _, _) -> n = name) edges with
            | Some (_, f, l) -> path := (f, l) :: !path
            | None -> ())
         | None -> ());
        walk parent_name
    in
    walk target;
    (* Find which entry point we started from *)
    let rec find_entry name =
      match Hashtbl.find_opt parent name with
      | None | Some None ->
        List.find (fun e -> e.function_name = name) entries
      | Some (Some (parent_name, _)) ->
        find_entry parent_name
    in
    let entry = find_entry target in
    Some (entry, !path)

(* ── Main analysis ──────────────────────────────────────────────────── *)

(** Build reachability info for a list of findings.
    Returns a list of (finding_index, reachability) pairs. *)
let analyze (nodes : Security_node.t list)
    (findings : Finding.t list)
    ~(custom_patterns : string list)
    : reachability list =
  let scopes = build_scopes nodes in
  let adj = build_call_adjacency nodes scopes in
  let entries = detect_entry_points nodes custom_patterns in

  if entries = [] then
    (* No entry points found → everything is "Dormant" by default *)
    List.map (fun _ -> {
      status = `Dormant;
      entry_point = None;
      entry_function = None;
      path_length = 0;
      path = [];
    }) findings
  else begin
    let reachable = reachable_from entries adj in
    List.map (fun f ->
      let scope = find_scope scopes f.Finding.file f.Finding.line in
      match scope with
      | None ->
        { status = `Dormant; entry_point = None;
          entry_function = None; path_length = 0; path = [] }
      | Some s ->
        if StringSet.mem s.func_name reachable then begin
          match trace_path entries adj s.func_name with
          | Some (entry, path) ->
            { status = `Live;
              entry_point = Some (Printf.sprintf "%s:%d" entry.file entry.line);
              entry_function = Some entry.function_name;
              path_length = List.length path + 1;
              path = (entry.file, entry.line) :: path }
          | None ->
            { status = `Live;
              entry_point = None;
              entry_function = None;
              path_length = 0;
              path = [] }
        end
        else
          { status = `Dormant; entry_point = None;
            entry_function = None; path_length = 0; path = [] }
    ) findings
  end
