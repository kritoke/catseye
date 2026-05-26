(* lib/catseye_engine/reachability.ml
   Predator Vision — lightweight reachability analysis.

   Builds a call adjacency map from Security_node Def/Call scopes,
   detects entry points (HTTP handlers, CLI mains), then BFS from
   each entry point to determine which functions are reachable.

   Findings in reachable functions are "Live", others are "Dormant". *)

open Base
open Catseye_types
open Security_node

(* Shadow string comparison - Base makes these polymorphic *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )

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
type call_adjacency = (string, (string * string * int) list) Map.Poly.t

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
let build_scopes (nodes : t list) : scope_info list =
  let file_defs : (string, scope_info list) Map.Poly.t ref = ref Map.Poly.empty in
  (* Collect Def nodes grouped by file *)
  Stdlib.List.iter (fun n ->
    if n.node_type = Def then begin
      let file = n.file in
      let new_scope = { func_name = n.name; file; start_line = n.line; end_line = Stdlib.max_int } in
      let existing = match Map.Poly.find !file_defs file with Some l -> l | None -> [] in
      file_defs := Map.Poly.set !file_defs ~key:file ~data:(new_scope :: existing)
    end
  ) nodes;
  (* Sort each file's defs by line, set end_line to next def's start_line *)
  let all_scopes = ref [] in
  let file_defs_list = Map.Poly.to_alist !file_defs in
  Stdlib.List.iter (fun (_file, defs) ->
    let sorted = Stdlib.List.sort (fun a b -> Int.compare a.start_line b.start_line) defs in
    let rec set_ends = function
      | [] -> ()
      | [last] ->
        all_scopes := { last with end_line = Stdlib.max_int } :: !all_scopes
      | cur :: ((next :: _) as rest) ->
        all_scopes := { cur with end_line = next.start_line } :: !all_scopes;
        set_ends rest
    in
    set_ends sorted
  ) file_defs_list;
  !all_scopes

(** Find which function scope contains a given file:line *)
let find_scope (scopes : scope_info list) (file : string) (line : int)
    : scope_info option =
  Stdlib.List.find_opt (fun s ->
    s.file = file && line >= s.start_line && line < s.end_line
  ) scopes

(* ── Call adjacency ─────────────────────────────────────────────────── *)

(** Build call adjacency: for each Call node, add an edge from its
    enclosing function to the called function. *)
let build_call_adjacency (nodes : Security_node.t list)
    (scopes : scope_info list) : call_adjacency =
  let call_graph = ref Map.Poly.empty in
  Stdlib.List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then begin
      match find_scope scopes n.Security_node.file n.Security_node.line with
      | Some scope ->
        let key = scope.func_name in
        let edges = match Map.Poly.find !call_graph key with Some l -> l | None -> [] in
        let edge = (n.Security_node.name, n.Security_node.file, n.Security_node.line) in
        (* Avoid duplicate edges *)
        if not (Stdlib.List.exists (fun (name, _, _) -> name = n.Security_node.name) edges) then
          call_graph := Map.Poly.set !call_graph ~key ~data:(edge :: edges)
      | None -> ()
    end
  ) nodes;
  !call_graph

(* ── Entry point detection ──────────────────────────────────────────── *)

(** Detect entry points from Def nodes and their arguments. *)
let detect_entry_points (nodes : Security_node.t list)
    (custom_patterns : string list) : entry_point list =
  let results = ref [] in
  Stdlib.List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Def then begin
      let name = n.Security_node.name in
      let args = n.Security_node.args in
      let file = n.Security_node.file in
      let line = n.Security_node.line in

      (* Check HTTP handler patterns *)
      let is_http =
        Stdlib.List.exists (fun a ->
          Stdlib.List.exists (fun p ->
            Stdlib.String.length a.Security_node.value >= Stdlib.String.length p
            && Stdlib.String.sub a.Security_node.value 0 (Stdlib.String.length p) = p
          ) http_param_patterns
        ) args
        || Stdlib.List.exists (fun p ->
          Stdlib.String.length name >= Stdlib.String.length p
          && Stdlib.String.sub name 0 (Stdlib.String.length p) = p
        ) http_function_patterns
      in

(* Check CLI patterns - use explicit comparison to avoid Base conflict *)
      let is_cli =
        Stdlib.List.exists (fun p -> p = name) cli_function_names
        || Stdlib.List.exists (fun a ->
          Stdlib.List.exists (fun p -> a.Security_node.value = p) cli_param_patterns
        ) args
      in

      (* Check custom patterns *)
      let is_custom =
        Stdlib.List.exists (fun p ->
          Stdlib.String.length name >= Stdlib.String.length p
          && Stdlib.String.sub name 0 (Stdlib.String.length p) = p
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
  Stdlib.List.rev !results

(* ── BFS reachability ───────────────────────────────────────────────── *)

(** BFS from entry points through call adjacency.
    Returns set of reachable function names. *)
let reachable_from (entries : entry_point list) (call_graph : call_adjacency)
    : string Set.Poly.t =
  let visited = ref Set.Poly.empty in
  let queue = Stdlib.Queue.create () in
  Stdlib.List.iter (fun e ->
    if not (Set.mem !visited e.function_name) then begin
      visited := Set.add !visited e.function_name;
      Stdlib.Queue.push e.function_name queue
    end
  ) entries;
  while not (Stdlib.Queue.is_empty queue) do
    let current = Stdlib.Queue.pop queue in
    (match Map.Poly.find call_graph current with
     | Some edges ->
       Stdlib.List.iter (fun (called, _, _) ->
         if not (Set.mem !visited called) then begin
           visited := Set.add !visited called;
           Stdlib.Queue.push called queue
         end
       ) edges
     | None -> ())
  done;
  !visited

(* ── Path tracing ───────────────────────────────────────────────────── *)

(** Trace the shortest call path from an entry point to a target function.
    Returns the path as [(file, line), ...] or [] if unreachable. *)
let trace_path (entries : entry_point list) (call_graph : call_adjacency)
    (target : string) : (entry_point * (string * int) list) option =
  (* BFS with parent tracking using Map *)
  let parent : (string, (string * string) option) Map.Poly.t ref = ref Map.Poly.empty in
  let visited : string Set.Poly.t ref = ref Set.Poly.empty in
  let queue : string Stdlib.Queue.t = Stdlib.Queue.create () in
  Stdlib.List.iter (fun e ->
    if not (Set.mem !visited e.function_name) then begin
      visited := Set.add !visited e.function_name;
      parent := Map.Poly.set !parent ~key:e.function_name ~data:None;
      Stdlib.Queue.push e.function_name queue
    end
  ) entries;
  let found = ref None in
  while not (Stdlib.Queue.is_empty queue) && !found = None do
    let current = Stdlib.Queue.pop queue in
    if current = target then
      found := Some current
    else
      (match Map.Poly.find call_graph current with
       | Some edges ->
         Stdlib.List.iter (fun (called, _f, _l) ->
           if not (Set.mem !visited called) then begin
             visited := Set.add !visited called;
             parent := Map.Poly.set !parent ~key:called ~data:(Some (current, called));
             Stdlib.Queue.push called queue
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
      match Map.Poly.find !parent name with
      | None -> () (* entry point reached *)
      | Some None -> ()
      | Some (Some (parent_name, _child)) ->
        (* Find the edge for file/line info *)
        (match Map.Poly.find call_graph parent_name with
         | Some edges ->
           (match Stdlib.List.find_opt (fun (n, _, _) -> n = name) edges with
            | Some (_, f, l) -> path := (f, l) :: !path
            | None -> ())
         | None -> ());
        walk parent_name
    in
    walk target;
    (* Find which entry point we started from *)
    let rec find_entry name =
      match Map.Poly.find !parent name with
      | None | Some None ->
        Stdlib.List.find (fun e -> e.function_name = name) entries
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
  let call_graph = build_call_adjacency nodes scopes in
  let entries = detect_entry_points nodes custom_patterns in

  if entries = [] then
    (* No entry points found → everything is "Dormant" by default *)
    Stdlib.List.map (fun _ -> {
      status = `Dormant;
      entry_point = None;
      entry_function = None;
      path_length = 0;
      path = [];
    }) findings
  else begin
    let reachable = reachable_from entries call_graph in
    Stdlib.List.map (fun f ->
      let scope = find_scope scopes f.Finding.file f.Finding.line in
      match scope with
      | None ->
        { status = `Dormant; entry_point = None;
          entry_function = None; path_length = 0; path = [] }
      | Some s ->
        if Set.mem reachable s.func_name then begin
          match trace_path entries call_graph s.func_name with
          | Some (entry, path) ->
            { status = `Live;
              entry_point = Some (Stdlib.Printf.sprintf "%s:%d" entry.file entry.line);
              entry_function = Some entry.function_name;
              path_length = Stdlib.List.length path + 1;
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
