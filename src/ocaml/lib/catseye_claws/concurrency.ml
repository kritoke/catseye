(* lib/catseye_claws/concurrency.ml
   Concurrency Trap Detection for Crystal fiber/channel patterns.

   Detects:
   1. Muted Pack — Channel.send without matching Channel.receive
      (messages sent but never consumed)
   2. Dead Letter — Channel.close before .receive
      (channel closed while sender or receiver is active)
   3. Orphaned Spawn — spawn without error handling
      (fiber that can crash silently)

   Uses the flat node stream from the Crystal extractor.
   Tracks channel variables and their lifecycle within function scopes. *)

open Catseye_types

(* ── Channel lifecycle tracking ─────────────────────────────────────── *)

type channel_action =
  | Create of string  (* variable name *)
  | Send of string    (* variable name *)
  | Receive of string (* variable name *)
  | Close of string   (* variable name *)

(** Extract channel actions from a list of call nodes within a function scope.
    Tracks: Channel(X).new -> Create, x.send -> Send, x.receive -> Receive,
    x.close -> Close.
    Only tracks variables that were created via Channel.new — avoids false
    positives from HTTP::Client.close, IO.close, etc. *)
let extract_channel_actions (body : Security_node.t list) : channel_action list =
  (* First pass: find all channel variable names from Channel.new assigns *)
  let channel_vars : (string, bool) Hashtbl.t = Hashtbl.create 8 in
  List.iter (fun (n : Security_node.t) ->
    if n.Security_node.node_type = Security_node.Call then begin
      let name = n.Security_node.name in
      let nl = String.length name in
      if nl >= 4 && String.sub name (nl - 4) 4 = ".new" then begin
        (* Check if this is a Channel constructor *)
        let is_channel =
          let rec check i =
            i + 7 <= nl &&
            (String.sub name i 7 = "Channel" || check (i + 1))
          in check 0
        in
        if is_channel then begin
          (* Find the variable it was assigned to *)
          let assign = List.find_opt (fun (a : Security_node.t) ->
            a.Security_node.node_type = Security_node.Assign
            && a.Security_node.line = n.Security_node.line
            && a.Security_node.file = n.Security_node.file
          ) body in
          (match assign with
           | Some a -> Hashtbl.replace channel_vars a.Security_node.name true
           | None ->
             (* Try next-line assign (e.g., ch = ... on same line as call) *)
             let assign2 = List.find_opt (fun (a : Security_node.t) ->
               a.Security_node.node_type = Security_node.Assign
               && a.Security_node.line >= n.Security_node.line
               && a.Security_node.line <= n.Security_node.line + 1
               && a.Security_node.file = n.Security_node.file
             ) body in
             (match assign2 with
              | Some a -> Hashtbl.replace channel_vars a.Security_node.name true
              | None -> ()))
        end
      end
    end
  ) body;
  (* Second pass: extract actions only for known channel variables *)
  List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type <> Security_node.Call then None
    else
      let name = n.Security_node.name in
      let nl = String.length name in
      (* Channel send: var.send — only if var is a known channel *)
      if nl >= 5 && String.sub name (nl - 5) 5 = ".send" then begin
        let obj = String.sub name 0 (nl - 5) in
        if Hashtbl.mem channel_vars obj then Some (Send obj)
        else None
      end
      (* Channel receive: var.receive or var.receive? — 8 or 9 chars *)
      else if (nl >= 9 && String.sub name (nl - 9) 9 = ".receive?")
              || (nl >= 8 && String.sub name (nl - 8) 8 = ".receive")
      then begin
        let suffix_len = if nl >= 9 && String.sub name (nl - 9) 9 = ".receive?" then 9 else 8 in
        let obj = String.sub name 0 (nl - suffix_len) in
        if Hashtbl.mem channel_vars obj then Some (Receive obj)
        else None
      end
      (* Channel close: var.close *)
      else if nl >= 6 && String.sub name (nl - 6) 6 = ".close" then begin
        let obj = String.sub name 0 (nl - 6) in
        if Hashtbl.mem channel_vars obj then Some (Close obj)
        else None
      end
      else None
  ) body

(** Check for Muted Pack: channel with send but no receive in same scope *)
let check_muted_pack (actions : channel_action list) : (string * string) list =
  let sent = Hashtbl.create 8 in
  let received = Hashtbl.create 8 in
  List.iter (function
    | Send var -> Hashtbl.replace sent var true
    | Receive var -> Hashtbl.replace received var true
    | _ -> ()
  ) actions;
  Hashtbl.fold (fun var _ acc ->
    if not (Hashtbl.mem received var) then (var, "send without receive") :: acc
    else acc
  ) sent []

(** Check for Dead Letter: channel closed before receive *)
let check_dead_letter (actions : channel_action list) : (string * string) list =
  let results = ref [] in
  let received = Hashtbl.create 8 in
  (* Check if close comes before any receive *)
  List.iter (function
    | Close var ->
      if not (Hashtbl.mem received var) then
        results := (var, "closed before receive") :: !results
    | Receive var -> Hashtbl.replace received var true
    | _ -> ()
  ) actions;
  !results

(** Check for Orphaned Spawn: spawn calls without rescue/ensure.
    Checks both Call nodes (inline rescue) and Control nodes
    (begin/rescue/end blocks, exception_handler nodes). *)
let check_orphaned_spawn (body : Security_node.t list) : bool =
  let has_spawn = List.exists (fun (n : Security_node.t) ->
    n.Security_node.node_type = Security_node.Call
    && n.Security_node.name = "spawn"
  ) body in
  let has_rescue = List.exists (fun (n : Security_node.t) ->
    (* Control nodes: exception_handler, rescue (from begin/rescue/end blocks) *)
    (n.Security_node.node_type = Security_node.Control
     && (n.Security_node.name = "exception_handler"
         || n.Security_node.name = "rescue"
         || n.Security_node.name = "begin"))
    ||
    (* Call nodes: inline rescue, rescue suffix *)
    (n.Security_node.node_type = Security_node.Call
     && (let name = n.Security_node.name in
         String.length name >= 6 &&
         String.sub name (String.length name - 6) 6 = "rescue"))
  ) body in
  let has_ensure = List.exists (fun (n : Security_node.t) ->
    n.Security_node.node_type = Security_node.Call
    && (let name = n.Security_node.name in
        String.length name >= 7 &&
        String.sub name (String.length name - 7) 7 = "ensure")
  ) body in
  has_spawn && not has_rescue && not has_ensure

(* ── Scope builder (shared with extra_smells) ──────────────────────── *)

type scope = {
  def : Security_node.t;
  body : Security_node.t list;
}

let build_scopes (nodes : Security_node.t list) : scope list =
  let scopes = ref [] in
  let current_def = ref None in
  let current_body = ref [] in
  let current_file = ref "" in
  List.iter (fun (n : Security_node.t) ->
    if n.Security_node.node_type = Security_node.Def then begin
      (match !current_def with
       | Some d ->
         scopes := { def = d; body = List.rev !current_body } :: !scopes
       | None -> ());
      current_def := Some n;
      current_body := [];
      current_file := n.Security_node.file
    end else if n.Security_node.node_type = Security_node.Class
              || n.Security_node.node_type = Security_node.Module then
      ()  (* class/module boundaries don't reset scope *)
    else
      current_body := n :: !current_body
  ) nodes;
  (match !current_def with
   | Some d ->
     scopes := { def = d; body = List.rev !current_body } :: !scopes
   | None -> ());
  List.rev !scopes

(* ── Main analysis ─────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (_config : Types.claws_config)
    : Finding.t list =
  let scopes = build_scopes nodes in
  List.concat_map (fun ({ def; body } : scope) ->
    let actions = extract_channel_actions body in
    let muted = check_muted_pack actions in
    let dead = check_dead_letter actions in
    let orphaned = check_orphaned_spawn body in

    let muted_findings = List.map (fun (var, desc) ->
      { Finding.rule = "MutedPack";
        severity = "High";
        file = def.Security_node.file;
        line = def.Security_node.line;
        message = Printf.sprintf
          "Channel '%s' has %s in '%s'. Messages may be lost — \
           no consumer exists." var desc def.Security_node.name;
        flow = [ {
          Finding.file = def.Security_node.file;
          line = def.Security_node.line;
          message = Printf.sprintf "In '%s'" def.Security_node.name;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    ) muted in

    let dead_findings = List.map (fun (var, desc) ->
      { Finding.rule = "DeadLetter";
        severity = "High";
        file = def.Security_node.file;
        line = def.Security_node.line;
        message = Printf.sprintf
          "Channel '%s' is %s in '%s'. Sender will get ClosedError." var desc def.Security_node.name;
        flow = [ {
          Finding.file = def.Security_node.file;
          line = def.Security_node.line;
          message = Printf.sprintf "In '%s'" def.Security_node.name;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    ) dead in

    let orphan_findings =
      if orphaned then [
        { Finding.rule = "OrphanedSpawn";
          severity = "Medium";
          file = def.Security_node.file;
          line = def.Security_node.line;
          message = Printf.sprintf
            "Spawned fiber in '%s' has no error handling (rescue/ensure). \
             Fiber will die silently on unhandled exception." def.Security_node.name;
          flow = [ {
            Finding.file = def.Security_node.file;
            line = def.Security_node.line;
            message = Printf.sprintf "In '%s'" def.Security_node.name;
          } ];
          language = "crystal";
          dependency = None;
          reachability = None; suggestion = None;
        }
      ] else []
    in

    muted_findings @ dead_findings @ orphan_findings
  ) scopes
