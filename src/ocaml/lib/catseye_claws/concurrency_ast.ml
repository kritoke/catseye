(* lib/catseye_claws/concurrency_ast.ml *)

open Catseye_ast.Types
open Catseye_types

let make_finding file line lang rule severity message : Finding.t =
  { Finding.rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = lang
  ; dependency = None; reachability = None; suggestion = None }

let rec expr_var_name (e : expr) : string option =
  match e.expr_value with
  | EVar name -> Some name
  | EFieldAccess (inner, _) -> expr_var_name inner
  | _ -> None

let is_channel_new_call (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EFieldAccess (inner, "new") ->
       (match inner.expr_value with EVar "Channel" -> true | _ -> false)
     | _ -> false)
  | _ -> false

type channel_action =
  | Create of string
  | Send of string
  | Receive of string
  | Close of string

let rec extract_channel_actions (e : expr) : channel_action list =
  match e.expr_value with
  | EAssignment (lhs, rhs) ->
    (match lhs.expr_value with
     | EVar name when is_channel_new_call rhs -> [Create name]
     | _ -> extract_channel_actions lhs)
    @ extract_channel_actions rhs
  | EBlock es ->
    let creates = ref [] in
    let all_actions = ref [] in
    List.iter (fun stmt ->
      (match stmt.expr_value with
       | EAssignment (lhs, rhs) when is_channel_new_call rhs ->
         (match lhs.expr_value with
          | EVar name -> creates := name :: !creates
          | _ -> ())
       | _ -> ());
      all_actions := extract_channel_actions stmt @ !all_actions
    ) es;
    let known = !creates in
    List.filter (function
      | Send v | Receive v | Close v -> List.mem v known
      | Create _ -> true
    ) !all_actions
  | ELet (_, e1, e2) ->
    extract_channel_actions e1 @ extract_channel_actions e2
  | EIf (cond, then_e, else_opt) ->
    extract_channel_actions cond @ extract_channel_actions then_e
    @ (match else_opt with Some e -> extract_channel_actions e | None -> [])
  | ECase (_, branches) ->
    List.concat_map (fun (_, body) -> extract_channel_actions body) branches
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EFieldAccess (inner, meth) ->
       (match expr_var_name inner with
        | Some name when meth = "send" -> [Send name]
        | Some name when meth = "receive" || meth = "receive?" -> [Receive name]
        | Some name when meth = "close" -> [Close name]
        | _ -> [])
     | _ -> [])
    @ extract_channel_actions fn
  | ERecord fields -> List.concat_map (fun (_, v) -> extract_channel_actions v) fields
  | ERecordUpdate (e, fields) ->
    extract_channel_actions e @ List.concat_map (fun (_, v) -> extract_channel_actions v) fields
  | EFieldAccess (inner, _) -> extract_channel_actions inner
  | EBinOp (e1, _, e2) -> extract_channel_actions e1 @ extract_channel_actions e2
  | EUnOp (_, e) -> extract_channel_actions e
  | ETuple es | EList es -> List.concat_map extract_channel_actions es
  | EFn (_, body) -> extract_channel_actions body
  | _ -> []

let rec has_error_handling (e : expr) : bool =
  match e.expr_value with
  | EUnknown s when s = "exception_handler" || s = "rescue" || s = "ensure" -> true
  | EApp (fn, args) ->
    (match fn.expr_value with
     | EVar name ->
       String.length name >= 6 &&
       (String.sub name (String.length name - 6) 6 = "rescue" ||
        String.sub name (String.length name - 6) 6 = "ensure")
     | EFieldAccess _ -> has_error_handling fn
     | _ -> false)
    || List.exists has_error_handling args
  | EBlock es -> List.exists has_error_handling es
  | ELet (_, e1, e2) -> has_error_handling e1 || has_error_handling e2
  | EIf (cond, then_e, else_opt) ->
    has_error_handling cond || has_error_handling then_e
    || (match else_opt with Some e -> has_error_handling e | None -> false)
  | ECase (_, branches) -> List.exists (fun (_, body) -> has_error_handling body) branches
  | EAssignment (e1, e2) -> has_error_handling e1 || has_error_handling e2
  | ERecord fields -> List.exists (fun (_, v) -> has_error_handling v) fields
  | EFieldAccess (inner, _) -> has_error_handling inner
  | EBinOp (e1, _, e2) -> has_error_handling e1 || has_error_handling e2
  | EUnOp (_, e) -> has_error_handling e
  | EFn (_, body) -> has_error_handling body
  | ETuple es | EList es -> List.exists has_error_handling es
  | _ -> false

let rec has_spawn (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, args) ->
    (match fn.expr_value with
     | EVar "spawn" -> true
     | EFieldAccess (inner, "spawn") ->
       (match inner.expr_value with EVar "Fiber" -> true | _ -> false)
     | _ -> false)
    || has_spawn fn
    || List.exists has_spawn args
  | EBlock es -> List.exists has_spawn es
  | ELet (_, e1, e2) -> has_spawn e1 || has_spawn e2
  | EIf (cond, then_e, else_opt) ->
    has_spawn cond || has_spawn then_e
    || (match else_opt with Some e -> has_spawn e | None -> false)
  | ECase (_, branches) -> List.exists (fun (_, body) -> has_spawn body) branches
  | EAssignment (e1, e2) -> has_spawn e1 || has_spawn e2
  | ERecord fields -> List.exists (fun (_, v) -> has_spawn v) fields
  | EFieldAccess (inner, _) -> has_spawn inner
  | EBinOp (e1, _, e2) -> has_spawn e1 || has_spawn e2
  | EUnOp (_, e) -> has_spawn e
  | EFn (_, body) -> has_spawn body
  | ETuple es | EList es -> List.exists has_spawn es
  | _ -> false

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

let check_dead_letter (actions : channel_action list) : (string * string) list =
  let results = ref [] in
  let received = Hashtbl.create 8 in
  List.iter (function
    | Close var ->
      if not (Hashtbl.mem received var) then
        results := (var, "closed before receive") :: !results
    | Receive var -> Hashtbl.replace received var true
    | _ -> ()
  ) actions;
  !results

(** Check for error handling in the function body or in begin/end blocks.
    Note: Crystal's flat extractor doesn't nest exception_handler inside the
    function body - it's a sibling item. For now, we rely on the AST-level
    detection (EUnknown patterns). This may have FPs for method-level rescue. *)
let has_error_handling_full (scope : Ast_scope.ast_scope) : bool =
  has_error_handling scope.body

let analyze (modules : Catseye_ast.Types.t list)
    (_config : Types.claws_config) : Finding.t list =
  List.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let scopes = Ast_scope.build [mod_] in
    List.concat_map (fun (scope : Ast_scope.ast_scope) ->
      let actions = extract_channel_actions scope.body in
      let muted = check_muted_pack actions in
      let dead = check_dead_letter actions in
      let has_err = has_error_handling_full scope in
      let orphaned = has_spawn scope.body && not has_err in

      let muted_findings = List.map (fun (var, desc) ->
        make_finding scope.file scope.line scope.lang "MutedPack" "High"
          (Printf.sprintf "Channel '%s' has %s in '%s'. Messages may be lost — no consumer exists."
             var desc scope.fn_name)
      ) muted in

      let dead_findings = List.map (fun (var, desc) ->
        make_finding scope.file scope.line scope.lang "DeadLetter" "High"
          (Printf.sprintf "Channel '%s' is %s in '%s'. Sender will get ClosedError."
             var desc scope.fn_name)
      ) dead in

      let orphan_findings =
        if orphaned then [
          make_finding scope.file scope.line scope.lang "OrphanedSpawn" "Medium"
            (Printf.sprintf "Spawned fiber in '%s' has no error handling (rescue/ensure). Fiber will die silently on unhandled exception."
               scope.fn_name)
        ] else []
      in

      muted_findings @ dead_findings @ orphan_findings
    ) scopes
  ) modules
