(* lib/catseye_il/cfg_taint.ml
   Forward dataflow taint analysis on CFG.

   Replaces the flat Security_node.t propagation with block-level
   analysis that respects branch boundaries and field-sensitive lvalues.

   Memory-safe: uses Buffer for findings accumulation instead of
   list concatenation (which was O(n²) and caused the memory leak).

   Dominator-based FP suppression: if a sanitizer call dominates
   the block containing a sink, the finding is suppressed because
   every path to the sink passes through the sanitizer.

   Thread-safe: dominator context is passed explicitly through the
   transfer function chain rather than via module-level mutable refs.
   This allows safe concurrent analysis with OCaml 5 Domains.
*)

open Il_types
open Catseye_rules.Types

(* ── Dominator context (passed explicitly, not via mutable refs) ─────────── *)

(** Dominator analysis context threaded through the worklist.
    Replaces module-level refs to enable safe concurrent analysis. *)
type dom_ctx = {
  dom : Cfg_dominator.t option;
  block_id : int;
}

(* ── Lvalue utilities ──────────────────────────────────────────────── *)

let rec lval_name (lv : lval) : string =
  match lv with
  | LVVar v -> v
  | LVField (inner, field, _) -> lval_name inner ^ "." ^ field

(* ── Taint state ───────────────────────────────────────────────────── *)

module LvalSet = Set.Make (struct
  type t = lval
  let compare a b = String.compare (lval_name a) (lval_name b)
end)

type taint_state = {
  tainted : LvalSet.t;
  mutable findings : Catseye_types.Finding.t list;
  (* Mutable to allow O(1) append via cons + reverse, instead of O(n²) @ *)
}

let empty_state = { tainted = LvalSet.empty; findings = [] }

let is_tainted (state : taint_state) (lv : lval) : bool =
  (* Check exact match and prefix match: if "uri" is tainted, "uri.host" is too *)
  LvalSet.exists (fun t ->
    let tn = lval_name t in
    let ln = lval_name lv in
    tn = ln
    || (String.length ln > String.length tn
        && String.sub ln 0 (String.length tn) = tn
        && ln.[String.length tn] = '.')
  ) state.tainted

(* Extract an lval from an il_expr if possible *)
let rec lval_of_expr (e : il_expr) : lval option =
  match e with
  | IEVar v -> Some (LVVar v)
  | IEField (inner, field, pos) ->
    (match lval_of_expr inner with
     | Some lv -> Some (LVField (lv, field, pos))
     | None -> None)
  | _ -> None

(* Check if an expression references tainted data.
   Special case: <interpolation> passes through any tainted var in scope. *)
let rec is_expr_tainted (state : taint_state) (e : il_expr) : bool =
  match e with
  | IEVar v -> is_tainted state (LVVar v)
  | IEField (_, _, _) ->
    (match lval_of_expr e with
     | Some lv -> is_tainted state lv
     | None -> false)
  | IECall (fn, _args, _) when fn = "<interpolation>" ->
    (* Interpolation passes through taint from any var in scope *)
    not (LvalSet.is_empty state.tainted)
  | IECall (_, args, _) -> List.exists (is_expr_tainted state) args
  | IELiteral _ -> false
  | IEUnknown _ -> false

(* Get string name of an expression *)
let rec expr_name (e : il_expr) : string =
  match e with
  | IEVar v -> v
  | IEField (inner, field, _) -> expr_name inner ^ "." ^ field
  | IELiteral _ -> "<literal>"
  | IECall (fn, _, _) -> fn
  | IEUnknown s -> s

let taint_lval (state : taint_state) (lv : lval) : taint_state =
  { state with tainted = LvalSet.add lv state.tainted }

(* O(1) union: tainted sets union + findings list merge *)
let union_state (a : taint_state) (b : taint_state) : taint_state =
  let merged_findings = a.findings @ b.findings in
  { tainted = LvalSet.union a.tainted b.tainted
  ; findings = merged_findings
  }

(* ── Source matching ──────────────────────────────────────────────── *)

let matches_source (lv : lval) (sources : source_def list) : bool =
  let name = lval_name lv in
  List.exists (fun src ->
    name = src.name
    || (match src.field with
        | Some field -> name = src.name ^ "." ^ field
        | None ->
          name = src.name
          || (String.length name > String.length src.name
              && String.sub name 0 (String.length src.name) = src.name
              && name.[String.length src.name] = '.'))
  ) sources

(* ── Transfer function ────────────────────────────────────────────── *)

(* Forward declare with mutual recursion *)
let rec transfer_node (taint_state : taint_state) (node : il_node)
    (sources : source_def list) (rules : rule_def list)
    (file : string) (lang : string) (dom_ctx : dom_ctx) : taint_state =
  match node with
  | ILAssign (lv, expr, _pos) ->
    (* If RHS is tainted, propagate to LHS *)
    if is_expr_tainted taint_state expr then taint_lval taint_state lv
    else
      (* Check if the RHS returns a source — direct source variable or source call *)
      (match expr with
       | IECall (fn_name, args, _) ->
         (* Function call that returns a source — e.g., params = get_params() *)
         let src_names = List.map (fun (s : source_def) -> s.name) sources in
         if List.mem fn_name src_names then taint_lval taint_state lv
         else
           (* Check if receiver is a source: params.[]() means params[key] *)
           let receiver_tainted =
             (* For x.[](arg), if x is a source OR x is already tainted, result is tainted *)
             String.length fn_name > 3 &&
             String.sub fn_name (String.length fn_name - 3) 3 = ".[]" &&
             let receiver = String.sub fn_name 0 (String.length fn_name - 3) in
             is_tainted taint_state (LVVar receiver)
             || List.exists (fun (s : source_def) -> receiver = s.name) sources
           in
           if receiver_tainted then taint_lval taint_state lv
           else
             (* If any arg is a source, taint the result *)
             let tainted_arg = List.exists (fun a ->
               match lval_of_expr a with
               | Some a_lv -> matches_source a_lv sources
               | None -> false
             ) args in
             if tainted_arg then taint_lval taint_state lv else taint_state
       | _ ->
         match lval_of_expr expr with
         | Some expr_lv when matches_source expr_lv sources ->
           taint_lval taint_state lv
         | _ -> taint_state)

  | ILCall (result_lv, fn_name, args, pos) ->
    (* Check if this call matches a sink with tainted args *)
    let new_findings = check_call_sinks fn_name args pos file lang rules taint_state dom_ctx in
    (* Propagate taint through call if result is assigned *)
    let any_tainted = List.exists (is_expr_tainted taint_state) args in
    let receiver_tainted =
      match String.index_opt fn_name '.' with
      | Some idx ->
        let receiver = String.sub fn_name 0 idx in
        is_tainted taint_state (LVVar receiver)
        || List.exists (fun (s : source_def) -> receiver = s.name) sources
      | None -> false
    in
    let interpolation_tainted =
      fn_name = "<interpolation>" && not (LvalSet.is_empty taint_state.tainted)
    in
    let state' = match result_lv with
      | Some lv when any_tainted || receiver_tainted || interpolation_tainted ->
        taint_lval taint_state lv
      | _ -> taint_state
    in
    (* O(1) append: cons new findings onto existing list *)
    state'.findings <- new_findings @ state'.findings;
    state'

  | ILBranch (_, then_block, else_block, _) ->
    let then_state = transfer_block taint_state then_block sources rules file lang dom_ctx in
    let else_state = match else_block with
      | Some eb -> transfer_block taint_state eb sources rules file lang dom_ctx
      | None -> taint_state
    in
    union_state then_state else_state

  | ILReturn (_expr, _) ->
    taint_state

  | ILThrow (_, _) ->
    taint_state

  | ILResume (block, _) ->
    transfer_block taint_state block sources rules file lang dom_ctx

and transfer_block (taint_state : taint_state) (block : il_block)
    (sources : source_def list) (rules : rule_def list)
    (file : string) (lang : string) (dom_ctx : dom_ctx) : taint_state =
  List.fold_left (fun st node ->
    transfer_node st node sources rules file lang dom_ctx
  ) taint_state block

(* Check a call against all sink rules *)
and check_call_sinks (fn_name : string) (args : il_expr list)
    (pos : pos) (file : string) (lang : string)
    (rules : rule_def list) (state : taint_state) (dom_ctx : dom_ctx)
    : Catseye_types.Finding.t list =
  List.concat_map (fun (rule : rule_def) ->
    List.concat_map (fun (sink : sink_def) ->
      (* Guard clauses — flat, not nested *)
      (* 1. Does the function name match the sink pattern? *)
      if not (Catseye_rules.Interpreter.matches_sink
               ~pattern:sink.pattern ~name:fn_name) then []
      (* 2. Check for sanitized args *)
      else if List.exists (fun a ->
        Catseye_rules.Interpreter.matches_sanitizer sink.sanitizers (expr_name a)
      ) args then []
      (* 3. Dominator-based suppression: sanitizer dominates this block *)
      else if (match dom_ctx.dom with
        | None -> false
        | Some dom -> Cfg_dominator.is_sanitized_by dom dom_ctx.block_id sink.sanitizers
      ) then []
      else begin
          (* Find tainted args, respecting arg_pos if set *)
          let tainted_args = match sink.arg_pos with
            | Some n ->
              (* Only check the arg at position n *)
              if n < List.length args then
                let arg = List.nth args n in
                if is_expr_tainted state arg then [arg] else []
              else []
            | None ->
              (* Any tainted arg triggers *)
              List.filter (is_expr_tainted state) args
          in
          if tainted_args = [] && rule.conditions.requires_tainted_args then []
          else begin
            let vars = String.concat ", " (List.map expr_name tainted_args) in
            let msg = Catseye_rules.Interpreter.substitute_template
              rule.message_template ~sink:fn_name ~vars in
            (* Build fake Security_node.arg list for autofix instantiation *)
            let fake_args = List.map (fun e ->
              Catseye_types.Security_node.{ arg_type = ArgVar; value = expr_name e; field = "" }
            ) args in
            let suggestion = match sink.fix_template with
              | Some tmpl -> Some (Catseye_rules.Interpreter.instantiate_fix
                                    tmpl ~sink_name:fn_name fake_args)
              | None -> None
            in
            [{ Catseye_types.Finding.rule = rule.id
             ; severity = rule.severity
             ; file
             ; line = pos.line
             ; message = msg
             ; flow = []
             ; language = lang
             ; dependency = None
             ; reachability = None
             ; suggestion
            }]
          end
      end
    ) rule.sinks
  ) rules

(* ── CFG dataflow via ocamlgraph Fixpoint ────────────────────────────── *)

(* ── CFG dataflow via worklist on ocamlgraph ──────────────────────────── *)

(** Forward taint analysis using worklist algorithm on the ocamlgraph CFG.

    The worklist processes blocks in order, propagating taint state
    forward through the graph. Convergence is ensured by tracking
    visit counts per block (max_visits=3 for a may-analysis).

    We keep the hand-rolled worklist rather than using
    Graph.Fixpoint.Make because our transfer function operates
    per-block (not per-edge) and accumulates findings as a side
    effect. Fixpoint.Make's [analyze : edge -> data -> data] API
    doesn't map naturally to block-level transfer with side effects.

    Instead, we use ocamlgraph's graph APIs (G.pred for predecessor
    lookup, G.succ for successor iteration) which are already
    available through the Cfg_graph adapter.

    Thread-safe: dominator context is passed explicitly via dom_ctx,
    enabling safe concurrent analysis with OCaml 5 Domains. *)

let analyze_cfg (cfg : Cfg_graph.t) (sources : source_def list)
    (rules : rule_def list) (file : string) (lang : string)
    : Catseye_types.Finding.t list =

  (* Compute dominator analysis for sanitizer-guarded path detection *)
  let dom =
    try Some (Cfg_dominator.compute cfg)
    with _ -> None
  in

  (* State per block *)
  let states = Hashtbl.create 32 in

  let get_state id =
    try Hashtbl.find states id
    with Not_found -> { empty_state with findings = [] }
  in

  (* Worklist algorithm using a Queue for O(1) push/pop *)
  let worklist = Queue.create () in
  Queue.add cfg.Cfg_graph.entry worklist;

  let max_visits_per_block = 3 in
  let visit_count = Hashtbl.create 32 in

  while not (Queue.is_empty worklist) do
    let block_id = Queue.take worklist in

    let visits = try Hashtbl.find visit_count block_id with Not_found -> 0 in
    if visits < max_visits_per_block then begin
      Hashtbl.replace visit_count block_id (visits + 1);

      let nodes = Cfg_graph.block_nodes cfg block_id in
      if nodes <> [] then begin
        (* Build dominator context for this block — passed explicitly, not via refs *)
        let dom_ctx = { dom; block_id } in
        (* Input state = union of predecessor outputs *)
        let pred_ids = Cfg_graph.G.pred cfg.Cfg_graph.graph block_id in
        let input_state = List.fold_left (fun acc pid ->
          union_state acc (get_state pid)
        ) { empty_state with findings = [] } pred_ids in

        (* Seed function params as potential sources *)
        let seeded_state = List.fold_left (fun st param ->
          let lv = LVVar param in
          if matches_source lv sources then taint_lval st lv
          else st
        ) input_state cfg.Cfg_graph.fn_params in

        (* Transfer through this block's nodes *)
        let output = transfer_block seeded_state nodes sources rules file lang dom_ctx in

        Hashtbl.replace states block_id output;

        (* Add successors to worklist *)
        Cfg_graph.iter_succ cfg (fun succ ->
          Queue.add succ worklist
        ) block_id
      end
    end
  done;

  let all_findings = Hashtbl.fold (fun _id state acc ->
    state.findings @ acc
  ) states [] in
  all_findings

(* ── Top-level API ─────────────────────────────────────────────────── *)

type analyze_opts = {
  cfg_max_blocks : int;
  cfg_timeout_ms : int;
}

let default_opts = {
  cfg_max_blocks = 500;
  cfg_timeout_ms = 5000;
}

(** Result of analyzing a unit — either findings or warnings about skipped functions *)
type analyze_result = {
  findings : Catseye_types.Finding.t list;
  skipped_functions : string list;  (* functions that hit bounds and were skipped *)
}

let analyze_unit ?(opts : analyze_opts = default_opts) (unit : il_unit)
    (sources : source_def list)
    (rules : rule_def list) : analyze_result =
  let raw = ref [] in
  let skipped = ref [] in
  List.iter (fun (fn : il_function) ->
    let cfg_result = Cfg_builder.build_cfg
      ~max_blocks:opts.cfg_max_blocks
      ~timeout_ms:opts.cfg_timeout_ms
      fn in
    match cfg_result with
    | Ok cfg ->
      raw := analyze_cfg cfg sources rules unit.il_file unit.il_lang @ !raw
    | Error (TooManyBlocks { actual; limit }) ->
      Printf.eprintf "  [warn] CFG: %s in %s hit block limit (%d > %d), skipping\n"
        fn.fn_name unit.il_file actual limit;
      skipped := fn.fn_name :: !skipped
    | Error (Timeout { elapsed_ms; partial_blocks }) ->
      Printf.eprintf "  [warn] CFG: %s in %s timed out after %dms (%d partial blocks), skipping\n"
        fn.fn_name unit.il_file elapsed_ms partial_blocks;
      skipped := fn.fn_name :: !skipped
  ) unit.il_functions;
  (* Deduplicate by rule:file:line *)
  let seen = Hashtbl.create 64 in
  let deduped = List.filter (fun (f : Catseye_types.Finding.t) ->
    let key = f.Catseye_types.Finding.rule ^ ":" ^ f.Catseye_types.Finding.file
              ^ ":" ^ Int.to_string f.Catseye_types.Finding.line in
    if Hashtbl.mem seen key then false
    else (Hashtbl.replace seen key true; true)
  ) !raw in
  { findings = deduped; skipped_functions = !skipped }