(* lib/catseye_il/cfg_taint.ml
   Forward dataflow taint analysis on CFG.

   Replaces the flat Security_node.t propagation with block-level
   analysis that respects branch boundaries and field-sensitive lvalues.
*)

open Il_types
open Catseye_rules.Types

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
  findings : Catseye_types.Finding.t list;
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

let union_state (a : taint_state) (b : taint_state) : taint_state =
  { tainted = LvalSet.union a.tainted b.tainted
  ; findings = a.findings @ b.findings
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
let rec transfer_node (state : taint_state) (node : il_node)
    (sources : source_def list) (rules : rule_def list)
    (file : string) (lang : string) : taint_state =
  match node with
  | ILAssign (lv, expr, _pos) ->
    (* If RHS is tainted, propagate to LHS *)
    if is_expr_tainted state expr then taint_lval state lv
    else
      (* Check if the RHS returns a source — direct source variable or source call *)
      (match expr with
       | IECall (fn_name, args, _) ->
         (* Function call that returns a source — e.g., params = get_params() *)
         let src_names = List.map (fun (s : source_def) -> s.name) sources in
         if List.mem fn_name src_names then taint_lval state lv
         else
           (* Check if receiver is a source: params.[]() means params[key] *)
           let receiver_tainted =
             (* For x.[](arg), if x is a source OR x is already tainted, result is tainted *)
             String.length fn_name > 3 &&
             String.sub fn_name (String.length fn_name - 3) 3 = ".[]" &&
             let receiver = String.sub fn_name 0 (String.length fn_name - 3) in
             is_tainted state (LVVar receiver)
             || List.exists (fun (s : source_def) -> receiver = s.name) sources
           in
           if receiver_tainted then taint_lval state lv
           else
             (* If any arg is a source, taint the result *)
             let tainted_arg = List.exists (fun a ->
               match lval_of_expr a with
               | Some a_lv -> matches_source a_lv sources
               | None -> false
             ) args in
             if tainted_arg then taint_lval state lv else state
       | _ ->
         match lval_of_expr expr with
         | Some expr_lv when matches_source expr_lv sources ->
           taint_lval state lv
         | _ -> state)

  | ILCall (result_lv, fn_name, args, pos) ->
    (* Check if this call matches a sink with tainted args *)
    let new_findings = check_call_sinks fn_name args pos file lang rules state in
    (* Propagate taint through call if result is assigned *)
    (* Check: (1) any explicit arg is tainted, (2) receiver is tainted (params.[]),
       (3) <interpolation> passes through any taint *)
    let any_tainted = List.exists (is_expr_tainted state) args in
    let receiver_tainted =
      match String.index_opt fn_name '.' with
      | Some idx ->
        let receiver = String.sub fn_name 0 idx in
        is_tainted state (LVVar receiver)
        || List.exists (fun (s : source_def) -> receiver = s.name) sources
      | None -> false
    in
    let interpolation_tainted =
      fn_name = "<interpolation>" && not (LvalSet.is_empty state.tainted)
    in
    let state' = match result_lv with
      | Some lv when any_tainted || receiver_tainted || interpolation_tainted ->
        taint_lval state lv
      | _ -> state
    in
    { state' with findings = state'.findings @ new_findings }

  | ILBranch (_, then_block, else_block, _) ->
    let then_state = transfer_block state then_block sources rules file lang in
    let else_state = match else_block with
      | Some eb -> transfer_block state eb sources rules file lang
      | None -> state
    in
    union_state then_state else_state

  | ILReturn (_expr, _) ->
    state

  | ILThrow (_, _) ->
    state

  | ILResume (block, _) ->
    transfer_block state block sources rules file lang

and transfer_block (state : taint_state) (block : il_block)
    (sources : source_def list) (rules : rule_def list)
    (file : string) (lang : string) : taint_state =
  List.fold_left (fun st node ->
    transfer_node st node sources rules file lang
  ) state block

(* Check a call against all sink rules *)
and check_call_sinks (fn_name : string) (args : il_expr list)
    (pos : pos) (file : string) (lang : string)
    (rules : rule_def list) (state : taint_state)
    : Catseye_types.Finding.t list =
  List.concat_map (fun (rule : rule_def) ->
    List.concat_map (fun (sink : sink_def) ->
      (* Does the function name match the sink pattern? *)
      if not (Catseye_rules.Interpreter.matches_sink
               ~pattern:sink.pattern ~name:fn_name) then []
      else begin
        (* Check for sanitized args *)
        let has_sanitizer = List.exists (fun a ->
          let name = expr_name a in
          Catseye_rules.Interpreter.matches_sanitizer sink.sanitizers name
        ) args in
        if has_sanitizer then []
        else begin
          (* Find tainted args *)
          let tainted_args = List.filter (is_expr_tainted state) args in
          if tainted_args = [] && rule.conditions.requires_tainted_args then []
          else begin
            let vars = String.concat ", " (List.map expr_name tainted_args) in
            let msg = Catseye_rules.Interpreter.substitute_template
              rule.message_template ~sink:fn_name ~vars in
            [{ Catseye_types.Finding.rule = rule.id
             ; severity = rule.severity
             ; file
             ; line = pos.line
             ; message = msg
             ; flow = []
             ; language = lang
             ; dependency = None
             ; reachability = None
             ; suggestion = None
            }]
          end
        end
      end
    ) rule.sinks
  ) rules

(* ── CFG dataflow ──────────────────────────────────────────────────── *)

module IntMap = Map.Make (struct type t = int let compare = compare end)

let analyze_cfg (cfg : cfg) (sources : source_def list)
    (rules : rule_def list) (file : string) (lang : string)
    : Catseye_types.Finding.t list =

  let block_map = List.fold_left (fun m (bb : basic_block) ->
    IntMap.add bb.id bb m
  ) IntMap.empty cfg.cfg_blocks in

  (* Build predecessor map *)
  let preds = List.fold_left (fun m (bb : basic_block) ->
    List.fold_left (fun m succ ->
      let existing = try IntMap.find succ m with Not_found -> [] in
      IntMap.add succ (bb.id :: existing) m
    ) m bb.successors
  ) IntMap.empty cfg.cfg_blocks in

  (* State per block *)
  let states = ref IntMap.empty in

  let get_state id =
    try IntMap.find id !states
    with Not_found -> empty_state
  in

  (* Worklist algorithm *)
  let worklist = ref [cfg.cfg_entry] in
  let visited = Hashtbl.create 16 in

  while !worklist <> [] do
    let block_id = List.hd !worklist in
    worklist := List.tl !worklist;

    if not (Hashtbl.mem visited block_id) then begin
      Hashtbl.replace visited block_id true;

      (match IntMap.find_opt block_id block_map with
       | None -> ()
       | Some bb ->
         (* Input state = union of predecessor outputs *)
         let pred_ids = try IntMap.find block_id preds with Not_found -> [] in
         let input_state = List.fold_left (fun acc pid ->
           union_state acc (get_state pid)
         ) empty_state pred_ids in

         (* Seed function params as potential sources *)
         let seeded_state = List.fold_left (fun st param ->
           let lv = LVVar param in
           if matches_source lv sources then taint_lval st lv
           else st
         ) input_state cfg.cfg_fn_params in

         (* Transfer through this block's nodes *)
         let output = transfer_block seeded_state bb.nodes sources rules file lang in

         states := IntMap.add block_id output !states;

         (* Add successors to worklist *)
         List.iter (fun succ ->
           if not (Hashtbl.mem visited succ) then
             worklist := succ :: !worklist
         ) bb.successors)
    end
  done;

  (* Collect all findings from all blocks *)
  let all_findings = ref [] in
  IntMap.iter (fun _id state ->
    all_findings := !all_findings @ state.findings
  ) !states;
  !all_findings

(* ── Top-level API ─────────────────────────────────────────────────── *)

let analyze_unit (unit : il_unit) (sources : source_def list)
    (rules : rule_def list) : Catseye_types.Finding.t list =
  let cfgs = Cfg_builder.build_cfgs unit in
  let raw = List.concat_map (fun (cfg : cfg) ->
    analyze_cfg cfg sources rules unit.il_file unit.il_lang
  ) cfgs in
  (* Deduplicate by rule:file:line *)
  let seen = Hashtbl.create 64 in
  List.filter (fun (f : Catseye_types.Finding.t) ->
    let key = f.Catseye_types.Finding.rule ^ ":" ^ f.Catseye_types.Finding.file
              ^ ":" ^ string_of_int f.Catseye_types.Finding.line in
    if Hashtbl.mem seen key then false
    else (Hashtbl.replace seen key true; true)
  ) raw
