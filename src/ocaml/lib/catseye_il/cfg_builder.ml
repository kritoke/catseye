(* lib/catseye_il/cfg_builder.ml
   Build a Control Flow Graph from il_block.

   Each function's il_block is converted to a list of basic_blocks
   with successor edges. Branches create separate blocks that merge
   at the continuation point.
*)

open Il_types

(* ── Split block at branch points ───────────────────────────────────── *)

(* Take all linear (non-branch) nodes from the front of the list *)
let take_linear (nodes : il_node list) : il_node list * il_node list =
  let rec go acc = function
    | [] -> (List.rev acc, [])
    | (ILBranch _ | ILResume _) as hd :: _ -> (List.rev acc, hd :: [])
    | hd :: tl -> go (hd :: acc) tl
  in
  go [] nodes

(* ── CFG builder ────────────────────────────────────────────────────── *)

(* NOTE: build_block_bounded and build_block_inner are defined below
   after the Public API section, using mutual recursion with bounds checking. *)

(* ── Public API ─────────────────────────────────────────────────────── *)

let build_cfg ?(max_blocks : int = 500) ?(timeout_ms : int = 5000)
    (fn : il_function) : (Cfg_graph.t, cfg_error) result =
  let cfg = Cfg_graph.create fn in
  let next_id = ref 0 in
  let start_time = Unix.gettimeofday () in
  let alloc_id () =
    let id = !next_id in
    incr next_id;
    id
  in
  let check_bounds () =
    if !next_id > max_blocks then
      Some (TooManyBlocks { actual = !next_id; limit = max_blocks })
    else if timeout_ms > 0 then
      let elapsed = (Unix.gettimeofday () -. start_time) *. 1000.0 in
      if int_of_float elapsed > timeout_ms then
        Some (Timeout { elapsed_ms = int_of_float elapsed; partial_blocks = !next_id })
      else None
    else None
  in
  let error = ref None in
  (* emit: create a block with the given nodes, return its ID *)
  let emit nodes =
    let id = alloc_id () in
    let _ = Cfg_graph.add_block cfg id nodes in
    id
  in
  let rec build_block_bounded nodes cont =
    (match !error with
     | Some _ -> emit []  (* bail out *)
     | None ->
       (match check_bounds () with
        | Some e -> error := Some e; 0
        | None -> build_block_inner nodes cont))
  and build_block_inner nodes cont : int =
    let linear, rest = take_linear nodes in
    match rest with
    | [] ->
      let id = emit linear in
      (match cont with Some cid -> Cfg_graph.add_edge cfg id cid | None -> ());
      id
    | [ILBranch (_cond, then_block, else_block, _pos)] ->
      let merge_id = emit [] in
      (match cont with Some cid -> Cfg_graph.add_edge cfg merge_id cid | None -> ());
      let then_id = build_block_bounded then_block (Some merge_id) in
      let else_id = match else_block with
        | Some eb -> build_block_bounded eb (Some merge_id)
        | None -> merge_id
      in
      let id = emit linear in
      Cfg_graph.add_edge cfg id then_id;
      Cfg_graph.add_edge cfg id else_id;
      id
    | [ILResume (rescue_block, _pos)] ->
      let inner_id = build_block_bounded rescue_block cont in
      let id = emit linear in
      Cfg_graph.add_edge cfg id inner_id;
      (match cont with Some cid -> Cfg_graph.add_edge cfg id cid | None -> ());
      id
    | _ ->
      let id = emit (linear @ rest) in
      (match cont with Some cid -> Cfg_graph.add_edge cfg id cid | None -> ());
      id
  in
  let entry_id = build_block_bounded fn.fn_body None in
  Cfg_graph.set_entry cfg entry_id;
  match !error with
  | Some e -> Error e
  | None -> Ok cfg

let build_cfgs ?(max_blocks : int = 500) ?(timeout_ms : int = 5000)
    (unit : il_unit) : Cfg_graph.t list =
  (* Filter out functions that hit bounds, keep successful CFGs *)
  List.filter_map (fun fn ->
    match build_cfg ~max_blocks ~timeout_ms fn with
    | Ok cfg -> Some cfg
    | Error _ -> None
  ) unit.il_functions

(* ── IntMap re-exported from Il_types ─────────────────────────────────── *)

(* ── Debug printing ─────────────────────────────────────────────────── *)

let rec string_of_lval (lv : lval) : string =
  match lv with
  | LVVar v -> v
  | LVField (inner, field, _) -> string_of_lval inner ^ "." ^ field

let rec string_of_expr (e : il_expr) : string =
  match e with
  | IEVar v -> v
  | IEField (inner, field, _) -> string_of_expr inner ^ "." ^ field
  | IELiteral s -> s
  | IECall (fn, args, _) ->
    fn ^ "(" ^ String.concat ", " (List.map string_of_expr args) ^ ")"
  | IEUnknown s -> "?(?" ^ s ^ ")"

let string_of_node = function
  | ILAssign (lv, expr, _) ->
    string_of_lval lv ^ " = " ^ string_of_expr expr
  | ILCall (None, fn, args, _) ->
    fn ^ "(" ^ String.concat ", " (List.map string_of_expr args) ^ ")"
  | ILCall (Some lv, fn, args, _) ->
    string_of_lval lv ^ " = " ^ fn ^ "(" ^ String.concat ", " (List.map string_of_expr args) ^ ")"
  | ILBranch (_, then_, else_, _) ->
    "if ... then [" ^ Int.to_string (List.length then_) ^ " nodes]" ^
    (match else_ with Some b -> " else [" ^ Int.to_string (List.length b) ^ " nodes]" | None -> "")
  | ILReturn (expr, _) -> "return " ^ string_of_expr expr
  | ILThrow (expr, _) -> "throw " ^ string_of_expr expr
  | ILResume (block, _) -> "rescue [" ^ Int.to_string (List.length block) ^ " nodes]"

let print_cfg (cfg : Cfg_graph.t) : string =
  let buf = Buffer.create 256 in
  let pr fmt = Printf.bprintf buf fmt in
  pr "CFG for %s (entry: %d)\n" cfg.Cfg_graph.fn_name cfg.Cfg_graph.entry;
  Cfg_graph.iter_vertices cfg (fun vid ->
    pr "  Block %d:\n" vid;
    List.iter (fun n ->
      pr "    %s\n" (string_of_node n)
    ) (Cfg_graph.block_nodes cfg vid);
    let succs = Cfg_graph.succ_list cfg vid in
    if succs <> [] then
      pr "    → %s\n" (String.concat ", " (List.map Int.to_string succs))
  );
  Buffer.contents buf
