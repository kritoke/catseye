(* lib/catseye_il/cfg_builder.ml
   Build a Control Flow Graph from il_block.

   Each function's il_block is converted to a list of basic_blocks
   with successor edges. Branches create separate blocks that merge
   at the continuation point.
*)

open Il_types

(* ── Block accumulator ──────────────────────────────────────────────── *)

type block_acc = {
  mutable blocks : basic_block list;
  mutable next_id : int;
}

let make_acc () = { blocks = []; next_id = 0 }

let alloc_id (acc : block_acc) : int =
  let id = acc.next_id in
  acc.next_id <- id + 1;
  id

let emit_block (acc : block_acc) (nodes : il_node list) (successors : int list) : int =
  let id = alloc_id acc in
  acc.blocks <- { id; nodes; successors } :: acc.blocks;
  id

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

(* Build CFG from an il_block, returning the entry block ID.
   'cont' is the continuation block ID (what follows this block). *)
let rec build_block (acc : block_acc) (nodes : il_node list) (cont : int option) : int =
  let linear, rest = take_linear nodes in
  match rest with
  | [] ->
    (* All linear — single basic block pointing to cont *)
    let succs = match cont with Some id -> [id] | None -> [] in
    emit_block acc linear succs

  | [ILBranch (_cond, then_block, else_block, _pos)] ->
    (* Branch is the last node. Split into then/else, merge at cont. *)
    let merge_succ = match cont with
      | Some id -> [id]
      | None -> []  (* exit block *)
    in
    let merge_id = emit_block acc [] merge_succ in

    (* Build then-branch → merge *)
    let then_id = build_block acc then_block (Some merge_id) in

    (* Build else-branch → merge *)
    let else_id = match else_block with
      | Some eb -> build_block acc eb (Some merge_id)
      | None -> merge_id
    in

    (* Emit the linear prefix, pointing to both branches *)
    emit_block acc linear [then_id; else_id]

  | [ILResume (rescue_block, _pos)] ->
    (* Resume/rescue block. For taint purposes, both paths are possible. *)
    let inner_id = build_block acc rescue_block cont in
    let succs = match cont with
      | Some id -> [id; inner_id]
      | None -> [inner_id]
    in
    emit_block acc linear succs

  | _ ->
    (* Shouldn't happen — take_linear stops at first branch node *)
    let succs = match cont with Some id -> [id] | None -> [] in
    emit_block acc (linear @ rest) succs

(* ── Public API ─────────────────────────────────────────────────────── *)

let build_cfg (fn : il_function) : cfg =
  let acc = make_acc () in
  let _entry_id = build_block acc fn.fn_body None in
  let blocks = List.rev acc.blocks in
  (* The entry block is the first one emitted for the function body *)
  let entry = match blocks with
    | { id; _ } :: _ -> id
    | [] -> 0
  in
  { cfg_fn_name = fn.fn_name
  ; cfg_fn_params = fn.fn_params
  ; cfg_entry = entry
  ; cfg_blocks = blocks
  ; cfg_pos = fn.fn_pos
  }

let build_cfgs (unit : il_unit) : cfg list =
  List.map build_cfg unit.il_functions

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
    "if ... then [" ^ string_of_int (List.length then_) ^ " nodes]" ^
    (match else_ with Some b -> " else [" ^ string_of_int (List.length b) ^ " nodes]" | None -> "")
  | ILReturn (expr, _) -> "return " ^ string_of_expr expr
  | ILThrow (expr, _) -> "throw " ^ string_of_expr expr
  | ILResume (block, _) -> "rescue [" ^ string_of_int (List.length block) ^ " nodes]"

let print_cfg (cfg : cfg) : string =
  let buf = Buffer.create 256 in
  Buffer.add_string buf (Printf.sprintf "CFG for %s (entry: %d)\n" cfg.cfg_fn_name cfg.cfg_entry);
  List.iter (fun bb ->
    Buffer.add_string buf (Printf.sprintf "  Block %d:\n" bb.id);
    List.iter (fun n ->
      Buffer.add_string buf (Printf.sprintf "    %s\n" (string_of_node n))
    ) bb.nodes;
    if bb.successors <> [] then
      Buffer.add_string buf (Printf.sprintf "    → %s\n"
        (String.concat ", " (List.map string_of_int bb.successors)))
  ) cfg.cfg_blocks;
  Buffer.contents buf
