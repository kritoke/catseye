(* lib/catseye_il/il_types.ml
   Intermediate Language for dataflow analysis.

   Derived from CatseyeAST.t but focused on what the taint engine needs:
   - Field-sensitive lvalues (x.a.b)
   - Explicit branches (if/else with separate blocks)
   - Arg-position tracking on calls
   - No complex AST constructs that don't affect dataflow
*)

(** Source position — carried through from CatseyeAST *)
type pos = {
  line : int;
  col : int;
}

(** Field-sensitive lvalues — tracks x.a.b as nested structure *)
type lval =
  | LVVar of string
  | LVField of lval * string * pos   (* lv.field at pos *)

(** IL expressions — rvalues, used in assigns and call args *)
type il_expr =
  | IEVar of string
  | IEField of il_expr * string * pos
  | IELiteral of string                (* string representation *)
  | IECall of string * il_expr list * pos  (* fn_name, args, pos *)
  | IEUnknown of string                (* fallback for unhandled constructs *)

(** IL nodes — the unit of dataflow *)
type il_node =
  | ILAssign of lval * il_expr * pos       (* lv = expr *)
  | ILCall of lval option * string * il_expr list * pos
      (** result? = fn(args). None = discarded result. *)
  | ILBranch of il_expr * il_block * il_block option * pos
      (** if cond then block [else block] *)
  | ILReturn of il_expr * pos              (* return expr *)
  | ILThrow of il_expr * pos               (* raise expr *)
  | ILResume of il_block * pos             (* rescue/ensure block *)

and il_block = il_node list

(** A function in IL form — one CFG is built per function *)
type il_function = {
  fn_name : string;
  fn_params : string list;      (* param names extracted from patterns *)
  fn_body : il_block;
  fn_pos : pos;                 (* location of function definition *)
}

(** Full IL translation unit — all functions from one source file *)
type il_unit = {
  il_file : string;
  il_lang : string;             (* "crystal" or "gleam" *)
  il_functions : il_function list;
}

(** CFG basic block *)
type basic_block = {
  id : int;
  nodes : il_node list;
  successors : int list;        (* block IDs *)
}

(** IntMap for block lookups *)
module IntMap = Map.Make (struct type t = int let compare = compare end)

(** CFG construction error — returned when bounds are exceeded *)
type cfg_error =
  | TooManyBlocks of { actual : int; limit : int }
  | Timeout of { elapsed_ms : int; partial_blocks : int }

(** Control flow graph — built from il_function *)
type cfg = {
  cfg_fn_name : string;
  cfg_fn_params : string list;
  cfg_entry : int;              (* entry block ID *)
  cfg_blocks : basic_block list;
  cfg_block_map : basic_block IntMap.t;  (* O(1) lookup by block ID *)
  cfg_pos : pos;
}
