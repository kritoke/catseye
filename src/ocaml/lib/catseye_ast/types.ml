(* src/ocaml/lib/catseye_ast/types.ml
   Unified AST schema for Catseye - single type for Gleam and Crystal
 *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(** Supported languages *)
type lang = Gleam | Crystal | Svelte | TypeScript | JavaScript | Rust | OCaml | Elixir | FSharp | Other of string

let lang_to_string = function
  | Gleam -> "gleam"
  | Crystal -> "crystal"
  | Svelte -> "svelte"
  | TypeScript -> "typescript"
  | JavaScript -> "javascript"
  | Rust -> "rust"
  | OCaml -> "ocaml"
  | Elixir -> "elixir"
  | FSharp -> "fsharp"
  | Other s -> s

(** Source position *)
module Position : sig
  type t = {
    line : int;
    column : int;
    byte_offset : int;
  }
  
  val zero : t
  val make : line:int -> column:int -> byte_offset:int -> t
end = struct
  type t = {
    line : int;
    column : int;
    byte_offset : int;
  }
  
  let zero = { line = 0; column = 0; byte_offset = 0 }
  let make ~line ~column ~byte_offset = { line; column; byte_offset }
end

(** Range in source *)
type range = {
  start : Position.t;
  end_ : Position.t;
}

(** Literal values *)
type literal =
  | LString of string
  | LInt of string
  | LFloat of string
  | LBool of bool
  | LUnit
  | LNull
  | LChar of char

(** Type annotations *)
type typ =
  | TInt
  | TFloat
  | TString
  | TBool
  | TUnit
  | TVar of string
  | TApp of typ * typ list  (* Type application, e.g., List<int> *)
  | TList of typ
  | TTuple of typ list
  | TRecord of (string * typ) list
  | TFn of typ list * typ
  | TUnknown

(** Patterns *)
type pattern =
  | PVar of string
  | PDiscard
  | PLiteral of literal
  | PTuple of pattern list
  | PList of pattern list
  | PRecord of (string * pattern) list
  | PAlias of pattern * string
  | PType of string * pattern

(** Expressions *)
type expr_value =
  | EUnit
  | ELiteral of literal
  | EVar of string
  | EFieldAccess of expr * string
  | ETuple of expr list
  | EList of expr list
  | ERecord of (string * expr) list
  | ERecordUpdate of expr * (string * expr) list
  | EApp of expr * expr list
  | EFn of pattern list * expr
  | EIf of expr * expr * expr option
  | ECase of expr * (pattern * expr) list
  | ELet of pattern * expr * expr
  | ELetAssert of pattern * expr * expr
  | EUse of pattern * expr * expr  (* use pattern <- value (continuation body) *)
  | EAssignment of expr * expr
  | EBinOp of expr * string * expr
  | EUnOp of string * expr
  | EBlock of expr list
  | EError of string
  | ETryCatchFinally of {
      try_body : expr;
      rescue_clauses : rescue_clause list;
      ensure_body : expr option;
      else_body : expr option;
    }
  | EUnknown of string

(** Rescue clause inside a try/catch/finally block *)
and rescue_clause = {
  exception_var : string option;
  matched_types : string list;
  rescue_body : expr;
}

(** An expression with location *)
and expr = {
  expr_value : expr_value;
  expr_location : range;
}

(** Build a dotted name from an expression tree.
    EVar "x" → "x", EFieldAccess(EVar "a", "b") → "a.b".
    Returns "" for non-nameable expressions. *)
let rec expr_full_name (e : expr) : string =
  match e.expr_value with
  | EVar v -> v
  | EFieldAccess (recv, field) ->
    let prefix = expr_full_name recv in
    if prefix = "" then field
    else prefix ^ "." ^ field
  | _ -> ""

(** Item (top-level definitions) *)
type item_value =
  | IFunction of string * pattern list * typ option * expr
  | IImport of string * string option
  | ITypeAlias of string * (string * typ) list * typ
  | ITypeDef of string * (string * typ) list * variant list
  | IConstant of pattern * typ option * expr
  | IExternal of string * typ
  | IModule of string * item list
  | IClass of string * item list
  | IUnknown of string

(** A type variant *)
and variant = {
  variant_name : string;
  variant_args : typ list;
  variant_tag : int;
}

(** An item with location *)
and item = {
  item_value : item_value;
  item_location : range;
}

(** Complete module representation *)
type t = {
  mod_lang : lang;
  mod_path : string;
  mod_items : item list;
  parse_errors : string list;
}