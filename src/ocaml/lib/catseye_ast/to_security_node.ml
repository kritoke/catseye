(* lib/catseye_ast/to_security_node.ml
   Bridge: derive Security_node.t list from CatseyeAST.t.
 
   This allows the taint engine and Claws to consume CatseyeAST.t
   without rewriting their 529+ Security_node.t references.
 
   Pipeline: extractor → CatseyeAST.t → to_security_node → Security_node.t → engine
 
   Used when the orchestrator wants a single-parse pipeline instead of
   running extractors and mappers separately.
 *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

open Catseye_types
open Types

let lang_to_string = function
  | Gleam -> "gleam"
  | Crystal -> "crystal"
  | Svelte -> "svelte"
  | TypeScript -> "typescript"
  | JavaScript -> "javascript"
  | Rust -> "rust"
  | OCaml -> "ocaml"
  | Elixir -> "elixir"
  | Other s -> s

(* ── Helpers ────────────────────────────────────────────────────────── *)

let make_node ~node_type ~name ~args ~line ~file ~language : Security_node.t = {
  Security_node.node_type;
  name;
  args;
  line;
  taint = false;
  file;
  language;
  metadata = [];
}

let make_arg ~arg_type ~value : Security_node.arg = {
  Security_node.arg_type;
  value;
  field = "";
}

(* ── Pattern → arg extraction ───────────────────────────────────────── *)

let rec pattern_to_arg (pat : pattern) : Security_node.arg =
  match pat with
  | PVar v -> make_arg ~arg_type:Security_node.ArgVar ~value:v
  | PDiscard -> make_arg ~arg_type:Security_node.ArgVar ~value:"_"
  | PLiteral lit ->
    let value = match lit with
      | LString s -> s
      | LInt i -> i
      | LFloat f -> f
      | LBool b -> Stdlib.string_of_bool b
      | LUnit -> "()"
      | LNull -> "nil"
      | LChar c -> String.make 1 c
    in
    make_arg ~arg_type:Security_node.ArgLiteral ~value
  | PTuple _ -> make_arg ~arg_type:Security_node.ArgUnknown ~value:"<tuple>"
  | PList _ -> make_arg ~arg_type:Security_node.ArgUnknown ~value:"<list>"
  | PRecord _ -> make_arg ~arg_type:Security_node.ArgUnknown ~value:"<record>"
  | PAlias (p, _) -> pattern_to_arg p
  | PType (_, p) -> pattern_to_arg p

let patterns_to_args (pats : pattern list) : Security_node.arg list =
  List.map ~f:pattern_to_arg pats

(* ── Expression name extraction ─────────────────────────────────────── *)

let rec expr_full_name (e : expr) : string =
  match e.expr_value with
  | EVar v -> v
  | EFieldAccess (recv, field) ->
    let prefix = expr_full_name recv in
    if prefix = "" then field
    else prefix ^ "." ^ field
  | _ -> ""

(* ── Expression → node list ────────────────────────────────────────── *)

let rec walk_expr (e : expr) (file : string) (lang : string)
    : Security_node.t list =
  match e.expr_value with
  | EUnit | ELiteral _ | EVar _ ->
    (* These are too small to emit as standalone nodes — they appear as args *)
    []
  | EFieldAccess (recv, field) ->
    let recv_name = expr_full_name recv in
    let full = if recv_name = "" then field else recv_name ^ "." ^ field in
    let call_node = make_node
      ~node_type:Security_node.Call ~name:full ~args:[]
      ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr recv file lang @ [call_node]
  | ETuple es | EList es ->
    List.concat_map ~f:(fun e -> walk_expr e file lang) es
  | ERecord fields ->
    List.concat_map ~f:(fun (_, e) -> walk_expr e file lang) fields
  | ERecordUpdate (e, fields) ->
    walk_expr e file lang @
    List.concat_map ~f:(fun (_, e) -> walk_expr e file lang) fields
  | EApp (fn, args) ->
    let fn_name = expr_full_name fn in
    let fn_args = List.map ~f:(fun a ->
      match a.expr_value with
      | EVar v -> make_arg ~arg_type:Security_node.ArgVar ~value:v
      | ELiteral lit ->
        let value = match lit with
          | LString s -> s
          | LInt i -> i
          | LFloat f -> f
          | LBool b -> Stdlib.string_of_bool b
          | LUnit -> "()"
          | LNull -> "nil"
          | LChar c -> String.make 1 c
        in
        make_arg ~arg_type:Security_node.ArgLiteral ~value
      | _ ->
        let inner_name = expr_full_name a in
        if inner_name <> "" then
          make_arg ~arg_type:Security_node.ArgCall ~value:inner_name
        else
          make_arg ~arg_type:Security_node.ArgUnknown ~value:"<expr>"
    ) args in
    let call_node = make_node
      ~node_type:Security_node.Call ~name:fn_name ~args:fn_args
      ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr fn file lang @ List.concat_map ~f:(fun a -> walk_expr a file lang) args @ [call_node]
  | EFn (_, body) ->
    walk_expr body file lang
  | EIf (_cond, then_, else_) ->
    let control_node = make_node
      ~node_type:Security_node.Control
      ~name:(if else_ = None then "if" else "if_else")
      ~args:[] ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr then_ file lang @
    (match else_ with Some e -> walk_expr e file lang | None -> []) @
    [control_node]
  | ECase (_target, branches) ->
    let control_node = make_node
      ~node_type:Security_node.Control ~name:"case" ~args:[]
      ~line:e.expr_location.start.line ~file ~language:lang in
    List.concat_map ~f:(fun (_pat, body) -> walk_expr body file lang) branches @
    [control_node]
  | ELet (pat, e1, e2) | ELetAssert (pat, e1, e2) ->
    let var_name = match pat with
      | PVar v -> v
      | _ -> "_"
    in
    let assign_args = match e1.expr_value with
      | EVar v -> [make_arg ~arg_type:Security_node.ArgVar ~value:v]
      | ELiteral lit ->
        let value = match lit with
          | LString s -> s
          | LInt i -> i
          | LFloat f -> f
          | LBool b -> Stdlib.string_of_bool b
          | LUnit -> "()"
          | LNull -> "nil"
          | LChar c -> String.make 1 c
        in
        [make_arg ~arg_type:Security_node.ArgLiteral ~value]
      | _ ->
        let inner_name = expr_full_name e1 in
        if inner_name <> "" then
          [make_arg ~arg_type:Security_node.ArgCall ~value:inner_name]
        else []
    in
    let assign_node = make_node
      ~node_type:Security_node.Assign ~name:var_name ~args:assign_args
      ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr e1 file lang @ [assign_node] @ walk_expr e2 file lang
  | EAssignment (e1, e2) ->
    let name = expr_full_name e1 in
    (* Track the RHS call name so the taint engine can propagate through it *)
    let rhs_name = expr_full_name e2 in
    let assign_args =
      if rhs_name <> "" then
        [make_arg ~arg_type:Security_node.ArgCall ~value:rhs_name]
      else []
    in
    let assign_node = make_node
      ~node_type:Security_node.Assign ~name ~args:assign_args
      ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr e1 file lang @ walk_expr e2 file lang @ [assign_node]
  | EBinOp (e1, _op, e2) ->
    walk_expr e1 file lang @ walk_expr e2 file lang
  | EUnOp (_op, e1) ->
    walk_expr e1 file lang
  | EBlock es ->
    List.concat_map ~f:(fun e -> walk_expr e file lang) es
  | EError msg ->
    let term_node = make_node
      ~node_type:Security_node.Terminator ~name:"raise" ~args:[make_arg ~arg_type:Security_node.ArgLiteral ~value:msg]
      ~line:e.expr_location.start.line ~file ~language:lang in
    [term_node]
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body } ->
    let try_nodes = walk_expr try_body file lang in
    let rescue_nodes = List.concat_map ~f:(fun c -> walk_expr c.rescue_body file lang) rescue_clauses in
    let ensure_nodes = match ensure_body with Some e -> walk_expr e file lang | None -> [] in
    let else_nodes = match else_body with Some e -> walk_expr e file lang | None -> [] in
    try_nodes @ rescue_nodes @ ensure_nodes @ else_nodes
  | EUse (_pat, val_expr, body) ->
    (* use pattern <- value; body
       Treat as a call node so taint propagation works through the value *)
    let name = "use" in
    let assign_node = make_node
      ~node_type:Security_node.Assign ~name ~args:[]
      ~line:e.expr_location.start.line ~file ~language:lang in
    let call_node = make_node
      ~node_type:Security_node.Call ~name ~args:[]
      ~line:e.expr_location.start.line ~file ~language:lang in
    walk_expr val_expr file lang @ walk_expr body file lang @ [assign_node; call_node]
  | EUnknown _ -> []

(* ── Item → node list ───────────────────────────────────────────────── *)

let rec walk_item (item : item) (file : string) (lang : string)
    : Security_node.t list =
  let line = item.item_location.start.line in
  match item.item_value with
  | IFunction (name, params, _ret_type, body) ->
    let def_args = patterns_to_args params in
    let def_node = make_node
      ~node_type:Security_node.Def ~name ~args:def_args
      ~line ~file ~language:lang in
    let body_nodes = walk_expr body file lang in
    def_node :: body_nodes
  | IImport (mod_name, _) ->
    let import_node = make_node
      ~node_type:Security_node.Import ~name:"require"
      ~args:[make_arg ~arg_type:Security_node.ArgLiteral ~value:mod_name]
      ~line ~file ~language:lang in
    [import_node]
  | IClass (name, items) ->
    let class_node = make_node
      ~node_type:Security_node.Class ~name ~args:[]
      ~line ~file ~language:lang in
    class_node :: List.concat_map ~f:(fun i -> walk_item i file lang) items
  | IModule (name, items) ->
    let module_node = make_node
      ~node_type:Security_node.Module ~name ~args:[]
      ~line ~file ~language:lang in
    module_node :: List.concat_map ~f:(fun i -> walk_item i file lang) items
  | ITypeDef (name, _vars, _variants) ->
    [make_node ~node_type:Security_node.Enum ~name ~args:[] ~line ~file ~language:lang]
  | IConstant (pat, _, expr) ->
    let var_name = match pat with
      | PVar v -> v
      | _ -> "_"
    in
    let assign_node = make_node
      ~node_type:Security_node.Assign ~name:var_name
      ~args:[make_arg ~arg_type:Security_node.ArgUnknown ~value:(expr_full_name expr)]
      ~line ~file ~language:lang in
    walk_expr expr file lang @ [assign_node]
  | IExternal _ | ITypeAlias _ | IUnknown _ -> []

(* ── Main entry point ───────────────────────────────────────────────── *)

(** Derive a Security_node.t list from a CatseyeAST.t module.
    Produces nodes in the same format as the extractors, enabling the
    taint engine and Claws to work with CatseyeAST.t as input. *)
let derive (mod_ : t) : Security_node.t list =
  let lang = lang_to_string mod_.mod_lang in
  let file = mod_.mod_path in
  List.concat_map ~f:(fun item -> walk_item item file lang) mod_.mod_items
