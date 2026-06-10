(* lib/catseye_ast/fsharp_mapper.ml
   Bridge from F# extractor XML output to CatseyeAST.t.

   Consumes the wire format produced by src/extractor/fsharp/Program.fs.
   Wire format version: 1 (checked at parse time).

   The F# extractor uses FSharp.Compiler.Service (FCS) to parse .fs/.fsx/.fsi
   files and emit an XML representation of the typed AST. This mapper reads
   that XML and maps it onto the shared CatseyeAST.t type for taint analysis
   and code smell detection.

   See src/extractor/fsharp/README.md for the wire format spec.
   See tests/fixtures/fsharp/spike-output.xml for a concrete example.
*)

module PE = Error

open Base
open Types

module Tsx = Tree_sitter_xml

type xml = Tsx.xml = {
  tag : string;
  attrs : (string * string) list;
  children : xml list;
  text : string;
}

let attr = Tsx.attr
let line_of = Tsx.line_of
let find = Tsx.find
let parse_xml = Tsx.parse_xml

(* ── Position helpers ─────────────────────────────────────────────── *)

(* F# extractor emits 0-based rows (srow/erow). CatseyeAST uses 1-based lines. *)
let position_of_xml (n : xml) ~field =
  let row = try Stdlib.int_of_string (attr n field) + 1 with _ -> 0 in
  Position.make ~line:row ~column:0 ~byte_offset:0

let range_of_xml (n : xml) =
  { start = position_of_xml n ~field:"srow";
    end_ = position_of_xml n ~field:"erow" }

let children_with_tag (n : xml) ~(tag : string) : xml list =
  List.filter ~f:(fun c -> c.tag = tag) n.children

(* ── XML → CatseyeAST conversion ────────────────────────────────── *)

let text_of (n : xml) = String.strip n.text

(** Get the "name" attribute from an XML node. *)
let name_attr (n : xml) = attr n "name"

(** Parse a typ from a type_* XML element. *)
let rec walk_type (n : xml) : typ =
  match n.tag with
  | "type_longident" ->
    let name = text_of n in
    (match name with
     | "int" -> TInt
     | "float" -> TFloat
     | "string" -> TString
     | "bool" -> TBool
     | "unit" -> TUnit
     | _ -> TVar name)
  | "type_fun" ->
    (match n.children with
     | [arg; ret] -> TFn ([walk_type arg], walk_type ret)
     | _ -> TUnknown)
  | "type_tuple" ->
    TTuple (List.map ~f:walk_type n.children)
  | "type_app" ->
    (match n.children with
     | base :: _ -> TVar (match base with
       | { tag = "type_longident"; _ } -> text_of base
       | _ -> "<app>")
     | [] -> TUnknown)
  | "type_anon" -> TUnknown
  | _ -> TUnknown

(** Parse a pattern from a pat_* XML element. *)
let rec walk_pat (n : xml) : pattern =
  match n.tag with
  | "pat_named" -> PVar (text_of n)
  | "pat_wild" -> PDiscard
  | "pat_unit" -> PLiteral LUnit
  | "pat_string" -> PLiteral (LString (text_of n))
  | "pat_int" -> PLiteral (LInt (text_of n))
  | "pat_bool" -> PLiteral (LBool (String.equal (String.lowercase (text_of n)) "true"))
  | "pat_tuple" ->
    PTuple (List.map ~f:walk_pat n.children)
  | "pat_longident" ->
    let name = name_attr n in
    (* If there are child patterns, this is a constructor pattern like Circle r *)
    let inner_pats = List.map ~f:walk_pat n.children in
    (match inner_pats with
     | [] -> PVar name
     | [single] -> PType (name, single)
     | multiple -> PType (name, PTuple multiple))
  | "pat_typed" ->
    (* Typed pattern: <pat_typed> <pat_named>x</pat_named> <type_longident>T</type_longident> </pat_typed> *)
    let inner = List.filter ~f:(fun c -> String.is_prefix c.tag ~prefix:"pat_") n.children in
    let ty = List.filter ~f:(fun c -> String.is_prefix c.tag ~prefix:"type_") n.children in
    let pat = match inner with [p] -> walk_pat p | _ -> PDiscard in
    (match ty with
     | [{ tag = "type_longident"; _ } as t] -> PType (text_of t, pat)
     | _ -> pat)
  | "pat_listcons" ->
    (* List cons pattern — treat as PList for now *)
    PList (List.map ~f:walk_pat n.children)
  | _ -> PDiscard

(** Parse an expression from an expr_* XML element. *)
let rec walk_expr (n : xml) (file : string) : expr =
  let loc = range_of_xml n in
  let v = match n.tag with
    (* Identifiers *)
    | "expr_ident" -> EVar (text_of n)
    | "expr_longident" -> EVar (text_of n)

    (* Literals *)
    | "expr_string" -> ELiteral (LString (text_of n))
    | "expr_int" -> ELiteral (LInt (text_of n))
    | "expr_float" -> ELiteral (LFloat (text_of n))
    | "expr_bool" -> ELiteral (LBool (String.equal (String.lowercase (text_of n)) "true"))
    | "expr_unit" -> ELiteral LUnit
    | "expr_null" -> ELiteral LNull

    (* Function application *)
    | "expr_app" ->
      let child_exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match child_exprs with
       | fn :: args -> EApp (fn, args)
       | [] -> EUnit)

    (* Let binding in expression *)
    | "expr_let" ->
      let bindings = children_with_tag n ~tag:"binding" in
      let body_children = List.filter ~f:(fun c -> c.tag <> "binding") n.children in
      let body = match body_children with
        | [b] -> walk_expr b file
        | [] -> { expr_value = EUnit; expr_location = loc }
        | multiple ->
          let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
          { expr_value = EBlock exprs; expr_location = loc }
      in
      (match bindings with
       | [b] ->
         let pat = match children_with_tag b ~tag:"pat_named" with
           | [p] -> PVar (text_of p)
           | _ ->
             (* Try pat_longident for function bindings *)
             (match children_with_tag b ~tag:"pat_longident" with
              | [p] -> PVar (name_attr p)
              | _ -> PDiscard)
         in
         let rhs_children = List.filter ~f:(fun c ->
           not (String.is_prefix c.tag ~prefix:"pat_") && c.tag <> "binding"
         ) b.children in
         let rhs = match rhs_children with
           | [r] -> walk_expr r file
           | [] -> { expr_value = EUnit; expr_location = range_of_xml b }
           | multiple ->
             let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
             { expr_value = EBlock exprs; expr_location = range_of_xml b }
         in
         ELet (pat, rhs, body)
       | _ -> body.expr_value)

    (* If/then/else *)
    | "expr_if" ->
      let children_exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match children_exprs with
       | [cond; then_] -> EIf (cond, then_, None)
       | [cond; then_; else_] -> EIf (cond, then_, Some else_)
       | _ -> EUnknown "expr_if")

    (* Match expression *)
    | "expr_match" ->
      let scrutinee = match n.children with
        | first :: _ when first.tag <> "match_clause" -> walk_expr first file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      let clauses = children_with_tag n ~tag:"match_clause" in
      let cases = List.map ~f:(fun clause ->
        let pat = match List.filter ~f:(fun c -> String.is_prefix c.tag ~prefix:"pat_") clause.children with
          | [p] -> walk_pat p
          | _ -> PDiscard
        in
        let body_children = List.filter ~f:(fun c ->
          not (String.is_prefix c.tag ~prefix:"pat_")
        ) clause.children in
        let body = match body_children with
          | [b] -> walk_expr b file
          | [] -> { expr_value = EUnit; expr_location = range_of_xml clause }
          | multiple ->
            let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
            { expr_value = EBlock exprs; expr_location = range_of_xml clause }
        in
        (pat, body)
      ) clauses in
      ECase (scrutinee, cases)

    (* Lambda *)
    | "expr_lambda" ->
      let body = match n.children with
        | [b] -> walk_expr b file
        | [] -> { expr_value = EUnit; expr_location = loc }
        | multiple ->
          let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
          { expr_value = EBlock exprs; expr_location = loc }
      in
      EFn ([PDiscard], body)

    (* Tuple *)
    | "expr_tuple" ->
      ETuple (List.map ~f:(fun c -> walk_expr c file) n.children)

    (* List *)
    | "expr_list" ->
      EList (List.map ~f:(fun c -> walk_expr c file) n.children)

    (* Record construction *)
    | "expr_record" ->
      let fields = List.filter_map ~f:(fun c ->
        if c.tag = "record_field" then
          let fname = name_attr c in
          let value_children = List.filter ~f:(fun cc ->
            cc.tag <> "record_field"
          ) c.children in
          match value_children with
          | [v] -> Some (fname, walk_expr v file)
          | _ -> None
        else None
      ) n.children in
      ERecord fields

    (* Field access: expr_dotget *)
    | "expr_dotget" ->
      let field = name_attr n in
      let obj = match n.children with
        | [o] -> walk_expr o file
        | _ -> { expr_value = EUnit; expr_location = loc }
      in
      EFieldAccess (obj, field)

    (* Field set: expr_dotset *)
    | "expr_dotset" ->
      let field = name_attr n in
      let obj, value = match n.children with
        | [o; v] -> (walk_expr o file, walk_expr v file)
        | _ -> ({ expr_value = EUnit; expr_location = loc },
                { expr_value = EUnit; expr_location = loc })
      in
      EAssignment ({ expr_value = EFieldAccess (obj, field); expr_location = loc }, value)

    (* Sequential expressions *)
    | "expr_seq" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EBlock exprs)

    (* For-each loop *)
    | "expr_foreach" ->
      (* For-each becomes a block with the body expression *)
      let body_exprs = List.filter ~f:(fun c ->
        c.tag <> "pat_named" && c.tag <> "expr_ident"
      ) n.children in
      let exprs = List.map ~f:(fun c -> walk_expr c file) body_exprs in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EBlock exprs)

    (* For loop *)
    | "expr_for" ->
      let body = match n.children with
        | [b] -> walk_expr b file
        | [] -> { expr_value = EUnit; expr_location = loc }
        | multiple ->
          let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
          { expr_value = EBlock exprs; expr_location = loc }
      in
      body.expr_value

    (* While loop *)
    | "expr_while" ->
      let children_exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match children_exprs with
       | [cond; body] -> EIf (cond, body, None)
       | _ -> EUnknown "expr_while")

    (* Computation expression (async, etc.) *)
    | "expr_computationexpr" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EBlock exprs)

    (* Yield/return in computation expression *)
    | "expr_yieldorreturn" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EBlock exprs)

    (* Do expression *)
    | "expr_do" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EBlock exprs)

    (* Assert *)
    | "expr_assert" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> EApp ({ expr_value = EVar "assert"; expr_location = loc }, [single])
       | _ -> EUnknown "expr_assert")

    (* Type application *)
    | "expr_typeapp" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | single :: _ -> single.expr_value
       | [] -> EUnknown "expr_typeapp")

    (* New expression *)
    | "expr_new" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | arg :: _ -> EApp ({ expr_value = EVar "new"; expr_location = loc }, [arg])
       | [] -> EUnknown "expr_new")

    (* Type test *)
    | "expr_typetest" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EUnknown "expr_typetest")

    (* Quote *)
    | "expr_quote" ->
      let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
      (match exprs with
       | [single] -> single.expr_value
       | _ -> EUnknown "expr_quote")

    (* Catch-all for unknown expression types *)
    | _ ->
      (* If the node has children, try to walk them *)
      if n.children <> [] then
        let exprs = List.map ~f:(fun c -> walk_expr c file) n.children in
        (match exprs with
         | [single] -> single.expr_value
         | _ -> EBlock exprs)
      else EUnknown n.tag
  in
  { expr_value = v; expr_location = loc }

(** Parse a binding XML element into an item. *)
let walk_binding (n : xml) (file : string) : item option =
  let loc = range_of_xml n in
  (* Get the name from the pattern *)
  let name_opt =
    match children_with_tag n ~tag:"pat_named" with
    | [p] -> Some (text_of p)
    | _ ->
      (match children_with_tag n ~tag:"pat_longident" with
       | [p] -> Some (name_attr p)
       | _ -> None)
  in
  match name_opt with
  | None -> None
  | Some name ->
    (* Check if this is a function binding (has child patterns in pat_longident) *)
    let has_params = match children_with_tag n ~tag:"pat_longident" with
      | [p] -> List.length p.children > 0
      | _ -> false
    in
    (* Get the body expression — everything that's not a pattern *)
    let body_children = List.filter ~f:(fun c ->
      not (String.is_prefix c.tag ~prefix:"pat_")
    ) n.children in
    let body = match body_children with
      | [b] -> walk_expr b file
      | [] -> { expr_value = EUnit; expr_location = loc }
      | multiple ->
        let exprs = List.map ~f:(fun c -> walk_expr c file) multiple in
        { expr_value = EBlock exprs; expr_location = loc }
    in
    if has_params then
      Some { item_value = IFunction (name, [PDiscard], None, body); item_location = loc }
    else
      Some { item_value = IConstant (PVar name, None, body); item_location = loc }

(** Parse a type_defn XML element into an item. *)
let walk_type_defn (n : xml) : item =
  let loc = range_of_xml n in
  let name = name_attr n in
  (* Check if it's a record or union *)
  let is_record = List.exists ~f:(fun c -> c.tag = "record_repr") n.children in
  let is_union = List.exists ~f:(fun c -> c.tag = "union_repr") n.children in
  if is_record then
    let record_repr = List.find_exn ~f:(fun c -> c.tag = "record_repr") n.children in
    let fields = List.filter_map ~f:(fun c ->
      if c.tag = "field" then
        let fname = name_attr c in
        let ty = match children_with_tag c ~tag:"type_longident" with
          | [t] -> walk_type t
          | _ -> TUnknown
        in
        Some (fname, ty)
      else None
    ) record_repr.children in
    { item_value = ITypeDef (name, fields, []); item_location = loc }
  else if is_union then
    let union_repr = List.find_exn ~f:(fun c -> c.tag = "union_repr") n.children in
    let variants = List.filter_map ~f:(fun c ->
      if c.tag = "union_case" then
        let vname = name_attr c in
        Some { variant_name = vname; variant_args = []; variant_tag = 0 }
      else None
    ) union_repr.children in
    { item_value = ITypeDef (name, [], variants); item_location = loc }
  else
    { item_value = ITypeAlias (name, [], TUnknown); item_location = loc }

(** Parse an open statement into an item. *)
let walk_open (n : xml) : item =
  let loc = range_of_xml n in
  let module_name = text_of n in
  { item_value = IImport (module_name, None); item_location = loc }

(** Walk a module_or_namespace element and produce items. *)
let rec walk_module (n : xml) (file : string) : item list =
  List.concat_map ~f:(fun c -> walk_decl c file) n.children

(** Walk a top-level declaration and produce items. *)
and walk_decl (n : xml) (file : string) : item list =
  match n.tag with
  | "open" -> [walk_open n]
  | "type_defn" -> [walk_type_defn n]
  | "binding" ->
    (match walk_binding n file with
     | Some item -> [item]
     | None -> [])
  | "module_or_namespace" -> walk_module n file
  | "exception_decl" -> []
  | _ ->
    (* Recurse into unknown containers *)
    List.concat_map ~f:(fun c -> walk_decl c file) n.children

(* ── Extractor binary resolution ─────────────────────────────────── *)

(** Find the F# extractor binary.
    Search order:
    1. CATSEYE_FSHARP_EXTRACTOR env var
    2. dotnet run from src/extractor/fsharp/ (development mode)
    3. catseye-fsharp-extractor in PATH
*)
let find_extractor () : string option =
  (* 1. Env var *)
  (match Stdlib.Sys.getenv "CATSEYE_FSHARP_EXTRACTOR" with
   | path -> if Stdlib.Sys.file_exists path then Some path else None
   | exception Stdlib.Not_found ->
     (* 2. dotnet run from project source *)
     let src_dir = Stdlib.Filename.concat
       (Stdlib.Filename.dirname (Stdlib.Sys.executable_name))
       "../../../src/extractor/fsharp" in
     let fsproj = Stdlib.Filename.concat src_dir "Catseye.FSharp.Extractor.fsproj" in
     if Stdlib.Sys.file_exists fsproj then
       Some (Stdlib.Printf.sprintf "dotnet run --project %s --" (Stdlib.Filename.quote src_dir))
     else
       (* 3. In PATH *)
       Some "catseye-fsharp-extractor")

(* ── Parse entry point ─────────────────────────────────────────────── *)

let parse_file ~(path : string) : (t, PE.parse_error) Result.t =
  if not (Stdlib.Filename.check_suffix path ".fs"
       || Stdlib.Filename.check_suffix path ".fsx"
       || Stdlib.Filename.check_suffix path ".fsi") then
    Error (PE.make_error ~file:path ~message:"Not an F# file (.fs/.fsx/.fsi)")
  else
    match find_extractor () with
    | None ->
      Error (PE.make_error ~file:path ~message:"F# extractor not found. Set CATSEYE_FSHARP_EXTRACTOR or install dotnet SDK.")
    | Some extractor ->
      let cmd = Stdlib.Printf.sprintf "%s %s 2>/dev/null"
        extractor
        (Stdlib.Filename.quote path) in
      try
        let ic = Unix.open_process_in cmd in
        let xml_str = Stdlib.Buffer.create 16384 in
        (try while true do Stdlib.Buffer.add_channel xml_str ic 8192 done
         with Stdlib.End_of_file -> ());
        let status = Unix.close_process_in ic in
        match status with
        | Unix.WEXITED 0 ->
          let doc = parse_xml (Stdlib.Buffer.contents xml_str) in
          (* Check wire format version *)
          let version = attr doc "version" in
          if version <> "" && version <> "1" then
            Error (PE.make_error ~file:path
              ~message:(Stdlib.Printf.sprintf "F# extractor wire format version '%s' not supported (expected '1')" version))
          else begin
            (* Find the module_or_namespace element *)
            let modules = find doc ~tag:"module_or_namespace" in
            let items = match modules with
              | m :: _ -> walk_module m path
              | [] ->
                (* No module wrapper — walk top-level children *)
                List.concat_map ~f:(fun c -> walk_decl c path) doc.children
            in
            Ok { mod_lang = FSharp; mod_path = path; mod_items = items; parse_errors = [] }
          end
        | Unix.WEXITED 2 ->
          Error (PE.make_error ~file:path ~message:"F# parse error (extractor exited with code 2)")
        | _ ->
          Error (PE.make_error ~file:path ~message:"F# extractor failed")
      with Sys_error msg ->
        Error (PE.make_error ~file:path ~message:("F# extractor error: " ^ msg))
