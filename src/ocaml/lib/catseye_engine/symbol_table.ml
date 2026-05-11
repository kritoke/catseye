(* lib/catseye_engine/symbol_table.ml
   Cross-file symbol resolution.
   
   Maps function names → defining locations using Def + Import nodes.
   Supports resolving relative Crystal requires to file paths.
   
   Used by cross-file taint propagation to connect caller → callee
   across file boundaries. *)

open Catseye_types

type symbol = {
  name : string;
  file : string;
  line : int;
  args : Security_node.arg list;
}

type t = (string, symbol list) Hashtbl.t

(** Resolve a Crystal relative require to a file path.
    "./helpers" → "src/helpers.cr" or "src/helpers/index.cr".
    Returns None for absolute/lib requires (out of scope). *)
let resolve_require (source_file : string) (require_path : string) : string option =
  let len = String.length require_path in
  if len = 0 then None
  else if require_path.[0] <> '.' then None  (* lib require — skip *)
  else begin
    let dir = Filename.dirname source_file in
    let candidate = Filename.concat dir require_path in
    let extensions = [".cr"; "/index.cr"] in
    List.find_opt (fun ext -> Sys.file_exists (candidate ^ ext)) extensions
    |> Option.map (fun ext -> candidate ^ ext)
  end

(** Build the symbol table from all nodes.
    Collects Def nodes as symbols. Also builds a require map
    from Import nodes for later resolution. *)
let build (nodes : Security_node.t list) : t =
  let tbl = Hashtbl.create 32 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Def then begin
      let sym = {
        name = n.Security_node.name;
        file = n.Security_node.file;
        line = n.Security_node.line;
        args = n.Security_node.args;
      } in
      let existing = try Hashtbl.find tbl sym.name with Not_found -> [] in
      Hashtbl.replace tbl sym.name (sym :: existing)
    end
  ) nodes;
  tbl

(** Build a map from file → list of resolved import paths. *)
let build_import_map (nodes : Security_node.t list) : (string, string list) Hashtbl.t =
  let imap = Hashtbl.create 16 in
  (* Collect import nodes grouped by source file *)
  let imports_by_file = Hashtbl.create 16 in
  List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Import then begin
      let file = n.Security_node.file in
      let reqs = try Hashtbl.find imports_by_file file with Not_found -> [] in
      Hashtbl.replace imports_by_file file (n :: reqs)
    end
  ) nodes;
  (* Resolve each require to a file path *)
  Hashtbl.iter (fun file reqs ->
    let resolved = List.filter_map (fun n ->
      match n.Security_node.args with
      | [{ Security_node.arg_type = ArgLiteral; value; _ }] ->
        resolve_require file value
      | _ -> None
    ) reqs in
    Hashtbl.replace imap file resolved
  ) imports_by_file;
  imap

(** Resolve a function call to its definition.
    1. If exactly one definition exists, use it (unambiguous).
    2. If multiple, prefer one from an imported file.
    3. If ambiguous, pick the first match. *)
let resolve (tbl : t) (_caller_file : string) (fn_name : string)
    (imported_files : string list) : symbol option =
  match Hashtbl.find_opt tbl fn_name with
  | None -> None
  | Some [sym] -> Some sym
  | Some syms ->
    (* Multiple definitions — prefer imported file *)
    let imported_set = Hashtbl.create 4 in
    List.iter (fun f -> Hashtbl.replace imported_set f ()) imported_files;
    (match List.find_opt (fun sym -> Hashtbl.mem imported_set sym.file) syms with
     | Some sym -> Some sym
     | None -> Some (List.hd syms))

(** Lookup all definitions of a function name. *)
let lookup (tbl : t) (fn_name : string) : symbol list =
  try Hashtbl.find tbl fn_name with Not_found -> []

(** Stats: return number of unique function names. *)
let size (tbl : t) : int =
  Hashtbl.length tbl
