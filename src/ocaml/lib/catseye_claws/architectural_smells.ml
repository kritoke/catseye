(* lib/catseye_claws/architectural_smells.ml
   Architectural smell detectors: GodClass, InappropriateIntimacy, LCOM4.

   Uses Jane Street Base with explicit Stdlib qualification to avoid shadowing. *)

open Base

(* Shadow Base comparison operators with Stdlib versions *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_ast.Types
open Catseye_types

(* ── Helpers ────────────────────────────────────────────────────────── *)

let make_finding (file : string) (line : int) (lang : string) (rule : string)
    (severity : string) (message : string) : Finding.t =
  { Finding.rule; severity; file; line; message
  ; flow = [{ Finding.file; line; message }]
  ; language = lang
  ; dependency = None; reachability = None; suggestion = None
  }

(* ── LCOM4: Lack of Cohesion of Methods ─────────────────────────────── *)

(** Get all method names from a class definition. *)
let get_class_methods (items : item list) : string list =
  let rec loop acc = function
    | [] -> Stdlib.List.rev acc
    | item :: rest ->
      (match item.item_value with
       | IFunction (name, _, _, _) -> loop (name :: acc) rest
       | IClass (_, sub_items) -> loop acc (sub_items @ rest)
       | IModule (_, sub_items) -> loop acc (sub_items @ rest)
       | _ -> loop acc rest)
  in
  loop [] items

(** Extract @-prefixed field names from an expression. *)
let rec extract_field_accesses (e : expr) : string list =
  match e.expr_value with
  | EFieldAccess (base, field) ->
    let base_fields = extract_field_accesses base in
    field :: base_fields
  | EAssignment (base, value) ->
    extract_field_accesses base @ extract_field_accesses value
  | EApp (fn, args) ->
    extract_field_accesses fn @ Stdlib.List.concat_map extract_field_accesses args
  | EBlock es -> Stdlib.List.concat_map extract_field_accesses es
  | ELet (_, e1, e2) -> extract_field_accesses e1 @ extract_field_accesses e2
  | EIf (cond, then_e, else_opt) ->
    extract_field_accesses cond @ extract_field_accesses then_e
    @ (match else_opt with Some e -> extract_field_accesses e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> extract_field_accesses body) branches
  | ETuple es | EList es -> Stdlib.List.concat_map extract_field_accesses es
  | ERecord fields -> Stdlib.List.concat_map (fun (_, v) -> extract_field_accesses v) fields
  | EBinOp (e1, _, e2) -> extract_field_accesses e1 @ extract_field_accesses e2
  | _ -> []

(** Build method-to-fields matrix for LCOM4. *)
let build_method_field_matrix (items : item list) : (string * string list) list =
  let rec extract_methods acc = function
    | [] -> Stdlib.List.rev acc
    | item :: rest ->
      (match item.item_value with
       | IFunction (name, _, _, body) ->
         let fields = extract_field_accesses body
                    |> Stdlib.List.filter (fun f -> String.length f > 0 && Char.equal f.[0] '@')
                    |> Stdlib.List.sort_uniq String.compare
         in
         extract_methods ((name, fields) :: acc) rest
       | IClass (_, sub_items) -> extract_methods acc (sub_items @ rest)
       | IModule (_, sub_items) -> extract_methods acc (sub_items @ rest)
       | _ -> extract_methods acc rest)
  in
  extract_methods [] items

(** Calculate LCOM4 (Lack of Cohesion of Methods - Henderson-Sellers).
    LCOM4 = number of disconnected method groups - 1 *)
let calculate_lcom4 (items : item list) : float =
  let methods_fields = build_method_field_matrix items in
  let method_count = Stdlib.List.length methods_fields in
  
  if method_count < 2 then Float.of_int 0
  else begin
    (* Build adjacency list for method-method connections using list *)
    let rec build_graph = function
      | [] -> []
      | (m1, f1) :: rest ->
        let connections = Stdlib.List.filter (fun (_, f2) ->
          Stdlib.List.exists (fun field -> Stdlib.List.mem field f2) f1
        ) rest in
        let connected_to = Stdlib.List.map fst connections in
        (m1, connected_to) :: build_graph rest
    in
    let graph = build_graph methods_fields in
    
    (* Count connected components using BFS on list representation *)
    let visited = ref [] in
    let rec bfs = function
      | [] -> ()
      | node :: rest ->
        if Stdlib.List.mem node !visited then
          bfs rest
        else begin
          visited := node :: !visited;
          let neighbors = (try Stdlib.List.assoc node graph with Stdlib.Not_found -> []) in
          bfs (neighbors @ rest)
        end
    in
    
    let rec count_components = function
      | [] -> 0
      | (name, _) :: _ ->
        if not (Stdlib.List.mem name !visited) then begin
          bfs [name];
          1 + count_components (Stdlib.List.filter (fun (n, _) -> not (Stdlib.List.mem n !visited)) methods_fields)
        end else
          count_components (Stdlib.List.filter (fun (n, _) -> not (Stdlib.List.mem n !visited)) methods_fields)
    in
    
    let components = count_components methods_fields in
    Float.of_int components -. Float.of_int 1
  end

(* ── God Class Detection ────────────────────────────────────────────── *)

(** Check for God Class / Blob Anti-Pattern.
    Thresholds: LCOM4 > 2.0 AND method_count > 20 *)
let check_god_class (modules : t list) : Finding.t list =
  let check_in_module (mod_ : t) : Finding.t list =
    let lang = match mod_.mod_lang with
      | Gleam -> "gleam" 
      | Crystal -> "crystal" 
      | Svelte -> "svelte"
      | TypeScript -> "typescript" 
      | Rust -> "rust" 
      | JavaScript -> "javascript"
      | OCaml -> "ocaml"
      | Elixir -> "elixir"
      | FSharp -> "fsharp"
      | Other s -> s
    in
    let check_items items file findings =
      let rec loop acc = function
        | [] -> Stdlib.List.rev acc
        | item :: rest ->
          let new_findings = (match item.item_value with
            | IClass (name, class_items) ->
              let method_count = Stdlib.List.length (get_class_methods class_items) in
              let lcom4 = calculate_lcom4 class_items in
              let threshold = Float.of_int 2 in
              let is_god_class = Float.(>) lcom4 threshold && method_count > 20 in
              if is_god_class then
                [make_finding file item.item_location.start.line 
                            lang "GodClass" "High"
                   (Printf.sprintf "Class '%s' appears to be a God Class (LCOM4=%.2f, %d methods). Consider splitting into smaller classes."
                      name lcom4 method_count)]
              else []
            | IModule (_, sub_items) -> loop [] (sub_items @ rest)
            | _ -> loop [] rest)
          in
          loop (new_findings @ acc) rest
      in
      loop findings items
    in
    check_items mod_.mod_items mod_.mod_path []
  in
  Stdlib.List.concat_map check_in_module modules

(* ── Inappropriate Intimacy Detection ──────────────────────────────── *)

(** Find field accesses that look like sibling class internal access. *)
let rec find_sibling_field_accesses (e : expr) : string list =
  match e.expr_value with
  | EFieldAccess (base, field) ->
    let base_accesses = find_sibling_field_accesses base in
    if String.length field > 0 then
      let code = Char.to_int (String.get field 0) in
      let is_upper = code >= 65 && code <= 90 in
      if is_upper || code = 64 then  (* 64 = '@' *)
        field :: base_accesses
      else base_accesses
    else base_accesses
  | EApp (fn, args) ->
    find_sibling_field_accesses fn @ Stdlib.List.concat_map find_sibling_field_accesses args
  | EBlock es -> Stdlib.List.concat_map find_sibling_field_accesses es
  | ELet (_, e1, e2) -> find_sibling_field_accesses e1 @ find_sibling_field_accesses e2
  | EIf (cond, then_e, else_opt) ->
    find_sibling_field_accesses cond @ find_sibling_field_accesses then_e
    @ (match else_opt with Some e -> find_sibling_field_accesses e | None -> [])
  | ECase (_, branches) ->
    Stdlib.List.concat_map (fun (_, body) -> find_sibling_field_accesses body) branches
  | _ -> []

let check_inappropriate_intimacy (modules : t list) : Finding.t list =
  let check_in_items items file =
    let rec loop acc = function
      | [] -> Stdlib.List.rev acc
      | item :: rest ->
        let new_findings = (match item.item_value with
          | IFunction (name, _, _, body) ->
            let accesses = find_sibling_field_accesses body
                         |> Stdlib.List.filter (fun f -> 
                              not (String.equal f name || String.equal f "@self" || String.equal f "@this"))
            in
            if Stdlib.List.length accesses > 3 then
              [make_finding file item.item_location.start.line 
                           "" "InappropriateIntimacy" "Medium"
                 (Printf.sprintf "Method '%s' directly accesses %d fields that may be sibling class internals."
                    name (Stdlib.List.length accesses))]
            else []
          | IClass (_, sub_items) -> loop [] (sub_items @ rest)
          | IModule (_, sub_items) -> loop [] (sub_items @ rest)
          | _ -> loop [] rest)
        in
        loop (new_findings @ acc) rest
    in
    loop [] items
  in
  Stdlib.List.concat_map (fun (mod_ : t) ->
    check_in_items mod_.mod_items mod_.mod_path
  ) modules