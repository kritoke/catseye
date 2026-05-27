(* lib/catseye_claws/ast_scope.ml
   Shared AST scope type and builder for Claws detectors.

   Replaces the duplicated Security_node.t-based build_scopes across
   complexity.ml, anatomy.ml, extra_smells.ml, concurrency.ml with
   a single CatseyeAST-native scope builder.
*)

open Base
open Catseye_ast.Types

(* Use old List API via alias - Base.List.concat_map requires ~f label *)
module OldList = struct
  let concat_map = Stdlib.List.concat_map
  let filter = Stdlib.List.filter
  let filter_map = Stdlib.List.filter_map
  let length = Stdlib.List.length
end

(** An AST-native function scope.
    Unlike the Security_node scope which uses line-range heuristics,
    this scope comes directly from the IFunction definition. *)
type ast_scope = {
  fn_name : string;
  params : pattern list;
  body : expr;
  file : string;
  lang : string;
  line : int;
  (* Parent context — which class/module contains this function *)
  parent : string option;
}

(** Recursively walk items to find all IFunction definitions,
    tracking parent class/module context. *)
let rec collect_scopes (items : item list) (file : string) (lang : string)
    (parent : string option) : ast_scope list =
  OldList.concat_map (fun (item : item) ->
    let line = item.item_location.start.line in
    match item.item_value with
    | IFunction (name, params, _, body) ->
      [{ fn_name = name; params; body; file; lang; line; parent }]
    | IClass (name, children) ->
      collect_scopes children file lang (Some name)
    | IModule (name, children) ->
      collect_scopes children file lang (Some name)
    | _ -> []
  ) items

(** Build AST scopes from a list of parsed modules. *)
let build (modules : Catseye_ast.Types.t list) : ast_scope list =
  OldList.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    let lang = match mod_.mod_lang with
      | Gleam -> "gleam"
      | Crystal -> "crystal"
      | Svelte -> "svelte"
      | TypeScript -> "typescript"
      | JavaScript -> "javascript"
      | Rust -> "rust"
      | OCaml -> "ocaml"
      | Elixir -> "elixir"
      | Other s -> s
    in
    collect_scopes mod_.mod_items mod_.mod_path lang None
  ) modules

(** Count IFunction items under a class/module (for GodObject detection). *)
let count_methods_in_parent (modules : Catseye_ast.Types.t list)
    : (string * string * int) list =
  let rec count_in_items (items : item list) (file : string) =
    OldList.concat_map (fun (item : item) ->
      match item.item_value with
      | IClass (name, children) ->
        let fn_count = OldList.filter_map (fun (c : item) ->
          match c.item_value with IFunction _ -> Some () | _ -> None
        ) children |> OldList.length in
        (name, file, fn_count) :: count_in_items children file
      | IModule (name, children) ->
        let fn_count = OldList.filter_map (fun (c : item) ->
          match c.item_value with IFunction _ -> Some () | _ -> None
        ) children |> OldList.length in
        (name, file, fn_count) :: count_in_items children file
      | _ -> []
    ) items
  in
  OldList.concat_map (fun (mod_ : Catseye_ast.Types.t) ->
    count_in_items mod_.mod_items mod_.mod_path
  ) modules
