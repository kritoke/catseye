(* src/ocaml/lib/ai_linter/ast_rules.ml
   AST structural rules - operate on CatseyeAST.t only

   Per the "Ban the Regex" principle, these rules use pattern matching
   on the typed AST instead of regex.
 *)

open Base
open Catseye_ast.Types

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
module List = Stdlib.List

type severity = Types.severity = Hint | Warning | Error

(** A violation found during AST analysis *)
type violation = {
  rule_id: string;
  severity: severity;
  category: string;
  message: string;
  location: range;
  suggestion: string option;
}

(** Collect all function definitions *)
let all_functions (mod_ : t) =
  let rec collect = function
    | [] -> []
    | item :: rest ->
        match item.item_value with
        | IFunction (name, _, _, _) -> (name, item) :: collect rest
        | IModule (_, items) -> collect (items @ rest)
        | _ -> collect rest
  in
  collect mod_.mod_items

(** Check if expression contains todo/panic *)
let rec contains_todo (expr : expr) =
  match expr.expr_value with
  | EVar name when Stdlib.String.lowercase_ascii name = "todo" 
                || Stdlib.String.lowercase_ascii name = "panic" -> true
  | EApp (fn, args) ->
(match fn.expr_value with
       | EVar name when Stdlib.String.lowercase_ascii name = "todo" -> true
        | _ -> Stdlib.List.exists contains_todo (fn :: args))
  | EFn (_, body) -> contains_todo body
  | EIf (_, then_, else_) ->
      contains_todo then_ || (match else_ with None -> false | Some e -> contains_todo e)
  | ECase (_, branches) -> Stdlib.List.exists (fun (_, e) -> contains_todo e) branches
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) -> contains_todo e1 || contains_todo e2
  | EBlock es -> Stdlib.List.exists contains_todo es
  | _ -> false

(** Rule: Detect todo/panic in functions *)
let todo_rule = {
  rule_id = "todo-in-code";
  severity = Warning;
  category = "code-quality";
  message = "TODO or panic found in production code";
  location = { start = Position.zero; end_ = Position.zero };
  suggestion = Some "Replace with proper error handling";
}

(** Analyze a module and return all violations *)
let analyze_module (mod_ : t) : violation list =
  let fns = all_functions mod_ in
  List.fold_left (fun acc (name, item) ->
    match item.item_value with
    | IFunction (_, _, _, body) when contains_todo body ->
        { todo_rule with 
          message = Stdlib.Printf.sprintf "Function '%s' contains todo/panic" name;
          location = item.item_location } :: acc
    | _ -> acc
  ) [] fns