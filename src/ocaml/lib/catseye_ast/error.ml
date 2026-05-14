(* src/ocaml/lib/catseye_ast/error.ml
   Parsing error types - per "Ban the Regex" principle
*)

(** Parse error with location *)
type parse_error = {
  file : string;
  line : int option;
  column : int option;
  message : string;
}

(** Create a parse error *)
let make_error ~file ~message = {
  file;
  line = None;
  column = None;
  message;
}

(** Create error at specific line *)
let make_error_at ~file ~line ~message = {
  file;
  line = Some line;
  column = None;
  message;
}

(** Convert error to string *)
let error_to_string (err : parse_error) =
  let loc = match err.line with
    | Some l -> Printf.sprintf "%s:%d" err.file l
    | None -> err.file
  in
  Printf.sprintf "Parse error in %s: %s" loc err.message