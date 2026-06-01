(* lib/catseye_ast/elixir_mapper.ml
   Bridge from elixir-extractor JSON output to CatseyeAST.t.
   
   Maps onto CatseyeAST.t for taint analysis.
   Works as a drop-in scanner for any Elixir project.
*)

module PE = Error
open Base
open Types

(* ── JSON helpers ───────────────────────────────────────────────────── *)

let assoc key fields = List.Assoc.find ~equal:String.equal fields key

let json_string (json : Yojson.Safe.t) : string =
  match json with `String s -> s | _ -> ""

let json_int (json : Yojson.Safe.t) : int =
  match json with `Int n -> n | _ -> 0

(* ── Position helpers ────────────────────────────────────────────── *)

let pos line = Position.make ~line ~column:0 ~byte_offset:0
let range line = { start = pos line; end_ = pos line }

(* ── Build expressions from escript JSON call list ───────────────── *)

(* Counter for generating unique temp variable names *)
let temp_counter = ref 0

let fresh_temp () =
  Int.incr temp_counter;
  Printf.sprintf "__elixir_tmp_%d" !temp_counter

let build_call_list (fn_calls : Yojson.Safe.t list) : expr list =
  (* Each call becomes an EApp. Calls that produce values used by other calls
     get wrapped in a temp Assign so the taint engine can track data flow.
     E.g. "<>" (base, "...HEAD") → __elixir_tmp_1 = base <> "...HEAD" *)
  List.concat_map fn_calls ~f:(function
    | `Assoc cf ->
      let name = json_string (match assoc "name" cf with Some v -> v | _ -> `String "") in
      let line = json_int (match assoc "line" cf with Some v -> v | _ -> `Int 0) in
      let args_json = (match assoc "args" cf with Some (`List as_list) -> as_list | _ -> []) in
      let arg_exprs = List.filter_map args_json ~f:(function
        | `Assoc af ->
          let arg_name = json_string (match assoc "name" af with Some v -> v | _ -> `String "") in
          let arg_type = json_string (match assoc "type" af with Some v -> v | _ -> `String "var") in
          (match arg_type with
           | "literal" -> Some { expr_value = ELiteral (LString arg_name); expr_location = range line }
           | _ -> Some { expr_value = EVar arg_name; expr_location = range line })
        | `String s -> Some { expr_value = EVar s; expr_location = range line }
        | _ -> None)
      in
      let fn_expr = { expr_value = EVar name; expr_location = range line } in
      let call_expr = { expr_value = EApp (fn_expr, arg_exprs); expr_location = range line } in
      (* Module attribute access: @pi_bin → EVar "@pi_bin" so taint engine sees it as a variable *)
      if name = "@" && List.length arg_exprs >= 1 then begin
        let attr_name = match List.hd arg_exprs with
          | Some { expr_value = EVar v; _ } -> "@" ^ v
          | _ -> "@"
        in
        [{ expr_value = EVar attr_name; expr_location = range line }]
      end
      (* Special handling for assignment operator *)
      else if name = "=" && List.length arg_exprs >= 2 then begin
        let lhs = List.nth_exn arg_exprs 0 in
        let rhs = List.nth_exn arg_exprs 1 in
        [{ expr_value = EAssignment (lhs, rhs); expr_location = range line }]
      end
      (* Only wrap operators and string ops in temp Assign — not regular calls like System.cmd *)
      else
      let is_operator =
        List.exists ["<>"; "+"; "-"; "*"; "/"; "++"; "--"] ~f:(fun p -> name = p)
        || name = "Kernel.to_string"
        || name = "<<>>"  (* binary construction *)
      in
      if is_operator && arg_exprs <> [] then begin
        let temp = fresh_temp () in
        let temp_var = { expr_value = EVar temp; expr_location = range line } in
        let assign_expr = { expr_value = EAssignment (temp_var, call_expr); expr_location = range line } in
        [assign_expr]
      end else
        [call_expr]
    | _ -> [{ expr_value = EUnit; expr_location = range 0 }])

(* ── Build function item from a JSON function entry ─────────────── *)

let build_function_item (json_fn : Yojson.Safe.t) : item =
  match json_fn with
  | `Assoc fields ->
    let fn_name = json_string (match assoc "name" fields with Some v -> v | _ -> `String "") in
    let fn_line = json_int (match assoc "line" fields with Some v -> v | _ -> `Int 0) in
    let params = (match assoc "params" fields with 
                 | Some (`List ps) -> List.filter_map ps ~f:(function `String s -> Some (PVar s) | _ -> None) 
                 | _ -> []) in
    let fn_calls = (match assoc "calls" fields with Some (`List cs) -> cs | _ -> []) in
    let call_exprs = build_call_list fn_calls in
    let r = range fn_line in
    let body = { expr_value = EBlock call_exprs; expr_location = r } in
    { item_location = r; item_value = IFunction (fn_name, params, None, body) }
  | _ -> { item_location = range 0; item_value = IUnknown "parse_error" }

(* ── Convert escript JSON module to CatseyeAST.t ─────────────────── *)

let of_json (json : Yojson.Safe.t) : (t, PE.parse_error) Result.t =
  match json with
  | `Assoc fields ->
    (match assoc "file" fields with
     | Some (`String file) ->
       (match assoc "functions" fields with
        | Some (`List functions) ->
          let items = List.map functions ~f:build_function_item in
          Ok { mod_lang = Elixir; mod_path = file; mod_items = items; parse_errors = [] }
        | _ -> Ok { mod_lang = Elixir; mod_path = file; mod_items = []; parse_errors = [] })
     | _ -> Error (PE.make_error ~file:"?" ~message:"Missing file field"))
  | _ -> Error (PE.make_error ~file:"?" ~message:"Invalid elixir JSON")

(* ── Helpers ──────────────────────────────── *)

let get_realpath (path : string) : string =
  let cmd = Stdlib.Printf.sprintf "realpath %s" (Stdlib.Filename.quote path) in
  let ch = Unix.open_process_in cmd in
  let rec read_all acc = try read_all (Stdlib.input_line ch :: acc) with End_of_file -> List.rev acc in
  let lines = read_all [] in
  let _ = Unix.close_process_in ch in
  match lines with [p] -> p | _ -> path

let find_root (start_path : string) : string option =
  let start_dir = if Stdlib.Sys.is_directory start_path then start_path else Stdlib.Filename.dirname start_path in
  let rec search dir depth =
    if depth > 20 then None
    else
      let has_project =
        Stdlib.Sys.file_exists (Stdlib.Filename.concat dir "mix.exs") ||
        Stdlib.Sys.file_exists (Stdlib.Filename.concat dir "mix.lock") in
      if has_project then Some dir
      else
        let parent = Stdlib.Filename.dirname dir in
        if parent = dir then None else search parent (depth + 1) in
  search start_dir 0

(* ── Find catseye_extractor escript ──────────────────────────────── *)
(* Tries multiple locations in order of preference *)

let find_extractor () : string option =
  let candidates = [
    (* In catseye bin directory (where we build it) *)
    "/workspaces/catseye/bin/catseye_extractor";
    (* Relative to catseye binary location *)
    Stdlib.Filename.concat (Stdlib.Filename.dirname (Sys.get_argv ()).(0)) "catseye_extractor";
    (* In PATH *)
    "catseye_extractor";
  ] in
  let rec try_all = function
    | [] -> None
    | candidate :: rest ->
      if Stdlib.Sys.file_exists candidate then Some candidate
      else try_all rest
  in
  try_all candidates

(* ── Run extractor on a single file ──────────────────────────────── *)

let run_extractor_single (abs_file_path : string) : string option =
  match find_extractor () with
  | None -> None
  | Some extractor ->
    (* Use --file flag to extract a single file *)
    let cmd = Stdlib.Printf.sprintf "%s --file %s 2>/dev/null"
      (Stdlib.Filename.quote extractor)
      (Stdlib.Filename.quote abs_file_path)
    in
    let ch = Unix.open_process_in cmd in
    let rec read_all acc = 
      try read_all (Stdlib.input_line ch :: acc) 
      with End_of_file -> List.rev acc 
    in
    let lines = read_all [] in
    let status = Unix.close_process_in ch in
    if status = Unix.WEXITED 0 && lines <> [] then Some (String.concat ~sep:"\n" lines)
    else None

(* ── Parse file ───────────────────────────────────────────────────── *)

let parse_file ~(path : string) ~(extractor_cmd : string) : (t, PE.parse_error) Result.t =
  let _extractor_cmd = extractor_cmd in
  if not (Stdlib.Filename.check_suffix path ".ex" || Stdlib.Filename.check_suffix path ".exs") then
    Error (PE.make_error ~file:path ~message:"Not an Elixir file")
  else
    let abs_path = get_realpath path in
    match find_root abs_path with
    | None -> Error (PE.make_error ~file:path ~message:"Could not find Elixir project root")
    | Some _ ->
      (match run_extractor_single abs_path with
       | Some json_str ->
         (try 
           let json = Yojson.Safe.from_string json_str in
           of_json json
         with _ -> Error (PE.make_error ~file:path ~message:"Parse error"))
       | None -> Error (PE.make_error ~file:path ~message:"Extractor failed"))
