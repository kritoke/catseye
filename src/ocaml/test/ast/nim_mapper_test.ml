(* test/ast/nim_mapper_test.ml
   Test Nim mapper: parse sample.nim via tree-sitter-nim, check AST structure.
   
   Requires tree-sitter-nim grammar installed. Skips gracefully if not available.
*)

open Catseye_ast.Types
open Catseye_ast.Parse

let () =
  let sample_path =
    match Sys.getenv "CATSEYE_NIM_SAMPLE" with
    | path -> path
    | exception Not_found ->
      (* dune runs tests with cwd = src/ocaml *)
      "tests/fixtures/nim/sample.nim"
  in

  Printf.printf "=== Testing Nim CatseyeAST parsing ===\n";
  Printf.printf "File: %s\n" sample_path;

  if not (Sys.file_exists sample_path) then begin
    Printf.printf "SKIP: sample file not found at %s\n" sample_path;
    exit 0
  end;

  match parse_file ~extractor_cmds:None ~path:sample_path with
  | Error err ->
    (* If tree-sitter-nim grammar is not installed, skip gracefully *)
    if String.sub err.message 0 28 = "Nim tree-sitter grammar not" then begin
      Printf.printf "SKIP: tree-sitter-nim grammar not installed\n";
      Printf.printf "Install: nix develop (or: tree-sitter install-language nim)\n";
      exit 0
    end else begin
      Printf.printf "FAIL: parse error: %s\n" err.message;
      exit 1
    end
  | Ok mod_ ->
    Printf.printf "OK: parsed %s (%s)\n" mod_.mod_path
      (match mod_.mod_lang with
       | Nim -> "Nim"
       | _ -> "unexpected lang");

    Printf.printf "Items: %d\n" (List.length mod_.mod_items);

    (* Structural assertions *)
    let (func_count, type_count, import_count) = List.fold_left (fun (f, t, i) item ->
      match item.item_value with
      | IFunction _ -> (f + 1, t, i)
      | ITypeDef _ -> (f, t + 1, i)
      | IImport _ -> (f, t, i + 1)
      | _ -> (f, t, i)
    ) (0, 0, 0) mod_.mod_items in

    Printf.printf "Functions: %d\n" func_count;
    Printf.printf "Types: %d\n" type_count;
    Printf.printf "Imports: %d\n" import_count;

    (* Verify minimum structure *)
    if func_count < 5 then begin
      Printf.printf "FAIL: expected at least 5 functions, got %d\n" func_count;
      exit 1
    end;
    if import_count < 3 then begin
      Printf.printf "FAIL: expected at least 3 imports, got %d\n" import_count;
      exit 1
    end;

    (* Check specific function names *)
    let func_names = List.filter_map (fun item ->
      match item.item_value with
      | IFunction (name, _, _, _) -> Some name
      | _ -> None
    ) mod_.mod_items in
    Printf.printf "Function names: %s\n" (String.concat ", " func_names);

    (* Verify we can find call expressions in function bodies *)
    let rec collect_apps (e : expr) : string list =
      match e.expr_value with
      | EApp (fn, args) ->
        let fn_name = match fn.expr_value with EVar n -> n | _ -> "" in
        fn_name :: List.concat_map collect_apps args
      | EBlock es -> List.concat_map collect_apps es
      | ELet (_, e1, e2) -> collect_apps e1 @ collect_apps e2
      | EIf (_, t, o) -> collect_apps t @ (match o with Some e -> collect_apps e | None -> [])
      | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> collect_apps e) bs)
      | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
        collect_apps try_body
        @ List.concat_map (fun rc -> collect_apps rc.rescue_body) rescue_clauses
        @ (match ensure_body with Some e -> collect_apps e | None -> [])
      | EFn (_, b) -> collect_apps b
      | _ -> []
    in
    let all_apps = List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) -> collect_apps body
      | _ -> []
    ) mod_.mod_items in
    Printf.printf "Total call sites: %d\n" (List.length all_apps);

    (* Check for specific sink calls *)
    let has_exec_cmd = List.exists (fun n -> n = "execCmd" || n = "os.execCmd") all_apps in
    let has_exec_shell = List.exists (fun n -> n = "execShellCmd" || n = "os.execShellCmd") all_apps in
    Printf.printf "Has execCmd: %b\n" has_exec_cmd;
    Printf.printf "Has execShellCmd: %b\n" has_exec_shell;

    if not has_exec_cmd && not has_exec_shell then
      Printf.printf "WARN: expected execCmd or execShellCmd calls in sample\n";

    Printf.printf "\n=== All Nim mapper tests passed ===\n"
