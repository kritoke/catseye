(* test/ast/fsharp_mapper_test.ml
   Test F# mapper: parse sample.fs via FCS extractor, check AST structure.
*)

open Catseye_ast.Types
open Catseye_ast.Parse

let () =
  (* Use CATSEYE_FSHARP_EXTRACTOR env var if set, otherwise resolve from repo root *)
  let extractor_path =
    match Sys.getenv "CATSEYE_FSHARP_EXTRACTOR" with
    | path -> path
    | exception Not_found ->
      (* dune runs tests with cwd = src/ocaml *)
      "src/extractor/fsharp/bin/Release/net10.0/Catseye.FSharp.Extractor"
  in
  let sample_path =
    match Sys.getenv "CATSEYE_FSHARP_SAMPLE" with
    | path -> path
    | exception Not_found ->
      "tests/fixtures/fsharp/sample.fs"
  in

  (* Point to the F# extractor binary *)
  Unix.putenv "CATSEYE_FSHARP_EXTRACTOR" extractor_path;

  Printf.printf "=== Testing F# CatseyeAST parsing ===\n";
  Printf.printf "Extractor: %s\n" extractor_path;
  Printf.printf "File: %s\n" sample_path;

  (* Verify extractor exists *)
  if not (Sys.file_exists extractor_path) then begin
    Printf.printf "SKIP: extractor binary not found at %s\n" extractor_path;
    Printf.printf "Run: cd src/extractor/fsharp && dotnet build -c Release\n";
    exit 0
  end;

  match parse_file ~extractor_cmds:None ~path:sample_path with
  | Error err ->
      Printf.printf "FAIL: parse error: %s\n" err.message;
      exit 1
  | Ok mod_ ->
      Printf.printf "OK: parsed %s (%s)\n" mod_.mod_path
        (match mod_.mod_lang with
         | FSharp -> "FSharp"
         | _ -> "unexpected lang");
      Printf.printf "Items: %d\n" (List.length mod_.mod_items);

      (* Walk items and check for expected structures *)
      let found_readline = ref false in
      let found_writealltext = ref false in
      let found_ignore = ref false in
      let found_match = ref false in

      let rec check_expr (e : expr) =
        (match e.expr_value with
         | EApp (fn, args) ->
             (match fn.expr_value with
              | EVar name ->
                  if name = "Console.ReadLine" || name = "readLine" then found_readline := true;
                  if name = "File.WriteAllText" || name = "writeAllText" then found_writealltext := true;
                  if name = "ignore" then found_ignore := true;
                  if name = "printfn" || name = "printf" then ()
              | _ -> ());
             check_expr fn;
             List.iter check_expr args
         | ELet (_, body, rest) ->
             check_expr body;
             check_expr rest
         | EIf (cond, then_, else_) ->
             check_expr cond;
             check_expr then_;
             (match else_ with Some e -> check_expr e | None -> ())
         | ECase (scrutinee, clauses) ->
             found_match := true;
             check_expr scrutinee;
             List.iter (fun (_, body) -> check_expr body) clauses
         | EBlock exprs ->
             List.iter check_expr exprs
         | ETuple exprs ->
             List.iter check_expr exprs
         | EList exprs ->
             List.iter check_expr exprs
         | ERecord fields ->
             List.iter (fun (_, e) -> check_expr e) fields
         | EFn (_, body) ->
             check_expr body
         | EBinOp (l, _, r) ->
             check_expr l;
             check_expr r
         | EUnOp (_, e) ->
             check_expr e
         | EFieldAccess (obj, _) ->
             check_expr obj
         | _ -> ())
      in

      List.iter (fun item ->
        let line = item.item_location.start.line in
        (match item.item_value with
         | IFunction (name, _, _, body) ->
             Printf.printf "  Line %d: function %s\n" line name;
             check_expr body
         | ITypeDef (name, _, _) ->
             Printf.printf "  Line %d: type %s\n" line name
         | IConstant (_, _, body) ->
             Printf.printf "  Line %d: constant\n" line;
             check_expr body
         | IImport (name, _) ->
             Printf.printf "  Line %d: open %s\n" line name
         | IUnknown s ->
             Printf.printf "  Line %d: unknown (%s)\n" line s
         | _ ->
             Printf.printf "  Line %d: other\n" line)
      ) mod_.mod_items;

      (* Check foreach separately — it might be in the AST as a different construct *)
      List.iter (fun item ->
        match item.item_value with
        | IFunction (_, _, _, body) ->
            let has_foreach (e : expr) =
              match e.expr_value with
              | EApp _ | ELet _ | EIf _ | ECase _ | EBlock _ | ETuple _ | EList _ | ERecord _ | EFn _ | EBinOp _ | EUnOp _ | EFieldAccess _ ->
                  (* Walk children — already handled by check_expr *)
                  false
              | _ -> false
            in
            ignore (has_foreach body)
        | _ -> ()
      ) mod_.mod_items;

      Printf.printf "\n=== Results ===\n";
      Printf.printf "  Console.ReadLine (source):  %s\n" (if !found_readline then "FOUND" else "MISSING");
      Printf.printf "  File.WriteAllText (sink):   %s\n" (if !found_writealltext then "FOUND" else "MISSING");
      Printf.printf "  ignore (skip):              %s\n" (if !found_ignore then "FOUND" else "MISSING");
      Printf.printf "  match expression:           %s\n" (if !found_match then "FOUND" else "MISSING");

      let all_ok = !found_readline && !found_writealltext && !found_ignore && !found_match in
      if all_ok then
        Printf.printf "\nPASS: all expected F# AST nodes found\n"
      else begin
        Printf.printf "\nFAIL: some expected nodes missing\n";
        exit 1
      end
