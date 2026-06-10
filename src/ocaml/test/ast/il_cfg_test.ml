(* Test binary for IL/CFG conversion from CatseyeAST *)

open Catseye_ast.Types
open Catseye_ast.Parse
open Catseye_il.Of_catseye_ast
open Catseye_il.Il_types

let () =
  Unix.putenv "CATSEYE_CRYSTAL_EXTRACTOR" "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
  Unix.putenv "TREE_SITTER_GLEAM_GRAMMAR" "/workspaces/catseye";
  let cmds = {
    Catseye_types.Extractor_cmds.flat = "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
    Catseye_types.Extractor_cmds.hier = "crystal run /workspaces/catseye/src/extractor/extractor.cr --";
  } in

  (* Test with synthetic AST that has real branching *)
  let synthetic_mod = {
    mod_lang = Crystal;
    mod_path = "test.cr";
    mod_items = [{
      item_location = { start = Position.make ~line:1 ~column:0 ~byte_offset:0; end_ = Position.make ~line:10 ~column:0 ~byte_offset:100 };
      item_value = IFunction ("test_branch", [PVar "x"], None,
        { expr_value = EBlock [
          { expr_value = EIf (
            { expr_value = EVar "x"; expr_location = { start = Position.make ~line:2 ~column:3 ~byte_offset:10; end_ = Position.make ~line:2 ~column:4 ~byte_offset:11 } },
            { expr_value = EApp ({ expr_value = EVar "puts"; expr_location = { start = Position.make ~line:3 ~column:2 ~byte_offset:15; end_ = Position.make ~line:3 ~column:6 ~byte_offset:19 } }, [{ expr_value = ELiteral (LString "yes"); expr_location = { start = Position.make ~line:3 ~column:7 ~byte_offset:20; end_ = Position.make ~line:3 ~column:12 ~byte_offset:25 } }]); expr_location = { start = Position.make ~line:3 ~column:2 ~byte_offset:15; end_ = Position.make ~line:3 ~column:12 ~byte_offset:25 } },
            Some { expr_value = EApp ({ expr_value = EVar "puts"; expr_location = { start = Position.make ~line:5 ~column:2 ~byte_offset:30; end_ = Position.make ~line:5 ~column:6 ~byte_offset:34 } }, [{ expr_value = ELiteral (LString "no"); expr_location = { start = Position.make ~line:5 ~column:7 ~byte_offset:35; end_ = Position.make ~line:5 ~column:11 ~byte_offset:39 } }]); expr_location = { start = Position.make ~line:5 ~column:2 ~byte_offset:30; end_ = Position.make ~line:5 ~column:11 ~byte_offset:39 } }
          ); expr_location = { start = Position.make ~line:2 ~column:2 ~byte_offset:5; end_ = Position.make ~line:5 ~column:11 ~byte_offset:39 } };
          { expr_value = EApp ({ expr_value = EVar "sink"; expr_location = { start = Position.make ~line:7 ~column:2 ~byte_offset:42; end_ = Position.make ~line:7 ~column:6 ~byte_offset:46 } }, [{ expr_value = EVar "x"; expr_location = { start = Position.make ~line:7 ~column:7 ~byte_offset:47; end_ = Position.make ~line:7 ~column:8 ~byte_offset:48 } }]); expr_location = { start = Position.make ~line:7 ~column:2 ~byte_offset:42; end_ = Position.make ~line:7 ~column:8 ~byte_offset:48 } }
        ]; expr_location = { start = Position.make ~line:1 ~column:0 ~byte_offset:0; end_ = Position.make ~line:10 ~column:0 ~byte_offset:100 } }
      )
    }];
    parse_errors = []
  } in
  Printf.printf "\n=== Synthetic AST with if/else branch ===\n";
  let unit = translate synthetic_mod in
  List.iter (fun fn ->
    Printf.printf "\nFunction: %s (%d IL nodes)\n" fn.fn_name (List.length fn.fn_body);
    List.iter (fun (node : Catseye_il.Il_types.il_node) ->
      let line = match node with
        | ILAssign (_, _, p) -> p.line
        | ILCall (_, _, _, p) -> p.line
        | ILBranch (_, _, _, p) -> p.line
        | ILReturn (_, p) -> p.line
        | ILThrow (_, p) -> p.line
        | ILResume (_, p) -> p.line
      in
      Printf.printf "  L%d: %s\n" line (Catseye_il.Cfg_builder.string_of_node node)
    ) fn.fn_body;
    let cfg = Catseye_il.Cfg_builder.build_cfg fn in
    (match cfg with
     | Error e -> Printf.printf "  CFG build error: %s\n" (match e with TooManyBlocks { actual; limit } -> Printf.sprintf "too many blocks (%d > %d)" actual limit | Timeout { elapsed_ms; _ } -> Printf.sprintf "timeout (%dms)" elapsed_ms)
     | Ok cfg -> Printf.printf "\n%s\n" (Catseye_il.Cfg_builder.print_cfg cfg))
  ) unit.il_functions;

  let test_files = [
    ("/workspaces/catseye/test/samples/guard_test/guarded.cr", "crystal");
    ("/workspaces/catseye/test/samples/vulnerable.cr", "crystal");
    ("/workspaces/catseye/test/samples/vulnerable_lucky.cr", "crystal");
    ("/workspaces/catseye/test/samples/vulnerable_kemal.cr", "crystal");
    ("/workspaces/catseye/test/samples/unsafe_sql.cr", "crystal");
    ("/workspaces/catseye/test/samples/vulnerable_extra.cr", "crystal");
    ("/workspaces/catseye/test/samples/vulnerable_patterns.cr", "crystal");
    ("/workspaces/catseye/test/samples/smell_samples/dry_a.cr", "crystal");
    ("/workspaces/catseye/test/samples/smell_samples/dry_b.cr", "crystal");
  ] in

  List.iter (fun (path, _expected_lang) ->
    Printf.printf "\n=== IL/CFG for %s ===\n" path;
    match parse_file ~extractor_cmds:(Some cmds) ~path with
    | Error err ->
      Printf.printf "PARSE ERROR: %s\n" err.message
    | Ok mod_ ->
      Printf.printf "Lang: %s, Items: %d\n"
        (match mod_.mod_lang with Gleam -> "gleam" | Crystal -> "crystal" | Svelte -> "svelte" | TypeScript -> "typescript" | JavaScript -> "javascript" | Rust -> "rust" | OCaml -> "ocaml" | Elixir -> "elixir"
             | FSharp -> "fsharp" | Other s -> s)
        (List.length mod_.mod_items);

      let unit = translate mod_ in
      Printf.printf "IL unit: %s, %d functions\n" unit.il_lang (List.length unit.il_functions);

      List.iter (fun fn ->
        Printf.printf "\n--- Function: %s (%d params, %d IL nodes) ---\n"
          fn.fn_name (List.length fn.fn_params) (List.length fn.fn_body);

        (* Print IL nodes with line info *)
        List.iter (fun (node : Catseye_il.Il_types.il_node) ->
          let line = match node with
            | ILAssign (_, _, p) -> p.line
            | ILCall (_, _, _, p) -> p.line
            | ILBranch (_, _, _, p) -> p.line
            | ILReturn (_, p) -> p.line
            | ILThrow (_, p) -> p.line
            | ILResume (_, p) -> p.line
          in
          Printf.printf "  L%d: %s\n" line (Catseye_il.Cfg_builder.string_of_node node)
        ) fn.fn_body;

        (* Build and print CFG *)
        let cfg = Catseye_il.Cfg_builder.build_cfg fn in
        (match cfg with
         | Error _ -> Printf.printf "  CFG build error!\n"
         | Ok cfg -> Printf.printf "\n%s\n" (Catseye_il.Cfg_builder.print_cfg cfg))
      ) unit.il_functions
  ) test_files
