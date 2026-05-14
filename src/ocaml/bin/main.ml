(* bin/main.ml — Catseye CLI entry point *)

let () =
  let config = Catseye_cli.Args.parse_args () in
  let exit_code = Catseye_cli.Orchestrator.run config in
  exit exit_code
