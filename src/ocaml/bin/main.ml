(* bin/main.ml — Catseye CLI entry point *)

let () =
  (* CRITICAL: Set SIGPIPE to ignore at startup, BEFORE any domain spawns.
     OCaml 5.4's fast I/O with Domain parallelism can cause SIGPIPE when
     Crystal subprocess stdout is closed before Crystal finishes flushing.
     This must be at top-level to persist across domain creation. *)
  let (_ : Stdlib.Sys.signal_behavior) =
    Stdlib.Sys.signal Stdlib.Sys.sigpipe Stdlib.Sys.Signal_ignore
  in
  let config = Catseye_cli.Args.parse_args () in
  let exit_code = Catseye_cli.Orchestrator.run config in
  exit exit_code
