(* bin/main.ml — Catseye CLI entry point *)

let () =
  (* CRITICAL: Set SIGPIPE to ignore at startup, BEFORE any domain spawns.
     OCaml 5.4's fast I/O with Domain parallelism can cause SIGPIPE when
     Crystal subprocess stdout is closed before Crystal finishes flushing.
     This must be at top-level to persist across domain creation. *)
  let (_ : Sys.signal_behavior) =
    Sys.signal Sys.sigpipe Sys.Signal_ignore
  in
  (* Use Core.Command-based argument parsing *)
  Catseye_cli.Command.run_with_args ~run_impl:Catseye_cli.Orchestrator.run