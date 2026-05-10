{
  description = "catseye - Static security analysis for Crystal and Gleam";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    openspec.url = "github:Fission-AI/OpenSpec";
    # Ticket task management (non-flake input)
    ticket-src = {
      url = "github:wedow/ticket";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, openspec, ticket-src }:
    let
      system = "aarch64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Minimal derivation for the ticket bash script (exposed to the devShell)
      defaultTicket = pkgs.stdenv.mkDerivation {
        pname = "ticket";
        version = "latest";
        src = ticket-src;
        dontBuild = true;
        installPhase = ''
          mkdir -p $out/bin
          cp ticket $out/bin/ticket
          chmod +x $out/bin/ticket
        '';
      };

      crystal_1_18 =
        if builtins.hasAttr "crystal_1_18" pkgs
        then pkgs.crystal_1_18
        else pkgs.crystal;

      # ── OCaml toolchain ───────────────────────────────────────────────

      ocamlPkgs = pkgs.ocamlPackages;

      ocamlLibs = with ocamlPkgs; [
        # Core
        ocaml
        dune_3
        findlib

        # CLI
        cmdliner
        bos
        rresult
        logs
        fmt

        # Data formats
        yojson
        toml
        kdl

        # Engine
        ocamlgraph

        # Database
        ocaml_sqlite3

        # Async / Parallel (OCaml 5)
        eio
        eio_posix

        # Testing
        alcotest
      ];

      ocamlTools = with ocamlPkgs; [
        ocaml-lsp
        ocamlformat
        utop
        ocp-indent
      ];

      # ── Tree-sitter ───────────────────────────────────────────────────

      treeSitterLibs = [
        pkgs.tree-sitter
        pkgs.tree-sitter-grammars.tree-sitter-gleam
      ];

      # ── Private config ────────────────────────────────────────────────

      privateConfig =
        if builtins.pathExists ./flake.private.nix then
          (let content = builtins.readFile ./flake.private.nix;
           in
             if builtins.substring 0 2 content == "#!" then {}
             else
               let try_with_args = builtins.tryEval (import ./flake.private.nix { inherit pkgs; });
               in
                 if try_with_args.success then try_with_args.value
                 else
                   let try_no_args = builtins.tryEval (import ./flake.private.nix);
                   in
                     if try_no_args.success then
                       if builtins.hasAttr "outputs" try_no_args.value then {} else try_no_args.value
                     else {})
        else {};

      ticket = if privateConfig ? ticket then privateConfig.ticket else defaultTicket;
      privateShellHook = if privateConfig ? shellHook then privateConfig.shellHook else "";

    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          # Crystal extractor
          crystal_1_18

          # OCaml toolchain
          ocamlPkgs.ocaml
          ocamlPkgs.dune_3
          ocamlPkgs.findlib

          # OCaml libraries
        ] ++ ocamlLibs ++ ocamlTools ++ treeSitterLibs ++ [ just ];

        shellHook = ''
          echo "╔══════════════════════════════════════╗"
          echo "║        Catseye DevShell Active       ║"
          echo "╚══════════════════════════════════════╝"
          echo ""
          echo "  Crystal $(crystal version 2>/dev/null | head -1 | awk '{print $2}')"
          echo "  OCaml:  $(ocaml --version)"
          echo "  Dune:   $(dune --version 2>/dev/null | head -1)"
          echo ""
          export PATH="$PATH:${ticket}/bin"
          export TICKET_DIR="$PWD/.tickets"
          export TREE_SITTER_GLEAM_GRAMMAR="${pkgs.tree-sitter-grammars.tree-sitter-gleam}/parser"

          # OCaml environment
          export OCAMLFIND_DESTDIR="$PWD/src/ocaml/_opam/lib"

          if [ ! -d "$TICKET_DIR" ]; then
            echo "Initializing local Ticket storage in $TICKET_DIR"
            mkdir -p "$TICKET_DIR"
          fi
          '' + privateShellHook;
      };
    };
}
