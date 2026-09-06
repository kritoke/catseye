{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    opam-nix.url = "github:tweag/opam-nix";
    opam-nix.inputs.nixpkgs.follows = "nixpkgs";
    opam-repository.url = "github:ocaml/opam-repository";
    opam-repository.flake = false;
    flake-utils.url = "github:numtide/flake-utils";
    flake-utils.inputs.systems.follows = "opam-nix/flake-utils/systems";
    openspec.url = "github:Fission-AI/OpenSpec";
  };

  outputs = { self, nixpkgs, opam-nix, opam-repository, flake-utils, openspec, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        on = opam-nix.lib.${system};
        
        # 1. Standard package extraction from our local dune-project
        localPackagesQuery = builtins.mapAttrs (_: pkgs.lib.last) (on.listRepo (on.makeOpamRepo ./src/ocaml));
        
        devPackagesQuery = {
          ocaml-lsp-server = "*";
          ocamlformat = "*";
          incremental = "*";
        };

        query = localPackagesQuery // devPackagesQuery // {
          ocaml-base-compiler = "5.4.1";
        };

        sqliteOverlay = self: super: {
          sqlite3 = super.sqlite3.overrideAttrs (old: {
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.sqlite ];
            nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.pkg-config ];
          });
        };

        flattenOverlay = self: super:
          builtins.mapAttrs (name: drv:
            if drv ? overrideAttrs then
              drv.overrideAttrs (old: {
                nativeBuildInputs = pkgs.lib.flatten (old.nativeBuildInputs or [ ]);
                buildInputs = pkgs.lib.flatten (old.buildInputs or [ ]);
              })
            else drv
          ) super;

        scope = on.buildOpamProject' { repos = [ opam-repository ]; } ./src/ocaml query;

        finalScope = scope.overrideScope (pkgs.lib.composeExtensions sqliteOverlay flattenOverlay);

        # Map each tree-sitter grammar package to its language name.
        # The nix packages ship a `parser` binary at the package root;
        # tree-sitter CLI + Catseye's resolve_grammar look for {lang}.so in
        # ~/.tree-sitter/. The shellHook below symlinks them so the fast
        # first-lookup path hits, instead of falling back to a slow
        # `find /nix/store`.
        grammars = {
          gleam        = pkgs.tree-sitter-grammars.tree-sitter-gleam;
          javascript   = pkgs.tree-sitter-grammars.tree-sitter-javascript;
          typescript   = pkgs.tree-sitter-grammars.tree-sitter-typescript;
          svelte       = pkgs.tree-sitter-grammars.tree-sitter-svelte;
          ocaml        = pkgs.tree-sitter-grammars.tree-sitter-ocaml;
          rust         = pkgs.tree-sitter-grammars.tree-sitter-rust;
          nim          = pkgs.tree-sitter-grammars.tree-sitter-nim;
        };

        # Build a shellHook snippet per grammar: symlink {pkg}/parser -> ~/.tree-sitter/{lang}.so
        linkGrammars = pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList
          (lang: drv: ''
            if [ -f "${drv}/parser" ]; then
              mkdir -p "$HOME/.tree-sitter"
              ln -sf "${drv}/parser" "$HOME/.tree-sitter/${lang}.so"
            fi
          '')
          grammars);

        grammarPackages = pkgs.lib.attrValues grammars;
      in {
        packages.default = finalScope.catseye;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ finalScope.catseye ];
          buildInputs = with pkgs; [
            gnumake
            sqlite
            pkg-config
            tree-sitter
          ] ++ grammarPackages ++ [
            (if builtins.hasAttr "crystal_1_18" pkgs then pkgs.crystal_1_18 else pkgs.crystal)
            just
            go
            dotnetCorePackages.sdk_10_0
            openspec.packages.${system}.default
          ];
          shellHook = ''
            ${linkGrammars}
            # Help tree-sitter CLI find grammars by parser-directories too
            export TREE_SITTER_GRAMMAR_DIR="$HOME/.tree-sitter"
          '';
        };
      }
    );
}