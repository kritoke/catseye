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
      in {
        packages.default = finalScope.catseye;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ finalScope.catseye ];
          buildInputs = with pkgs; [
            gnumake
            sqlite
            pkg-config
            tree-sitter
            tree-sitter-grammars.tree-sitter-gleam
            tree-sitter-grammars.tree-sitter-javascript
            tree-sitter-grammars.tree-sitter-typescript
            tree-sitter-grammars.tree-sitter-svelte
            tree-sitter-grammars.tree-sitter-ocaml
            tree-sitter-grammars.tree-sitter-rust
            (if builtins.hasAttr "crystal_1_18" pkgs then pkgs.crystal_1_18 else pkgs.crystal)
            just
            go
            openspec.packages.${system}.default
          ];
        };
      }
    );
}