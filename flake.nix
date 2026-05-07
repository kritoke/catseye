{
  description = "catseye Spoke - nim,gleam,crystal";

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

# Nim module definition
nim = pkgs.nim;
nimble = pkgs.nimble;
# Gleam module definition - use official pre-built binary to avoid compiling from source
gleamBin = pkgs.stdenv.mkDerivation {
  pname = "gleam";
  version = "1.16.0";
  src = pkgs.fetchurl {
    url = "https://github.com/gleam-lang/gleam/releases/download/v1.16.0/gleam-v1.16.0-aarch64-unknown-linux-musl.tar.gz";
    sha256 = "e7af3677a04a1b88f19896b7b351f407784c62e97078fe680f90a91a5da162d8";
  };
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out/bin
    cp gleam $out/bin/gleam
    chmod +x $out/bin/gleam
  '';
  unpackPhase = "tar xzf $src";
  stripAllFrom = [ "bin/gleam" ];
};
# Note: erlang is not needed for the gleam compiler, only for running compiled gleam code
erlang = pkgs.erlang;
# Crystal 1.18.2 module definition
# Use direct crystal_1_18 from nixpkgs (like fetcher.cr approach)
# Prefer the nixpkgs-provided Crystal 1.18 package when available.
# Fall back to pkgs.crystal if the specific attr is not present.
crystal_1_18 = if builtins.hasAttr "crystal_1_18" pkgs then pkgs.crystal_1_18 else pkgs.crystal;

      # Read flake.private.nix for per-developer overrides (like fetcher.cr)
      # This allows developers to provide custom shellHook, ticket, etc.
      privateConfig =
        if builtins.pathExists ./flake.private.nix then
          let
            content = builtins.readFile ./flake.private.nix;
            try_with_args = builtins.tryEval (import ./flake.private.nix { inherit pkgs; });
            try_no_args = builtins.tryEval (import ./flake.private.nix);
          in
            if builtins.substring 0 2 content == "#!" then {}
            else if try_with_args.success then try_with_args.value
            else if try_no_args.success then (if try_no_args.value ? outputs then {} else try_no_args.value)
            else {}
        else {};

      # Get ticket from privateConfig if provided, otherwise use the default ticket derivation
      ticket = if privateConfig ? ticket then privateConfig.ticket else defaultTicket;

      # Get shellHook from privateConfig if provided
      privateShellHook = if privateConfig ? shellHook then privateConfig.shellHook else "";

pwLibs = [];

    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [ nim nimble gleamBin crystal_1_18 rebar3 just ] ++ pwLibs;

        shellHook = ''
          echo "catseye DevShell Active"
           export PATH="$PATH:${ticket}/bin"
           export TICKET_DIR="$PWD/.tickets"
           if [ ! -d "$TICKET_DIR" ]; then
             echo "Initializing local Ticket storage in $TICKET_DIR"
             mkdir -p "$TICKET_DIR"
           fi
           '' + privateShellHook;
      };
    };
}