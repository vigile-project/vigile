# Vigile flake (Phase 9) — provides the NixOS module and packages.
#
# Usage in your flake.nix:
#   inputs.vigile.url = "github:vigile-project/vigile";
#
#   # in nixosConfiguration:
#   imports = [ inputs.vigile.nixosModules.vigile ];
#   services.vigile = {
#     enable = true;
#     serverUrl = "https://vigile.example.com";
#     package = inputs.vigile.packages.${system}.vigile;
#   };

{
  description = "Vigile — Open-source Zero Trust application control for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    {
      nixosModules = {
        vigile = import ./packaging/nix/vigile-module.nix;
        default = self.nixosModules.vigile;
      };
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.vigile = pkgs.rustPlatform.buildRustPackage {
          pname = "vigile";
          version = "0.1.0";

          src = self;

          # Build the Rust workspace.
          buildPhase = ''
            cd rust
            cargo build --release --workspace
          '';

          installPhase = ''
            mkdir -p $out/bin $out/share/vigile/web
            cp target/release/vigile-agent $out/bin/
            cp target/release/vigile-executor $out/bin/
            cp target/release/vigile-server $out/bin/
            cp ../web/index.html $out/share/vigile/web/
          '';

          # cargoHash must be updated when dependencies change.
          # cargoHash = "sha256-...";
          cargoLock = {
            lockFile = ./rust/Cargo.lock;
          };

          meta = with pkgs.lib; {
            description = "Open-source Zero Trust application control for Linux";
            homepage = "https://github.com/vigile-project/vigile";
            license = licenses.agpl3Plus;
            platforms = platforms.linux;
          };
        };
      });
}
