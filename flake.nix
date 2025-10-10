{
  description = "A development environment for a rust project.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rusttoolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustWithWasm = rusttoolchain.override {
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      rec {
        # nix develop
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustWithWasm
            pkg-config
          ];
        };

      }
    );
}
