{
  description = "A build for cloaked search proxy.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rusttoolchain =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in rec {
        # `nix build`
        packages = {
          cloaked-search-proxy = pkgs.rustPlatform.buildRustPackage {
            pname = "cloaked-search-proxy";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoLock.outputHashes = {
              "base64_type-0.1.0" = "nQLg2cyNG+RKxG1DpmkWuobxRMLSHimYjvde84k/31A=";
              "phonetic-normalizer-0.1.0" = "1o49Wnu/tyLzjhuUK1GceM1UGjlR8aC9u0MVGQILud4=";
            };
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ rusttoolchain pkgs.libiconv ]
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
              [ pkgs.darwin.apple_sdk.frameworks.Security ];
          };
        };
        defaultPackage = packages.cloaked-search-proxy;

        # nix develop
        devShell = pkgs.mkShell {
          buildInputs = with pkgs;
            [ rusttoolchain pkg-config pkgs.libiconv ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
            [ pkgs.darwin.apple_sdk.frameworks.Security ];
        };

      });
}
