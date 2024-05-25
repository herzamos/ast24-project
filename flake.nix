
{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
      overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "cargo" "rustc" ];
        };
      in
      {
        devShell = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (p: [
              p.z3-solver
            ]))
            pkgs.texlive.combined.scheme-full
          ];
          buildInputs = [ rust pkgs.z3 pkgs.graphviz ];
          #shellHook = ''
          #  export LD_LIBRARY_PATH=":${pkgs.z3}/lib:LD_LIBRARY_PATH"
          #'';
          RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
        };
      }
    );
}

