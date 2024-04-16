
{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        fhsEnv = pkgs.buildFHSUserEnv {
          name = "fhs-env";
          targetPkgs = pkgs: (with pkgs; [
            python311
            python311Packages.pip
            z3
          ]);
          runScript = "bash";
        };
      in
      {
        defaultPackage = fhsEnv;
        devShell = pkgs.mkShell {
          buildInputs = [fhsEnv pkgs.z3 ];
          #shellHook = ''
          #  export LD_LIBRARY_PATH=":${pkgs.z3}/lib:LD_LIBRARY_PATH"
          #'';
        };
      }
    );
}

