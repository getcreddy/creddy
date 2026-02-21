{
  description = "Creddy - Ephemeral credentials for AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_23  # Latest stable, 1.25 not yet released
            gopls
            golangci-lint
            sqlite
          ];

          shellHook = ''
            export GOPATH="$HOME/go"
            export PATH="$GOPATH/bin:$PATH"
            echo "Creddy dev environment loaded"
            echo "Go version: $(go version)"
          '';
        };

        packages.default = pkgs.buildGoModule {
          pname = "creddy";
          version = "0.1.0";
          src = ./.;
          vendorHash = null;  # Update after first build

          meta = with pkgs.lib; {
            description = "Ephemeral credentials for AI agents";
            homepage = "https://github.com/marccampbell/creddy";
            license = licenses.mit;
          };
        };
      }
    );
}
