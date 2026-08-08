{
  description = "zed-api-server.rs — environment secrets (ores-sops) for the Zed registry API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # The env-secret tooling is org-agnostic and lives in its own repo, so every
    # zed-pkg repo shares one implementation rather than a copied justfile.
    ores-sops.url = "github:ORESoftware/ores-sops";
  };

  outputs = { self, nixpkgs, flake-utils, ores-sops }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ores-sops.overlays.default ];
        };
      in
      {
        # Env-secret tooling only. Rust builds stay on the repo's
        # rust-toolchain.toml (rustup); this shell does not provide a compiler.
        devShells.default = pkgs.mkShell {
          name = "zed-api-server";
          packages = with pkgs; [
            # Qualified deliberately: `with pkgs;` does not shadow the outputs
            # function's arguments, so a bare `ores-sops` here resolves to the
            # flake INPUT (an attrset) rather than the package, and nix fails
            # with "Dependency is not of a valid type".
            pkgs.ores-sops
            sops
            age
            just
            git

            # k8s manifests in this repo (k8s/base + overlays).
            kubectl
            kustomize
          ];
        };
      });
}
