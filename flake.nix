{
  inputs = {
    nixpkgs.url = "github:meta-introspector/nixpkgs?ref=feature/CRQ-016-nixify"; # Or your preferred nixpkgs branch/commit
    flake-utils.url = "github:meta-introspector/flake-utils?ref=feature/CRQ-016-nixify"; # Or a stable flake-utils URL
    cargo2nix.url = "github:cargo2nix/cargo2nix/release-0.12"; # Pin to a specific release for stability
  };

  outputs = inputs: with inputs;
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ cargo2nix.overlays.default ];
            config = {
              permittedInsecurePackages = [ "openssl-1.1.1w" ];
            };
          };

          rustToolchain = pkgs.rust-bin.nightly."2025-09-16".default; # Example nightly

          rustPkgs = pkgs.rustBuilder.makePackageSet {
            packageFun = import ./Cargo.nix; # Links to your generated Cargo.nix
            rustChannel = "nightly"; # Or "stable"
            rustVersion = "latest"; # Or a specific version like "1.81.0"

            rootFeatures = [
              "base64/default"
              "base64/alloc"
              "base64/std"
            ];

            packageOverrides = pkgs: [
              # Add any necessary package overrides here
            ];
          };

          workspaceShell = pkgs.mkShell {
            packages = [
              pkgs.statix
              pkgs.openssl_1_1.dev
            ];
            shellHook = ''
              export PKG_CONFIG_PATH=${pkgs.openssl_1_1.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
              export PATH=${rustToolchain}/bin:$PATH
            '';
          };

        in
        rec {
          devShells = {
            default = workspaceShell;
          };

          packages = rec {
            base64 = rustPkgs.workspace.base64 {};
            default = base64;
          };

          apps = {};
        }
      );
}
