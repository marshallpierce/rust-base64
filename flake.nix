{
  description = "A minimal development shell for a Rust project";

  inputs = {
    nixpkgs.url = "github:meta-introspector/nixpkgs?ref=feature/CRQ-016-nixify";
    rust-overlay = {
      url = "github:meta-introspector/rust-overlay?ref=feature/CRQ-016-nixify";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:meta-introspector/flake-utils?ref=feature/CRQ-016-nixify";
    # Assuming cargo2nix is available as an input, or we can reference it from the main project
    cargo2nix-root.url = "path:../.."; # Relative path to the main cargo2nix project
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, cargo2nix-root }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };

        # Use the cargo2nix from the root project to generate the package set
        cargo2nixPkgs = cargo2nix-root.packages.${system}.rustPkgs;
        
        # The name of the crate in this directory. This needs to be dynamic.
        # For now, let's assume the crate name is the directory name.
        # This might need adjustment if the Cargo.toml has a different name.
        crateName = (builtins.baseNameOf (builtins.toString self)); # This will be the directory name

        # Generate the Cargo.nix for this specific crate
        # This assumes Cargo.nix is generated in the current directory
        rustPkgs = pkgs.rustBuilder.makePackageSet {
          packageFun = import ./Cargo.nix;
          rustChannel = "nightly";
          rustVersion = "latest";
          # Add any specific package overrides if needed for submodules
          # packageOverrides = pkgs: [
          #   (pkgs.rustBuilder.rustLib.makeOverride {
          #     name = "some-crate";
          #     overrideAttrs = old: { ... };
          #   })
          # ];
        };

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            openssl.dev
            pkg-config
          ];
          shellHook = ''
            export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
          '';
        };

        packages.default = rustPkgs.workspace.${crateName} or rustPkgs.unknown.${crateName}."0.1.0" or rustPkgs.unknown.${crateName}."*" or (throw "Could not find crate ${crateName} in Cargo.nix");
      }
    );
}