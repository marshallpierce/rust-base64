.PHONY: all build nix-build nix-flake-build

all: nix-build

build:
	cargo build

nix-build:
	nix develop --command cargo build

nix-flake-build:
	nix build

clean:
	rm -f Cargo.nix
	cargo clean
	nix store gc --optimise