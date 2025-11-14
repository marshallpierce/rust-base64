# Makefile.submodule
# This Makefile is intended to be copied into submodules and invoked recursively.

.PHONY: submodule-build-and-push clean

CARGO_GIT_MANAGE_BIN := $(CARGO2NIX_ROOT)/submodules/cargo/cargo-submodule-tool/target/debug/cargo-git-manage

CARGO_GIT_MANAGE_BIN_PATH := $(CARGO2NIX_ROOT)/submodules/cargo/target/debug/cargo-git-manage
CARGO2NIX_BIN_PATH := $(CARGO2NIX_ROOT)/target/debug/cargo2nix

submodule-build-and-push:
	@echo "Building and pushing submodule $(notdir $(CURDIR)) (Depth: $(CURRENT_RECURSION_DEPTH))"

	# Inject cargo2nix_path into Cargo.toml if not present
	@if ! grep -q "\[package\.metadata\.cargo2nix\]" Cargo.toml; then \
		echo "Adding [package.metadata.cargo2nix] to Cargo.toml"; \
		echo "" >> Cargo.toml; \
		echo "[package.metadata.cargo2nix]" >> Cargo.toml; \
		echo "cargo2nix_path = \"$(CARGO2NIX_BIN_PATH)\"" >> Cargo.toml; \
	elif ! grep -q "cargo2nix_path" Cargo.toml; then \
		echo "Adding cargo2nix_path to [package.metadata.cargo2nix] in Cargo.toml"; \
		sed -i "/\[package\.metadata\.cargo2nix\]/a cargo2nix_path = \"$(CARGO2NIX_BIN_PATH)\"" Cargo.toml; \
	else \
		echo "Updating cargo2nix_path in Cargo.toml"; \
		sed -i "s|cargo2nix_path = \".*\"|cargo2nix_path = \"$(CARGO2NIX_BIN_PATH)\"|" Cargo.toml; \
	fi

	PATH=$(CARGO2NIX_ROOT)/submodules/cargo/target/debug:$$PATH \
	$(CARGO_GIT_MANAGE_BIN_PATH)
	nix build
	git add .
	git commit -m "feat: Update, vendor, cargo2nix, and build for $(notdir $(CURDIR))"
	git push origin feature/CRQ-016-nixify

clean:
	@echo "Cleaning submodule $(notdir $(CURDIR))"
	rm -f Cargo.nix
	cargo clean
	nix store gc --optimise
