# Makefile.submodule
# This Makefile is intended to be copied into submodules and invoked recursively.

.PHONY: submodule-build-and-push clean

CARGO_GIT_MANAGE_BIN := $(CARGO2NIX_ROOT)/submodules/cargo/cargo-submodule-tool/target/debug/cargo-git-manage

submodule-build-and-push:
	@echo "Building and pushing submodule $(notdir $(CURDIR)) (Depth: $(CURRENT_RECURSION_DEPTH))"
	PATH=$(CARGO2NIX_ROOT)/submodules/cargo/target/debug:$$PATH \
	/data/data/com.termux.nix/files/home/pick-up-nix2/vendor/rust/cargo2nix/submodules/cargo/target/debug/cargo-git-manage
	nix build
	git add .
	git commit -m "feat: Update, vendor, cargo2nix, and build for $(notdir $(CURDIR))"
	git push origin feature/CRQ-016-nixify

clean:
	@echo "Cleaning submodule $(notdir $(CURDIR))"
	rm -f Cargo.nix
	cargo clean
	nix store gc --optimise
