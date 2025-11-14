# Makefile.submodule
# This Makefile is intended to be copied into submodules and invoked recursively.

.PHONY: submodule-build-and-push clean

submodule-build-and-push:
	@echo "Building and pushing submodule $(notdir $(CURDIR)) (Depth: $(CURRENT_RECURSION_DEPTH))"
	/nix/store/1x74bj4qh82967g90knam14sc51rqhfk-cargo-1.89.0-aarch64-unknown-linux-gnu/bin/cargo update
	/nix/store/1x74bj4qh82967g90knam14sc51rqhfk-cargo-1.89.0-aarch64-unknown-linux-gnu/bin/cargo vendor
	$(CARGO2NIX_ROOT)/target/debug/cargo2nix -o Cargo.nix
	nix build
	git add .
	git commit -m "feat: Update, vendor, cargo2nix, and build for $(notdir $(CURDIR))"
	git push origin feature/CRQ-016-nixify

clean:
	@echo "Cleaning submodule $(notdir $(CURDIR))"
	rm -f Cargo.nix
	cargo clean
	nix store gc --optimise
