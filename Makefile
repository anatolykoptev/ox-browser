.PHONY: build test test-doc lint fmt check preflight deny install-tools

build:
	cargo build --workspace

test-doc:
	cargo test --locked --doc --workspace

test:
	cargo nextest run --locked --all-targets --workspace
	$(MAKE) test-doc

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

check: fmt lint test
	@echo "All checks passed"

## CI gate — fmt check + clippy -D warnings + nextest + doctests + fingerprint feature check
preflight: fmt lint test
	cargo check -p ox-http --all-targets --features fingerprint
	@echo "Preflight passed"

deny:
	cargo deny check

install-tools:
	cargo binstall --no-confirm cargo-nextest cargo-deny
