.PHONY: build test lint fmt check install-tools

build:
	cargo build --workspace

test:
	cargo nextest run --workspace
	cargo test --doc --workspace

lint:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

check: fmt lint test
	@echo "All checks passed"

install-tools:
	cargo binstall --no-confirm cargo-nextest
