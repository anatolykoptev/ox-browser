.PHONY: build test lint fmt check

build:
	cargo build --workspace

test:
	cargo test --workspace

lint:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

check: fmt lint test
	@echo "All checks passed"
