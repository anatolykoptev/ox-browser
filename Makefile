.PHONY: build test test-doc lint fmt fmt-check check preflight lock-version-check deny install-tools

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

fmt-check:
	cargo fmt --all -- --check

check: fmt lint test
	@echo "All checks passed"

## Backstop: the root workspace member's version in Cargo.lock must equal
## [workspace.package].version in Cargo.toml. Catches a stale lockfile at PR
## time with an actionable message, before the expensive test/clippy steps.
## (The `test` target's --locked would also fail on a stale lock, but with a
## generic "lock file out of date" error; this names the cause.)
lock-version-check:
	@toml_v=$$(grep '# x-release-please-version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'); \
	lock_v=$$(awk '/^name = "ox-browser"/{getline; print}' Cargo.lock | sed -E 's/.*"([^"]+)".*/\1/'); \
	if [ "$$toml_v" != "$$lock_v" ]; then \
		echo "ERROR: Cargo.lock ox-browser version ($$lock_v) != Cargo.toml workspace version ($$toml_v)." >&2; \
		echo "       Regenerate with: cargo update --workspace --offline" >&2; \
		exit 1; \
	fi

## CI gate — lock-version backstop + fmt --check + clippy -D warnings + nextest + doctests + fingerprint feature clippy
preflight: lock-version-check fmt-check lint test
	cargo clippy -p ox-http --all-targets --features fingerprint -- -D warnings
	@echo "Preflight passed"

deny:
	cargo deny check

install-tools:
	cargo binstall --no-confirm cargo-nextest cargo-deny
