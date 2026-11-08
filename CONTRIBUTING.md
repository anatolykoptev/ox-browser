# Contributing

Bug reports, fixes and focused features are welcome. For a larger change, open an issue first so
the approach can be agreed before you write it. Report a vulnerability privately, as described in
[SECURITY.md](SECURITY.md), not in an issue.

## Development

Rust 1.97 or newer (edition 2024) and [cargo-nextest](https://nexte.st) for the test target:

```sh
git clone https://github.com/anatolykoptev/ox-browser.git
cd ox-browser
make build        # cargo build --workspace
make preflight    # the CI gate
```

`make preflight` is exactly what CI runs on `ubuntu-24.04-arm` (`.github/workflows/ci.yml`): the
`Cargo.lock` version check, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
-- -D warnings`, `cargo nextest run --locked --all-targets --workspace`, doctests, and clippy on
`ox-http` with `--features fingerprint`. If it passes locally it passes there. `make deny` runs
`cargo deny check` and is not part of the gate.

A pull request that changes only documents (Markdown, `docs/`, licence, issue and pull-request
templates) skips that job.

## Commits

[Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `perf:`, `refactor:`,
`docs:`, `deps:`; `chore:`, `ci:`, `test:` and `build:` are hidden from the changelog. release-please
reads them on `main`, opens a release PR that bumps the version and `CHANGELOG.md`, and tags on
merge. Do not edit the version, `CHANGELOG.md` or `.release-please-manifest.json` by hand and do not
tag manually.

## Pull requests

One concern per pull request. State what changed and how you tested it, and add a test with every
behaviour change; a fix for a regression needs a test that fails without it. Network behaviour is
covered by tests against local fixtures, not live sites. Do not put hostnames, credentials or
personal data in code, fixtures or documents. Add new documents to [docs/INDEX.md](docs/INDEX.md).
