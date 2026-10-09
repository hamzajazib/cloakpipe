# Contributing to CloakPipe

Thanks for your interest in contributing to CloakPipe! This document covers the basics you need to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/cloakpipe.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Push and open a pull request

## Development Setup

CloakPipe builds with the current stable Rust toolchain (CI uses `dtolnay/rust-toolchain@stable`).

```bash
# Build everything
cargo build --workspace

# Run the full test suite
cargo test --workspace

# Lint exactly as CI does
cargo clippy --workspace --all-targets -- -D warnings

# Run the proxy with debug logging
RUST_LOG=debug cargo run -p cloakpipe-cli -- start

# Try detection (no API key needed)
cargo run -p cloakpipe-cli -- test --text "Send $1.2M to alice@acme.com"
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) also runs end-to-end
gates for release manifests, certification, audit packs, the verifier and the
CloakLeak zero-leak benchmark. A change that alters the golden release hash in
`crates/cloakpipe-release/testdata` invalidates every hash already issued, so call
it out explicitly in your PR.

## Project Structure

CloakPipe is a Cargo workspace; see the crate map in the [README](README.md#architecture).
Normative specifications live in [`docs/`](docs): `AGENT_RELEASE.md`,
`CERTIFICATION.md`, `ANCHORING.md` and `AUDIT_PACK.md`. If you change a format
or a verification rule, update the matching document in the same PR.

## What to Contribute

- **Bug fixes** -- Always welcome. Please include a test that reproduces the bug.
- **New detection patterns** -- Add regex patterns to `cloakpipe-core/src/detector/patterns.rs` or financial patterns to `financial.rs`.
- **Documentation** -- Improvements to README, inline docs, or usage examples.
- **Tests** -- More coverage is always good. Integration tests live in `cloakpipe-core/tests/`.

For larger changes (new features, architectural changes), please open an issue first to discuss the approach.

## Code Guidelines

- Run `cargo test --workspace` before submitting. All tests must pass.
- Run `cargo clippy --workspace --all-targets -- -D warnings`; CI denies warnings.
- Use [Conventional Commits](https://www.conventionalcommits.org/) style messages, e.g. `fix(verify): ...`, `feat(cli): ...`, `docs: ...`.
- Follow existing code style -- no need to reformat files you didn't change.
- Keep PRs focused. One feature or fix per PR.
- Add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for user-facing changes.
- Write tests for new functionality.

## Security

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the same license as the project: MIT.
