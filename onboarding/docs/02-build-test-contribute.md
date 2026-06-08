---
sidebar_position: 2
title: Build, Test, and Contribute
description:
  "The local commands a contributor needs, the CI gates a PR has to pass, and a
  concrete first-PR scenario."
---

# Build, Test, and Contribute

## 1. Why this chapter exists

The crate has no `CONTRIBUTING.md`. The "what does a passing PR look like"
question is answered only by the CI workflow files. This chapter inlines the
rules a PR has to satisfy, in the order CI runs them, and ends with a worked
example: pick an open issue, write the patch, run the right commands locally,
and open the PR.

If you only read one chapter before opening a PR, read this one.

## 2. Definitions

**Definition 2.1 (PR gate).** A merge-ready PR against
[`zcash/sapling-crypto`](https://github.com/zcash/sapling-crypto) must satisfy
every job in
[`.github/workflows/ci.yml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/ci.yml)
and every job in
[`.github/workflows/audits.yml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/audits.yml).
There is no enforced PR template; nothing checks the description. Everything is
enforced as CI.

**Definition 2.2 (MSRV).** The Minimum Supported Rust Version is 1.85.1,
declared in
[`rust-toolchain.toml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/rust-toolchain.toml).
Clippy is invoked at the MSRV channel (not stable). A patch that compiles on
stable but fails clippy at 1.85.1 fails CI.

**Definition 2.3 (no_std purity).** The crate compiles under
`--no-default-features` for `wasm32-wasip1` and `thumbv7em-none-eabihf`. The CI
job `build-nostd` synthesises a fresh crate, drops all dev-dependencies, and
builds the synthetic crate against the targets. Any new `use std::*` import that
is not gated by `#[cfg(feature = "std")]` will break this.

## 3. The local commands

### 3.1 One-time setup

```bash
git clone git@github.com:zcash/sapling-crypto.git
cd sapling-crypto
# The toolchain file pins the channel. Rustup picks it up
# automatically on the first cargo command.
rustup show
rustup target add wasm32-wasip1 thumbv7em-none-eabihf
cargo install cargo-vet --version "~0.10"
cargo install cargo-deny
```

### 3.2 Per-change workflow

In the order CI runs them:

```bash
cargo fmt -- --check                                   # fmt
cargo clippy --all-targets -- -D warnings              # clippy at MSRV
cargo test --all-features --verbose --release          # test
cargo build --all-targets --all-features --verbose     # build-latest

# no_std targets (build-nostd, simplified):
cd /tmp && cargo new --lib ci-build && cd ci-build
echo '#![no_std]' > src/lib.rs
cargo add --path /path/to/sapling-crypto --no-default-features
cargo add lazy_static --no-default-features --features "spin_no_std"
cargo build --target wasm32-wasip1
cargo build --target thumbv7em-none-eabihf

# Then back in the crate root:
cd /path/to/sapling-crypto
cargo doc --all-features --document-private-items      # doc-links
cargo build --all --benches                            # bitrot
cargo vet --locked                                     # cargo-vet
cargo deny check licenses                              # cargo-deny
```

If you only have time for one command before pushing, run
`cargo test --all-features --release`. That covers the most common mistake (a
refactor that breaks a test vector). If you have time for two, add
`cargo clippy --all-targets -- -D warnings`.

### 3.3 Running a focused test

```bash
cargo test --all-features -- spend_auth_sig_test_vectors
cargo test --all-features -- circuit::test_input_circuit_with_bls12_381
cargo test --all-features --release -- --ignored
```

The release build is non-optional for circuit tests: the Groth16 prover is far
too slow in debug. Expect ~1 minute per Spend proof under the `--release` flag
on an x86 desktop.

### 3.4 Benchmarks

```bash
cargo bench --bench circuit         # sapling-spend-prove
cargo bench --bench pedersen_hash   # raw pedersen hash throughput
```

The `circuit` bench uses `pprof` on Unix to dump a flamegraph; the output is in
`target/criterion/`.

## 4. The CI jobs, annotated

```yaml reference title=".github/workflows/ci.yml"
https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/ci.yml
```

Annotated reading:

- `test`: matrix on Linux, Windows, macOS. The `--release` flag is not optional
  because the proving system is too slow in debug.
- `build-latest`: removes `Cargo.lock` before building. This catches
  semver-incompatible upper-bound regressions in dependencies (a new minor
  version that broke something the crate uses). If a dependabot PR touches
  `Cargo.lock`, this job is the one that catches the breakage.
- `build-nostd`: the synthetic-crate trick (see section 3.2). The synthetic
  crate has no dev-dependencies, which would otherwise pull in `pprof`,
  `criterion`, etc. that do not build for embedded targets.
- `clippy`: at the MSRV toolchain, with `-D warnings`. If you add a new lint
  trigger that only the latest clippy catches, this job catches it next time the
  MSRV bumps.
- `doc-links`: builds rustdoc with private items. The crate sets
  `#![deny(rustdoc::broken_intra_doc_links)]` in
  [`src/lib.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/lib.rs#L17),
  so any `[broken_link]` in a doc comment fails the build.
- `fmt`: `cargo fmt -- --check`. There is no `rustfmt.toml`; defaults are in
  effect.

The audits workflow runs two extra checks:

```yaml reference title=".github/workflows/audits.yml"
https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/audits.yml
```

- `cargo-vet`: every dependency is either trusted via a local audit in
  [`supply-chain/audits.toml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/supply-chain/audits.toml)
  or delegated to a trusted import (Mozilla, Bytecode Alliance, Embark, ZF)
  listed in `supply-chain/imports.lock`. If you bump a dependency to an
  un-audited version, this job fails. The fix is to add an exemption or write
  the audit; do not delete the audits file.
- `cargo-deny check licenses`: only Apache-2.0 and MIT are allowed by default,
  with three named exceptions (see
  [deny.toml](https://github.com/zcash/sapling-crypto/blob/0.7.0/deny.toml)).
  Adding a dependency with a different license fails this job. The fix is to
  remove the dependency or to add a `[[licenses.clarify]]` block, which requires
  reviewer judgement.

## 5. Changelog discipline

Every behavioural PR adds an entry to `CHANGELOG.md` under the unreleased
section. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) with sections `Added`,
`Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.

Look at the
[recent CHANGELOG entries](https://github.com/zcash/sapling-crypto/blob/0.7.0/CHANGELOG.md#070---2026-04-21)
for the tone: terse, declarative, no marketing. Each entry references the
modified symbol with its full crate path.

```markdown reference title="CHANGELOG.md (head)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/CHANGELOG.md#L1-L30
```

There is no enforcement that the CHANGELOG entry lives in its own commit; this
is a soft convention for this crate, unlike many other Zcash repos.

## 6. A worked first PR

Pick issue [#106](https://github.com/zcash/sapling-crypto/issues/106): "Change
ask -> ak derivation to use an explicit method rather than From".

What the issue is asking for, concretely:

```rust reference title="src/keys.rs (current From impl)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L160-L164
```

The
`From<&`[`SpendAuthorizingKey`][SpendAuthorizingKey]`> for `[`SpendValidatingKey`][SpendValidatingKey]
impl makes a load-bearing cryptographic derivation look like a type coercion.
Replacing it with an explicit method (e.g.
`SpendValidatingKey::derive_from(&ask)`) makes downstream calls more greppable
and matches the orchard crate's style.

A reasonable PR plan:

1. Add
   `impl SpendValidatingKey { pub fn derive_from(ask: &SpendAuthorizingKey) -> Self { ... } }`
   with the existing `From` body inlined.
2. Replace every call site of `SpendValidatingKey::from(&ask)` in the crate with
   `SpendValidatingKey::derive_from(&ask)`. Use `cargo check` to find them;
   expect roughly half a dozen.
3. Decide whether to keep the `From` impl for backwards compatibility. The issue
   does not say either way; a polite PR keeps it with `#[deprecated]`.
4. Add a CHANGELOG entry under `### Changed` referencing both the new method and
   the deprecation.
5. Run the full local workflow from section 3.2.
6. Open the PR with a body that quotes the issue link and explains the
   deprecation choice.

You can verify your patch against the existing test
[`spend_auth_sig_test_vectors`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L745-L770)
which exercises the `SpendAuthorizingKey -> SpendValidatingKey` derivation
through `From`. If your refactor breaks that test, the math went wrong.

## 7. Failure modes

- **CI green locally, red on GitHub: forgot `--all-features`.** Several modules
  (`circuit`, `prover`, `verifier`) are feature-gated. Running `cargo test`
  without `--all-features` skips most of the test suite silently. Caught by:
  nothing locally if you forget; the CI `test` job catches it.
- **clippy passes on stable, fails at MSRV.** clippy lints get retired in newer
  toolchains; MSRV clippy still emits them. Run
  `cargo +1.85.1 clippy --all-targets -- -D warnings` to mirror CI. Caught by:
  the CI `clippy` job.
- **`cargo vet` fails on a new dependency.** You added a dep that isn't audited.
  Caught by: the CI `cargo-vet` job. Do not delete the dep from
  `supply-chain/imports.lock`. Either run
  `cargo vet fetch && cargo vet certify <crate>` to write a local audit, or ask
  a maintainer to delegate to a trusted import set.

## 8. Spec pointers

- [`.github/workflows/ci.yml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/ci.yml)
  is the canonical PR gate. If this chapter contradicts that file, the file
  wins.
- [`.github/workflows/audits.yml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/.github/workflows/audits.yml)
  enforces the supply chain checks; see
  [cargo-vet documentation](https://mozilla.github.io/cargo-vet/) for how the
  audit file format works.

## 9. Exercises

1. **Reproduce the CI matrix locally.** Run every command in section 3.2, in
   order. Time each one and write down the result. Identify the slowest job and
   explain in one sentence why it is slow.
2. **Break a CI job intentionally.** Add a `println!("debug")` to
   `src/builder.rs`. Run `cargo clippy --all-targets -- -D warnings` and observe
   the failure. Remove the line. Now add an unused `use std::println;` (yes,
   `std` not `core`) at the top of `src/keys.rs`. Build the no_std target.
   Observe the failure. Revert.
3. **Land a CHANGELOG-only PR.** Pick a previously-merged PR from the
   [recent merge history](https://github.com/zcash/sapling-crypto/pulls?q=is%3Apr+is%3Aclosed+sort%3Aupdated-desc).
   Add a sentence to its CHANGELOG entry that you think clarifies it. Open a PR
   with only that diff. Run the full local workflow. This is the smallest
   possible non-noop PR; useful for testing that your local setup matches CI.

**Answers in the code.** For exercise 1, expect
`cargo test --all-features --release` to be the slowest single command (full
Groth16 test cycle). For exercise 2, the `println!` failure is caught by
`clippy::print_stdout` (lint). For exercise 3, look at
[PR #182](https://github.com/zcash/sapling-crypto/pull/182) as an example of a
near-no-op merge.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[SpendAuthorizingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L73
[SpendValidatingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L158
