# Discovery notes

Frozen against upstream `zcash/sapling-crypto` at tag `0.7.0`
(commit `c5e596c239dbf9138a74246b843bcd01413f51c7`). Every `reference`
code embed in the course pins to this SHA.

## Workspace shape

Single Rust crate, edition 2021, MSRV 1.85.1. No workspace, no
sub-crates. Library only; no binaries. Default features
`["multicore", "circuit"]`; alternative builds drop the Groth16
circuits to keep `no_std` consumers (mobile wallets, embedded
signers) lean.

Source tree under `src/`:

- `lib.rs` declares the public module graph.
- `constants.rs` carries fixed curve generators and BLAKE2s
  personalisations.
- `spec.rs` collects the small functions the protocol spec names
  outright (`crh_ivk`, `diversify_hash`, `mixing_pedersen_hash`,
  `prf_nf`, `ka_sapling_*`).
- `group_hash.rs` is the hash-to-curve primitive.
- `pedersen_hash.rs` is the Pedersen hash used outside the circuit;
  `circuit/pedersen_hash.rs` is the in-circuit gadget.
- `note.rs`, `note/commitment.rs`, `note/nullifier.rs` define notes.
- `value.rs`, `value/sums.rs` cover monetary values and the
  homomorphic value commitment.
- `keys.rs` covers ask, ak, nsk, nk, ivk, ovk, the Sapling key tree
  bottom layer.
- `zip32.rs` covers HD key derivation per ZIP 32 (1876 lines, the
  largest single file).
- `tree.rs` defines `Node`, `Anchor`, and wires up the
  `incrementalmerkletree` crate at `NOTE_COMMITMENT_TREE_DEPTH = 32`.
- `note_encryption.rs` is the in-band note encryption (`Domain` impl
  for `zcash_note_encryption`, sapling KDF, PRF^ock).
- `bundle.rs` defines `Bundle`, `SpendDescription`, `OutputDescription`,
  the `Authorization` trait and its `EffectsOnly` / `Authorized`
  markers.
- `builder.rs` is the transaction builder (1387 lines).
- `pczt.rs` and `pczt/*.rs` implement the multi-role partially-created
  transaction protocol (Creator, Constructor, Updater, IO Finalizer,
  Prover, Signer, Combiner, Spend Finalizer, Transaction Extractor).
- `circuit.rs` and `circuit/{ecc,pedersen_hash,constants}.rs` are the
  Groth16 circuits and the gadget library.
- `prover.rs` exposes the `SpendProver` and `OutputProver` traits and
  their `MockSpendProver`/`MockOutputProver` test doubles.
- `verifier.rs`, `verifier/single.rs`, `verifier/batch.rs` are the
  consensus-rule checkers.

## CI graph

`.github/workflows/ci.yml`:

- `test`: `cargo test --all-features --verbose --release` on Linux,
  Windows, macOS.
- `build-latest`: builds with `Cargo.lock` removed (latest deps) on
  the same three OSes.
- `build-nostd`: synthesises a tiny consumer crate, drops
  dev-dependencies, builds `sapling-crypto` for `wasm32-wasip1` and
  `thumbv7em-none-eabihf`. The synthetic-crate pattern is how the
  crate guards `no_std` purity.
- `bitrot`: `cargo build --all --benches`.
- `clippy`: clippy at MSRV via `auguwu/clippy-action@1.5.0`, denying
  warnings.
- `doc-links`: `cargo doc --all-features --document-private-items`
  to catch broken intra-doc links (the crate sets
  `#![deny(rustdoc::broken_intra_doc_links)]`).
- `fmt`: `cargo fmt -- --check`.

`.github/workflows/audits.yml`:

- `cargo-vet --locked` against the audits in `supply-chain/`.
- `cargo-deny check licenses` against `deny.toml`.

## Hot files (last 2 years)

- `CHANGELOG.md`, `Cargo.toml`, `Cargo.lock` (release plumbing).
- `src/builder.rs` (15 changes, largest behavioural surface).
- `.github/workflows/ci.yml` (9 changes).
- `src/keys.rs` (8 changes).
- `src/zip32.rs` (7 changes).
- `src/pczt/updater.rs` (7 changes), `src/pczt.rs` (6), all PCZT
  submodules (4 each). PCZT churn dominates 2024-2026.
- `src/value/sums.rs`, `src/circuit.rs`, `src/note_encryption.rs`,
  `src/prover.rs`, `src/pedersen_hash.rs` (3-4 changes each).

The PCZT module was added in 0.4 and remains the most active area.
A new contributor wanting to land changes will most likely be touching
`pczt/`, `builder.rs`, or `keys.rs`. The cryptographic primitives
(`group_hash.rs`, `pedersen_hash.rs`, `spec.rs`, `constants.rs`) are
essentially frozen.

## Authoritative external references

- Zcash Protocol Specification, `protocol.pdf` (sections 4.1.6,
  4.2.2, 4.7.2, 4.8, 4.13, 4.16, 4.17, 4.19, 5.4, 5.6).
- ZIP 32 (HD key derivation), ZIP 212 (note plaintext / `Rseed`),
  ZIP 216 (canonical RedJubjub encoding), ZIP 244 (transaction
  digests, indirectly).
- Hopwood, Bowe, Hornby, Wilcox, "Zcash Protocol Specification",
  Network Upgrade 5 revision and later.
- BLS12-381 design (Bowe, Sean), Jubjub design notes (`jubjub`
  crate), bellman `groth16` (Sean Bowe et al.).

## PR / contribution gates

No `CONTRIBUTING.md`, no `AGENTS.md`, no `CLAUDE.md`. The contribution
gate is what CI enforces:

1. `cargo fmt -- --check` must pass.
2. `cargo clippy --all-targets -- -D warnings` must pass at the MSRV
   toolchain (1.85.1).
3. `cargo test --all-features --release` must pass on Linux, Windows,
   and macOS.
4. `no_std` builds for `wasm32-wasip1` and `thumbv7em-none-eabihf`
   must succeed.
5. `cargo doc --all-features --document-private-items` must produce
   no broken intra-doc link warnings.
6. `cargo vet --locked` must pass: any new dependency or new version
   needs an entry in `supply-chain/audits.toml` or a delta against
   a trusted import set in `supply-chain/imports.lock`.
7. `cargo deny check licenses` must accept the dependency tree
   (Apache-2.0 / MIT / a few pinned exceptions).

There is no enforced PR template, but every commit on `main` since
0.6 has either a CHANGELOG entry in the same PR or is part of a
release commit. The release process is manual (`Release sapling-crypto
version X.Y.Z` style commits, then a tagged GitHub PR merge).

## Open issues queue (snapshot 2026-05-28)

Tracked at <https://github.com/zcash/sapling-crypto/issues>. Selected
items that anchor exercises in the contribution chapter:

- #168: "Refactor ivk types to make zero unrepresentable" - touches
  `keys.rs::SaplingIvk`.
- #160: "decrypt_diversifier incorrectly returns None" - touches
  `zip32.rs`.
- #145: "Add tests for the Sapling proving and verifying APIs" -
  touches `prover.rs`, `verifier.rs`.
- #136: "Create specific types for batch-verifying Spend and Output
  proofs separately" - touches `verifier/batch.rs`.
- #122: "Consider padding to 1 Sapling spend in non-coinbase bundles"
  - touches `builder.rs::BundleType`.
- #118: "Refactor sapling_crypto::keys API to be more like
  orchard::keys" - touches `keys.rs`.
- #106: "Change ask -> ak derivation to use an explicit method rather
  than From" - touches `keys.rs::SpendValidatingKey::from`.

Tag-based labelling is minimal (no "good first issue" label).
Comparable starter work is in #145 (tests) and #122 (boolean default
flip in BundleType).
