---
sidebar_position: 1
title: Crate and Module Map
description:
  "Top-level layout of the sapling-crypto crate: every module, what it owns,
  what tests exercise it."
---

# Crate and Module Map

## 1. Why this chapter exists

The crate has no `CONTRIBUTING.md`, no architecture document, and 38 Rust source
files clustered into 9 named modules. A new contributor who clones it cold has
to derive the module graph from scratch by reading `lib.rs` and grepping for
re-exports. This chapter does that work once. Every later chapter
cross-references it: "the value commitment lives in
[`value::ValueCommitment`](#42-data-types-read-constantly-rarely-modified) and
is consumed by the Spend circuit in
[`circuit::expose_value_commitment`](#44-circuit-and-prover-feature-gated)."

Concretely: by the end of this chapter you should know which file to open for
any of the six load-bearing concepts (keys, notes, values, commitments,
circuits, bundles).

## 2. Definitions

**Definition 1.1 (Sapling bundle).** A Sapling bundle is a tuple
$B = (\mathbf{S}, \mathbf{O}, v_b, \mathsf{auth})$ where $\mathbf{S}$ is a
vector of spend descriptions, $\mathbf{O}$ is a vector of output descriptions,
$v_b \in \mathbb{Z}$ is the net value transferred out of the shielded pool, and
$\mathsf{auth}$ is the authorisation (binding signature plus, per spend, a spend
authorisation signature and a Groth16 proof). In code this is
[`bundle::Bundle<A, V>`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L54).

**Definition 1.2 (authorisation marker).** The phantom type `A` in
[`Bundle`][Bundle]`<A, V>` tags the state of the authorising data: from
[`EffectsOnly`][EffectsOnly] (no proofs, no signatures, used by light clients
inspecting effects) through several [`InProgress`][InProgress]`<P, S>` states
inside the builder to [`Authorized`][Authorized] (full proofs and signatures,
ready for consensus). The [`Authorization`][Authorization] trait associates a
[`SpendProof`][SpendProof], [`OutputProof`][OutputProof], and
[`AuthSig`][AuthSig] type with each marker.

**Invariant 1.3 (one anchor per bundle).** Every spend in a single bundle
references the same Merkle anchor; the builder rejects heterogeneous anchors at
construction time, and the circuit re-derives the anchor from the witnessed
authentication path so the verifier re-checks it.

## 3. The crate root

The library's module set is fixed in `lib.rs`. Two of them are gated behind the
`circuit` feature, which is on by default but is turned off by `no_std`
consumers that only need to verify or construct effects.

```rust reference title="src/lib.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/lib.rs#L1-L72
```

The re-export block at the bottom of `lib.rs` (`pub use ...`) is the "true"
public surface most users touch: [`PaymentAddress`][PaymentAddress],
[`Bundle`][Bundle], the key types, [`Note`][Note], [`Nullifier`][Nullifier],
[`Anchor`][Anchor], [`CommitmentTree`][CommitmentTree],
[`MerklePath`][MerklePath], [`Node`][Node],
[`NOTE_COMMITMENT_TREE_DEPTH`][NOTE_COMMITMENT_TREE_DEPTH], plus
[`BatchValidator`][BatchValidator] and
[`SaplingVerificationContext`][SaplingVerificationContext] from the `verifier`
module when `circuit` is on.

## 4. Module-by-module breakdown

### 4.1 Primitives (frozen)

These modules implement the primitives the Zcash protocol spec names outright.
They are essentially frozen; expect to read them, not to modify them.

- `constants`
  ([src/constants.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs)):
  fixed curve generators (the seven Pedersen-hash bases, the value commitment
  generators, the spending-key generator, the proof-generation-key generator),
  BLAKE2s personalisations (`b"Zcashivk"`, `b"Zcash_nf"`, `b"Zcash_PH"`, ...),
  and the Groth16 proof size constant
  [`GROTH_PROOF_SIZE`][GROTH_PROOF_SIZE]` = 192` bytes.
- `group_hash`
  ([src/group_hash.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/group_hash.rs)):
  hash-to-curve into the Jubjub prime-order subgroup. One function.
- `pedersen_hash`
  ([src/pedersen_hash.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs)):
  the Sapling Pedersen hash, out-of-circuit. The in-circuit gadget is separate:
  [`circuit::pedersen_hash`][circuit::pedersen_hash] lives under `src/circuit/`.
- `spec`
  ([src/spec.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs)):
  small functions named by the protocol spec ([`crh_ivk`][crh_ivk],
  [`diversify_hash`][diversify_hash],
  [`mixing_pedersen_hash`][mixing_pedersen_hash], [`prf_nf`][prf_nf],
  `ka_sapling_*`, [`extract_p`][extract_p],
  [`windowed_pedersen_commit`][windowed_pedersen_commit]). Private
  (`pub(crate)`).

### 4.2 Data types (read constantly, rarely modified)

- `note`
  ([src/note.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs)
  plus `note/commitment.rs` and `note/nullifier.rs`): the [`Note`][Note] struct,
  [`Rseed`][Rseed], [`NoteCommitment`][NoteCommitment] /
  [`ExtractedNoteCommitment`][ExtractedNoteCommitment],
  [`Nullifier`][Nullifier].
- `address`
  ([src/address.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs)):
  the [`PaymentAddress`][PaymentAddress] type (private module, only
  `PaymentAddress` itself is re-exported).
- `value`
  ([src/value.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs)
  plus `value/sums.rs`): [`NoteValue`][NoteValue],
  [`ValueCommitment`][ValueCommitment],
  [`ValueCommitTrapdoor`][ValueCommitTrapdoor], [`ValueSum`][ValueSum],
  [`CommitmentSum`][CommitmentSum], [`TrapdoorSum`][TrapdoorSum],
  [`BalanceError`][BalanceError].
- `tree`
  ([src/tree.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs)):
  the depth-32 Merkle tree ([`Node`][Node], [`Anchor`][Anchor],
  [`CommitmentTree`][CommitmentTree],
  [`IncrementalWitness`][IncrementalWitness], [`MerklePath`][MerklePath]) on top
  of the `incrementalmerkletree` crate.
- `keys`
  ([src/keys.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs)):
  the entire Sapling key tree below ZIP 32.
  [`SpendAuthorizingKey`][SpendAuthorizingKey],
  [`SpendValidatingKey`][SpendValidatingKey],
  [`ExpandedSpendingKey`][ExpandedSpendingKey],
  [`ProofGenerationKey`][ProofGenerationKey],
  [`NullifierDerivingKey`][NullifierDerivingKey], [`ViewingKey`][ViewingKey],
  [`FullViewingKey`][FullViewingKey],
  [`OutgoingViewingKey`][OutgoingViewingKey], [`SaplingIvk`][SaplingIvk],
  [`PreparedIncomingViewingKey`][PreparedIncomingViewingKey],
  [`DiversifiedTransmissionKey`][DiversifiedTransmissionKey],
  [`Diversifier`][Diversifier], [`EphemeralSecretKey`][EphemeralSecretKey],
  [`EphemeralPublicKey`][EphemeralPublicKey],
  [`PreparedEphemeralPublicKey`][PreparedEphemeralPublicKey],
  [`SharedSecret`][SharedSecret].

### 4.3 ZIP 32 and note encryption

- `zip32`
  ([src/zip32.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs),
  1876 lines): HD key derivation per [ZIP 32](https://zips.z.cash/zip-0032).
  Exposes [`ExtendedSpendingKey`][ExtendedSpendingKey],
  [`ExtendedFullViewingKey`][ExtendedFullViewingKey],
  [`DiversifiableFullViewingKey`][DiversifiableFullViewingKey],
  [`IncomingViewingKey`][IncomingViewingKey],
  [`DiversifierKey`][DiversifierKey]. This is the largest single source file in
  the crate.
- `note_encryption`
  ([src/note_encryption.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs),
  1514 lines): implements the
  [`zcash_note_encryption::Domain`](https://docs.rs/zcash_note_encryption) trait
  for Sapling, defines [`Zip212Enforcement`][Zip212Enforcement], exposes the
  `try_sapling_*_decryption` entry points, and contains the bulk of the test
  vectors in `test_vectors/note_encryption.rs`.

### 4.4 Circuit and prover (feature-gated)

These three modules are behind `feature = "circuit"`:

- `circuit`
  ([src/circuit.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs)
  plus `circuit/{ecc,pedersen_hash,constants}.rs`): the bellman `Circuit` impls
  for [`Spend`][Spend] and [`Output`][Output], plus the Edwards-curve gadget
  library and the in-circuit Pedersen-hash gadget.
- `prover`
  ([src/prover.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs)):
  the [`SpendProver`][SpendProver] and [`OutputProver`][OutputProver] traits,
  plus
  `mock::{`[`MockSpendProver`][MockSpendProver]`, `[`MockOutputProver`][MockOutputProver]`}`
  for tests.
- `verifier`
  ([src/verifier.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs)
  plus `verifier/{single,batch}.rs`):
  [`SaplingVerificationContext`][SaplingVerificationContext] for verifying one
  transaction, [`BatchValidator`][BatchValidator] for verifying many.

### 4.5 Transaction assembly

- `bundle`
  ([src/bundle.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs),
  623 lines): the [`Bundle`][Bundle], [`SpendDescription`][SpendDescription],
  [`OutputDescription`][OutputDescription], and [`Authorization`][Authorization]
  types. Pure data; no logic beyond accessors and
  [`map_authorization`][map_authorization].
- `builder`
  ([src/builder.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs),
  1387 lines): the [`Builder`][Builder], [`SpendInfo`][SpendInfo],
  [`OutputInfo`][OutputInfo], [`BundleType`][BundleType], and the
  [`InProgress`][InProgress]`<P, S>` state machine. The largest behavioural
  surface in the crate.
- `pczt`
  ([src/pczt.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt.rs)
  plus `pczt/*.rs`): partially-created Zcash transactions. Has its own actors
  (Creator, Constructor, Updater, IO Finalizer, Prover, Signer, Combiner, Spend
  Finalizer, Transaction Extractor) and its own error types per actor.

### 4.6 Re-exports at the crate root

```rust reference title="src/lib.rs (re-exports)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/lib.rs#L49-L68
```

Anything not in that re-export block is reachable only via
`sapling_crypto::module_name::Type`. The crate makes that explicit by leaving
`mod address`, `mod spec`, `mod tree`, `mod verifier` private at the crate root.

## 5. Failure modes

- **Importing a deprecated path.** The crate has been moved out of
  `zcash_primitives` (see CHANGELOG entry for 0.1.0); some external
  documentation still refers to the old paths (`zcash_primitives::sapling::*`).
  If you see those, treat the external doc as stale. Caught by: nothing
  automatic in this workspace; downstream crates discover this at compile time.
- **Using `circuit::`[`Spend`][Spend] without the `circuit` feature.** The
  module is gated behind `#[cfg(feature = "circuit")]`. Without it, none of the
  Groth16 types compile. Caught by: the `build-nostd` CI matrix
  (`wasm32-wasip1`, `thumbv7em-none-eabihf`) which builds the synthetic crate
  `--no-default-features`.
- **Confusing [`pedersen_hash`][pedersen_hash] (out-of-circuit) with
  [`circuit::pedersen_hash`][circuit::pedersen_hash] (in-circuit gadget).** They
  are named identically but live in different modules and have different
  signatures. The first takes an iterator of `bool`; the second takes a
  `bellman::ConstraintSystem` and an iterator of `boolean::Boolean`. Caught by:
  the type system.

## 6. Spec pointers

- [Zcash Protocol Specification, sec. 4.1.6 (Sapling)](https://zips.z.cash/protocol/protocol.pdf#sapling)
  gives the protocol-level reading of every module above. This is the document
  the in-source `//` comments most often cite.
- The crate's own
  [README](https://github.com/zcash/sapling-crypto/blob/0.7.0/README.md) notes
  the `no_std` constraint: downstream `no_std` consumers must enable
  `lazy_static`'s `spin_no_std` feature.

## 7. Exercises

1. **Identify the smallest entry point.** Open
   [src/lib.rs](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/lib.rs)
   and list every symbol re-exported at the crate root. For each, answer: which
   module file does it live in, and is it visible without the `circuit` feature?
   Compare your list with the re-export block above.
2. **Map module dependencies.** Grep the source for `use crate::` and
   `use super::` statements. Draw the resulting dependency graph by hand. Hint:
   `keys`, `note`, and `value` sit at the bottom; `builder` and `pczt` sit on
   top of everything else.
3. **Add a missing accessor.** `bundle::`[`Bundle`][Bundle] has accessors for
   [`shielded_spends`][shielded_spends], [`shielded_outputs`][shielded_outputs],
   [`value_balance`][value_balance], and [`authorization`][authorization], but
   not for the total count of spends or outputs. Add
   `pub fn num_spends(&self) -> usize` and `pub fn num_outputs(&self) -> usize`
   on `Bundle<A, V>`. Add a unit test that builds an
   [`EffectsOnly`][EffectsOnly] bundle and asserts both counts. Run
   `cargo test --all-features` and verify the test passes.

**Answers in the code.** For exercise 1, the re-export list is in
[src/lib.rs lines 49-68](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/lib.rs#L49-L68).
For exercise 3, the `Bundle::shielded_spends` and `Bundle::shielded_outputs`
accessors already return slices, so the implementation is
`self.shielded_spends.len()` / `self.shielded_outputs.len()`.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[Bundle]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L54
[EffectsOnly]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L31
[InProgress]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L946
[Authorized]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L42
[Authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L23
[SpendProof]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L24
[OutputProof]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L25
[AuthSig]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L26
[PaymentAddress]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs#L15
[Note]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L46
[Nullifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L15
[Anchor]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L75
[CommitmentTree]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L16
[MerklePath]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L20
[Node]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L116
[NOTE_COMMITMENT_TREE_DEPTH]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L15
[BatchValidator]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/batch.rs#L17
[SaplingVerificationContext]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs#L13
[GROTH_PROOF_SIZE]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L43
[circuit::pedersen_hash]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/pedersen_hash.rs#L21
[crh_ivk]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L25
[diversify_hash]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L46
[mixing_pedersen_hash]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L55
[prf_nf]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L67
[extract_p]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L159
[windowed_pedersen_commit]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L143
[Rseed]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L25
[NoteCommitment]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L19
[ExtractedNoteCommitment]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L63
[NoteValue]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L56
[ValueCommitment]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L134
[ValueCommitTrapdoor]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L86
[ValueSum]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L43
[CommitmentSum]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L177
[TrapdoorSum]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L108
[BalanceError]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L15
[IncrementalWitness]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L18
[SpendAuthorizingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L73
[SpendValidatingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L158
[ExpandedSpendingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L234
[ProofGenerationKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L323
[NullifierDerivingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L347
[ViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L350
[FullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L371
[OutgoingViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L230
[SaplingIvk]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L451
[PreparedIncomingViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L467
[DiversifiedTransmissionKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L505
[Diversifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L488
[EphemeralSecretKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L563
[EphemeralPublicKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L596
[PreparedEphemeralPublicKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L614
[SharedSecret]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L632
[ExtendedSpendingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L262
[ExtendedFullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L524
[DiversifiableFullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L658
[IncomingViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L845
[DiversifierKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L152
[Zip212Enforcement]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L63
[Spend]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L51
[Output]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L86
[SpendProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L22
[OutputProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L53
[MockSpendProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L190
[MockOutputProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L236
[SpendDescription]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L215
[OutputDescription]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L333
[map_authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L106
[Builder]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L568
[SpendInfo]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L175
[OutputInfo]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L356
[BundleType]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L44
[pedersen_hash]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L32
[shielded_spends]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L82
[shielded_outputs]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L87
[value_balance]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L94
[authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L101
