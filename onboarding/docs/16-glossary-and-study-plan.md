---
sidebar_position: 16
title: Glossary and Study Plan
description:
  "Sapling-internal abbreviations and a week-by-week schedule that converges on
  a real contribution."
---

# Glossary and Study Plan

## 1. Why this chapter exists

The crate uses roughly 40 abbreviations: `ask`, `ak`, `nsk`, `nk`, `ivk`, `ovk`,
`dk`, `cm`, `cmu`, `cv`, `bsk`, `bvk`, `pk_d`, `g_d`, `epk`, `esk`, `rcm`,
`rcv`, `rk`, `rseed`, `pos`, `nf`, `ock`, `PCZT`, ZIP-32, ZIP-212, ZIP-216,
ZIP-244, KDF, OCK, PRF, CRH, FF1, FVK, FFVK, IVK, KA, MPC, MerkleCRH. Reading
the code without these is much harder than it needs to be.

The glossary is one section. The study plan that follows it is the second half
of the chapter: a four-week schedule that ends in a plausible PR.

## 2. Glossary

Each entry links to the source file where the term is defined.

| Term                                                 | Meaning                                                                                                                                                                                 | Source                                        |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `ak`                                                 | Spend validating key; the public-key half of the spend authorisation signature. Type [`SpendValidatingKey`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L152-L226).  | `keys.rs`                                     |
| `ar`                                                 | Per-spend randomiser for the spend authorisation key. A jubjub::Scalar.                                                                                                                 | `circuit.rs::Spend::ar`                       |
| `ask`                                                | Spend authorising key; the secret-key half of the spend authorisation signature. Type [`SpendAuthorizingKey`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L67-L150). | `keys.rs`                                     |
| `bsk`                                                | Binding signature signing key, derived from per-spend / per-output trapdoors.                                                                                                           | `value/sums.rs::TrapdoorSum::into_bsk`        |
| `bvk`                                                | Binding signature verification key, derived from value commitments and value balance.                                                                                                   | `value/sums.rs::CommitmentSum::into_bvk`      |
| `cm`, `cm_full_point`                                | Note commitment as a Jubjub point. Private; lives in `note.rs`.                                                                                                                         | `note/commitment.rs`                          |
| `cmu`                                                | Extracted note commitment (u-coordinate of `cm`). The Merkle leaf.                                                                                                                      | `note/commitment.rs::ExtractedNoteCommitment` |
| `cv`                                                 | Value commitment, an element of [`jubjub::ExtendedPoint`][jubjub::ExtendedPoint].                                                                                                       | `value.rs::ValueCommitment`                   |
| `dk`                                                 | Diversifier key for ZIP-32 HD wallets.                                                                                                                                                  | `zip32.rs::DiversifierKey`                    |
| `epk`                                                | Ephemeral public key in note encryption.                                                                                                                                                | `keys.rs::EphemeralPublicKey`                 |
| `esk`                                                | Ephemeral secret key in note encryption. Post-ZIP-212, deterministically derived from [`rseed`][rseed].                                                                                 | `keys.rs::EphemeralSecretKey`                 |
| `FVK`                                                | Full viewing key.                                                                                                                                                                       | `keys.rs::FullViewingKey`                     |
| `g_d`                                                | Diversified base point on Jubjub, $g_d = \mathsf{DiversifyHash}(d)$.                                                                                                                    | `keys.rs::Diversifier::g_d`                   |
| `ivk`                                                | Incoming viewing key. The scalar by which [`g_d`][g_d] is multiplied to get [`pk_d`][pk_d].                                                                                             | `keys.rs::SaplingIvk`                         |
| `KA`                                                 | Key agreement (Diffie-Hellman on Jubjub).                                                                                                                                               | `spec.rs::ka_sapling_*`                       |
| `KDF`                                                | Key derivation function (BLAKE2b-32 with `Zcash_SaplingKDF`).                                                                                                                           | `keys.rs::SharedSecret::kdf_sapling`          |
| `MPC`                                                | Multi-party computation; here the Sapling trusted-setup ceremony.                                                                                                                       | external                                      |
| `MerkleCRH^Sapling`                                  | The Merkle hash on `(d, lhs, rhs)`.                                                                                                                                                     | `tree.rs::merkle_hash_field`                  |
| `nf`                                                 | Nullifier (32 bytes).                                                                                                                                                                   | `note/nullifier.rs::Nullifier`                |
| `nk`                                                 | Nullifier deriving key.                                                                                                                                                                 | `keys.rs::NullifierDerivingKey`               |
| `nsk`                                                | Nullifier secret key.                                                                                                                                                                   | `keys.rs::ExpandedSpendingKey::nsk`           |
| `ock`                                                | Outgoing cipher key (per-output BLAKE2b-32 hash of ovk and metadata).                                                                                                                   | `note_encryption.rs::prf_ock`                 |
| `ovk`                                                | Outgoing viewing key. 32-byte opaque value.                                                                                                                                             | `keys.rs::OutgoingViewingKey`                 |
| `PCZT`                                               | Partially-created Zcash transaction.                                                                                                                                                    | `pczt.rs`                                     |
| `pk_d`                                               | Diversified transmission key. $[\mathsf{ivk}] \mathsf{g_d}$.                                                                                                                            | `keys.rs::DiversifiedTransmissionKey`         |
| `pos`                                                | Position of a note in the commitment tree.                                                                                                                                              | `circuit.rs::Spend::auth_path` position bits  |
| `PRF^Expand`, `PRF^nf`, `PRF^ock`                    | Sapling pseudorandom functions.                                                                                                                                                         | `spec.rs`, `note_encryption.rs`               |
| `rcm`                                                | Note commitment trapdoor. Derived from `rseed` post-ZIP-212.                                                                                                                            | `note/commitment.rs::NoteCommitTrapdoor`      |
| `rcv`                                                | Value commitment trapdoor.                                                                                                                                                              | `value.rs::ValueCommitTrapdoor`               |
| `rk`                                                 | Randomised verification key. `rk = ak + [ar] G_{sk}`.                                                                                                                                   | `keys.rs::ViewingKey::rk`                     |
| `rseed`                                              | Note seed randomness (post-ZIP-212, 32 bytes).                                                                                                                                          | `note.rs::Rseed::AfterZip212`                 |
| `URS`                                                | Uniform reference string. The base block for the Sapling group hash.                                                                                                                    | `constants.rs::GH_FIRST_BLOCK`                |
| `Zip212Enforcement`                                  | Enum: `Off / GracePeriod / On`.                                                                                                                                                         | `note_encryption.rs::Zip212Enforcement`       |
| `ZIP-32`, `ZIP-212`, `ZIP-216`, `ZIP-244`, `ZIP-316` | Zcash Improvement Proposals. See [zips.z.cash](https://zips.z.cash).                                                                                                                    | external                                      |

## 3. The study plan

A four-week schedule that converges on opening a real PR. Each week combines
reading (one or two chapters), a code-touching exercise, and one diagnostic.
Adjust the pace; the structure is what matters.

### Week 1: orient and run

**Reading.** Chapters [0 (home)](./), [1 (crate map)](./crate-and-module-map),
[2 (build and contribute)](./build-test-contribute),
[3 (cryptographic primer)](./cryptographic-primer).

**Practical.** Set up the toolchain. Run the full local CI mirror from
chapter 2. Identify the slowest step.

**Diagnostic.** Can you state, in one sentence each, what every top-level module
in `src/` is responsible for? If not, re-read chapter 1.

### Week 2: the data layer

**Reading.** Chapters [4 (group hash and Pedersen)](./group-hash-and-pedersen),
[5 (note commitments)](./pedersen-and-commitments),
[6 (commitment tree)](./note-commitment-tree),
[7 (keys and ZIP-32)](./keys-and-zip32),
[8 (notes and nullifiers)](./notes-and-nullifiers).

**Practical.** Re-derive the empty-tree anchor by hand (exercise 1 from chapter
6). Then compute one nullifier by hand (exercise 2 from chapter 8). Compare
against the source.

**Diagnostic.** Sketch the data dependency graph from `seed` to
[`Nullifier`][Nullifier]. Identify every PRF / hash call on the path. Six is
about right; if you count fewer, you missed one.

### Week 3: value, encryption, and the circuit

**Reading.** Chapters [9 (value commitments)](./value-commitments),
[10 (note encryption)](./note-encryption),
[11 (circuits)](./spend-and-output-circuits).

**Practical.** Print `cs.num_aux()` for the Spend circuit (exercise 1 from
chapter 11). Add a CHANGELOG-only PR (exercise 3 from chapter 2) to confirm you
can clear the CI gate end-to-end on a noop change.

**Diagnostic.** Open
[`src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs)
and identify the line range that implements clauses 7, 8, 9, 10 of the Spend
relation (Definition 11.1). If any clause is missing, you have a real bug to
file; if all four are present, your reading matches the spec.

### Week 4: assemble and ship

**Reading.** Chapters [12 (provers and verifiers)](./provers-and-verifiers),
[13 (bundle and builder)](./bundle-and-builder), [14 (PCZT)](./pczt),
[15 (threat model)](./threat-model).

**Practical.** Pick one of the following open issues and open a PR:

- [#122](https://github.com/zcash/sapling-crypto/issues/122): "Consider padding
  to 1 Sapling spend in non-coinbase bundles". A boolean default flip in
  [`BundleType::DEFAULT`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L60-L64)
  plus updating the tests and the CHANGELOG.
- [#145](https://github.com/zcash/sapling-crypto/issues/145): "Add tests for the
  Sapling proving and verifying APIs". A pure test addition; pick one specific
  path (e.g. "verify a known good proof using the test parameters") and write
  the test. No behavioural change required.
- [#106](https://github.com/zcash/sapling-crypto/issues/106): "Change ask -> ak
  derivation to use an explicit method rather than From". A name refactor; see
  the
  [worked example in chapter 2](./build-test-contribute#6-a-worked-first-pr).

Open the PR. Run the local mirror once before pushing. The PR review cycle is
the final exam.

## 4. Hot files cheat sheet

If your patch touches one of these, expect more review:

- `builder.rs`: 15 commits in the last 2 years; the largest behavioural surface.
- `keys.rs`: 8 commits; the key tree.
- `zip32.rs`: 7 commits; HD derivation, FF1 over AES.
- `pczt/*.rs`: PCZT is under active design; 4-7 commits each.

If your patch touches one of these, it is almost certainly a non-issue (these
are frozen):

- `pedersen_hash.rs`, `group_hash.rs`, `constants.rs`, `spec.rs`: the
  primitives. Any change here requires extreme care; the generators and
  personalisations are consensus-fixed.

## 5. Spec pointers

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf): the
  authority for every term in the glossary above.
- [ZIP index](https://zips.z.cash/) collects ZIP-32, ZIP-212, ZIP-216, ZIP-244,
  ZIP-316.
- [`zcash/sapling-crypto`](https://github.com/zcash/sapling-crypto/tree/0.7.0)
  is where every "Source" column in section 2 points; treat the upstream code as
  the canonical definition when it disagrees with this glossary.

## 6. Exercises

1. **Pick an issue.** Read every open issue at
   <https://github.com/zcash/sapling-crypto/issues> and select three that match
   your interest. For each, identify the chapter of this course that best
   prepares you. Note any chapter that feels underprepared; that is your reading
   gap.
2. **Run the CI gate.** Pick any small PR from the
   [merged queue](https://github.com/zcash/sapling-crypto/pulls?q=is%3Apr+is%3Aclosed+sort%3Aupdated-desc).
   Check out its base. Apply the diff. Run every CI step locally. If anything
   fails, the PR's CI must have run a different command; the gap is your local
   environment.
3. **Open a one-line PR.** Find a typo in any of the in-source doc comments
   (`grep -r 'recieve\|seperate\|sucess' src/`). Open a PR fixing it. Include a
   CHANGELOG entry under `### Fixed`. This is the smallest possible non-noop PR;
   it tests your CI and PR workflow end-to-end.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[jubjub::ExtendedPoint]:
  https://docs.rs/jubjub/latest/jubjub/struct.ExtendedPoint.html
[rseed]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L96
[g_d]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L491
[pk_d]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs#L88
[Nullifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L15
