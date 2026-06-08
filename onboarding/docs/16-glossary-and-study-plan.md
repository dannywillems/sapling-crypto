---
sidebar_position: 16
title: Glossary
description:
  "Sapling-internal abbreviations: what each one expands to, what it means, and
  where it is defined in the crate."
---

# Glossary

## 1. Why this chapter exists

The crate uses roughly 40 abbreviations: `ask`, `ak`, `nsk`, `nk`, `ivk`, `ovk`,
`dk`, `cm`, `cmu`, `cv`, `bsk`, `bvk`, `pk_d`, `g_d`, `epk`, `esk`, `rcm`,
`rcv`, `rk`, `rseed`, `pos`, `nf`, `ock`, `PCZT`, ZIP-32, ZIP-212, ZIP-216,
ZIP-244, KDF, OCK, PRF, CRH, FF1, FVK, FFVK, IVK, KA, MPC, MerkleCRH. Reading
the code without these is much harder than it needs to be. The table below gives
the expansion (the words behind the letters), the meaning in context, and the
source file for each.

## 2. Glossary

Each row gives what the abbreviation expands to (the words behind the letters),
what it means in context, and the source file where the term is defined. Most
Sapling symbols are built from a small set of letter fragments: `sk` = secret
key, `vk` = viewing key, `k` = key, `r` = randomness/randomiser, `d` =
diversified/diversifier, `cm` = commitment, `cv` = value commitment, `pk` =
public key.

| Term                                                 | Expands to                                            | Meaning                                                                                                                                                                                 | Source                                        |
| ---------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `ak`                                                 | authorization key (public)                            | Spend validating key; the public-key half of the spend authorisation signature. Type [`SpendValidatingKey`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L152-L226).  | `keys.rs`                                     |
| `ar`                                                 | authorization randomiser                              | Per-spend randomiser for the spend authorisation key. A jubjub::Scalar.                                                                                                                 | `circuit.rs::Spend::ar`                       |
| `ask`                                                | authorizing key (secret)                              | Spend authorising key; the secret-key half of the spend authorisation signature. Type [`SpendAuthorizingKey`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L67-L150). | `keys.rs`                                     |
| `bsk`                                                | binding signing key                                   | Binding signature signing key, derived from per-spend / per-output trapdoors.                                                                                                           | `value/sums.rs::TrapdoorSum::into_bsk`        |
| `bvk`                                                | binding verification key                              | Binding signature verification key, derived from value commitments and value balance.                                                                                                   | `value/sums.rs::CommitmentSum::into_bvk`      |
| `cm`, `cm_full_point`                                | commitment (note commitment)                          | Note commitment as a Jubjub point. Private; lives in `note.rs`.                                                                                                                         | `note/commitment.rs`                          |
| `cmu`                                                | commitment, u-coordinate                              | Extracted note commitment (u-coordinate of `cm`). The Merkle leaf.                                                                                                                      | `note/commitment.rs::ExtractedNoteCommitment` |
| `cv`                                                 | commitment to value (value commitment)                | Value commitment, an element of [`jubjub::ExtendedPoint`][jubjub::ExtendedPoint].                                                                                                       | `value.rs::ValueCommitment`                   |
| `CRH`                                                | collision-resistant hash                              | A hash for which finding two inputs with the same output is infeasible; the basis of `MerkleCRH` and the `ivk` derivation.                                                              | `spec.rs`                                     |
| `dk`                                                 | diversifier key                                       | Diversifier key for ZIP-32 HD wallets.                                                                                                                                                  | `zip32.rs::DiversifierKey`                    |
| `epk`                                                | ephemeral public key                                  | Ephemeral public key in note encryption.                                                                                                                                                | `keys.rs::EphemeralPublicKey`                 |
| `esk`                                                | ephemeral secret key                                  | Ephemeral secret key in note encryption. Post-ZIP-212, deterministically derived from [`rseed`][rseed].                                                                                 | `keys.rs::EphemeralSecretKey`                 |
| `FF1`                                                | format-preserving encryption mode FF1                 | NIST FF1 (AES-based) format-preserving encryption, used by ZIP-32 to derive diversifiers.                                                                                               | `zip32.rs`                                    |
| `FVK`                                                | full viewing key                                      | Full viewing key.                                                                                                                                                                       | `keys.rs::FullViewingKey`                     |
| `g_d`                                                | base point (generator), diversified                   | Diversified base point on Jubjub, $g_d = \mathsf{DiversifyHash}(d)$.                                                                                                                    | `keys.rs::Diversifier::g_d`                   |
| `ivk`                                                | incoming viewing key                                  | Incoming viewing key. The scalar by which [`g_d`][g_d] is multiplied to get [`pk_d`][pk_d].                                                                                             | `keys.rs::SaplingIvk`                         |
| `KA`                                                 | key agreement                                         | Key agreement (Diffie-Hellman on Jubjub).                                                                                                                                               | `spec.rs::ka_sapling_*`                       |
| `KDF`                                                | key derivation function                               | Key derivation function (BLAKE2b-32 with `Zcash_SaplingKDF`).                                                                                                                           | `keys.rs::SharedSecret::kdf_sapling`          |
| `MPC`                                                | multi-party computation                               | Multi-party computation; here the Sapling trusted-setup ceremony.                                                                                                                       | external                                      |
| `MerkleCRH^Sapling`                                  | Merkle collision-resistant hash                       | The Merkle hash on `(d, lhs, rhs)`.                                                                                                                                                     | `tree.rs::merkle_hash_field`                  |
| `nf`                                                 | nullifier                                             | Nullifier (32 bytes).                                                                                                                                                                   | `note/nullifier.rs::Nullifier`                |
| `nk`                                                 | nullifier (deriving) key                              | Nullifier deriving key.                                                                                                                                                                 | `keys.rs::NullifierDerivingKey`               |
| `nsk`                                                | nullifier secret key                                  | Nullifier secret key.                                                                                                                                                                   | `keys.rs::ExpandedSpendingKey::nsk`           |
| `ock`                                                | outgoing cipher key                                   | Outgoing cipher key (per-output BLAKE2b-32 hash of ovk and metadata).                                                                                                                   | `note_encryption.rs::prf_ock`                 |
| `ovk`                                                | outgoing viewing key                                  | Outgoing viewing key. 32-byte opaque value.                                                                                                                                             | `keys.rs::OutgoingViewingKey`                 |
| `PCZT`                                               | partially-created Zcash transaction                   | Partially-created Zcash transaction.                                                                                                                                                    | `pczt.rs`                                     |
| `pk_d`                                               | public key, diversified                               | Diversified transmission key. $[\mathsf{ivk}] \mathsf{g_d}$.                                                                                                                            | `keys.rs::DiversifiedTransmissionKey`         |
| `pos`                                                | position                                              | Position of a note in the commitment tree.                                                                                                                                              | `circuit.rs::Spend::auth_path` position bits  |
| `PRF^Expand`, `PRF^nf`, `PRF^ock`                    | pseudorandom function                                 | Sapling pseudorandom functions.                                                                                                                                                         | `spec.rs`, `note_encryption.rs`               |
| `rcm`                                                | random commitment (note commitment randomness)        | Note commitment trapdoor. Derived from `rseed` post-ZIP-212.                                                                                                                            | `note/commitment.rs::NoteCommitTrapdoor`      |
| `rcv`                                                | random value commitment (value commitment randomness) | Value commitment trapdoor.                                                                                                                                                              | `value.rs::ValueCommitTrapdoor`               |
| `rk`                                                 | randomised key                                        | Randomised verification key. `rk = ak + [ar] G_{sk}`.                                                                                                                                   | `keys.rs::ViewingKey::rk`                     |
| `rseed`                                              | random seed                                           | Note seed randomness (post-ZIP-212, 32 bytes).                                                                                                                                          | `note.rs::Rseed::AfterZip212`                 |
| `URS`                                                | uniform reference string                              | Uniform reference string. The base block for the Sapling group hash.                                                                                                                    | `constants.rs::GH_FIRST_BLOCK`                |
| `Zip212Enforcement`                                  | (type name, not an abbreviation)                      | Enum: `Off / GracePeriod / On`.                                                                                                                                                         | `note_encryption.rs::Zip212Enforcement`       |
| `ZIP-32`, `ZIP-212`, `ZIP-216`, `ZIP-244`, `ZIP-316` | Zcash Improvement Proposal                            | Zcash Improvement Proposals. See [zips.z.cash](https://zips.z.cash).                                                                                                                    | external                                      |

## 3. Hot files cheat sheet

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

## 4. Spec pointers

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf): the
  authority for every term in the glossary above.
- [ZIP index](https://zips.z.cash/) collects ZIP-32, ZIP-212, ZIP-216, ZIP-244,
  ZIP-316.
- [`zcash/sapling-crypto`](https://github.com/zcash/sapling-crypto/tree/0.7.0)
  is where every "Source" column in section 2 points; treat the upstream code as
  the canonical definition when it disagrees with this glossary.

## 5. Exercises

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
