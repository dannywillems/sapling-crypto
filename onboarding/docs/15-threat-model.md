---
sidebar_position: 15
title: Threat Model and Audits
description:
  "Adversary capabilities, defended properties, and where each defence lives in
  the source."
---

# Threat Model and Audits

## 1. Why this chapter exists

A new contributor must know, before touching any cryptographic code, which
attacks the existing code defends against and which are out of scope. This
chapter is the single place where that table lives. Read it once before writing
your first non-trivial behavioural patch.

The table is opinionated about scope: a property the
[Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
defines and this crate implements is in scope; consensus state (double-spend
prevention across history) is out of scope because this crate does not maintain
a chain state.

## 2. Definitions

**Definition 15.1 (in scope).** A property is in scope for this crate iff the
[Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
defines it and this crate implements at least one mechanism that participates in
enforcing it.

**Definition 15.2 (out of scope).** A property is out of scope iff its
enforcement requires state this crate does not maintain (e.g. the global
nullifier set), a layer this crate does not own (network, OS, ceremony), or a
separate ZIP this crate does not implement.

**Definition 15.3 (defended by reduction).** A property "defended by
cryptographic reduction" is one whose breaking implies breaking a stated
cryptographic assumption (discrete log on Jubjub, $q$-power knowledge of
exponent on BLS12-381, BLAKE2 collision resistance). For each row in section
3.1, the reduction is named or cited.

**Definition 15.4 (defended by code-review invariant).** A property "defended by
code-review invariant" is one whose absence is not caught by any existing test
in the workspace and is preserved only because reviewers actively look for its
violation. These rows are the most fragile and the best candidates for new
regression tests.

## 3. Threat-model table

### 3.1 Defended by cryptographic reduction

| Adversary capability                                                       | Formal goal                                                                                          | Defence in this crate                                                                                                                                                                                                            | Regression test                                                                                                                                                                        |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Forge a valid Spend without knowing the spending key                       | Knowledge soundness of $R_{\mathsf{Spend}}$                                                          | Groth16 verifier in [`verifier/single.rs::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs#L28-L52); reduction is Theorem 11.3                                                            | [`circuit::test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L635-L782)                                                            |
| Spend a note twice                                                         | Nullifier collision resistance (PRF^nf one-way)                                                      | Faerie-gold mixing: [`spec::mixing_pedersen_hash`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L50-L60) plus [`spec::prf_nf`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L62-L78)         | [`circuit::test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L731-L780) (asserts in-circuit `nf` matches out-of-circuit `note.nf`) |
| Inflate the shielded supply                                                | Balance preservation (Theorem 9.4)                                                                   | Binding signature over `bvk` derived from `cv_sum - [valueBalance] G_{cv,v}` ([`verifier::SaplingVerificationContextInner::final_check`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L135-L148))          | [`value::tests::bsk_consistent_with_bvk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L236-L266)                                                                   |
| Forge a spend authorisation signature                                      | Existential unforgeability of RedJubjub                                                              | Signature verification in [`verifier/single.rs::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs#L46-L52); the `redjubjub` crate handles the cryptography                                 | [`keys::tests::spend_auth_sig_test_vectors`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L745-L770)                                                                 |
| Bind a note to multiple ivk-decryptable plaintexts via a small-order `epk` | Subgroup discipline ([Invariant 3.4](./cryptographic-primer#21-the-two-curves-bls12-381-and-jubjub)) | `epk.is_small_order()` check in [`SaplingVerificationContextInner::check_output`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L97-L133) lines 108-110; `g_d.assert_not_small_order` in the Output circuit | [`circuit::test_output_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L967-L1073)                                                          |
| Bind a spend to a small-order `rk`                                         | Subgroup discipline                                                                                  | `rk.is_small_order()` check in [`SaplingVerificationContextInner::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L46-L51) lines 47-51                                                          | None automated in this workspace; caught by audit only                                                                                                                                 |
| Slip a non-canonical `cmu` encoding past consensus                         | Canonical encoding rule (Invariant 5.5)                                                              | [`ExtractedNoteCommitment::from_bytes`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L65-L74) requires `Scalar::from_repr`                                                                          | None automated; caught by integration tests in downstream crates (`zcash_primitives`)                                                                                                  |

### 2.2 Defended by side-channel discipline (constant-time)

| Adversary capability                                    | Defence                                                                                                                                                                                                                                                                                                                                            | Regression test                                                       |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Timing side channel on secret-dependent comparison      | `subtle::ConstantTimeEq` impls: [`Nullifier`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L51-L55), [`ExtractedNoteCommitment`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L98-L108), [`EphemeralSecretKey`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L565-L569) | None; constant-time is a code-review invariant, not an automated test |
| Timing side channel on conditional branch over `Option` | `subtle::CtOption` everywhere a public-key-derived branch happens: see [`SpendAuthorizingKey::from_bytes`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L111-L130)                                                                                                                                                               | None automated                                                        |

### 2.3 Out of scope for this crate

| Adversary capability                             | Why out of scope                                                                                              | Where it is enforced                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Replay a nullifier (already-seen across chain)   | This crate computes nullifiers; it does not maintain the seen-set                                             | `zebrad` / `zcashd` consensus state                                                |
| Double-spend across forks                        | Same as above                                                                                                 | `zebrad` / `zcashd` consensus state                                                |
| Network-level deanonymisation (timing, topology) | Out of scope for any crypto crate                                                                             | Tor / Heartbeats, `zcashd` peer-discipline                                         |
| Memory disclosure of secrets at runtime          | This crate uses `Zeroize` selectively (e.g. through `redjubjub`); a process-level memory dump is out of scope | OS-level mitigations                                                               |
| Trusted setup compromise (Sapling MPC)           | The trusted-setup ceremony is one-time and external                                                           | [Sapling MPC](https://electriccoin.co/blog/announcing-the-sapling-mpc/), 2017-2018 |

## 4. Where audits live

The crate has been through multiple third-party audits as part of its history
under `librustzcash`. Public audit reports:

- [QED-it Sapling review](https://github.com/zcash/zcash/issues/2624) (the issue
  thread; reports linked from comments). Test exercises from this review are
  tracked in [issue #94](https://github.com/zcash/sapling-crypto/issues/94),
  which is open and a reasonable contribution target.
- [NCC Group review of bellman](https://research.nccgroup.com/2020/06/12/zcash-cryptographic-protocol-and-implementation-audit/)
  is not specific to sapling-crypto but covers the underlying Groth16 backend.

The crate maintains its own supply-chain audit infrastructure via `cargo-vet` in
[`supply-chain/audits.toml`](https://github.com/zcash/sapling-crypto/blob/0.7.0/supply-chain/audits.toml).
Read it before adding any dependency.

## 5. Failure modes (this chapter's own)

- **Treating the table as definitive.** This table summarises the
  defence-in-depth surface as of 0.7.0. Future versions will add rows (new
  attacks, new mitigations) and remove some (an attack found to be subsumed by
  another). Treat it as a snapshot and check the source first. Caught by: this
  very disclaimer.

## 6. Spec pointers

- [Zcash Protocol Specification §4.1.6 (Sapling)](https://zips.z.cash/protocol/protocol.pdf#sapling)
  defines the adversary model in the "Security properties" subsections of each
  component.
- [ZF Audit Repository](https://github.com/zcashfoundation/zcash-audits) is the
  index of public third-party audits across the Zcash codebase.

## 7. Exercises

1. **Locate the small-order check.** Without using grep, identify from this
   table the file and line range that rejects a small-order `rk` in a spend
   description. Open the file and confirm the check is exactly what the table
   says.
2. **Add a regression test for the small-order `rk` check.** Construct a
   `SpendDescription` whose `rk` is one of the eight small-order Jubjub points
   (the trick: $[r_J/8] G$ for a prime-order generator $G$ would be the
   identity; cofactor points are explicitly enumerated in the Jubjub paper).
   Call `SaplingVerificationContext::check_spend`. Confirm the verifier returns
   `false`. Add this as a test.
3. **Find a missing test.** This table marks "non-canonical `cmu` encoding" as
   having no automated test in this workspace. Write one. Hint: construct a
   32-byte buffer corresponding to a value above the field modulus, pass it to
   [`ExtractedNoteCommitment::from_bytes`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L65-L74),
   and assert the result is `None`. This is the kind of test issue
   [#145](https://github.com/zcash/sapling-crypto/issues/145) exists to attract.

**Answers in the code.** For exercise 1, the small-order `rk` check is at
[`src/verifier.rs` lines 47-51](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L47-L51).
For exercise 3, the canonical `bls12_381::Scalar` modulus is
$q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001$; any
32-byte value above this is non-canonical.
