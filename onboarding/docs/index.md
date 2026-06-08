---
sidebar_position: 0
title: Home
description:
  "Graduate-level onboarding course for the zcash/sapling-crypto Rust crate,
  pinned to release 0.7.0."
---

# sapling-crypto onboarding

A code-anchored walk through the Zcash Sapling cryptography crate
(`zcash/sapling-crypto`). The intent is operational: by the end you should be
able to read an open issue against this repository, locate the relevant file,
and write a small PR.

The course is pinned to upstream tag
[`0.7.0`](https://github.com/zcash/sapling-crypto/tree/0.7.0) (commit
`c5e596c239dbf9138a74246b843bcd01413f51c7`). Every embedded code block points at
that ref so the course cannot drift when the working tree refactors.

<!-- prettier-ignore-start -->
:::warning Auto-generated. The code is the law.

This site was generated automatically (Claude Code) by reading the
upstream sources. Errors may have been introduced in translation, and
the math statements may not capture every consensus-relevant subtlety.
Treat every claim here as a hypothesis that the upstream source either
confirms or contradicts.

When in doubt, refer to:

- the source at
  [zcash/sapling-crypto@0.7.0](https://github.com/zcash/sapling-crypto/tree/0.7.0),
- the [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf),
- the relevant ZIPs ([ZIP 32](https://zips.z.cash/zip-0032),
  [ZIP 212](https://zips.z.cash/zip-0212),
  [ZIP 216](https://zips.z.cash/zip-0216)).

Corrections welcome: open an issue or PR against the
[`onboarding` branch](https://github.com/dannywillems/sapling-crypto/tree/onboarding)
of the fork.

:::
<!-- prettier-ignore-end -->

## What this crate is

`sapling-crypto` implements the cryptography used by the Zcash "Sapling"
shielded pool: notes (private UTXOs), nullifiers (double-spend protection),
value commitments (homomorphic balance), Pedersen hashes, the Sapling note
commitment Merkle tree, ZIP 32 HD key derivation, in-band note encryption, the
Groth16 Spend and Output circuits, and the prover / verifier APIs (single and
batch).

It does **not** implement: full Zcash consensus, transaction serialization above
the Sapling bundle, the Orchard shielded pool, or the transparent UTXO model.
Those live in the wider [`librustzcash`](https://github.com/zcash/librustzcash)
workspace.

## Notation used throughout

We pin the following notation across all chapters. The protocol spec uses
slightly different blackboard letters in places; we standardise.

- $\mathbb{F}_q$: a prime field of order $q$.
  - $q_{\mathbb{S}}$: the base field of BLS12-381's scalar field, also the base
    field of the Jubjub curve. Bit size 255.
  - $r_{\mathbb{J}}$: the order of the Jubjub prime-order subgroup.
- $\mathbb{J}$: the Jubjub Edwards curve (in this code,
  `jubjub::ExtendedPoint`).
- $\mathbb{J}^{(r)}$: the prime-order subgroup of $\mathbb{J}$
  (`jubjub::SubgroupPoint`).
- $[k]P$: scalar multiplication of curve point $P$ by scalar $k$.
- $\mathsf{Com}(m; r)$: a Pedersen commitment to bit-string $m$ with randomness
  $r$, taking values in $\mathbb{J}^{(r)}$.
- $H_\ell^{p}(\cdot)$: a BLAKE2s or BLAKE2b hash with $\ell$-bit output,
  personalised by tag $p$.
- $\mathsf{PRF}^{x}_{k}(\cdot)$: a keyed pseudorandom function named $x$ with
  key $k$.
- $a \mathbin{\|} b$: concatenation of byte strings.
- $\stackrel{\mathdollar}{\leftarrow}$: uniform sampling.
- $\mathsf{cmu}$: the u-coordinate of a note commitment. The leaf of the note
  commitment tree.
- $\mathsf{nf}$: a nullifier.
- $\mathsf{cv}$: a value commitment (an element of $\mathbb{J}$).
- $\mathsf{rk}$: a re-randomised spend validating key.

## How to read this course

Each chapter is standalone. The minimum guaranteed structure is:

1. **Why this chapter exists.**
2. **Definitions.** Numbered formal blocks (`Definition X.Y`, `Lemma X.Y`,
   `Invariant X.Y`, `Theorem X.Y`). Mathematical content is stated formally
   before any walkthrough.
3. **The code.** Live embeds from the pinned upstream source.
4. **Failure modes.** Each ending with a pointer to the test that catches the
   regression (or noting if the workspace has no automated test for it).
5. **Spec pointers.** External authorities, with one sentence each on why the
   chapter cites them.
6. **Exercises.** A minimum of three; at least one requires modifying the code
   or adding a test.

Chapters 01 and 02 are the navigation chapters: the crate / module map and the
build, test, contribution loop. Read them first. After that, the dependency
graph is roughly linear; you can skip ahead to a specific topic, but each
chapter assumes you have at least skimmed the primer (chapter 03).

## Threat model snapshot

A full table lives in the [Threat model and audits](./threat-model) chapter. For
now: the goal of this crate is to give Zcash full nodes and wallets a sound
implementation of Sapling such that

- **shielded transactions hide sender, recipient, and amount** from third
  parties watching the ledger (Sapling-shielded notes look like random
  commitments and ciphertexts), subject to
- **balance preservation** (no inflation), enforced by the binding signature
  over value commitments, and
- **spend authorisation soundness** (no spending without knowledge of the
  spending key), enforced by Groth16 knowledge soundness plus the RedJubjub
  spend authorisation signature.

The implementation aims to be constant-time at every secret-dependent branch (it
leans on `subtle::CtOption`, `subtle::ConstantTimeEq`, `group::cofactor`
clearings, etc.). The Groth16 trusted setup is out of scope for this crate; it
is a separate ceremony.
