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

:::warning[Auto-generated. The code is the law.]

This site was generated automatically (Claude Code) by reading the upstream
sources. Errors may have been introduced in translation, and the math statements
may not capture every consensus-relevant subtlety. Treat every claim here as a
hypothesis that the upstream source either confirms or contradicts.

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

## What Sapling does

Sapling is the shielded-payment layer of Zcash. It moves value while hiding the
sender, the recipient, and the amount from anyone reading the chain, while still
letting every node verify that no money was created or double-spent. The
cryptography in this crate is what makes those hidden payments checkable.

The whole protocol rests on four objects:

- **Note.** A shielded coin: an amount, the recipient's key material, and some
  randomness. A note is never published. What is published is its **commitment**
  (a hiding, binding Pedersen commitment; its extracted form is `cmu`). See
  [Note commitments](./pedersen-and-commitments).
- **Commitment tree.** Every note commitment ever created is appended as a leaf
  of a fixed-depth Merkle tree. The current root is the **anchor**. See
  [The note commitment tree](./note-commitment-tree).
- **Nullifier.** Spending a note publishes a **nullifier** (`nf`), derived
  deterministically from the note and the owner's nullifier key. Each note has
  exactly one nullifier, and nodes reject a transaction whose nullifier has
  already appeared; that is what prevents double-spends. An observer cannot link
  the nullifier back to the note's commitment. See
  [Notes and nullifiers](./notes-and-nullifiers).
- **Value commitment.** Amounts are hidden behind additively homomorphic
  Pedersen commitments (`cv`). Because they add, a verifier can check that
  inputs minus outputs equal the declared balance without learning any single
  amount; that check is the **binding signature**. See
  [Value commitments](./value-commitments).

### What the circuits actually prove

There are two circuits, and they are near mirror images. A transaction carries
**one Spend proof per note it consumes** and **one Output proof per note it
creates**: the Spend circuit proves you own an existing note in the tree and may
destroy it, while the Output circuit proves a new note is well-formed for its
recipient. The two sides are tied together only by the homomorphic value
commitments, balanced by the binding signature.

It is tempting to read the Spend proof as "just a Merkle path". The path is one
clause of several. The Spend circuit proves, in zero knowledge, the
**conjunction** of:

1. **Membership (the Merkle path).** The spent note's commitment is a leaf of
   the tree whose root is the public anchor. This is the clause usually pictured
   first, and it is where privacy comes from: the path and the note are private
   witnesses, so the proof shows "some note in the tree" without revealing which
   one.
2. **Value consistency.** The public value commitment `cv` commits to the same
   amount that is inside that note.
3. **Nullifier integrity.** The public nullifier `nf` is the correct nullifier
   for that note under the owner's nullifier key, so the right note is the one
   being marked spent.
4. **Spend authority.** The prover knows the spend authorising key behind the
   validating key `ak`, and the public randomised key `rk` is a re-randomisation
   of `ak`, tying the proof to the signature that authorises the spend.

The Output circuit is the dual. It proves that a freshly created note's
commitment and its value commitment `cv` are well-formed for the stated amount,
and that the ephemeral public key is consistent with the diversified base. It
does not touch the tree, because a new note has no path yet.

What is deliberately **not** in either circuit: the transaction-wide balance.
That is checked outside the SNARK by the binding signature over the value
commitments. Each circuit reasons about a single note;
[Spend and Output circuits](./spend-and-output-circuits) states both relations
clause by clause.

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
  [`jubjub::ExtendedPoint`][jubjub::ExtendedPoint]).
- $\mathbb{J}^{(r)}$: the prime-order subgroup of $\mathbb{J}$
  ([`jubjub::SubgroupPoint`][jubjub::SubgroupPoint]).
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

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[jubjub::ExtendedPoint]:
  https://docs.rs/jubjub/latest/jubjub/struct.ExtendedPoint.html
[jubjub::SubgroupPoint]:
  https://docs.rs/jubjub/latest/jubjub/struct.SubgroupPoint.html
