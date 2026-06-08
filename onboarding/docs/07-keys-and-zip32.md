---
sidebar_position: 7
title: Keys and ZIP 32
description:
  "The Sapling key tree: spending key, ask, ak, nsk, nk, ivk, ovk, dk,
  diversifiers, and the ZIP 32 HD derivation that produces them."
---

# Keys and ZIP 32

## 1. Why this chapter exists

Sapling has eight named keys that derive from one root, plus a diversifier key,
plus the ephemeral keys used for encryption. The relationships among them are
not documented in any single comment in the source; you have to read four files
(`keys.rs`, `zip32.rs`, `address.rs`, `spec.rs`) and the protocol spec to
reconstruct the tree.

By the end you should be able to draw, from memory, the derivation DAG from
`seed` to [`PaymentAddress`][PaymentAddress], name each edge function, and
locate each node in the source.

## 1.5 A one-page reminder of how a Sapling spend works

Before naming eight keys it helps to remember what actually happens when a
shielded user spends. The keys are not arbitrary; each one exists because some
step below needs exactly that capability and no more. Read this section as a
checklist of "what must someone be able to do", then read section 2 as "which
key gives them that ability".

### 1.5.1 The state on chain

A shielded balance is not an account. It is a set of **notes**. A note is a
tuple

$$
\mathsf{note} = (\mathsf{d}, \mathsf{pk_d}, v, \mathsf{rcm})
$$

where $(\mathsf{d}, \mathsf{pk_d})$ identifies the recipient (the
`PaymentAddress`), $v$ is the value, and $\mathsf{rcm}$ is the commitment
trapdoor. The chain never stores the note. It stores only

- the **note commitment**
  $\mathsf{cm} =
  \mathsf{NoteCommit}(\mathsf{g_d}, \mathsf{pk_d}, v, \mathsf{rcm})$,
  appended to a global incremental Merkle tree (the note commitment tree);
- the **nullifier set**, a set of opaque 32-byte tags that record which notes
  have already been spent.

Spending a note is therefore: prove that some note exists in the tree, reveal
its nullifier, and create new notes for the recipients of the spend.

### 1.5.2 The four things the spender must do

For each input note the spender must be able to:

1. **Prove the note is in the tree.** Knowledge of a Merkle path from
   $\mathsf{cm}$ to the published anchor. No key needed for the path itself, but
   the spender must know the note, which means the spender must have been able
   to **decrypt it on receipt**.
2. **Prove that the note has not already been spent**, by revealing its
   nullifier $\mathsf{nf}$. The chain refuses any transaction whose nullifier is
   already in the set. Deriving $\mathsf{nf}$ requires a secret tied to the note
   (otherwise anyone could mark anyone's notes as spent).
3. **Authorize the spend**, so that only the legitimate holder of the note can
   move it. This is a signature over the transaction, tied to a public value
   committed inside the Spend proof.
4. **Produce the proof itself**, a Groth16 Spend proof certifying that (1), (2),
   and (3) are consistent: the spender knows a note in the tree, the revealed
   nullifier matches that note, and the signing key matches the note's owner.

The same spender must also, for each new recipient, **create an output**: build
a fresh note, encrypt it to the recipient, and prove (in the Output circuit)
that the encrypted note is well-formed and its value commitment is consistent
with the spend.

Add to that the bookkeeping side: a wallet observer must be able to **recognize
own activity** without holding the spending key, both on the incoming side
(notes addressed to me) and the outgoing side (notes I sent, which I want to
remember after I no longer have the plaintext).

### 1.5.3 Mapping each ability to a key

Each ability in 1.5.2 is granted by exactly one secret, and the names of the
keys track that one-to-one mapping:

| Ability                                                    | Secret used                 | Name                                              |
| ---------------------------------------------------------- | --------------------------- | ------------------------------------------------- |
| decrypt an incoming note to learn $(v, \mathsf{rcm})$      | incoming viewing key        | $\mathsf{ivk}$                                    |
| compute the nullifier of a note I own                      | nullifier secret            | $\mathsf{nsk}$ (or its public form $\mathsf{nk}$) |
| sign the spend authorization                               | spend authorizing secret    | $\mathsf{ask}$ (public form $\mathsf{ak}$)        |
| build the Spend proof without holding $\mathsf{ask}$       | proving capability          | $(\mathsf{ak}, \mathsf{nsk})$                     |
| re-decrypt a note I sent (audit / change tracking)         | outgoing viewing key        | $\mathsf{ovk}$                                    |
| publish a fresh unlinkable receive address                 | diversifier layer           | $\mathsf{d}, \mathsf{g_d}, \mathsf{pk_d}$         |
| derive many diversifiers deterministically from an HD seed | diversifier key             | $\mathsf{dk}$                                     |
| encrypt one output to its recipient                        | per-output ephemeral secret | $\mathsf{esk}$                                    |

Two consequences fall out of this table and explain the rest of the chapter:

- The reason `ProofGenerationKey = (ak, nsk)` exists is that abilities 1
  (decrypt), 2 (nullifier), and 4 (proof) can all be done without ability 3
  (sign). That is the hardware-wallet split: the slow machine proves, the small
  machine signs.
- The reason `FullViewingKey = (ak, nk, ovk)` exists is that audit needs to
  recognize both incoming and outgoing activity without ever signing or proving.
  It cannot move funds because it lacks $\mathsf{nsk}$ (cannot produce a valid
  in-circuit nullifier preimage) and $\mathsf{ask}$ (cannot sign).

Section 2 now restates this as a capability ladder and gives the workflows that
motivate each rung.

## 2. Why so many keys

Sapling could in principle drive everything from one secret. It does not. The
wallet is instead split into a **capability ladder**: each rung holds strictly
less power than the rung above, and the names of the keys track which capability
they grant. The point is **least privilege**, so each counterparty (signer,
prover, viewer, payment processor, recipient) only ever holds what it needs.
That is what produces the long list of keys: each key isolates one capability
that some real workflow wants to hand out independently.

### 2.1 The capability ladder

From most powerful to least powerful:

| Rung                           | Key bundle                                                           | What it lets you do                                                                                 |
| ------------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Spend                          | `ExpandedSpendingKey` $= (\mathsf{ask}, \mathsf{nsk}, \mathsf{ovk})$ | Sign spends, build Spend proofs, decrypt own outgoing notes. Full control of funds.                 |
| Prove                          | `ProofGenerationKey` $= (\mathsf{ak}, \mathsf{nsk})$                 | Build Spend proofs (and the in-circuit nullifier) without `ask`. Cannot sign, so cannot move funds. |
| View (full)                    | `FullViewingKey` $= (\mathsf{ak}, \mathsf{nk}, \mathsf{ovk})$        | Detect own spends, decrypt incoming notes, decrypt own outgoing notes. Read access to all activity. |
| View (incoming only)           | $\mathsf{ivk}$                                                       | Trial-decrypt incoming notes. Cannot detect own spends, cannot see outgoing.                        |
| View (outgoing only)           | $\mathsf{ovk}$                                                       | Re-decrypt notes this wallet sent (change tracking, audit).                                         |
| Receive (one unlinkable label) | `PaymentAddress` $= (\mathsf{d}, \mathsf{pk_d})$                     | Receive funds. Many `d` values under one `ivk` give unlinkable addresses on chain.                  |

Workflows that motivate the splits:

- A hardware wallet holds $\mathsf{ask}$ and signs spends. A faster online
  machine holds $(\mathsf{ak}, \mathsf{nsk})$ and runs the heavy Groth16 prover.
  The online machine cannot move funds even if it is compromised.
- An auditor or watch-only wallet holds the `FullViewingKey`. It sees the
  wallet's entire transaction history on both sides but cannot spend.
- A payment processor holds only $\mathsf{ivk}$ to detect incoming payments and
  learns nothing about what the receiver later spends.
- A user advertises many `PaymentAddress` values (one per counterparty) under
  one wallet, so that on-chain observers cannot link them.

The picture inside the [Spend circuit](./spend-and-output-circuits) is the
mirror image of this ladder: the circuit witnesses the proving-capability keys
$(\mathsf{ak}, \mathsf{nsk})$ and derives every downstream key in zero
knowledge, so the proof certifies "I hold the proving capability for this note"
without revealing any key directly.

### 2.2 A mnemonic for the names

The alphabet soup is regular once you see the prefixes:

- **a** stands for "auth". $\mathsf{ask}$ is the spend-**a**uthorizing
  **s**ecret **k**ey; $\mathsf{ak}$ is the matching validating point.
- **n** stands for "nullifier". $\mathsf{nsk}$ is the **n**ullifier **s**ecret
  **k**ey; $\mathsf{nk} = [\mathsf{nsk}] G_{\mathsf{pgk}}$ is its public
  deriving point.
- **i** stands for "incoming". $\mathsf{ivk}$ is the **i**ncoming **v**iewing
  **k**ey.
- **o** stands for "outgoing". $\mathsf{ovk}$ is the **o**utgoing **v**iewing
  **k**ey.
- **d** is the diversifier layer: $\mathsf{d}$ is the 88-bit diversifier;
  $\mathsf{g_d}$ is its hash to a Jubjub base;
  $\mathsf{pk_d} = [\mathsf{ivk}]
  \mathsf{g_d}$ is the diversified transmission
  key; $\mathsf{dk}$ is the AES-256 key used by FF1 (ZIP 32) to map indices to
  diversifiers.

In one sentence: every secret/public pair is "$X\mathsf{sk}$ to $X\mathsf{k}$ by
scalar multiplication on a fixed generator"; $\mathsf{ivk}$ comes from a hash of
$(\mathsf{ak}, \mathsf{nk})$ because the incoming-view capability is logically
downstream of both auth and nullifier; the diversifier layer at the bottom is
freshly generated as needed.

### 2.3 Where each key shows up (cheat sheet)

| Key             | Lives in           | Used by Spend circuit?                             | Used by Output circuit?                                    |
| --------------- | ------------------ | -------------------------------------------------- | ---------------------------------------------------------- |
| $\mathsf{ask}$  | spending key only  | no (signing is out of circuit)                     | no                                                         |
| $\mathsf{ak}$   | proving / viewing  | yes: witness, feeds $\mathsf{rk}$ and ivk preimage | no                                                         |
| $\mathsf{nsk}$  | proving / spending | yes: witness, $\mathsf{nk} = [\mathsf{nsk}] G$     | no                                                         |
| $\mathsf{nk}$   | viewing            | yes: derived in-circuit, feeds $\mathsf{nf}$ + ivk | no                                                         |
| $\mathsf{ivk}$  | incoming viewing   | yes: derived in-circuit, gives $\mathsf{pk_d}$     | no                                                         |
| $\mathsf{ovk}$  | outgoing viewing   | no                                                 | no (used by note encryption only)                          |
| $\mathsf{d}$    | address            | no                                                 | no                                                         |
| $\mathsf{g_d}$  | address            | yes: witness, small-order check, note commitment   | yes: witness, small-order check, $\mathsf{epk}$, commit    |
| $\mathsf{pk_d}$ | address            | yes: $[\mathsf{ivk}] \mathsf{g_d}$, in note commit | yes: witnessed without on-curve check, in note commit      |
| $\mathsf{dk}$   | ZIP 32             | no                                                 | no                                                         |
| $\mathsf{esk}$  | per-output secret  | no                                                 | yes: witness, $\mathsf{epk} = [\mathsf{esk}] \mathsf{g_d}$ |

The two viewing keys ($\mathsf{ivk}$, $\mathsf{ovk}$) never enter a circuit
themselves; they live in the note-encryption pipeline. Everything in the
"proving" rung ($\mathsf{ak}$, $\mathsf{nsk}$) is what the Spend circuit
actually witnesses.

## 3. Definitions

### 3.1 The Sapling key tree (below ZIP 32)

Starting from a 32-256 byte spending key $\mathsf{sk}$ (typically output by ZIP
32 child derivation):

**Definition 7.1 (ask, ak).** The **spend authorizing key** is
$\mathsf{ask} = \mathsf{PRF^{Expand,ASK}}(\mathsf{sk}) \in
\mathbb{F}_{r_{\mathbb{J}}}$,
restricted to nonzero scalars, and is wrapped by
[`SpendAuthorizingKey`][SpendAuthorizingKey]. The **spend validating key** is
$\mathsf{ak} = [\mathsf{ask}] \cdot
\mathsf{SpendingKeyGenerator} \in \mathbb{J}^{(r)}$,
wrapped by [`SpendValidatingKey`][SpendValidatingKey]. The Sapling RedJubjub
signature scheme uses $(\mathsf{ask}, \mathsf{ak})$ as its signing /
verification key pair.

Role: $\mathsf{ask}$ signs the spend authorization signature
$\mathsf{spendAuthSig}$ over the SIGHASH out of circuit; it never enters either
circuit. $\mathsf{ak}$ is witnessed in the
[Spend circuit](./spend-and-output-circuits) and used in two places: the
re-randomized form $\mathsf{rk} = \mathsf{ak} + [\mathsf{ar}] G_{\mathsf{sk}}$
is exposed as a public input (clause 2 of $R_{\mathsf{Spend}}$), and
$\mathsf{repr}(\mathsf{ak})$ is the first half of the in-circuit $\mathsf{ivk}$
preimage (clause 4).

**Definition 7.2 (nsk, nk).** The **nullifier secret key** is
$\mathsf{nsk} = \mathsf{PRF^{Expand,NSK}}(\mathsf{sk}) \in
\mathbb{F}_{r_{\mathbb{J}}}$.
The **nullifier deriving key** is
$\mathsf{nk} = [\mathsf{nsk}] \cdot
\mathsf{ProofGenerationKeyGenerator} \in \mathbb{J}^{(r)}$,
wrapped by [`NullifierDerivingKey`][NullifierDerivingKey]. The pair
$(\mathsf{ak}, \mathsf{nsk})$ is the [`ProofGenerationKey`][ProofGenerationKey];
the pair $(\mathsf{ak}, \mathsf{nk})$ is the **viewing key**.

Role: $\mathsf{nsk}$ is witnessed in the
[Spend circuit](./spend-and-output-circuits), where clause 3 of
$R_{\mathsf{Spend}}$ enforces $\mathsf{nk} = [\mathsf{nsk}] G_{\mathsf{pgk}}$.
The derived $\mathsf{nk}$ is then mixed into the in-circuit nullifier
$\mathsf{nf} = \mathsf{BLAKE2s}(\mathsf{repr}(\mathsf{nk})
\mathbin{\|} \mathsf{repr}(\rho))$
(clause 10) and into the $\mathsf{ivk}$ preimage (clause 4). Out of circuit, a
holder of $\mathsf{nk}$ can recognise their own notes' nullifiers once they have
decrypted the note (this is the "detect own spends" capability of the
`FullViewingKey`).

**Definition 7.3 (ivk).** The **incoming viewing key** is

$$
\mathsf{ivk} = \mathsf{CRH^{ivk}}(\mathsf{repr}_{\mathbb{J}}(\mathsf{ak}),
  \mathsf{repr}_{\mathbb{J}}(\mathsf{nk})),
$$

specifically $\mathsf{BLAKE2s}_{32, \mathsf{Zcashivk}}(\cdot)$ with the
most-significant 5 bits cleared so it fits in the Jubjub scalar field. It is
computed by [`crh_ivk`][crh_ivk] and exposed as
[`ViewingKey::ivk`][ViewingKey::ivk].

Role: out of circuit, the receiver uses $\mathsf{ivk}$ to trial-decrypt every
new on-chain Output (see [Note encryption](./note-encryption)). Inside the
[Spend circuit](./spend-and-output-circuits), $\mathsf{ivk}$ is recomputed from
$\mathsf{ak}, \mathsf{nk}$ (clause 4) and immediately used to derive
$\mathsf{pk_d} = [\mathsf{ivk}] \mathsf{g_d}$ (clause 6); this is how the proof
certifies that the spent note's recipient was indeed the wallet behind this
$\mathsf{ivk}$.

**Definition 7.4 (ovk).** The **outgoing viewing key**,
[`OutgoingViewingKey`][OutgoingViewingKey], is a 32-byte opaque value
$\mathsf{ovk} = \mathsf{PRF^{Expand,OVK}}(\mathsf{sk})$ truncated to 32 bytes.
It is used to let the sender re-decrypt their own outputs without revealing them
to the receiver's ivk.

Role: $\mathsf{ovk}$ is purely out of circuit. Note encryption derives the
`OutgoingCipherKey` from $\mathsf{ovk}$ to wrap $(\mathsf{pk_d}, \mathsf{esk})$
into the `out_ciphertext`; a wallet that keeps $\mathsf{ovk}$ can later recover
the recipient address and amount of any Output it created. Neither the Spend nor
the Output circuit sees $\mathsf{ovk}$.

**Definition 7.5 (d, g_d, pk_d).** A **diversifier**
[`Diversifier`][Diversifier] $\mathsf{d} \in \{0,1\}^{88}$ defines the base of a
payment address. Each diversifier yields
$\mathsf{g_d} = \mathsf{DiversifyHash}(\mathsf{d}) \in \mathbb{J}^{(r)}
\cup \{\bot\}$;
about 50% of diversifiers fail ([`g_d`][g_d]` = None`). The **diversified
transmission key** is $\mathsf{pk_d} = [\mathsf{ivk}] \cdot \mathsf{g_d}$,
computed by
[`DiversifiedTransmissionKey::derive`][DiversifiedTransmissionKey::derive]. The
payment address $(\mathsf{d}, \mathsf{pk_d})$ is a
[`PaymentAddress`][PaymentAddress].

Role: the diversifier $\mathsf{d}$ itself never enters either circuit; only its
image $\mathsf{g_d}$ does, in both. In the
[Spend circuit](./spend-and-output-circuits), $\mathsf{g_d}$ is witnessed and
small-order-checked, then used both to derive
$\mathsf{pk_d} = [\mathsf{ivk}]
\mathsf{g_d}$ (clause 6) and to feed the note
commitment (clause 8). In the [Output circuit](./spend-and-output-circuits),
$\mathsf{g_d}$ is witnessed and small-order-checked, then used to expose the
sender's ephemeral key $\mathsf{epk} = [\mathsf{esk}] \mathsf{g_d}$ (clause 3)
and to feed the note commitment (clause 4); the Output circuit witnesses
$\mathsf{pk_d}$ without an on-curve check, because the recipient's decryption
will detect any malformed value off chain.

### 3.2 ZIP 32

**Definition 7.6 (ZIP 32 extended key).** An extended Sapling spending key is a
quintuple

$$
\mathsf{xsk} = (\mathsf{depth}, \mathsf{parent\_fvk\_tag}, \mathsf{i},
  \mathsf{c}, \mathsf{expsk}, \mathsf{dk}),
$$

where $\mathsf{expsk}$ is the [`ExpandedSpendingKey`][ExpandedSpendingKey] and
$\mathsf{dk}$ is the [`DiversifierKey`][DiversifierKey]. Child derivation uses
$\mathsf{PRF^{Expand}}$ instances indexed by [ZIP 32's tag
constants][zip32-master] (`ZIP32_SAPLING_*`) to mix in the child index and the
parent chain code. Hardened-only children: ZIP 32 forbids non-hardened Sapling
derivation because the deterministic derivation of a child verification key from
a parent's $\mathsf{ak}$ is not desired here.

Role of $\mathsf{dk}$: $\mathsf{dk}$ is a 32-byte AES-256 key. It is used by FF1
to map a 11-byte diversifier index $j$ to the 88-bit candidate diversifier
$\mathsf{d}_j$ (Section 4.3); the same $\mathsf{dk}$ therefore enumerates the
family of addresses under one wallet. It never enters either circuit and is not
part of any viewing key shared with third parties.

**Invariant 7.7 (non-zero ask).** $\mathsf{ask}$ must be nonzero. The
probability of a zero ask from $\mathsf{PRF^{Expand,ASK}}$ is negligible
($2^{-252}$ ish), but the code explicitly handles it: every constructor of
[`SpendAuthorizingKey`][SpendAuthorizingKey] checks the scalar and returns
`None` on zero. The
[`ExpandedSpendingKey::from_spending_key`][ExpandedSpendingKey::from_spending_key]
constructor panics if this triggers, accepting the negligible probability of an
unrecoverable seed.

**Invariant 7.8 (ak prime-order).** $\mathsf{ak}$ must be an element of
$\mathbb{J}^{(r)}$ and not the identity. The deserializer rejects
non-prime-order points:
[`SpendValidatingKey::from_bytes`][SpendValidatingKey::from_bytes] uses
[`jubjub::SubgroupPoint`][jubjub::SubgroupPoint]`::from_bytes` and an explicit
`!p.is_identity()` check.

## 4. The code

### 4.1 The bottom layer: `keys.rs`

`keys.rs` defines every key in the tree except the ZIP 32 extended ones. It is
the file you will reread most often. Three regions to internalise:

- The signing key types ([`SpendAuthorizingKey`][SpendAuthorizingKey],
  [`SpendValidatingKey`][SpendValidatingKey]) and their
  [`From<&SpendAuthorizingKey>`][SpendValidatingKey::from] impl that derives the
  validating key. These are wrappers around `redjubjub` types.
- [`ExpandedSpendingKey`][ExpandedSpendingKey],
  [`ProofGenerationKey`][ProofGenerationKey], [`ViewingKey`][ViewingKey],
  [`FullViewingKey`][FullViewingKey]. The chain of `From<&Foo> for Bar` impls
  plus named methods ([`to_viewing_key`][ProofGenerationKey::to_viewing_key],
  [`from_expanded_spending_key`][FullViewingKey::from_expanded_spending_key]).
- [`SaplingIvk`][SaplingIvk] and
  [`PreparedIncomingViewingKey`][PreparedIncomingViewingKey]. The "prepared"
  variant exists to amortise a `WnafScalar` precomputation across many
  trial-decryption attempts.

```rust reference title="src/keys.rs (SpendAuthorizingKey)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L67-L150
```

The derivation chain
`seed -> ExpandedSpendingKey -> ProofGenerationKey -> ViewingKey -> SaplingIvk -> PaymentAddress`
is wired through the `Into` / method impls:

```rust reference title="src/keys.rs (ExpandedSpendingKey::from_spending_key)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L247-L262
```

```rust reference title="src/keys.rs (ProofGenerationKey -> ViewingKey)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L336-L367
```

### 4.2 The ZIP 32 layer: `zip32.rs`

`zip32.rs` is the largest single file in the crate (1876 lines). It mostly does
plumbing: serialise/deserialise extended keys, derive children, find
diversifiers via FF1 over AES-256.

```rust reference title="src/zip32.rs (constants and master derivation)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L27-L66
```

```rust reference title="src/zip32.rs (internal-vs-external FVK)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L79-L110
```

A subtle structural detail is the **internal full viewing key**: a derivative of
a "normal" [`DiversifiableFullViewingKey`][DiversifiableFullViewingKey] used to
detect transactions that the wallet itself originated (e.g. change outputs). The
derivation mixes in a separate personalisation
([`ZIP32_SAPLING_INT_PERSONALIZATION`][ZIP32_SAPLING_INT_PERSONALIZATION]) so
that the internal and external scopes do not share an ivk.

### 4.3 Diversifier search via FF1

ZIP 32 reuses FF1 over AES-256 as a 88-bit format-preserving pseudo-random
permutation to map a diversifier index to an actual 88-bit diversifier:

```rust reference title="src/zip32.rs (DiversifierKey::diversifier)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L154-L230
```

The find-loop in [`DiversifierKey::diversifier`][DiversifierKey::diversifier]
walks consecutive indices until it lands on one whose output happens to be a
valid Jubjub-friendly diversifier (about 1 in 2). On average two indices are
tried per address.

## 5. Failure modes

- **Confusing ask and ak.** The signing key is `ask` (a scalar); the
  verification key is `ak` (a curve point). The
  [`From<&SpendAuthorizingKey> for SpendValidatingKey`][SpendValidatingKey::from]
  impl in `keys.rs` makes derivation look like a coercion; if you see
  `SpendValidatingKey::from(&ask)`, that is a real scalar-multiplication, not a
  no-op cast. See
  [issue #106](https://github.com/zcash/sapling-crypto/issues/106). Caught by:
  review.
- **Trying to derive a non-hardened child.** ZIP 32 for Sapling forbids
  non-hardened derivation. The [`KeyIndex::new`][KeyIndex::new] helper rejects
  this; trying to derive yields
  [`DecodingError`][DecodingError]`::UnsupportedChildIndex`. Caught by: that
  error variant and the
  [unit tests in `zip32.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L1500).
- **`pk_d = identity`.** If [`ivk`][ivk]` = 0` (or the diversifier produces an
  [`g_d`][g_d] that happens to multiply to the identity), the resulting
  [`pk_d`][pk_d] is the identity and there is no recipient. The
  [`DiversifiedTransmissionKey`][DiversifiedTransmissionKey] constructors reject
  this:
  [`PaymentAddress::from_parts_unchecked`][PaymentAddress::from_parts_unchecked]
  checks [`is_identity`][is_identity] and returns `None`. Caught by: that check.
  See also [issue #168](https://github.com/zcash/sapling-crypto/issues/168) for
  the related "make `ivk = 0` unrepresentable" refactor.
- **Lossy "prepared" form drift.**
  [`PreparedIncomingViewingKey`][PreparedIncomingViewingKey] caches a
  `WnafScalar`; if [`SaplingIvk`][SaplingIvk] changes its scalar encoding but
  the prepared form is not regenerated, decryption silently fails. Caught by:
  trial decryption tests in `note_encryption.rs`.

## 6. Spec pointers

- [Zcash Protocol Specification, §4.2.2 (Sapling Key Components)](https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents)
  is the master source for every relationship above.
- [ZIP 32 (HD wallets for Zcash)](https://zips.z.cash/zip-0032), specifically
  §"Sapling extended spending keys", is the master source for `zip32.rs`.
- [ZIP 316 (Unified addresses and viewing keys)](https://zips.z.cash/zip-0316)
  is the source for the
  [`DiversifiableFullViewingKey`][DiversifiableFullViewingKey] shape and the
  "internal" FVK derivation.

## 7. Exercises

1. **Trace one derivation.** Pick a 32-byte spending key (e.g. all zeros). Step
   by step, compute `ask`, `ak`, `nsk`, `nk`, `ivk`, `ovk` using the public APIs
   in `keys.rs`. Verify each intermediate against
   [`ExpandedSpendingKey::from_spending_key`][ExpandedSpendingKey::from_spending_key].
2. **Add a `Display` impl for [`SaplingIvk`][SaplingIvk].** Pick a stable
   encoding (hex of the scalar's little-endian representation) and add
   `impl fmt::Display for SaplingIvk`. Add a doctest that matches against a
   known value derived from a fixed test vector (you can grab one from the
   existing
   [`spend_auth_sig_test_vectors`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L745-L770)).
3. **Compute a diversifier index round-trip.** Use
   [`DiversifierKey::diversifier_index`][DiversifierKey::diversifier_index] on a
   known diversifier and confirm the index returned, when fed back through
   [`diversifier`][DiversifierKey::diversifier], yields the original byte
   string. This exercises the FF1 round-trip.

**Answers in the code.** For exercise 1, the four "PRF expand" calls
(`SAPLING_ASK`, `SAPLING_NSK`, `SAPLING_OVK`, `SAPLING_ZIP32_*`) live in the
`zcash_spec` crate. For exercise 3, note that "valid diversifier" is a property
of the 88-bit output, not the index; the index round-trip works on any 11-byte
buffer but only some of those buffers represent valid Sapling diversifiers.

<!-- Source links (zcash/sapling-crypto @ 0.7.0) -->

[SpendAuthorizingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L67-L150
[SpendValidatingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L152-L226
[SpendValidatingKey::from]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L160-L172
[SpendValidatingKey::from_bytes]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L193-L214
[OutgoingViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L228-L230
[ExpandedSpendingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L232-L320
[ExpandedSpendingKey::from_spending_key]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L247-L262
[ProofGenerationKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L321-L343
[ProofGenerationKey::to_viewing_key]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L337-L343
[NullifierDerivingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L344-L347
[ViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L350-L368
[ViewingKey::ivk]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L355-L367
[FullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L371-L387
[FullViewingKey::from_expanded_spending_key]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L389-L408
[SaplingIvk]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L451
[PreparedIncomingViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L467
[Diversifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L487-L494
[DiversifiedTransmissionKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L505
[DiversifiedTransmissionKey::derive]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L513-L518
[crh_ivk]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L20-L41
[PaymentAddress]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs#L14-L99
[PaymentAddress::from_parts_unchecked]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs#L46-L55
[zip32-master]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L27-L66
[ZIP32_SAPLING_INT_PERSONALIZATION]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L29
[DiversifierKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L150-L230
[DiversifierKey::diversifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L192
[DiversifierKey::diversifier_index]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L201-L209
[DiversifiableFullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L658
[KeyIndex::new]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L242-L252
[g_d]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L491
[jubjub::SubgroupPoint]:
  https://docs.rs/jubjub/latest/jubjub/struct.SubgroupPoint.html
[DecodingError]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L36
[ivk]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L360
[pk_d]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/address.rs#L88
[is_identity]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L531
