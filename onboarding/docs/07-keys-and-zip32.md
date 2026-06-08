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

## 2. Definitions

### 2.1 The Sapling key tree (below ZIP 32)

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

**Definition 7.2 (nsk, nk).** The **nullifier secret key** is
$\mathsf{nsk} = \mathsf{PRF^{Expand,NSK}}(\mathsf{sk}) \in
\mathbb{F}_{r_{\mathbb{J}}}$.
The **nullifier deriving key** is
$\mathsf{nk} = [\mathsf{nsk}] \cdot
\mathsf{ProofGenerationKeyGenerator} \in \mathbb{J}^{(r)}$,
wrapped by [`NullifierDerivingKey`][NullifierDerivingKey]. The pair
$(\mathsf{ak}, \mathsf{nsk})$ is the [`ProofGenerationKey`][ProofGenerationKey];
the pair $(\mathsf{ak}, \mathsf{nk})$ is the **viewing key**.

**Definition 7.3 (ivk).** The **incoming viewing key** is

$$
\mathsf{ivk} = \mathsf{CRH^{ivk}}(\mathsf{repr}_{\mathbb{J}}(\mathsf{ak}),
  \mathsf{repr}_{\mathbb{J}}(\mathsf{nk})),
$$

specifically $\mathsf{BLAKE2s}_{32, \mathsf{Zcashivk}}(\cdot)$ with the
most-significant 5 bits cleared so it fits in the Jubjub scalar field. It is
computed by [`crh_ivk`][crh_ivk] and exposed as
[`ViewingKey::ivk`][ViewingKey::ivk].

**Definition 7.4 (ovk).** The **outgoing viewing key**,
[`OutgoingViewingKey`][OutgoingViewingKey], is a 32-byte opaque value
$\mathsf{ovk} = \mathsf{PRF^{Expand,OVK}}(\mathsf{sk})$ truncated to 32 bytes.
It is used to let the sender re-decrypt their own outputs without revealing them
to the receiver's ivk.

**Definition 7.5 (d, g_d, pk_d).** A **diversifier**
[`Diversifier`][Diversifier] $\mathsf{d} \in \{0,1\}^{88}$ defines the base of a
payment address. Each diversifier yields
$\mathsf{g_d} = \mathsf{DiversifyHash}(\mathsf{d}) \in \mathbb{J}^{(r)}
\cup \{\bot\}$;
about 50% of diversifiers fail (`g_d = None`). The **diversified transmission
key** is $\mathsf{pk_d} = [\mathsf{ivk}] \cdot \mathsf{g_d}$, computed by
[`DiversifiedTransmissionKey::derive`][DiversifiedTransmissionKey::derive]. The
payment address $(\mathsf{d}, \mathsf{pk_d})$ is a
[`PaymentAddress`][PaymentAddress].

### 2.2 ZIP 32

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
`jubjub::SubgroupPoint::from_bytes` and an explicit `!p.is_identity()` check.

## 3. The code

### 3.1 The bottom layer: `keys.rs`

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

### 3.2 The ZIP 32 layer: `zip32.rs`

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

### 3.3 Diversifier search via FF1

ZIP 32 reuses FF1 over AES-256 as a 88-bit format-preserving pseudo-random
permutation to map a diversifier index to an actual 88-bit diversifier:

```rust reference title="src/zip32.rs (DiversifierKey::diversifier)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L154-L230
```

The find-loop in [`DiversifierKey::diversifier`][DiversifierKey::diversifier]
walks consecutive indices until it lands on one whose output happens to be a
valid Jubjub-friendly diversifier (about 1 in 2). On average two indices are
tried per address.

## 4. Failure modes

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
  this; trying to derive yields `DecodingError::UnsupportedChildIndex`. Caught
  by: that error variant and the
  [unit tests in `zip32.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/zip32.rs#L1500).
- **`pk_d = identity`.** If `ivk = 0` (or the diversifier produces an `g_d` that
  happens to multiply to the identity), the resulting `pk_d` is the identity and
  there is no recipient. The
  [`DiversifiedTransmissionKey`][DiversifiedTransmissionKey] constructors reject
  this:
  [`PaymentAddress::from_parts_unchecked`][PaymentAddress::from_parts_unchecked]
  checks `is_identity` and returns `None`. Caught by: that check. See also
  [issue #168](https://github.com/zcash/sapling-crypto/issues/168) for the
  related "make `ivk = 0` unrepresentable" refactor.
- **Lossy "prepared" form drift.**
  [`PreparedIncomingViewingKey`][PreparedIncomingViewingKey] caches a
  `WnafScalar`; if [`SaplingIvk`][SaplingIvk] changes its scalar encoding but
  the prepared form is not regenerated, decryption silently fails. Caught by:
  trial decryption tests in `note_encryption.rs`.

## 5. Spec pointers

- [Zcash Protocol Specification, §4.2.2 (Sapling Key Components)](https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents)
  is the master source for every relationship above.
- [ZIP 32 (HD wallets for Zcash)](https://zips.z.cash/zip-0032), specifically
  §"Sapling extended spending keys", is the master source for `zip32.rs`.
- [ZIP 316 (Unified addresses and viewing keys)](https://zips.z.cash/zip-0316)
  is the source for the
  [`DiversifiableFullViewingKey`][DiversifiableFullViewingKey] shape and the
  "internal" FVK derivation.

## 6. Exercises

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
