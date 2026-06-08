---
sidebar_position: 13
title: Bundle and Builder
description:
  "How a Sapling bundle is assembled: the Authorization state machine,
  BundleType padding rules, and the in-progress -> proven -> signed transitions."
---

# Bundle and Builder

## 1. Why this chapter exists

A Sapling **bundle** is the unit Zcash consensus operates on: a list of spend
descriptions, a list of output descriptions, a value balance, and the
authorising data (proofs, signatures, binding signature). The **builder** is the
state machine that produces one. It is also the largest behavioural surface in
the crate (1387 lines of `builder.rs`) and one of the two most-modified areas
across the 0.x line.

If you intend to make any non-trivial behavioural change to this crate, you will
touch `builder.rs`. This chapter walks the state machine and identifies the
named transitions.

### 1.1 Relation to the Bitcoin UTXO model

A Sapling bundle maps onto the structure of a Bitcoin transaction, which is a
useful starting analogy if you already know Bitcoin:

- A Sapling **note** is the shielded analogue of a Bitcoin **UTXO**: a discrete
  amount, created once and later consumed in full. There is no partial spend;
  change is returned as a new output note, exactly as in Bitcoin.
- A **spend description** plays the role of a transaction **input**: it consumes
  an existing note.
- An **output description** plays the role of a transaction **output**: it
  creates a new note for a recipient.
- The bundle's two vectors plus its value balance mirror a transaction's `vin`,
  `vout`, and fee.

The analogy stops at privacy. The table contrasts the two models on the points
that differ:

| Aspect                      | Bitcoin                               | Sapling                                                                                                               |
| --------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Input references its source | `txid:vout` pointer, public           | none; a spend proves tree membership in zero knowledge (see [Spend and Output circuits](./spend-and-output-circuits)) |
| Double-spend prevention     | remove the UTXO from the UTXO set     | publish a [nullifier](./notes-and-nullifiers); nodes reject repeats without learning which note                       |
| Is the spent coin deleted?  | yes, from the UTXO set                | no; the commitment tree is append-only, and spent-ness lives in a separate nullifier set                              |
| Amounts                     | in the clear                          | hidden behind [value commitments](./value-commitments)                                                                |
| Balance check               | `sum(inputs) >= sum(outputs)`, public | homomorphic: the value commitments must net to the value balance, enforced by the binding signature                   |

The one-line summary: spend = input, output = output, note = UTXO, but a Bitcoin
input is a public pointer to the coin it spends, whereas a Sapling spend is a
zero-knowledge proof of ownership that reveals only a nullifier. The net value
balance is revealed when value crosses between the transparent and shielded
pools; that is where a transparent, Bitcoin-style input or output connects to
the shielded side.

## 2. Definitions

**Definition 13.1 (Authorization marker).** A phantom type that encodes the
bundle's authorisation state at the type level:

```rust reference title="src/bundle.rs (Authorization trait)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L22-L51
```

The two extremes:

- [`EffectsOnly`][EffectsOnly]: no proofs, no signatures.
  [`SpendProof`][SpendProof] `= ()`, [`OutputProof`][OutputProof] `= ()`,
  [`AuthSig`][AuthSig] `= ()`. Used by light clients inspecting the effects of a
  transaction without verifying it.
- [`Authorized`][Authorized]: full proofs and signatures.
  `SpendProof = `[`GrothProofBytes`][GrothProofBytes],
  `OutputProof = GrothProofBytes`, `AuthSig = redjubjub::Signature<SpendAuth>`.
  The state in which a bundle can be serialised into a Zcash transaction.

Between those two extremes the builder uses an
[`InProgress`][InProgress]`<P, S>` marker, with `P` tracking proof state
([`Unproven`][Unproven] / [`Proven`][Proven]) and `S` tracking signature state
([`Unsigned`][Unsigned] / [`PartiallyAuthorized`][PartiallyAuthorized]). Those
four states encode a 2x2 grid of intermediate authorisation.

**Definition 13.2 (BundleType).** A small enum that constrains the output /
spend padding rules:

```rust reference title="src/builder.rs (BundleType)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L43-L118
```

Two variants:

- `Transactional { bundle_required }`: if `bundle_required` or
  `requested_spends > 0`, the builder pads to at least 1 spend and 2 outputs
  (dummies added if necessary). If both are zero and `!bundle_required`, the
  builder returns `None` (no bundle is produced).
- `Coinbase`: spends are forbidden. No output padding.

**Invariant 13.3 (one anchor per bundle).** Every spend in a bundle must
reference the same Merkle anchor. The builder records the anchor at construction
time
([`Builder`][Builder]`::`[`new`][Builder::new]`(zip212_enforcement, anchor, bundle_type)`)
and rejects spends whose witness does not verify against that anchor:

```rust reference title="src/builder.rs (SpendInfo::has_matching_anchor)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L222-L229
```

**Invariant 13.4 (dummy outputs always added).** A non-Coinbase bundle with
$n \in \{0, 1\}$ requested outputs is padded with $2 - n$ dummy outputs. The
reason is anonymity-set size: every Sapling bundle on chain looks like "at least
one spend, at least two outputs". Code:
[`OutputInfo::dummy`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L390-L420).

## 3. The code

### 3.1 The Bundle type

`bundle::`[`Bundle`][Bundle]`<A, V>` is two `Vec`s plus a value balance plus an
authorisation:

```rust reference title="src/bundle.rs (Bundle)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L53-L104
```

The methods are mostly trivial accessors plus the state-transition functions
[`map_authorization`][map_authorization] and
[`try_map_authorization`][try_map_authorization], which take a context, four
mapping functions (one per associated type), and a final auth-conversion
function. The latter is what the builder uses to "promote" a bundle from
[`InProgress`][InProgress]`<`[`Unproven`][Unproven]`, `[`Unsigned`][Unsigned]`>`
to `InProgress<`[`Proven`][Proven]`, Unsigned>`, then to
`InProgress<Proven, `[`PartiallyAuthorized`][PartiallyAuthorized]`>`, then
finally to [`Authorized`][Authorized]:

```rust reference title="src/bundle.rs (Bundle::map_authorization)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L105-L143
```

### 3.2 SpendDescription and OutputDescription

Pure data wrappers, parametrised by `A: `[`Authorization`][Authorization]:

```rust reference title="src/bundle.rs (SpendDescription)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L214-L294
```

Note that [`cv`][cv], [`anchor`][anchor], [`nullifier`][nullifier], [`rk`][rk]
are present in every authorisation state; what varies across states is
[`zkproof`][zkproof] and [`spend_auth_sig`][spend_auth_sig].

### 3.3 The builder's lifecycle

The builder's state machine, ordered by call sequence:

1. **[`Builder`][Builder]`::`[`new`][Builder::new]`(zip212_enforcement, anchor, bundle_type)`**:
   create a builder with the given parameters.
2. **`Builder::`[`add_spend`][add_spend]`(extsk, note, merkle_path)`** and
   **`Builder::`[`add_output`][add_output]`(ovk, to, value, memo)`**: append
   spends and outputs.
3. **`Builder::`[`build`][build]`::<SpendProver, OutputProver, R>(spending_keys, bundle_type, rng)`**:
   produce an [`UnauthorizedBundle`][UnauthorizedBundle]
   `= Bundle<InProgress<Unproven, Unsigned>, V>` plus a
   [`SaplingMetadata`][SaplingMetadata] capturing the post-shuffle indices.
4. **`Bundle::`[`create_proofs`][create_proofs]`::<SpendProver, OutputProver, R>(spend_pk, output_pk, rng)`**:
   produce the Groth16 proofs, transitioning to
   `Bundle<InProgress<Proven, Unsigned>, V>`.
5. **`Bundle::`[`prepare`][prepare]`(rng, sighash)`**: transition to
   `Bundle<InProgress<Proven, PartiallyAuthorized>, V>`. This is where the
   binding signature is generated.
6. **`Bundle::`[`sign`][sign]`(rng, extsks)`** and/or
   **`Bundle::`[`append_signatures`][append_signatures]`(sigs)`**: collect
   spend-auth signatures.
7. **`Bundle::`[`finalize`][finalize]`()`**: transition to
   `Bundle<Authorized, V>`.

### 3.4 The SaplingMetadata

The builder shuffles spends and outputs into a random order before proving (to
avoid leaking the original ordering through side channels). The metadata
returned by [`build`][build] records the new position of each requested spend /
output so the caller can map back:

```rust reference title="src/builder.rs (SaplingMetadata search for usage)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L501-L570
```

(Search for [`SaplingMetadata`][SaplingMetadata] in the file; it is constructed
near the end of `build`.)

## 4. Failure modes

- **Anchor mismatch.** `Builder::`[`add_spend`][add_spend] checks the witness
  against the anchor at the time of the call. A note with a stale Merkle path
  (because its position changed between the time the wallet built the witness
  and the time it called `add_spend`) yields [`Error`][Error]`::AnchorMismatch`.
  Caught by: the
  [`has_matching_anchor`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L222-L229)
  check, exercised by builder tests.
- **Coinbase bundle with a spend.** [`BundleType`][BundleType]`::Coinbase`
  rejects any spend at construction time. Caught by:
  [`BundleType::num_spends`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L72-L89)
  returning an error.
- **MissingSpendingKey.** `Builder::`[`build`][build] walks every non-dummy
  spend and matches the spend's [`FullViewingKey`][FullViewingKey] against the
  supplied spending keys. If no key matches, `Error::MissingSpendingKey`. Caught
  by:
  [the matching loop](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L277-L292)
  in `PreparedSpendInfo::build`.
- **DuplicateSignature.** RedJubjub's signing uses `alpha`, sampled fresh per
  spend. If two spends accidentally receive the same `alpha`, the same spend
  authorisation signature would validate for both. The builder samples `alpha`
  independently per spend
  ([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L262)),
  and emits `Error::DuplicateSignature` if it ever does see a duplicate. Caught
  by: the error variant exists for completeness; it would indicate a critical
  RNG failure.

## 5. Spec pointers

- [Zcash Protocol Specification, §3.4](https://zips.z.cash/protocol/protocol.pdf#transactions)
  defines the transaction containing the Sapling bundle.
- [Zcash issue #3615](https://github.com/zcash/zcash/issues/3615) is the
  historical source of the 2-output padding rule cited at
  [`MIN_SHIELDED_OUTPUTS`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L40)
  in the source.

## 6. Exercises

1. **Build the smallest legal bundle.** Construct a [`Builder`][Builder] with
   [`BundleType`][BundleType]`::Transactional { bundle_required: true }`, no
   spends, no outputs, and the empty-tree anchor. Call [`build`][build] with
   [`MockSpendProver`][MockSpendProver] and
   [`MockOutputProver`][MockOutputProver]. Inspect the resulting bundle: it
   should have 1 dummy spend and 2 dummy outputs.
2. **Trigger an anchor mismatch.** Add a spend whose merkle path roots to a
   different anchor than the one passed to `Builder::`[`new`][Builder::new].
   Confirm that [`Error`][Error]`::AnchorMismatch` is returned.
3. **Print the post-shuffle order.** Build a bundle with three spends in a known
   order. Print the [`SaplingMetadata`][SaplingMetadata]. Verify that the spend
   at original index 0 has moved to a different position in the bundle.

**Answers in the code.** For exercise 1, the dummy padding logic is in
[`Builder::build`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L450-L560).
For exercise 2, the
[anchor check](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L470-L495)
is invoked from `Builder::build`, not from `add_spend`; the error surfaces at
`build` time, not at `add_spend` time.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[EffectsOnly]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L31
[SpendProof]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L24
[OutputProof]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L25
[AuthSig]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L26
[Authorized]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L42
[GrothProofBytes]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L20
[InProgress]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L946
[Unproven]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L963
[Proven]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L973
[Unsigned]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1099
[PartiallyAuthorized]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1125
[Builder]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L568
[Builder::new]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L184
[Bundle]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L54
[map_authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L106
[try_map_authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L145
[Authorization]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L23
[cv]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L255
[anchor]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L260
[nullifier]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L265
[rk]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L270
[zkproof]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L275
[spend_auth_sig]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L280
[add_spend]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L624
[add_output]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L653
[build]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L278
[UnauthorizedBundle]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L927
[SaplingMetadata]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L531
[create_proofs]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1070
[prepare]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L231
[sign]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1220
[append_signatures]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1242
[finalize]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L1158
[Error]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L122
[BundleType]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L44
[FullViewingKey]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L371
[MockSpendProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L190
[MockOutputProver]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L236
