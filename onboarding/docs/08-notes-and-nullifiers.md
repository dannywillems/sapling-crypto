---
sidebar_position: 8
title: Notes and Nullifiers
description: "How Sapling notes are constructed, how their nullifiers are derived, and the faerie-gold defence built into the nullifier formula."
---

# Notes and Nullifiers

## 1. Why this chapter exists

The Sapling pool of shielded UTXOs is, in implementation terms, a
set of two append-only structures: the Merkle tree of note
commitments (chapter 6) and a flat set of nullifiers maintained by
each full node. A spend reveals a nullifier; nodes reject any block
that contains a nullifier that already appeared in the chain. The
nullifier formula has a subtle property called **faerie-gold
defence** that prevents an attacker who shares a `cmu` with another
note from being able to spend it twice.

This chapter spells out the formula, the position-in-tree
parameter, and the path from `Note::from_parts` to `Nullifier`.

## 2. Definitions

**Definition 8.1 (nullifier).** Given a note $n$ with
$\mathsf{NoteCommit}(n) = c \in \mathbb{J}^{(r)}$, its nullifier
at tree position $\rho_{\mathsf{pos}} \in [0, 2^{32})$ under the
nullifier-deriving key $\mathsf{nk} \in \mathbb{J}^{(r)}$ is
$$
\mathsf{nf}(n, \mathsf{nk}, \rho_{\mathsf{pos}}) =
  \mathsf{PRF^{nf}_{\mathsf{nk}}}\big(
    c + [\rho_{\mathsf{pos}}] \cdot G_{\mathsf{nf}}
  \big),
$$
where $G_{\mathsf{nf}} = \mathsf{NULLIFIER\_POSITION\_GENERATOR}$
and $\mathsf{PRF^{nf}_{\mathsf{nk}}}$ is the BLAKE2s instance
personalised with `b"Zcash_nf"`, keyed by serialising $\mathsf{nk}$
followed by the perturbed commitment. Code:
[`Nullifier::derive`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L34-L42),
[`spec::mixing_pedersen_hash`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L50-L60),
[`spec::prf_nf`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L62-L78).

**Lemma 8.2 (faerie-gold defence).** Two notes whose commitments
coincide ($c_1 = c_2$) at distinct tree positions
($\rho_1 \neq \rho_2$) have distinct nullifiers under any fixed
$\mathsf{nk}$. Proof sketch: the perturbed inputs to the PRF are
$c + [\rho_1] G_{\mathsf{nf}}$ and $c + [\rho_2] G_{\mathsf{nf}}$.
These are equal iff $[\rho_1 - \rho_2] G_{\mathsf{nf}} = 0$, which
in $\mathbb{J}^{(r)}$ requires $\rho_1 \equiv \rho_2 \pmod{r_{\mathbb{J}}}$.
Since $\rho_{\mathsf{pos}} < 2^{32}$ and $r_{\mathbb{J}} > 2^{251}$,
distinct positions never collide. The PRF then injects this distinction
into the 32-byte output. Without the position mixing, an attacker
could find two distinct notes with the same commitment (e.g. by
guessing `rseed`) and spend one twice.

**Invariant 8.3 (nullifier uniqueness is a global property).** No
single full node enforces nullifier uniqueness by examining a block
in isolation: a block must be checked against the entire history of
nullifiers seen so far. This crate does not maintain that set; it
only computes nullifiers and exposes them. Maintenance is the
caller's job (typically `zebrad` or `zcashd`).

**Definition 8.4 (Rseed and rcm).** A note's seed randomness is
either pre-ZIP-212 (a $\mathbb{F}_{r_{\mathbb{J}}}$ scalar used as
`rcm` directly) or post-ZIP-212 (a 32-byte buffer from which both
`rcm` and the ephemeral encryption secret `esk` are derived via
`PrfExpand::SAPLING_RCM` / `SAPLING_ESK`). Code:
[`Rseed`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L19-L42),
[`Note::derive_esk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L147-L155).

## 3. The code

### 3.1 The nullifier

`Nullifier` is a 32-byte newtype. The derivation is two lines:

```rust reference title="src/note/nullifier.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs
```

Note that `Nullifier::derive` is `pub(super)`, so callers cannot
construct one without going through `Note::nf`. The only public
entry point is the byte-level
[`Nullifier::from_slice`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L26-L28),
which is for parsing wire data, not for deriving.

### 3.2 Position mixing

`mixing_pedersen_hash` is the function that adds the position to the
commitment. Despite its name, it is a single scalar multiplication
plus an addition, not a Pedersen hash:

```rust reference title="src/spec.rs::mixing_pedersen_hash"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L50-L60
```

The name comes from the spec: in the protocol document this is
called `MixingPedersenHash` because the protocol's editorial
convention treats this as a one-input Pedersen hash where the
generator is selected by position. The implementation uses scalar
multiplication directly because no other Pedersen-hash machinery is
needed.

### 3.3 The PRF

```rust reference title="src/spec.rs::prf_nf"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L62-L78
```

Both inputs go through Jubjub's compressed encoding (`to_bytes`),
then through BLAKE2s with the `b"Zcash_nf"` personalisation. The
output is exactly 32 bytes; the result is constant-size regardless
of the inputs' representations.

### 3.4 Notes

The `Note` type ties it all together:

```rust reference title="src/note.rs (Note::nf)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L100-L120
```

A note can also be a **dummy**: a synthetic note with `value = 0`
used to pad bundles to a minimum size. The dummy constructor
generates a fresh master key, derives an address from it, and
samples a fresh `rseed`:

```rust reference title="src/note.rs (Note::dummy)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L157-L177
```

The dummy spend's nullifier is well-defined but not consensus-relevant
(no real note's nullifier can collide with it for an honest user).
The dummy exists so that every spend in a bundle has the same shape
and the bundle's size leaks no information about the spending
pattern.

## 4. Failure modes

- **Position omitted from the nullifier formula.** A naive
  $\mathsf{PRF^{nf}_{\mathsf{nk}}}(c)$ formulation lets an attacker
  who finds two notes with the same `cmu` (e.g. by maliciously
  choosing `rseed`) spend each one twice. The position mixing
  defeats this. Caught by: the
  [Spend circuit](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L398-L427)
  computes the perturbed commitment in-circuit and feeds it to a
  BLAKE2s gadget; without the perturbation the constraint count
  changes and the `cs.num_constraints() == 98777` assertion fails.
- **rseed mistakenly used as rcm directly post-ZIP-212.** A
  refactor that elided the
  [`Rseed::rcm`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L34-L42)
  branch would cause post-ZIP-212 notes to use the raw rseed bytes
  as a Jubjub scalar, which is a different commitment than the
  spec's `PrfExpand` derivation. Caught by: the existing test
  vectors in `test_vectors::note_encryption` exercise both pre- and
  post-ZIP-212 paths.
- **Nullifier byte order swapped.** The 32 bytes returned by
  `prf_nf` are written into the wire format as-is. Reversing them
  on the wire (e.g. by accidentally calling `.reverse()` somewhere)
  produces nullifiers that other nodes' indexes do not match.
  Caught by: nothing automatic; a deviation here breaks consensus
  immediately and is caught on the first block built.

## 5. Spec pointers

- [Zcash Protocol Specification, §5.4.2 (Pseudo Random Functions)](https://zips.z.cash/protocol/protocol.pdf#concreteprfs)
  defines `PRF^nfSapling` and the personalisation tags.
- [Zcash Protocol Specification, §4.16 (Note Commitments and
  Nullifiers)](https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers)
  defines `DeriveNullifier` and motivates the faerie-gold defence.
- [ZIP 212](https://zips.z.cash/zip-0212) explains the rseed
  derivation and the grace period semantics.

## 6. Exercises

1. **Show that the position generator is non-trivial.** Inspect
   [`NULLIFIER_POSITION_GENERATOR`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L81-L94)
   and confirm via the existing
   [`nullifier_position_generator` test](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L319-L325)
   that it equals
   `find_group_hash(&[], NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION)`.
   Run that test.
2. **Compute one nullifier by hand.** Construct a `Note` with
   value zero, deterministic recipient, and `Rseed::BeforeZip212(0)`.
   Compute its `cm_full_point` by hand using the windowed Pedersen
   commitment. Then mix in `position = 0`. Then BLAKE2s with
   personalisation `b"Zcash_nf"`, keyed by `nk` serialized as 32
   bytes. Compare to `note.nf(&nk, 0).0`.
3. **Add a constant-time-equality test for `Nullifier`.**
   `Nullifier` already impls
   [`ConstantTimeEq`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/nullifier.rs#L51-L55).
   Add a unit test that checks two equal nullifiers return
   `Choice::from(1)` and two unequal ones return `Choice::from(0)`.
   Verify the test passes under `cargo test --all-features`.

**Answers in the code.** For exercise 1, `NULLIFIER_POSITION_GENERATOR`
is derived from the personalisation `b"Zcash_J_"`; see
[`constants.rs` line 40](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L40)
and the test that recomputes it from the personalisation tag.
For exercise 2, the position-0 mixing is trivial (`0 *
NULLIFIER_POSITION_GENERATOR = identity`, so the perturbed
commitment equals the original commitment).
