---
sidebar_position: 5
title: Note Commitments
description:
  "How notes are committed to: the windowed Pedersen commitment and the cmu
  coordinate extractor."
---

# Note Commitments

## 1. Why this chapter exists

A **note commitment** is what the Sapling protocol writes into the Merkle tree
to mark "this note exists and has been received". The commitment hides the
note's contents (value, recipient, randomness) from anyone who does not know
them. The commitment scheme is built out of the Pedersen hash from the previous
chapter and one extra component: the coordinate extractor that maps a Jubjub
point to a single $\mathbb{F}_q$ field element.

By the end you should be able to walk through the path note plaintext $\to$
`NoteCommitment` (a Jubjub point) $\to$ `ExtractedNoteCommitment` (a single
field element, called `cmu`) $\to$ Merkle leaf, and identify which file holds
each transformation.

## 2. Definitions

**Definition 5.1 (note plaintext).** A Sapling note is the tuple

$$
n = (\mathsf{d}, \mathsf{pk_d}, v, \mathsf{rseed}),
$$

where $\mathsf{d} \in \{0,1\}^{88}$ is the recipient's diversifier,
$\mathsf{pk_d} \in \mathbb{J}^{(r)}$ is the recipient's diversified transmission
key, $v \in [0, 2^{64})$ is the non-negative note value, and $\mathsf{rseed}$ is
the note seed randomness (either a pre-ZIP-212 scalar or a ZIP-212 32-byte seed;
see [Notes, commitments, nullifiers](./notes-and-nullifiers)).

**Definition 5.2 (note commitment).** Given a note $n$, the note commitment is

$$
\mathsf{NoteCommit}(n) = \mathsf{WindowedPedersenCommit}_{\mathsf{rcm}}(
  v \mathbin{\|} \mathsf{repr}_{\mathbb{J}}(\mathsf{g_d}) \mathbin{\|}
  \mathsf{repr}_{\mathbb{J}}(\mathsf{pk_d})
),
$$

where $\mathsf{rcm}$ is derived from $\mathsf{rseed}$ via either the identity
map (pre-ZIP-212) or $\mathsf{PRF^{Expand,rcm}}(\mathsf{rseed})$ (post-ZIP-212),
$\mathsf{g_d} = \mathsf{DiversifyHash}(\mathsf{d})$, and
$\mathsf{repr}_{\mathbb{J}}$ is the 32-byte encoding of a Jubjub point. The
output lives in $\mathbb{J}^{(r)}$. The bit-length of the input is
$64 + 256 + 256 = 576$ bits.

**Definition 5.3 (extracted note commitment, cmu).** Let
$c = \mathsf{NoteCommit}(n) \in \mathbb{J}^{(r)}$. Convert $c$ to affine
coordinates $(u, v) \in \mathbb{F}_q \times \mathbb{F}_q$ and take its
u-coordinate:

$$
\mathsf{cmu}(n) = u(c) \in \mathbb{F}_q.
$$

This is what the protocol writes into the Merkle tree.

**Lemma 5.4 (cmu is injective on the prime-order subgroup).** Because
$c \in \mathbb{J}^{(r)}$ and the prime-order subgroup is the preimage of an
injective function under the u-coordinate map (Hopwood, Spec §5.4.9.4),
$\mathsf{cmu}$ is injective on $\mathbb{J}^{(r)}$. Without this fact, two
distinct notes could share the same Merkle leaf and the nullifier check would
not guarantee uniqueness. Citation: Zcash Protocol Specification §5.4.9.4.

**Invariant 5.5 (cmu serialization is canonical).** When `cmu` is read from the
wire (e.g. when verifying a block), the byte representation must be the
canonical $\mathsf{LEBS2OSP}_{256}(\mathsf{repr}_{\mathbb{F}_q}(\cdot))$.
Non-canonical encodings (a field element written as a value above the field
modulus) are rejected. Enforced by
[`ExtractedNoteCommitment::from_bytes`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L65-L74)
via the `bls12_381::Scalar::from_repr` check.

## 3. The code

### 3.1 The internals

The full implementation of `NoteCommitment::derive` and
`ExtractedNoteCommitment` is one short file:

```rust reference title="src/note/commitment.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs
```

Read the bit-ordering carefully:

- Line 53: `v.to_le_bits()` is little-endian, 64 bits.
- Line 54: `BitArray::<_, Lsb0>::new(g_d).iter().by_vals()`, also
  least-significant-bit-first, 256 bits.
- Line 55: ditto for `pk_d`, 256 bits.

If you ever swap LSB-first for MSB-first by mistake, every test vector in the
crate fails immediately.

### 3.2 The trapdoor: rcm

The randomness `rcm` is wrapped in a small newtype because the protocol
distinguishes between the user-visible "rseed" (a 32-byte buffer) and the
derived scalar that goes into the commitment. The newtype prevents the wrong
field from being passed:

```rust reference title="src/note/commitment.rs (NoteCommitTrapdoor)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L13-L25
```

The derivation lives one module up, in `note.rs`:

```rust reference title="src/note.rs (Rseed -> rcm)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L19-L42
```

Before ZIP 212, `rcm` is sampled directly as a Jubjub scalar. After ZIP 212,
`rcm` is derived from a 32-byte `rseed` via `PrfExpand::SAPLING_RCM`. The change
matters because pre-ZIP-212 notes have a "small" `rcm` value (only ~252 bits of
entropy because the scalar was sampled in the field), while post-ZIP-212 notes
get a full 256-bit `rseed` from which both `rcm` and the ephemeral key are
deterministically derived.

### 3.3 From point to field element

The coordinate extractor is in `spec.rs`:

```rust reference title="src/spec.rs::extract_p"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L154-L165
```

The `From<NoteCommitment> for ExtractedNoteCommitment` impl wires this in:

```rust reference title="src/note/commitment.rs (extraction)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L86-L96
```

`extract_p` is exactly one operation on the affine form: take the u-coordinate.
The comment on line 161 documents the injectivity fact from Lemma 5.4.

### 3.4 The Note type

The user-facing type ties it together:

```rust reference title="src/note.rs (Note::cm_full_point, Note::cmu)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L100-L120
```

Three observations:

1. The note exposes `cmu()` for "give me the Merkle leaf" and `cm_full_point()`
   (private) for "give me the Jubjub point that feeds into the nullifier".
2. `Note::eq` is defined as equality of `cmu`
   ([source line 56-60](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L55-L62)).
   This is canonical: two notes with the same commitment are by definition the
   same note (even if their `rseed` differs as long as `rcm` matches).
3. The `Nullifier` derivation also consumes `cm_full_point()`; see
   [Notes, commitments, nullifiers](./notes-and-nullifiers).

## 4. Failure modes

- **Using `cm_full_point` where the protocol expects `cmu`.** The Merkle tree
  stores `cmu`, not the full point. Confusing them produces a tree where the
  verifier cannot reconstruct the leaf from the witness. Caught by: the type
  system. `cm_full_point` is not public (it is private to `note.rs`); only
  `ExtractedNoteCommitment` escapes.
- **A non-canonical `cmu` encoding.** A byte buffer that decodes to a value
  above the field modulus is silently rejected by
  `ExtractedNoteCommitment::from_bytes`. If a wire-format parser forgets to call
  this and instead does `bls12_381::Scalar::from_bytes`, the canonicality
  consensus rule is bypassed. Caught by: the type system;
  `ExtractedNoteCommitment::from_bytes` is the only public constructor from
  bytes.
- **Forgetting the windowed-Pedersen randomization step.** A bare Pedersen hash
  is not a hiding commitment; the randomization by `rcm` makes it one. If a
  refactor stripped the `[r] * NOTE_COMMITMENT_RANDOMNESS_GENERATOR` term, two
  notes with identical $(v, \mathsf{d}, \mathsf{pk_d})$ would commit to the same
  value, and an observer who knows the bit-string could trivially correlate them
  on the chain. Caught by: nothing automatic in this workspace; the
  [Spec §5.4.8.2 invariant](https://zips.z.cash/protocol/protocol.pdf#concretewindowedcommit)
  is enforced by code review.

## 5. Spec pointers

- [Zcash Protocol Specification, §5.4.8.2 (Windowed Pedersen commitments)](https://zips.z.cash/protocol/protocol.pdf#concretewindowedcommit)
  defines `WindowedPedersenCommit`, exactly the function
  `spec::windowed_pedersen_commit` implements.
- [Zcash Protocol Specification, §5.4.9.4 (Coordinate extractor for Jubjub)](https://zips.z.cash/protocol/protocol.pdf#concreteextractorjubjub)
  defines `Extract_J`, exactly the function `spec::extract_p` implements. The
  injectivity claim lives here.
- [ZIP 212 (Allow Recipient to Derive Ephemeral Secret Key from Note Plaintext)](https://zips.z.cash/zip-0212)
  explains the Rseed::AfterZip212 path and why it exists (a fix for
  decryption-time DoS).

## 6. Exercises

1. **Derive cmu for the zero note.** Take a note with `value = 0`, `g_d` and
   `pk_d` both serialized as 32 zero bytes (not a valid Sapling note but a clean
   toy input), and `rcm = jubjub::Fr::ZERO`. By hand, compute
   `WindowedPedersenCommit_0(64 zero bits || 256 zero bits || 256 zero bits)`.
   This equals `pedersen_hash(NoteCommitment, 576 zero bits)`. Then apply
   `extract_p`. Compare against a Rust program that does the same.
2. **Add a check that a `Note` round-trips through its commitment.** Construct a
   `Note` via `Note::from_parts` with random fields, compute `note.cmu()`, then
   check
   `ExtractedNoteCommitment::from_bytes(&note.cmu().to_bytes()) == note.cmu()`.
   Add this as a proptest under
   [`src/note.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs)
   using the `arb_note` generator. Run `cargo test --all-features`.
3. **Read the canonicality check.** Open
   [`src/note/commitment.rs` line 65-79](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note/commitment.rs#L65-L79).
   In one sentence, state the consensus rule the doc comment references and the
   function that enforces it. Then read
   [`src/value.rs::ValueCommitment::from_bytes_not_small_order`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L156-L176)
   and explain the difference between "canonical encoding" (for `cmu`) and "not
   small order" (for `cv`).

**Answers in the code.** For exercise 1, the result is the u-coordinate of
`pedersen_hash(Personalization::NoteCommitment, [false; 576])`. For exercise 2,
the existing
[`arb_cmu`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L202-L210)
strategy is a near-fit but generates random field elements, not random
commitments; you will want `arb_note` instead. For exercise 3: `cmu` is
canonical (only the unique 32-byte encoding of each field element is accepted),
while `cv` is not-small-order (any encoding decoding to a small-order point is
rejected, regardless of canonicality).
