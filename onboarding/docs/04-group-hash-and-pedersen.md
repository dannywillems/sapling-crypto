---
sidebar_position: 4
title: Group Hash and Pedersen Hash
description:
  "Hashing into the Jubjub curve and the windowed Pedersen hash construction
  Sapling uses for commitments and Merkle nodes."
---

# Group Hash and Pedersen Hash

## 1. Why this chapter exists

Sapling's note commitment, value commitment, and Merkle tree all bottom out in
two primitives: a hash-to-curve operation called the **group hash**
([`group_hash`][group_hash] in code) and a **Pedersen hash** built on top of
seven fixed generators. Both are fully defined inside this crate; both have been
the subject of side-channel and collision considerations that you should know
before you touch `pedersen_hash.rs`, `constants.rs`, or
`circuit/pedersen_hash.rs`.

By the end you should know exactly which file holds which generator, what each
personalisation tag is for, and why the in-circuit and out-of-circuit Pedersen
hashes are deliberately separate.

## 2. Definitions

**Definition 4.1 (Sapling group hash).** Given a tag $t \in
\{0,1\}^*$ and a
personalisation $p \in \{0,1\}^{64}$,

$$
\mathsf{GroupHash}_p(t) = \mathsf{clear\_cofactor}\big(
  \mathsf{abst}_{\mathbb{J}}(
    \mathsf{BLAKE2s}_{32, p}(
      \mathsf{GH\_FIRST\_BLOCK} \mathbin{\|} t
    )
  )
\big),
$$

returning a `Option<SubgroupPoint>`. The function returns `None` when the
BLAKE2s output does not decode to a valid Jubjub point, or when clearing the
cofactor produces the identity. The 64-byte [`GH_FIRST_BLOCK`][GH_FIRST_BLOCK]
([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L13-L14))
is a deliberately arbitrary ASCII hex string that domain-separates group-hash
inputs from anything else BLAKE2s might be used for.

**Definition 4.2 (Pedersen hash).** Given the seven fixed generators
$G_0, \ldots, G_6 \in \mathbb{J}^{(r)}$ defined in
[`PEDERSEN_HASH_GENERATORS`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L146-L231),
a personalisation prefix $p \in \{0,1\}^6$ (six bits from
[`Personalization::get_bits`][Personalization::get_bits]), and a bit-string
$m \in \{0,1\}^*$, the Sapling Pedersen hash is

$$
\mathsf{PedersenHash}(p, m) = \sum_{i=0}^{\lceil L / S \rceil - 1}
  \big[\mathrm{enc}_i(p, m)\big] G_i,
$$

where $L = |p \mathbin{\|} m|$, $S = 3 \cdot 63 = 189$ bits per generator
(windows of 3 bits, up to 63 chunks per segment), and $\mathsf{enc}_i$ is the
signed-window encoding of segment $i$
([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L44-L78)).
The output lives in $\mathbb{J}^{(r)}$.

**Definition 4.3 (Personalization).** A two-variant enum that selects the 6-bit
prefix prepended to the message:
[`Personalization::NoteCommitment`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L13-L30)
yields `0b111111`, and `Personalization::MerkleTree(d)` yields the 6-bit binary
encoding of the depth $d \in \{0, \ldots, 62\}$. The prefix domain-separates
note commitments from Merkle inner nodes and between Merkle levels.

**Lemma 4.4 (collision resistance, informal).** Finding two distinct inputs
$m \neq m'$ with $\mathsf{PedersenHash}(p, m) =
\mathsf{PedersenHash}(p, m')$
implies finding a non-trivial discrete log relation among $G_0, \ldots, G_6$.
Since the generators are derived from independent group-hash outputs, no such
relation is known. Caveat: this is contingent on no linear relation existing
between the seven points; see [Failure modes](#5-failure-modes).

**Invariant 4.5 (no algebraic relation among generators).** The seven
Pedersen-hash generators are jointly non-degenerate: none is the identity, no
two are equal, no one is the inverse of another, and no one is the sum of any
two others. These are checked at build/test time, not at runtime:

```rust reference title="src/constants.rs (generator consistency tests)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L351-L427
```

## 3. The code

### 3.1 The group hash

The hash-to-curve primitive is one function. Read it in full once:

```rust reference title="src/group_hash.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/group_hash.rs
```

Three things to note:

- The personalisation must be exactly 8 bytes (line 16).
- The 64-byte [`GH_FIRST_BLOCK`][GH_FIRST_BLOCK] is constant across all calls
  (line 25); only the tag varies.
- The cofactor is cleared on line 33. This is the step that turns a potentially
  small-order point into a guaranteed prime-order element (or the identity,
  which is then rejected on line 35).

### 3.2 The Pedersen hash, out of circuit

The out-of-circuit Pedersen hash uses a pre-computed exponentiation table
(`PEDERSEN_HASH_EXP_TABLE`) that converts the segment scalars into points via
window-based table lookups instead of generic double-and-add. The table is built
lazily by
[`generate_pedersen_hash_exp_table`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L246-L276)
at first access via `lazy_static!`.

```rust reference title="src/pedersen_hash.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L32-L120
```

Two structural facts to internalize:

1. The 3-bit window is signed: the negation step on lines 65-67 handles the sign
   bit. This matters in the circuit, where the negation has to be expressed as a
   constraint, not a conditional branch.
2. The outer loop iterates over segments of 189 bits each
   ([`PEDERSEN_HASH_CHUNKS_PER_GENERATOR`][PEDERSEN_HASH_CHUNKS_PER_GENERATOR]
   `= 63` chunks of 3 bits). An input longer than $7 \times 189 = 1323$ bits
   would exhaust the generator pool and panic on
   `generators.next().expect(...)`. The note commitment input is 576 bits (64
   value + 256 g_d + 256 pk_d), well under the cap.

### 3.3 The Pedersen hash, in circuit

The in-circuit gadget is a separate file:

```rust reference title="src/circuit/pedersen_hash.rs (header)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/pedersen_hash.rs#L1-L60
```

The two implementations have to agree byte-for-byte on every test vector. The
agreement is tested in
[`circuit::test_input_circuit_with_bls12_381_external_test_vectors`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L784-L965)
and in the standalone
[`pedersen_hash::test::test_pedersen_hash_points`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L136-L157),
which loads the 716-line test vector table:

```rust reference title="src/pedersen_hash/test_vectors.rs (head)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash/test_vectors.rs#L1-L40
```

## 4. The fixed generators

The seven Pedersen bases and the six application-specific generators are all
fixed constants in
[`constants.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L46-L143).
Each comes paired with a unit test that asserts it equals $\mathsf{GroupHash}$
of a small seed:

```rust reference title="src/constants.rs (generator tests)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L278-L362
```

The tests serve two purposes. First, they prevent a refactor from silently
swapping a generator. Second, they document the seed used to derive the
generator; the seed is needed to re-derive the generator in another
implementation (e.g. a C++ port).

## 5. Failure modes

- **A new generator that is a linear combination of existing ones.** This would
  break Pedersen-hash collision resistance. The invariant is enforced by the
  test
  [`pedersen_hash_generators_consistency`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L425-L428).
  Caught by: that test.
- **The in-circuit and out-of-circuit Pedersen hashes drift.** If a PR modifies
  one but not the other, every Spend or Output proof in existence becomes
  unverifiable against the new code. Caught by: the test vectors at
  [`pedersen_hash::test::test_pedersen_hash_points`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L136-L157)
  (out-of-circuit) and the constraint hash assertion in
  [`circuit::test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L750-L756)
  (`assert_eq!(cs.hash(), "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89")`).
  Both will fail loudly.
- **Personalisation reuse.** Two different uses of BLAKE2s with the same
  personalisation collide trivially across the two contexts. Caught by: code
  review. No automated test in this workspace; the personalisations live in
  `constants.rs` and the contract is "do not collide them" rather than "we test
  that they do not collide."
- **An input exceeds 1323 bits.** The Pedersen-hash main loop panics with
  `"we don't have enough generators"`. The only inputs the protocol passes are
  bounded by construction, so this is a guarded invariant rather than a runtime
  check. Caught by: nothing automatic; a contributor who extends the Spend
  circuit must check the bound by hand.

## 6. Spec pointers

- [Zcash Protocol Specification, §5.4.1.7 (Pedersen hash function)](https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash)
  is the authority. Cross-reference the encoding equation in §5.4.1.7 against
  the loop body in `src/pedersen_hash.rs`.
- [Zcash Protocol Specification, §5.4.9.6 (Sapling Group Hash)](https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub)
  defines `GroupHash_URS^Sapling`, which is what `group_hash::group_hash`
  implements.

## 7. Exercises

1. **Re-derive `NOTE_COMMITMENT_RANDOMNESS_GENERATOR`.** Run the existing test
   [`note_commitment_randomness_generator`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L310-L317).
   Read its `find_group_hash` helper. Identify the tag and the personalisation.
   Implement the same loop in a scratch program and confirm you recover the same
   point.
2. **Compute one Pedersen hash by hand.** Take the input bits
   `[true, false, false, true]` (4 bits), the personalisation
   `Personalization::NoteCommitment`, and step through the loop in
   [`src/pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L32-L120).
   Show that exactly one segment is used (the first generator $G_0$), and that
   the scalar produced is a signed 3-bit number. Verify your computation against
   the function output.
3. **Add a regression test for a refactor.** Modify
   `pedersen_hash::pedersen_hash` to use a `for` loop instead of the
   `loop { ... break; }` pattern, preserving behaviour. Add a new unit test that
   hashes a fixed input and asserts a fixed expected output (use one of the
   existing test vectors). Run `cargo test --all-features -- pedersen_hash`. The
   existing test_pedersen_hash_points test still has to pass; your new test
   serves as a tighter regression anchor.

**Answers in the code.** For exercise 1, the seed for
`NOTE_COMMITMENT_RANDOMNESS_GENERATOR` is the byte `b"r"` plus
`PEDERSEN_HASH_GENERATORS_PERSONALIZATION`
([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L311-L316)).
For exercise 2, the first 4 bits encode prefix `0b111111` (NoteCommitment)
followed by your 4 bits, but the first segment only consumes the first 3 bits of
the combined string and ignores the rest; chase through the code carefully.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[group_hash]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/group_hash.rs#L15
[GH_FIRST_BLOCK]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L13
[Personalization::get_bits]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L20
[PEDERSEN_HASH_CHUNKS_PER_GENERATOR]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L234
