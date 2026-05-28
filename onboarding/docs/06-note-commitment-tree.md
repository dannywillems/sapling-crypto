---
sidebar_position: 6
title: The Note Commitment Tree
description: "The depth-32 incremental Merkle tree of cmu leaves: how nodes are combined, how anchors work, and how the empty tree is described."
---

# The Note Commitment Tree

## 1. Why this chapter exists

Every Sapling note becomes a leaf in a global, append-only Merkle
tree that the consensus rules maintain as part of block validation.
A Spend description proves "I know an opening of one of those
leaves" by providing an authentication path against an **anchor**
(the tree root). The tree is depth 32; the hashing function inside
it is the Pedersen hash from chapter 4, with the depth folded into
the personalisation.

This chapter spells out the tree's parameters, how empty subtrees are
represented, and where the integration with the
[`incrementalmerkletree`](https://github.com/zcash/incrementalmerkletree)
crate happens.

## 2. Definitions

**Definition 6.1 (Sapling Merkle tree).** A binary, append-only
Merkle tree of depth $D = 32$, whose leaves are
`ExtractedNoteCommitment` values (elements of $\mathbb{F}_q$). It
holds up to $2^{32}$ leaves; in practice the position of a note in
the tree is a `u64` that fits in 32 bits.

**Definition 6.2 (Merkle hash).** For depth $d \in \{0, \ldots, 31\}$
and two child node values $\ell, r \in \mathbb{F}_q$,
$$
\mathsf{MerkleCRH}^{\mathsf{Sapling}}(d, \ell, r) = \mathsf{Extract}_{\mathbb{J}}\big(
  \mathsf{PedersenHash}(\mathsf{Personalization::MerkleTree}(d),\;
    \mathsf{bits}_{255}(\ell) \mathbin{\|} \mathsf{bits}_{255}(r)
  )
\big).
$$
The first 255 bits of each child's little-endian encoding are
consumed (note: $\mathbb{F}_q$ has $\lceil \log_2 q \rceil = 255$
bits, exactly the capacity of one segment). The output is the
u-coordinate of the resulting Jubjub point.

**Definition 6.3 (anchor).** A 32-byte canonical
$\mathbb{F}_q$ encoding of the root node of the note commitment
tree at some block height. Spend descriptions reference an anchor;
the consensus rules accept any anchor from a recent block (subject
to ZIP-244 / ZIP-216 timing rules, which are not enforced in this
crate).

**Definition 6.4 (uncommitted leaf).** The placeholder value for an
empty leaf is the field element $1 \in \mathbb{F}_q$, declared as
`UNCOMMITTED_SAPLING`
([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L22-L24)).
Empty subtree roots are precomputed by repeated application of
`Node::combine` with both children equal to the previous level's
empty root.

**Invariant 6.5 (zero-value bypass).** A spend whose note value is
zero is a **dummy spend** and is allowed to use any anchor, not
necessarily one that contains its `cmu`. The circuit enforces this by
making the anchor equality constraint quadratic in the value:
$(\mathsf{cur} - \mathsf{rt}) \cdot \mathsf{value} = 0$
([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L386-L394)).
If $\mathsf{value} = 0$, any $\mathsf{rt}$ satisfies the
constraint; if $\mathsf{value} \neq 0$, the path must reconstruct
the anchor.

## 3. The code

The tree itself is mostly a thin wrapper around the
`incrementalmerkletree` crate; the Sapling-specific content is the
node type and the hash function:

```rust reference title="src/tree.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs
```

Reading priorities in that file:

- Lines 15-20: the tree depth (32) and the three type aliases
  (`CommitmentTree`, `IncrementalWitness`, `MerklePath`).
- Lines 22-34: empty leaf and precomputed empty roots.
- Lines 37-71: `merkle_hash` and `merkle_hash_field`. This is
  `MerkleCRH^Sapling`. Note the explicit truncation to 255 bits
  on lines 62-67.
- Lines 73-112: `Anchor`, the root wrapper.
- Lines 114-172: `Node` and the `Hashable` impl that the
  `incrementalmerkletree` crate consumes.

### 3.1 Why a separate Node type

`Node` is a thin wrapper around `jubjub::Base = bls12_381::Scalar`.
Wrapping the field element makes the trait implementations
type-safe: `Hashable::combine` takes `&Node`, not `&Scalar`, so
nothing else can be accidentally placed in the tree.

```rust reference title="src/tree.rs (Hashable impl)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L156-L172
```

### 3.2 Anchor

The anchor type carries an extra constructor:

```rust reference title="src/tree.rs (Anchor)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L73-L112
```

`Anchor::empty_tree()` returns the root of the all-empty tree at
depth 32. The
[doc comment](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L89-L94)
warns that this anchor cannot be used for ordinary spends (the
consensus rules require an anchor that appears in the chain). It is
used for coinbase bundles (which have no spends) and as a sentinel
for "no Sapling activity in this transaction".

### 3.3 Merkle path consumption in the circuit

The Spend circuit ascends the path one level at a time, swapping the
child order based on the position bit:

```rust reference title="src/circuit.rs (Merkle ascent)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L323-L398
```

`auth_path` is `Vec<Option<(Scalar, bool)>>`: the element at depth
$i$ is the sibling field element and the boolean "I am on the
right". The `conditionally_reverse` gadget swaps left/right based on
this bit. The Pedersen hash at line 369 is the in-circuit version
of `merkle_hash_field`, called with `MerkleTree(i)` so the depth
$i$ is folded into the personalisation prefix.

## 4. Failure modes

- **Wrong depth in the personalisation.** `MerkleTree(i)` carries
  the depth as a 6-bit number. If a refactor passed `MerkleTree(i+1)`
  by accident at any level, the tree's hash function would change at
  every level, every existing anchor would become unrecoverable, and
  every existing Merkle path would fail. Caught by: the test
  vectors in
  [`pedersen_hash::test::test_pedersen_hash_points`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pedersen_hash.rs#L136-L157)
  exercise specific `MerkleTree(d)` personalisations.
- **Truncation off-by-one.** `merkle_hash_field` truncates each
  child to `bls12_381::Scalar::NUM_BITS = 255` bits before feeding
  into the Pedersen hash. If a refactor took 256 bits, the high bit
  would be inconsistent with the in-circuit version (which can only
  feed `bls12_381::Scalar::CAPACITY = 254` bits without proving the
  reduction is canonical). Caught by: the
  [circuit constraint count assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L750-L756)
  (changing the bit count changes the constraint count, which would
  fail the explicit assertion).
- **Empty-tree anchor used in a real spend.** A spend with a
  non-zero value and `Anchor::empty_tree()` cannot satisfy the
  circuit equation $(\mathsf{cur} - \mathsf{rt}) \cdot
  \mathsf{value} = 0$ because the path of the note cannot lead to
  the all-empty root. Caught by: the circuit constraint at
  [`src/circuit.rs#L386-L394`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L386-L394).

## 5. Spec pointers

- [Zcash Protocol Specification, §5.4.1.3 (Merkle CRH for Sapling)](https://zips.z.cash/protocol/protocol.pdf#concretemerklecrh)
  defines `MerkleCRH^Sapling`. The depth-as-personalisation is on
  this page.
- [Zcash Protocol Specification, §5.6.1 (Merkle trees of note
  commitments)](https://zips.z.cash/protocol/protocol.pdf#merklecmtree)
  defines the tree depth, the uncommitted leaf, and the anchor
  semantics.
- [`incrementalmerkletree` crate](https://github.com/zcash/incrementalmerkletree)
  is where the actual tree state machine lives. This crate only
  supplies the `Hashable` impl.

## 6. Exercises

1. **Compute the empty-tree anchor.** Read the
   [`empty_roots`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L27-L34)
   function. By hand, compute the depth-0 empty root: it is
   `Node::empty_leaf() = Node(1)`. Now compute the depth-1 empty
   root: it is `Node::combine(0, Node(1), Node(1))`. Carry on for
   three more levels and verify against a Rust program that calls
   `Anchor::empty_tree()`.
2. **Find the maximum path length.** What is the longest authentication
   path the circuit accepts? Look at
   [`auth_path.len()`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L67-L74)
   and the test
   [`tree_depth = 32`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L651).
   What happens if you pass a 33-element vector? Modify the test
   to do so and run it.
3. **Add a debug print for the tree depth at compile time.** Where
   is `NOTE_COMMITMENT_TREE_DEPTH` declared? Add a
   `const _: () = assert!(NOTE_COMMITMENT_TREE_DEPTH == 32);`
   somewhere in the crate to make the depth invariant a compile-time
   check rather than a runtime parameter.

**Answers in the code.** For exercise 1, `Node::empty_leaf` is
declared at [tree.rs:157-159](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L157-L159).
For exercise 2, the circuit synthesizes constraints proportional to
`auth_path.len()`; a 33-element vector produces a circuit with more
constraints, and the `cs.num_constraints() == 98777` assertion in
[`circuit::test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L750-L756)
will fail. For exercise 3, the const assertion belongs near the
[declaration](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/tree.rs#L15).
