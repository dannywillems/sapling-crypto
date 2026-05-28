---
sidebar_position: 9
title: Value Commitments and Balance
description: "The homomorphic Pedersen-style commitment used to hide amounts, and how it produces the binding signature that proves no inflation."
---

# Value Commitments and Balance

## 1. Why this chapter exists

Sapling hides amounts by committing to them with a Pedersen-style
commitment whose value slot uses one generator and whose randomness
slot uses another. Because the scheme is additively homomorphic, the
sum of all spend value commitments minus the sum of all output value
commitments minus a `valueBalance` offset must equal a commitment to
zero. That fact is what the **binding signature** asserts. Without
the binding signature there is no inflation protection, and that
protection has to be implemented faithfully or Zcash is broken at
the protocol level.

By the end you should know exactly how the binding key `bvk` is
constructed, why the binding signature is over the same key the
prover knows, and where the value-balance integer-range bounds live.

## 2. Definitions

**Definition 9.1 (value commitment).** Given a non-negative note
value $v \in [0, 2^{64})$ and a trapdoor
$\mathsf{rcv} \in \mathbb{F}_{r_{\mathbb{J}}}$,
$$
\mathsf{cv}(v, \mathsf{rcv}) = [v] \cdot G_{\mathsf{cv,v}}
  + [\mathsf{rcv}] \cdot G_{\mathsf{cv,r}},
$$
where the two generators are
[`VALUE_COMMITMENT_VALUE_GENERATOR`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L98-L111)
and
[`VALUE_COMMITMENT_RANDOMNESS_GENERATOR`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L114-L127).
The commitment lives in $\mathbb{J}$, not in $\mathbb{J}^{(r)}$,
because the generators are points in $\mathbb{J}^{(r)}$ but the
result is treated as an `ExtendedPoint` so that subgroup tests can
reject small-order commitments at deserialisation. Code:
[`ValueCommitment::derive`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L138-L147).

**Definition 9.2 (value balance).** The net value moved into / out
of the shielded pool in a bundle is
$$
\mathsf{vbalance} = \sum_{i \in \text{spends}} v_i
  - \sum_{j \in \text{outputs}} v_j \in \mathbb{Z}.
$$
The protocol bounds $\mathsf{vbalance}$ to a signed 63-bit integer
(in Rust: `i64`, but only values in $[-(r_J-1)/2, (r_J-1)/2]$ are
valid in the abstract protocol). Code:
[`ValueSum`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L31-L64).

**Definition 9.3 (binding signing key bsk, binding verification key
bvk).** Set
$$
\mathsf{bsk} = \sum_{i \in \text{spends}} \mathsf{rcv}_i
  - \sum_{j \in \text{outputs}} \mathsf{rcv}_j
$$
and
$$
\mathsf{bvk} = \sum_{i \in \text{spends}} \mathsf{cv}_i
  - \sum_{j \in \text{outputs}} \mathsf{cv}_j
  - [\mathsf{vbalance}] \cdot G_{\mathsf{cv,v}}.
$$
Then
$\mathsf{bvk} = [\mathsf{bsk}] \cdot G_{\mathsf{cv,r}}$, so
$\mathsf{bsk}$ is the RedJubjub signing key whose verification key
is $\mathsf{bvk}$. The verifier reconstructs $\mathsf{bvk}$ from
the transaction's commitments and value-balance, and checks the
binding signature against it. Code:
[`TrapdoorSum::into_bsk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L116-L122),
[`CommitmentSum::into_bvk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L186-L210).

**Theorem 9.4 (balance soundness, informal).** If an adversary
produces a Sapling bundle that verifies (proofs valid, binding
signature valid, value commitments not small-order), then the sum
$\mathsf{vbalance} + \sum_j v_j - \sum_i v_i$ equals $0$ in
$\mathbb{Z}$, provided the discrete log of $G_{\mathsf{cv,r}}$ with
respect to $G_{\mathsf{cv,v}}$ is unknown. Proof sketch: a valid
binding signature on the constructed $\mathsf{bvk}$ requires
knowledge of a $\mathsf{bsk}$ such that
$\mathsf{bvk} = [\mathsf{bsk}] \cdot G_{\mathsf{cv,r}}$. Plugging
in the definitions: any attempt to inflate (e.g. claim a spend of
$v$ while committing to $v'$) forces $\mathsf{bvk}$ to contain a
nonzero multiple of $G_{\mathsf{cv,v}}$, but extracting $\mathsf{bsk}$
from such a $\mathsf{bvk}$ would yield a discrete log relation
between the two generators. Citation: Hopwood et al., Zcash Protocol
Specification §4.13.

**Invariant 9.5 (cv is not small order).** A value commitment
received from the wire must not be a small-order Jubjub point. The
defence at the consensus level is at deserialisation:

```rust reference title="src/value.rs::ValueCommitment::from_bytes_not_small_order"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L156-L176
```

A small-order $\mathsf{cv}$ would allow an attacker to manipulate the
binding key in a way that bypasses the soundness reduction; the
practical impact would be to commit to one value but produce a
signature compatible with a different value.

## 3. The code

### 3.1 The three layers

`value.rs` exposes three types:

- `NoteValue`: a transparent `u64` newtype with a `ZERO` constant.
- `ValueCommitTrapdoor`: a wrapper around `jubjub::Scalar`.
- `ValueCommitment`: a wrapper around `jubjub::ExtendedPoint`.

```rust reference title="src/value.rs (NoteValue)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L52-L82
```

```rust reference title="src/value.rs (ValueCommitTrapdoor)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L85-L117
```

```rust reference title="src/value.rs (ValueCommitment::derive)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L136-L147
```

### 3.2 Sums

`value/sums.rs` is where the homomorphism lives. It is essentially
a wrapper around field/group sums plus a conversion to the binding
key pair:

```rust reference title="src/value/sums.rs (ValueSum)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L31-L104
```

```rust reference title="src/value/sums.rs (TrapdoorSum::into_bsk)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L106-L173
```

```rust reference title="src/value/sums.rs (CommitmentSum::into_bvk)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L175-L210
```

The `Sub<&ValueCommitment> for ValueCommitment` impls (lines
234-261) are how spends contribute positively and outputs
negatively. Look at how the absolute-value handling works on lines
192-202: i64's range is asymmetric, so the function explicitly
handles `i64::MIN`.

### 3.3 The consistency test

There is one proptest that closes the loop:

```rust reference title="src/value.rs (bsk_consistent_with_bvk)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L236-L266
```

It generates a vector of `(value, trapdoor)` pairs, computes
`bsk` from the trapdoors, `bvk` from the commitments and value
balance, and asserts the RedJubjub equation
`VerificationKey::from(&bsk) == bvk`. This is the in-crate proof
that the homomorphism is correctly wired; if you change one of the
generators or break a sum direction, this test fails.

## 4. Failure modes

- **Wrong sign in `into_bvk`.** The function flips signs of the
  value balance based on whether `value_balance.is_negative()`. If
  that branch is inverted, the binding signature still verifies
  for some bundles (where vbalance happens to be zero) but fails
  for others. Caught by: the
  [`bsk_consistent_with_bvk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L236-L266)
  proptest with high probability.
- **Adding spends and outputs with the same sign.** If
  `CommitmentSum::add_assign` were accidentally used in the output
  loop instead of `sub_assign`, every output would inflate the
  binding sum by `+cv` instead of `-cv`. Caught by: the same
  proptest.
- **A small-order `cv` slipping past deserialisation.** If a wire
  parser called `ValueCommitment(jubjub::ExtendedPoint::from_bytes(b).unwrap())`
  instead of `ValueCommitment::from_bytes_not_small_order(b)`, a
  small-order commitment would be admitted, and an attacker could
  later exploit the cofactor 8 to claim a spend of $v$ while
  committing to a different value. Caught by:
  [`SaplingVerificationContextInner::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L33-L93)
  has the small-order check baked into the call sites; the comment
  on lines 45-48 documents the assumption.
- **Overflow in `vbalance`.** `ValueSum` is an `i128`, large enough
  to hold all sums up to `n_spends + n_outputs <= 2^64`. Casting it
  to `i64` for `into_bvk` can lose information; that is what
  `BalanceError::Overflow` and `try_into()` guard against. Caught
  by: tests in `value/sums.rs` and `value.rs`.

## 5. Spec pointers

- [Zcash Protocol Specification, §4.13 (Balance and Binding
  Signature)](https://zips.z.cash/protocol/protocol.pdf#saplingbalance)
  is the authority. The range bounds (the
  `[-(r_J - 1)/2..(r_J - 1)/2]` constraint cited in
  `value/sums.rs::ValueSum`) are quoted from this section.
- [Zcash Protocol Specification, §5.4.8.3 (Homomorphic Pedersen
  commitments)](https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit)
  is the source of `ValueCommit^Sapling` exactly as implemented in
  `ValueCommitment::derive`.

## 6. Exercises

1. **Verify the homomorphism by hand.** Take two spends with values
   $v_1 = 100$, $v_2 = 50$ and one output with value $v = 130$.
   Sample three trapdoors. Compute the three commitments. Compute
   `bsk = rcv_1 + rcv_2 - rcv`. Compute `bvk` two ways: (a) directly
   as $[\mathsf{bsk}] \cdot G_{\mathsf{cv,r}}$, (b) via
   `CommitmentSum::into_bvk` with `value_balance = 20`. Assert
   they match.
2. **Add a test for the `i64::MIN` edge case.** The
   [`into_bvk` absolute-value handler](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L191-L195)
   has a special case for `value.checked_abs() == None`, which only
   triggers at `value = i64::MIN`. Add a unit test that constructs
   a `CommitmentSum` (any sum) and calls `into_bvk(i64::MIN)`. The
   test should not panic.
3. **Tighten the range comment.** The
   [`ValueSum` doc comment](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value/sums.rs#L32-L41)
   cites the abstract bound
   `[-(r_J - 1)/2..(r_J - 1)/2]` and the concrete-Zcash bound
   `[−38913406623490299131842..104805176454780817500623]`. Verify
   numerically that the concrete bound is what you get from
   `21 * MAX_MONEY = 21 * 10^15` (where `MAX_MONEY` is the maximum
   per-output value Zcash allows). Comment on whether the asymmetry
   is intentional.

**Answers in the code.** For exercise 1, the homomorphism is the
exact subject of the
[`bsk_consistent_with_bvk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L236-L266)
proptest. For exercise 3, the asymmetric bound comes from
the fact that the protocol uses `i64` for vbalance but limits the
Sapling-transactable supply to $\le 2^{51}$ zatoshi; the concrete
upper bound is therefore approximately $(2^{51}) \times C$ for a
known constant $C$. See [Spec §4.13](https://zips.z.cash/protocol/protocol.pdf#saplingbalance).
