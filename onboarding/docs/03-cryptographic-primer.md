---
sidebar_position: 3
title: Cryptographic Primer
description: "Background on the curves, hashes, and proof system that the rest of the course assumes."
---

# Cryptographic Primer

## 1. Why this chapter exists

The Sapling protocol stacks several primitives on top of each other:
two elliptic curves with a particular embedding relationship, a hash
that lives on one of them, a Pedersen-style commitment scheme, an
incremental Merkle tree using a Pedersen-hash-based collision-resistant
function, and Groth16 over BLS12-381. None of those are standard
across cryptographic libraries, and the protocol spec is dense enough
that you cannot read the source without the primer.

This chapter is the minimum primer. It is deliberately concise: it
does not prove anything, it states the definitions you need to read
the rest of the course and points at the canonical reference for
each.

## 2. Definitions

### 2.1 The two curves: BLS12-381 and Jubjub

**Definition 3.1 (BLS12-381).** BLS12-381 is a pairing-friendly
curve $E_1: y^2 = x^3 + 4$ over $\mathbb{F}_{q}$ with embedding
degree 12, where $q$ is a 381-bit prime. Its prime-order subgroup
has order $r$, a 255-bit prime. We write $\mathbb{G}_1$, $\mathbb{G}_2$,
$\mathbb{G}_T$ for the three groups participating in the pairing. The
crate uses BLS12-381 only as the underlying curve for Groth16 proofs;
the application never manipulates $\mathbb{G}_2$ or $\mathbb{G}_T$
directly. The base field $\mathbb{F}_{q}$ of BLS12-381 has bit size
381, but the **scalar field** $\mathbb{F}_r$ has bit size 255, and
that 255-bit field is what we use as Jubjub's base field. Source:
[Bowe, "BLS12-381: New zk-SNARK Elliptic Curve Construction"](https://electriccoin.co/blog/new-snark-curve/).

**Definition 3.2 (Jubjub).** Jubjub is a twisted Edwards curve
defined over $\mathbb{F}_r$ (the scalar field of BLS12-381), with
equation
$$
-u^2 + v^2 = 1 + d \cdot u^2 v^2, \qquad d = -(10240/10241)
$$
in $\mathbb{F}_r$. The full Jubjub curve has cofactor 8; its
prime-order subgroup has order $r_{\mathbb{J}}$, a 252-bit prime.
We write $\mathbb{J}$ for the full curve and $\mathbb{J}^{(r)}$
for its prime-order subgroup. In code: `jubjub::ExtendedPoint` is
$\mathbb{J}$, `jubjub::SubgroupPoint` is $\mathbb{J}^{(r)}$,
`jubjub::Base` is $\mathbb{F}_r$, `jubjub::Scalar` (a.k.a.
`jubjub::Fr`) is $\mathbb{F}_{r_{\mathbb{J}}}$.

**Lemma 3.3 (the embedding).** Because Jubjub's base field equals
BLS12-381's scalar field, Jubjub point arithmetic can be carried out
inside a Groth16 circuit over BLS12-381 without field-emulation
overhead. This is the load-bearing fact that makes the Sapling
circuit feasible. Without this matching, the in-circuit Pedersen hash
would cost an order of magnitude more constraints. Citation: Hopwood
et al., Zcash Protocol Specification, §5.4.9.

**Invariant 3.4 (subgroup discipline).** Sapling primitives operate
on $\mathbb{J}^{(r)}$, not on the full curve $\mathbb{J}$. The
implementation enforces this both in code (most types are
`jubjub::SubgroupPoint`) and in the circuit
(`EdwardsPoint::assert_not_small_order` performs three doublings and
checks $u \neq 0$). A point outside the subgroup but inside
$\mathbb{J}$ is called **small-order** if it has order dividing the
cofactor 8.

### 2.2 Hashes and PRFs

**Definition 3.5 (BLAKE2 personalisation).** The Sapling crate uses
BLAKE2s for 32-byte outputs (`crh_ivk`, `prf_nf`, the group hash) and
BLAKE2b for 64-byte outputs (`kdf_sapling`, `prf_ock`, ZIP 32 child
derivations). Both hashes accept an 8-byte (BLAKE2s) or 16-byte
(BLAKE2b) **personalisation** that domain-separates calls. Every
personalisation string used by Sapling is enumerated in
[`constants.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L17-L40).

**Definition 3.6 (Pedersen hash).** Given an ordered list of fixed
generators $G_0, G_1, \ldots, G_{n-1} \in \mathbb{J}^{(r)}$ and a
bit-string $m \in \{0,1\}^*$, the Sapling Pedersen hash is
$$
\mathsf{PedersenHash}(m) = \sum_{i=0}^{n-1} [\,\sigma_i(m)\,] G_i
$$
where $\sigma_i$ encodes the $i$-th windowed segment of $m$ as a
signed scalar in $[-(2^{w}-1)/2, (2^{w}-1)/2]$. In Sapling, $w = 3$
(windows of 3 bits each) and each generator handles up to
$\mathsf{PEDERSEN\_HASH\_CHUNKS\_PER\_GENERATOR} = 63$ windows.
The output lives in $\mathbb{J}^{(r)}$. Collision resistance reduces
to discrete log on Jubjub. See chapter
[Pedersen hash and commitments](./pedersen-and-commitments).

**Definition 3.7 (windowed Pedersen commitment).** A randomised
variant of the Pedersen hash:
$$
\mathsf{WindowedPedersenCommit}_r(m) = \mathsf{PedersenHash}(m) +
  [r] \cdot G_{\mathsf{rcm}},
$$
where $G_{\mathsf{rcm}}$ is the
`NOTE_COMMITMENT_RANDOMNESS_GENERATOR`. This is what the note
commitment uses ([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L143-L152)).

**Definition 3.8 (homomorphic value commitment).** A second commitment
scheme, used for amounts:
$$
\mathsf{ValueCommit}(v, r_{cv}) = [v] G_{\mathsf{cv,v}} + [r_{cv}]
  G_{\mathsf{cv,r}}.
$$
Two fixed generators, no Pedersen hash. The point of using this
alternative scheme is the additive homomorphism over the value
slot: if $C_i = [v_i] G_{\mathsf{cv,v}} + [r_i] G_{\mathsf{cv,r}}$,
then $\sum_i C_i = [\sum_i v_i] G_{\mathsf{cv,v}} + [\sum_i r_i]
G_{\mathsf{cv,r}}$. That homomorphism is what makes the binding
signature work. See chapter
[Value commitments and balance](./value-commitments).

### 2.3 The proof system: Groth16

**Definition 3.9 (R1CS).** A Rank-1 Constraint System over a field
$\mathbb{F}$ is a triple $(A, B, C)$ of matrices in $\mathbb{F}^{m
\times (n+1)}$, where $m$ is the number of constraints and $n+1$ is
the number of variables (one constant "ONE" wire plus $n$ assigned
variables, partitioned into public inputs and private witnesses).
The constraint system is **satisfied** by an assignment
$\mathbf{w} \in \mathbb{F}^{n+1}$ iff for every row $i$:
$$
\langle A_i, \mathbf{w} \rangle \cdot \langle B_i, \mathbf{w}
\rangle = \langle C_i, \mathbf{w} \rangle.
$$
R1CS has no separate "selector" or "advice" notion; it has only
constraints and variables. Selectors are a Plonkish concept, not an
R1CS concept.

**Definition 3.10 (Groth16).** Groth16 (Groth, "On the Size of
Pairing-Based Non-interactive Arguments", EUROCRYPT 2016) is a
preprocessing zk-SNARK over a pairing-friendly curve (here
BLS12-381). For a fixed R1CS instance $R$, a one-time **trusted
setup** produces a proving key $\sigma$ and a verification key
$\sigma_v$. The prover, given a public input $x$ and witness $w$
with $R(x, w) = 1$, outputs a proof $\pi = (\pi_A, \pi_B, \pi_C)
\in \mathbb{G}_1 \times \mathbb{G}_2 \times \mathbb{G}_1$. The
verifier evaluates a single pairing equation. Proof size is fixed
at $48 + 96 + 48 = 192$ bytes regardless of $|R|$, encoded in
[`GROTH_PROOF_SIZE`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L43).

**Theorem 3.11 (knowledge soundness, informal).** Under the
$q$-power knowledge of exponent assumption in $\mathbb{G}_1$ and
$\mathbb{G}_2$, if an efficient prover produces a Groth16 proof
that verifies for public input $x$, then there exists an efficient
extractor that recovers a witness $w$ with $R(x, w) = 1$. The
"knowledge of exponent" assumption is non-falsifiable but standard.
Citation: Groth, EUROCRYPT 2016.

**Invariant 3.12 (trusted setup).** Groth16 needs a per-circuit
trusted setup. For Sapling, that ceremony was conducted as the
[Sapling MPC](https://electriccoin.co/blog/announcing-the-sapling-mpc/)
in 2017-2018. The setup outputs are not in this crate; they are
distributed as binary files (`sapling-spend.params`,
`sapling-output.params`). The crate exposes
[`SpendParameters::read`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L564-L570)
and
[`OutputParameters::read`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L605-L607)
to load them.

## 3. The code

The two curves and the proof system are external; this crate sits on
top of them.

```rust reference title="Cargo.toml (cryptographic deps)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/Cargo.toml#L21-L46
```

The relevant crates are `bls12_381` and `jubjub` for the curves,
`bellman` (gated behind `circuit`) for the Groth16 backend,
`redjubjub` for the signature scheme, `blake2b_simd` and
`blake2s_simd` for the hashes, and `subtle` for constant-time
primitives.

The hash-to-Jubjub primitive that everything else builds on is
small enough to read in one go:

```rust reference title="src/group_hash.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/group_hash.rs
```

Note the cofactor clearing on line 33 (`CofactorGroup::clear_cofactor`),
which is what guarantees the output lives in $\mathbb{J}^{(r)}$ rather
than in $\mathbb{J}$, and the explicit identity rejection on lines
34-39, which keeps `group_hash` from returning the neutral element.

## 4. Failure modes

- **Treating Jubjub like a Weierstrass curve.** Jubjub is twisted
  Edwards, so the affine identity is $(0, 1)$, not "the point at
  infinity"; equations use $u, v$ coordinates, not $x, y$.
  `jubjub::AffinePoint::identity()` and the related helpers handle
  this for you. Caught by: the type system (you cannot accidentally
  call a Weierstrass-only API).
- **Forgetting to clear the cofactor.** A point sampled in $\mathbb{J}$
  by hash-to-curve without `clear_cofactor` may have small order
  (order $1, 2, 4, 8$). Operations involving such a point can leak
  group structure or open up attacks like the one
  `from_bytes_not_small_order` defends against. Caught by:
  [`value::ValueCommitment::from_bytes_not_small_order`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L167-L170)
  rejects small-order points, and the circuit
  [asserts `g_d` is not small order](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L466-L470).
- **Using BLAKE2 without personalisation.** Two unrelated Sapling
  PRFs would collide if they used the same hash with the same key
  material. The personalisation strings in
  [`constants.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L17-L40)
  are not optional; they are domain-separation tags. Caught by: a
  reviewer with the protocol spec. No automated test in this
  workspace catches "wrong personalisation" because the test
  vectors hash with the right personalisation by definition.

## 5. Spec pointers

- [Zcash Protocol Specification, §5.4 (Cryptographic Constructions)](https://zips.z.cash/protocol/protocol.pdf#abstractprotocol)
  is the authority on every primitive in this chapter.
- [BLS12-381 design notes](https://hackmd.io/@benjaminion/bls12-381) by
  Benjamin Edgington, for the curve.
- [Jubjub design](https://github.com/zkcrypto/jubjub) for parameters and
  test vectors of the curve used as $\mathbb{J}$.
- [Groth, "On the Size of Pairing-Based Non-interactive Arguments",
  EUROCRYPT 2016](https://eprint.iacr.org/2016/260), for the proof
  system. Cited as Definition 3.10 above.
- [Hopwood, "Pedersen hashes in Sapling"](https://github.com/zcash/zcash/issues/2234)
  (issue thread) discusses the rationale for the windowed Pedersen
  construction.

## 6. Exercises

1. **Compute one BLAKE2s personalisation.** Take the input bytes
   `b"sapling"` and personalise the hash with `CRH_IVK_PERSONALIZATION
   = b"Zcashivk"`. Compute the 32-byte output by hand using any
   BLAKE2s reference implementation. Compare against the output of
   `Blake2sParams::new().hash_length(32).personal(b"Zcashivk")
   .hash(b"sapling")` from the `blake2s_simd` crate.
2. **Show the curve embedding numerically.** Open a Rust REPL and
   evaluate `bls12_381::Scalar::NUM_BITS`. Then evaluate
   `<jubjub::Base as ff::PrimeField>::NUM_BITS`. State the
   relationship in one sentence. (You should observe that they are
   both 255, because `jubjub::Base` is `bls12_381::Scalar`.)
3. **Verify subgroup membership.** Write a small program that takes
   the bytes
   `[0u8; 32]`, deserializes them with
   `jubjub::ExtendedPoint::from_bytes`, and checks
   `is_small_order()`. Observe that the result is `Some(true)` (the
   neutral element is in the small-order subset, with order 1).
   Then take the bytes of
   `constants::SPENDING_KEY_GENERATOR.to_bytes()` and run the same
   check. Observe `Some(false)`.

**Answers in the code.** For exercise 2, the embedding fact is
documented in
[`src/group_hash.rs` line 19](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/group_hash.rs#L19):
`assert!(bls12_381::Scalar::NUM_BITS == 255);`. For exercise 3, the
small-order check is in
[`src/value.rs::ValueCommitment::from_bytes_not_small_order`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/value.rs#L167-L170)
and
[`src/verifier.rs::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L48-L51).

## 7. Further reading

- Bowe, Grigg, Hopwood, "Sapling: Improved zk-SNARK Performance for
  Zcash", explains the design space the curves and Pedersen hash were
  chosen from.
- Daira Hopwood's
  [internal notes on Pedersen-hash collision attacks](https://github.com/zcash/zcash/issues/2234)
  motivate the
  [no-duplicate-and-no-linear-relation tests](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L364-L427)
  on the seven generators.
