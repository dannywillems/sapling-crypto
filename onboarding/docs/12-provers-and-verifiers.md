---
sidebar_position: 12
title: Provers and Verifiers
description: "The SpendProver / OutputProver traits, the single-proof verifier, and the BatchValidator."
---

# Provers and Verifiers

## 1. Why this chapter exists

The two Sapling circuits are abstract math; getting an executable
proof or verification out of them requires concrete trait
implementations against `bellman::groth16`, plus a verification
context that knows how to accumulate value commitments and check
signatures. This crate provides three layers:

- The `SpendProver` and `OutputProver` traits, with the production
  impl on `SpendParameters` / `OutputParameters` (real Groth16) and
  a `MockSpendProver` / `MockOutputProver` impl that emits zero
  bytes (for tests).
- The `SaplingVerificationContext` (single transaction).
- The `BatchValidator` (many transactions, batched Groth16 and
  RedJubjub verification).

This chapter pins down the interface, the consensus checks that
live in the verifier, and where the cost savings of batching come
from.

## 2. Definitions

**Definition 12.1 (Sapling consensus checks for one spend).** Given
a `SpendDescription` and a `sighash`, the verifier must:

1. Reject if `cv` is small order. (Done at deserialisation, not in
   the verifier proper; see
   [chapter 9](./value-commitments#4-failure-modes).)
2. Reject if `rk` is small order.
3. Verify the spend-authorisation signature: `rk.verify(sighash,
   spend_auth_sig)`.
4. Verify the Groth16 proof against
   $R_{\mathsf{Spend}}$ with public input
   `(rk_u, rk_v, cv_u, cv_v, anchor, nf[0], nf[1])`.
5. Accumulate `+cv` into the bundle's running value-commitment
   sum.

**Definition 12.2 (Sapling consensus checks for one output).** Given
an `OutputDescription`, the verifier must:

1. Reject if `epk` is small order.
2. Verify the Groth16 proof against
   $R_{\mathsf{Output}}$ with public input
   `(cv_u, cv_v, epk_u, epk_v, cmu)`.
3. Accumulate `-cv` into the bundle's running value-commitment
   sum.

**Definition 12.3 (final check).** After all spends and outputs are
checked, the verifier reconstructs the binding verification key
`bvk` from the accumulated `cv_sum` and the bundle's
`value_balance`, then verifies the binding signature against
`bvk`. If any check returns false, the whole bundle is rejected.

**Definition 12.4 (batch validation).** Given $N$ bundles, the
batch validator queues their Groth16 proofs and RedJubjub
signatures, then verifies each kind in bulk using
[`groth16::batch::Verifier`](https://docs.rs/bellman/latest/bellman/groth16/batch/struct.Verifier.html)
and
[`redjubjub::batch::Verifier`](https://docs.rs/redjubjub/latest/redjubjub/batch/struct.Verifier.html).
Batched verification gives `(false, set)` semantics: if any element
in the batch fails, the whole batch fails (the batch does not
identify which element). Callers who need per-bundle results must
construct one validator per bundle.

**Invariant 12.5 (consensus rules execute before batched checks).**
Consensus rules that are local to a spend / output (small-order
checks, value-commitment accumulation) execute eagerly inside
`check_spend` / `check_output`. Cryptographic verification
(signatures, proofs) is the part that gets queued. So a malformed
bundle (small-order `cv`) is rejected even before any batched
verification runs.

## 3. The code

### 3.1 The prover traits

The `SpendProver` and `OutputProver` traits split each operation
into "prepare the witness" and "actually create the proof". The
preparation step has no randomness; the creation step needs an
RNG.

```rust reference title="src/prover.rs (traits)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L21-L77
```

The production impl is on `SpendParameters` / `OutputParameters`,
which wrap a `groth16::Parameters<Bls12>` (the proving key from the
trusted setup):

```rust reference title="src/prover.rs (SpendProver for SpendParameters)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L79-L135
```

`encode_proof` converts a `groth16::Proof<Bls12>` into a fixed-size
`[u8; 192]`. The serialisation is `bellman`'s standard
$\mathbb{G}_1$ / $\mathbb{G}_2$ point encoding; the byte size 192
comes from `48 + 96 + 48` (compressed $\mathbb{G}_1$, compressed
$\mathbb{G}_2$, compressed $\mathbb{G}_1$).

### 3.2 The mock prover

A test-only prover that emits all zeros:

```rust reference title="src/prover.rs (MockSpendProver)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L177-L235
```

The mock is enabled by the `test-dependencies` feature. It is used
by integration tests that need to exercise the builder /
authorisation pipeline without paying the Groth16 cost (which is
~minutes per Spend in a debug build).

### 3.3 The single-transaction verifier

`SaplingVerificationContext` is the structure a node uses for a
single transaction. It holds a running sum of value commitments
and exposes three methods: `check_spend`, `check_output`,
`final_check`.

```rust reference title="src/verifier/single.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs
```

```rust reference title="src/verifier.rs (SaplingVerificationContextInner)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L17-L149
```

The `*Inner` struct is shared between the single and the batch
verifier; only the verification callback ("how do I verify a
signature / a proof") differs.

### 3.4 The batch verifier

```rust reference title="src/verifier/batch.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/batch.rs
```

Notice the structure:

- `check_bundle` is called once per bundle. It queues the proofs
  and signatures from that bundle into the batch verifiers (lines
  72-81 for the spend auth sig, 78-81 for the spend proof, 106-110
  for the output proof, 118-122 for the binding sig).
- `validate` is called once at the end and runs the three batched
  checks (signatures, spend proofs, output proofs).
- The `bundles_added` flag (lines 33, 53, 137-140) avoids running
  the verifier with empty batches, which is correct but not free.

The savings come from the fact that batched Groth16 verification
is `O(N)` rather than `O(N)` separate $O(1)$ verifications with
overhead. The crate uses `verify_multicore` when the `multicore`
feature is enabled (default), which parallelises with rayon.

## 4. Failure modes

- **Forgetting `final_check`.** A bundle's spend / output checks
  pass individually but the verifier never accumulates them into
  the binding signature check. The consequence: balance is not
  enforced. Caught by: the batch validator wraps the lifecycle
  explicitly; the single-transaction context's
  [`final_check`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs#L70-L82)
  is required to be called by the caller.
- **Passing the wrong `sighash` to a spend.** Each spend signs the
  transaction's full sighash; if the caller computes a stale
  sighash (e.g. computed before a recipient was added), the
  signature fails. Caught by: the caller; this crate accepts any
  32-byte sighash without inspecting it.
- **Calling `validate` on a `BatchValidator` that has had no
  bundles added.** Returns `true`; an empty batch is vacuously
  valid. This is correct, but unexpected if the caller treated
  `validate` as "did anything actually verify"; see the
  [`bundles_added` flag](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/batch.rs#L137-L140).
- **Trusted setup parameters loaded with `verify_point_encodings =
  false`.** The
  [`SpendParameters::read`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L562-L570)
  signature exposes this flag; if a caller sets it to `false`
  without independently verifying the parameter file's hash, a
  malformed parameter file could pass without alarm. Caught by:
  the function's doc comment warning; no automatic check.

## 5. Spec pointers

- [Zcash Protocol Specification, §4.17 / 4.18](https://zips.z.cash/protocol/protocol.pdf#spendstatement)
  defines what the verifier must check.
- [Zcash Protocol Specification, §4.13](https://zips.z.cash/protocol/protocol.pdf#saplingbalance)
  defines the binding signature check (Definition 12.3 above).
- [Zcash Protocol Specification, §5.4.7 (Signature Scheme: RedJubjub)](https://zips.z.cash/protocol/protocol.pdf#redjubjub)
  defines the signature primitive.
- [Boneh, Drijvers, Neven, "Compact Multi-Signatures for Smaller Blockchains"](https://eprint.iacr.org/2018/483)
  motivates the batch verification approach (the technique is
  reused by `redjubjub::batch::Verifier`).

## 6. Exercises

1. **Time a batch vs single verification.** Construct ten bundles
   using
   [`MockSpendProver`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/prover.rs#L177-L235)
   for the proofs (so the proofs themselves are zero bytes; the
   timing measures only the bookkeeping). Verify them one by one
   with `SaplingVerificationContext` and then in one shot with
   `BatchValidator`. Report the difference. (The improvement comes
   only from real proofs; with mocks the cost is similar.)
2. **Add a test for empty batches.** Construct an empty
   `BatchValidator`, call `validate` with fresh verifying keys and
   an RNG. Confirm the result is `true`. Add this as a unit test
   in `src/verifier/batch.rs`. The existing code already handles
   this case; you are formalising it as a test.
3. **Read the `multicore` cfg.** Find every `#[cfg(feature =
   "multicore")]` in the verifier. Explain in one sentence what
   the fallback does when the feature is off. Hint: `verify` (with
   an RNG) versus `verify_multicore`.

**Answers in the code.** For exercise 3, the fallback is at
[`src/verifier/batch.rs` lines 150-156](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/batch.rs#L150-L156):
without multicore, the batch verifier is randomised
(`verify(&mut rng, vk)`) rather than parallelised.
