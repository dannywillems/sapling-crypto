---
sidebar_position: 14
title: PCZT — Partially-Created Zcash Transactions
description:
  "The role-based protocol for offline transaction construction: Creator,
  Constructor, Updater, IO Finalizer, Prover, Signer, Combiner, Spend Finalizer,
  Transaction Extractor."
---

# PCZT - Partially-Created Zcash Transactions

## 1. Why this chapter exists

A PCZT is the Sapling analogue of Bitcoin's PSBT: a partially-created
transaction object that multiple parties (each with a different piece of secret
material) can pass around and incrementally fill in. The canonical use case is
hardware wallets, where the proving keys, the signing keys, and the witness data
live on different devices.

The PCZT machinery is the **most actively modified** part of this crate over the
0.x line and the most plausible place for a new contributor to land work. This
chapter spells out the actor roles, the per-role error types, and the per-actor
state transitions.

## 2. Definitions

**Definition 14.1 (PCZT bundle).** A `pczt::Bundle` is a holder for "a Sapling
bundle in some intermediate state of construction". It contains a vector of
`pczt::Spend` and `pczt::Output` (both of which are different from the
consensus-facing `SpendDescription` / `OutputDescription`), a running
`value_sum`, a fixed anchor, and an optional binding signing key set by the IO
Finalizer:

```rust reference title="src/pczt.rs (Bundle)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt.rs#L46-L93
```

**Definition 14.2 (PCZT Spend).** A spend record with optional fields for
everything an Updater, Prover, or Signer might need:

```rust reference title="src/pczt.rs (Spend)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt.rs#L95-L190
```

The fields are `Option<T>` because different actors are responsible for filling
each one in. Once an actor uses a field, it can sometimes redact it (e.g. the IO
Finalizer compresses every `rcv` into the bundle's `bsk` and the individual
`rcv` values can be erased afterward).

**Definition 14.3 (the actors).** A PCZT lifecycle involves these named roles,
each with a dedicated module under `src/pczt/`:

| Role                  | Module                                                                                           | Responsibility                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Creator               | (constructed manually)                                                                           | Initialise the empty `pczt::Bundle`.                                       |
| Constructor           | (caller code, often the builder via `build_for_pczt`)                                            | Add spends and outputs.                                                    |
| Updater               | [`updater.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/updater.rs)           | Fill in missing fields, e.g. the proof generation key, the merkle witness. |
| IO Finalizer          | [`io_finalizer.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/io_finalizer.rs) | Compute `bsk` from all `rcv`s, redact them.                                |
| Prover                | [`prover.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/prover.rs)             | Create the Groth16 proofs.                                                 |
| Signer                | [`signer.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/signer.rs)             | Create the spend auth signatures.                                          |
| Combiner              | (mostly trivial merging, via `Bundle::merge`)                                                    | Merge two PCZT bundles.                                                    |
| Spend Finalizer       | (drops dummies once signed)                                                                      | Clean up after signing.                                                    |
| Transaction Extractor | [`tx_extractor.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/tx_extractor.rs) | Produce the final `bundle::Bundle<Authorized, V>`.                         |

Each actor has its own error type, prefixed with the actor's role:
`UpdaterError`, `IoFinalizerError`, `ProverError`, `SignerError`,
`TxExtractorError`, plus `ParseError` and `VerifyError` for the parsing /
verification surfaces.

**Invariant 14.4 (no actor sees more than it needs).** The PCZT protocol is
designed so that a Signer that holds the `ask` does not need to see the `rseed`
or the `rcv`. A Prover that has the proving key does not need to see the `ask`.
The
[`Spend::recipient` field](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt.rs#L122-L127)
is held until the Prover finishes, then can be redacted. The mechanism is the
per-field `Option<T>` plus an explicit "redact" step.

**Invariant 14.5 (PCZT requires ZIP-212).** `Builder::build_for_pczt` rejects
bundles configured with `Zip212Enforcement::Off` because PCZT outputs must be
deterministically derived from their seeds (or the Prover-Signer split cannot
work).

```rust reference title="src/builder.rs (build_for_pczt requires ZIP-212)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L120-L143
```

See
[`Error::PcztRequiresZip212`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L136-L137).

## 3. The code

### 3.1 The module map

The top-level `pczt.rs` file is a façade; the per-actor logic lives in dedicated
submodules:

```rust reference title="src/pczt.rs (module declarations)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt.rs#L22-L45
```

### 3.2 The updater

The Updater is where most "fill in the missing field" logic lives. Its interface
is a pair of mutable closures invoked once per spend and once per output:

```rust reference title="src/pczt/updater.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/updater.rs
```

### 3.3 The IO Finalizer

Compresses every `rcv` into the binding signing key `bsk` and redacts the
individual `rcv` values. Once this step runs, the bundle no longer carries the
per-spend / per-output randomness, which means the bundle can be passed to a
less-trusted Prover or Signer.

```rust reference title="src/pczt/io_finalizer.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/io_finalizer.rs
```

### 3.4 The transaction extractor

Once all proofs and signatures are filled in, the extractor converts a
`pczt::Bundle` into a consensus-facing `Bundle<Authorized, V>`:

```rust reference title="src/pczt/tx_extractor.rs"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/tx_extractor.rs
```

Note the
[`Bundle::extract` signature change](https://github.com/zcash/sapling-crypto/blob/0.7.0/CHANGELOG.md#070---2026-04-21):
it now takes `&self` rather than `self` (so the PCZT bundle stays available
after extraction). This is one of the few behavioural changes between 0.6 and
0.7.

## 4. Failure modes

- **PcztRequiresZip212.** Trying to build a PCZT with `Zip212Enforcement::Off`
  returns `Error::PcztRequiresZip212`. Caught by:
  [`Builder::build_for_pczt`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L136-L140).
- **Signer rejects PCZTs with `dummy_ask` set.** The `dummy_ask` field is set by
  the constructor for dummy spends; once the IO Finalizer has used it, it is
  cleared. A Signer that sees a bundle still carrying `dummy_ask` was passed an
  unfinalized bundle. Caught by:
  [the Signer rule](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/signer.rs)
  (search for `dummy_ask` rejection).
- **ProverError::MissingProofGenerationKey.** The Prover needs the
  proof-generation key. If the Updater did not fill it in before the Prover ran,
  the Prover errors. Caught by: the
  [`pczt::ProverError` variants](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/prover.rs).

## 5. Spec pointers

- The PCZT format is not (as of 0.7.0) a published ZIP. The authoritative
  description is the in-source documentation under `src/pczt/`.
- [PSBT (BIP 174)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
  is the inspiration for the role-based decomposition. Sapling's PCZT differs in
  being aware of Groth16 proofs.
- Mostly relevant background reading:
  [Zcash Foundation FROST research](https://github.com/ZcashFoundation/frost),
  which uses PCZT as one of its deployment targets.

## 6. Exercises

1. **Walk one lifecycle.** Construct an empty PCZT bundle. Add a single spend
   via the builder's `build_for_pczt`. Run the IO Finalizer. Confirm the `rcv`
   fields are now `None` and the bundle's `bsk` is `Some(_)`.
2. **Identify a missing-field error.** Try running the Prover without first
   running the Updater to populate the proof generation key. Confirm the error
   variant returned and locate it in
   [`pczt/prover.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/prover.rs).
3. **Trace a redaction.** Pick the `recipient` field on `pczt::Spend`. Find
   every actor that sets it, reads it, or clears it. Reproduce the redaction
   order in prose (~3 sentences).

**Answers in the code.** For exercise 1, the IO Finalizer's "compress and
redact" pass is the body of
[`io_finalizer.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/pczt/io_finalizer.rs).
For exercise 3, the `recipient` field is set by the Constructor in
[`builder.rs::into_pczt`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/builder.rs#L325-L355).
