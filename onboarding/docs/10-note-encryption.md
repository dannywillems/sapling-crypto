---
sidebar_position: 10
title: Note Encryption
description:
  "In-band secret distribution: how a Sapling Output's ciphertext lets the
  recipient (and only the recipient) reconstruct the note."
---

# Note Encryption

## 1. Why this chapter exists

Every Sapling Output carries two ciphertexts on chain: an **enc_ciphertext**
(encrypted note plaintext, decryptable by the receiver's ivk) and an
**out_ciphertext** (encrypted symmetric keying material, decryptable by the
sender's ovk). Together they mean the receiver learns of incoming payments
without any out-of-band communication, and the sender can re-scan their own
history after a key rotation.

The cryptography is in this crate via an implementation of the
[`zcash_note_encryption::Domain`](https://docs.rs/zcash_note_encryption) trait.
This chapter pins down the KDF, the OCK derivation, the ZIP-212 enforcement
modes, and the trial-decryption entry points.

## 2. Definitions

**Definition 10.1 (Sapling KA).** A Diffie-Hellman key agreement on Jubjub.
Given an ephemeral secret $\mathsf{esk} \in \mathbb{F}_{r_J}$ and a public point
$\mathsf{pk_d} \in \mathbb{J}^{(r)}$ derived from the recipient's ivk and
diversifier:

$$
\mathsf{epk} = [\mathsf{esk}] \cdot \mathsf{g_d}, \qquad
\mathsf{dhsecret} = [\mathsf{8} \cdot \mathsf{esk}] \cdot \mathsf{pk_d} =
  [\mathsf{8} \cdot \mathsf{ivk}] \cdot \mathsf{epk}.
$$

The cofactor 8 ensures the agreed point lives in $\mathbb{J}^{(r)}$. Code:
[`spec::ka_sapling_agree_prepared`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L127-L136)
(the `.clear_cofactor()` call).

**Definition 10.2 (Sapling KDF).** Given the agreed shared secret and the
32-byte ephemeral public key encoding,

$$
\mathsf{kdf_{Sapling}}(\mathsf{dhsecret}, \mathsf{epk\_bytes}) =
  \mathsf{BLAKE2b}_{32, \mathsf{Zcash\_SaplingKDF}}(
    \mathsf{repr}_{\mathbb{J}}(\mathsf{dhsecret}) \mathbin{\|}
    \mathsf{epk\_bytes}
  ).
$$

The output is a 32-byte ChaCha20-Poly1305 key. Code:
[`SharedSecret::kdf_sapling`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/keys.rs#L663-L685).

**Definition 10.3 (PRF^ock).** A second BLAKE2b-32 instance, used to derive the
AEAD key for the **outgoing** ciphertext that lets the sender decrypt their own
outputs:

$$
\mathsf{ock} = \mathsf{BLAKE2b}_{32, \mathsf{Zcash\_Derive\_ock}}(
  \mathsf{ovk} \mathbin{\|} \mathsf{cv\_bytes} \mathbin{\|}
  \mathsf{cmu\_bytes} \mathbin{\|} \mathsf{epk\_bytes}
).
$$

Code:
[`note_encryption::prf_ock`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L38-L58).

**Definition 10.4 (ZIP-212 enforcement).** Three modes that govern which
note-plaintext versions are accepted at decryption time:

```rust reference title="src/note_encryption.rs (Zip212Enforcement)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L60-L67
```

- `Off`: accept both v1 (pre-ZIP-212, [`rcm`][rcm] field) and v2 (ZIP-212,
  [`rseed`][rseed] field). Used for pre-Canopy chains.
- `GracePeriod`: accept both versions; used during the transition blocks at
  Canopy activation.
- `On`: accept only v2 plaintexts. Used on every mainnet block after the grace
  window.

**Invariant 10.5 (esk binding for ZIP-212).** Under ZIP-212, the ephemeral
secret $\mathsf{esk}$ is not sampled fresh; it is derived from the note's
$\mathsf{rseed}$ via $\mathsf{PRF^{Expand,esk}}(\mathsf{rseed})$. This means the
$\mathsf{epk}$ in an Output description is a deterministic function of the
encrypted note. A decrypting receiver can verify this by recomputing
$\mathsf{epk}$ from the decrypted note; if it does not match the on-chain
$\mathsf{epk}$, the output is rejected. Code:
[`Note::derive_esk`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L147-L155).

## 3. The code

### 3.1 The Domain implementation

The crate's heavy lifting is to satisfy the `zcash_note_encryption::Domain`
trait, which abstracts over Sapling and Orchard's note encryption schemes. The
trait's associated types and methods get filled in here:

```rust reference title="src/note_encryption.rs (Domain header)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L116-L186
```

The interesting methods downstream of that header:

- [`derive_esk`][derive_esk]: pulls the ZIP-212 esk from the note (`None` for
  v1).
- [`ka_derive_public`][ka_derive_public]: computes
  $\mathsf{epk} = [\mathsf{esk}]
  \cdot \mathsf{g_d}$.
- [`ka_agree_enc`][ka_agree_enc] / [`ka_agree_dec`][ka_agree_dec]: the two
  directions of the DH.
- [`kdf`][kdf]: the BLAKE2b-32 with
  [`KDF_SAPLING_PERSONALIZATION`][KDF_SAPLING_PERSONALIZATION].

### 3.2 ZIP-212 grace period handling

The bulk of the rules live in the plaintext parser. Both versions of the
plaintext format share the first byte (`0x01` or `0x02`), the next 11 bytes
(diversifier), the next 8 bytes (value, little endian), and 32 bytes of
randomness. After ZIP-212, that last 32 bytes is [`rseed`][rseed] (used to
derive both [`rcm`][rcm] and `esk`); before, it is `rcm` directly:

```rust reference title="src/note_encryption.rs (parse note plaintext)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L69-L114
```

The version-validity gating at line 82
([`plaintext_version_is_valid`][plaintext_version_is_valid]) is what enforces
[`Zip212Enforcement`][Zip212Enforcement]`::On`: it returns `false` for v1
plaintexts when only v2 is accepted.

### 3.3 Trial decryption

The receiver scans every output with their ivk; the per-output trial-decrypt is
one call. The crate re-exports the `zcash_note_encryption` trial-decrypt
functions:

- `try_sapling_note_decryption(SaplingDomain, ivk, ShieldedOutput)`
- `try_sapling_compact_note_decryption(SaplingDomain, ivk, ShieldedOutput)`
  (skips the memo, used in light client sync)
- [`try_sapling_output_recovery_with_ock`][try_sapling_output_recovery_with_ock]
  / [`try_sapling_output_recovery`][try_sapling_output_recovery] (the sender's
  path, using ovk)

### 3.4 Memo bytes

Sapling memos are exactly 512 bytes (`[u8; 512]`). The crate does not impose
structure beyond that; encoding (UTF-8 vs binary "f6"-padding) is the caller's
responsibility, and changed signature in 0.5: see the
[CHANGELOG entry for 0.5.0](https://github.com/zcash/sapling-crypto/blob/0.7.0/CHANGELOG.md#050---2025-02-20).

## 4. Why decryption gives a spendable note

Section 2 defined the key agreement and the KDF; section 3 showed where they
live in the code. What is missing is the concrete answer to the recipient's
question: **what exactly did the sender publish on chain, and which of those
bytes do I need to spend the note later?** This section walks through the
on-chain payload byte by byte, identifies the small slice the receiver actually
consumes, and connects that slice to the Spend witness in
[chapter 11](./spend-and-output-circuits) (Definition 11.1).

### 4.1 What the sender publishes on chain

For every output the sender writes one `OutputDescription` to the block:

```rust reference title="src/bundle.rs (OutputDescription)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L332-L340
```

Six fields, with sizes fixed by the protocol (v4 transactions):

| Field            | Size      | What it is                                                                                              |
| ---------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| `cv`             | 32 bytes  | Pedersen value commitment to `v` with trapdoor `rcv`                                                    |
| `cmu`            | 32 bytes  | u-coordinate of the note commitment `cm`; appended to the tree                                          |
| `ephemeral_key`  | 32 bytes  | `epk = [esk] g_d`, the Diffie-Hellman ephemeral public key                                              |
| `enc_ciphertext` | 580 bytes | AEAD-wrapped 564-byte note plaintext, encrypted under the DH key                                        |
| `out_ciphertext` | 80 bytes  | AEAD-wrapped 64-byte sender-recovery plaintext, encrypted under `ock` (derived from the sender's `ovk`) |
| `zkproof`        | 192 bytes | Groth16 proof of the Output relation (Definition 11.2)                                                  |

The 580 bytes of `enc_ciphertext` are an AEAD wrapper (564-byte plaintext plus a
16-byte Poly1305 tag) around one **note plaintext**. The plaintext layout is the
same one the parser uses in section 3.2:

| Plaintext bytes | Field     | Notes                                   |
| --------------- | --------- | --------------------------------------- |
| `0`             | `version` | `0x01` (pre-Canopy) or `0x02` (ZIP 212) |
| `1..12`         | `d`       | 11-byte diversifier                     |
| `12..20`        | `v`       | 8-byte little-endian value              |
| `20..52`        | `rseed`   | 32 bytes (v2) or 32-byte `rcm` (v1)     |
| `52..564`       | `memo`    | 512-byte free-form memo                 |

The 80 bytes of `out_ciphertext` wrap a 64-byte plaintext `(esk || pk_d)`,
encrypted under a key derived from the sender's own `ovk`. This blob is for the
sender to re-decrypt their own outgoing history (see section 3.3); the
**receiver never reads it**.

### 4.2 What the receiver actually needs

Of the six fields above, the receiver needs exactly **two** to recover the note:

- `ephemeral_key` (= `epk`), to compute the DH shared secret
  $[\mathsf{ivk}] \cdot \mathsf{epk} = [\mathsf{esk}] \cdot \mathsf{pk_d}$ and
  unlock the AEAD;
- `enc_ciphertext`, the bytes to decrypt.

Trial decryption (`try_sapling_note_decryption(ivk, output)`) feeds those two
fields plus the receiver's `ivk` into the KDF + ChaCha20-Poly1305 chain defined
in section 2. On success it returns the 564-byte plaintext, of which the **first
52 bytes are all the spend-time circuit will ever see**:
`(version, d, v, rseed)`. The 512-byte memo is human-facing and never touches
the circuit.

The receiver also reads two more on-chain fields, not to decrypt them, but to
**cross-check the decryption**:

- `cmu`: after deriving `rcm` from `rseed` and `pk_d = [ivk] g_d`, the receiver
  recomputes `cm = NoteCommit(g_d, pk_d, v, rcm)` and checks its u-coordinate
  against the on-chain `cmu`. The same `cmu` doubles as the note's address
  inside the note commitment tree, so finding it there gives the receiver the
  Merkle position and the authentication path.
- `epk` (again): the receiver re-derives `esk` from `rseed`, computes
  `epk' = [esk] g_d`, and rejects the output if `epk' != epk` (Invariant 10.5).
  This is the binding check that prevents a malicious sender from attaching two
  valid plaintexts to one `epk`.

`cv`, `out_ciphertext`, and `zkproof` are never used by the receiver. They serve
the validator (`cv` and `zkproof`) or the sender (`out_ciphertext`).

So at the byte level the sender's job for the receiver is to publish the 52
bytes of compact note plaintext (wrapped as the AEAD payload of
`enc_ciphertext`) and the 32-byte `epk` needed to unwrap them. Everything else
the receiver needs they either compute from those bytes or already hold
themselves.

### 4.3 Reconstructing the Spend witness

Chapter 11, Definition 11.1, lists the Spend circuit's private witness as

$$
w = (\mathsf{ak}, \mathsf{nsk}, \mathsf{g_d}, v, \mathsf{rcv},
   \mathsf{rcm}, \mathsf{ar}, \mathsf{auth\_path}).
$$

Each component comes from exactly one place at spend time:

| Witness component | Source                                                                   |
| ----------------- | ------------------------------------------------------------------------ |
| `g_d`             | `GroupHash(d)`, with `d` from the decrypted compact note                 |
| `v`               | bytes 12..20 of the decrypted compact note                               |
| `rcm`             | $\mathsf{PRF^{Expand}_{rcm}}(\mathsf{rseed})$, `rseed` from bytes 20..52 |
| `auth_path`       | receiver's local note commitment tree, indexed by the on-chain `cmu`     |
| `ak`              | receiver's key tree (derived from `ask`)                                 |
| `nsk`             | receiver's key tree                                                      |
| `rcv`, `ar`       | freshly sampled per spend                                                |

The first four rows are exactly the data the sender delivered through
`enc_ciphertext` + the on-chain `cmu`. The next two come from the receiver's own
spending key. The last two are local randomness. Nothing more is needed, and in
particular the receiver never has to talk to the sender again.

The same logic explains why the receiver also recomputes `pk_d` from their own
`ivk` rather than reading it from the ciphertext: the Spend circuit re-derives
`pk_d = [ivk] g_d` as constraint 6 of Definition 11.1, and any inconsistency
between the decrypted note and the receiver's `ivk` shows up as a witness that
fails to satisfy constraint 8 (the note commitment).

### 4.4 Why the Output circuit can skip recipient authentication

Definition 11.2 has the Output circuit witnessing `pk_d` as an **unchecked field
element**: no on-curve check, no subgroup check, no proof that `pk_d`
corresponds to anyone's `ivk`. Chapter 11 notes the reason in passing; this is
the place to make it explicit.

At Output time the sender alone cannot authenticate the recipient even if the
protocol asked: the sender only has the public address `(d, pk_d)` and no
signature from the receiver. So the Output circuit constrains only what the
sender can prove unilaterally:

- `cv` is a valid value commitment opening to the witnessed `v`;
- `epk = [esk] g_d` for the witnessed `esk` and `g_d`;
- `g_d` is on-curve and not small order;
- `cmu` is the `u`-coordinate of `NoteCommit(v, g_d, pk_d, rcm)`.

If `pk_d` is garbage (not on the curve, in the small-order subgroup, or not
anyone's diversified key), the chain still accepts the OutputDescription. The
cost is borne entirely by the named recipient: they cannot spend the note
because no `ivk` they hold would let them derive a matching `pk_d` under
constraint 6 of Definition 11.1. The malformed output becomes unspendable
change, and the sender has burned their funds.

Authentication of the recipient is therefore deferred to spend time:

$$
\mathsf{pk_d} = [\mathsf{ivk}] \cdot \mathsf{g_d}
$$

inside the Spend circuit binds the note to the holder of `ivk`, and only that
holder could have decrypted the ciphertext in the first place. The two checks
(off-chain decryption with `ivk`, in-circuit `pk_d` equality) lock the same
identity at two different moments, with no need for the sender to participate in
either.

This is also the structural reason the Output circuit is much smaller than the
Spend circuit (section 3 of chapter 11): no Merkle ascent, no nullifier
derivation, no `ivk` re-derivation. All of those move to spend time, where the
actor with the secrets is also the actor doing the proving.

## 5. Failure modes

- **ZIP-212 enforcement misconfigured.** A node that runs with
  [`Zip212Enforcement`][Zip212Enforcement]`::Off` on a chain past the grace
  period will accept pre-Canopy notes that should have been rejected; a node
  that runs with `On` before the grace period activation will reject legitimate
  v1 notes. The crate does not pick the mode itself; it is the caller's
  responsibility (typically based on block height). Caught by: nothing automatic
  in this crate; the configuration surface is in the caller (e.g. `zebrad`).
- **`epk` decoded as a small-order point.** The deserializer for ephemeral keys
  rejects small-order points
  ([source](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L108-L110)).
  A bypass would let an attacker bind a note to multiple ivk-decryptable
  plaintexts. Caught by: the
  [`SaplingVerificationContextInner::check_output`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier.rs#L97-L133)
  consensus check.
- **Memo bytes left uninitialized.** Memos are 512-byte buffers and the
  encrypted form leaks the full 512 bytes (length is not hidden). A caller
  passing uninitialised memory leaks process state. The type signature
  (`[u8; 512]`, not `&[u8]`) makes this hard to do accidentally; constructing
  the array requires explicitly setting each byte. Caught by: the type system,
  mostly.
- **Reusing `esk` across two outputs.** Pre-ZIP-212, `esk` was sampled freely;
  nothing prevented reuse. Reuse breaks DH security (the shared secrets across
  the two outputs are related). ZIP-212 fixes this by deriving `esk`
  deterministically from `rseed`, so reuse requires reusing `rseed`, which
  itself is a per-note fresh sample. Caught by: see
  [Notes and nullifiers](./notes-and-nullifiers).

## 6. Spec pointers

- [Zcash Protocol Specification, §5.4.4 (In-band secret distribution)](https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband)
  is the authority on the protocol-level encryption.
- [Zcash Protocol Specification, §5.4.5.3 (Sapling key agreement)](https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement)
  defines the KA primitive (Definition 10.1 above).
- [ZIP 212](https://zips.z.cash/zip-0212) is the source of Definition 10.5 and
  the grace-period semantics.
- [`zcash_note_encryption` crate documentation](https://docs.rs/zcash_note_encryption/)
  is the trait this module implements. Read its `Domain` trait before extending
  the Sapling impl.

## 7. Exercises

1. **Decrypt a known test vector.** Open
   [`src/test_vectors/note_encryption.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/test_vectors/note_encryption.rs)
   and pick one. Construct the [`SaplingDomain`][SaplingDomain] with the right
   enforcement mode and call
   [`try_sapling_note_decryption`][try_sapling_note_decryption]. Verify the
   returned [`Note`][Note] matches the vector. The existing
   [`note_encryption.rs` tests](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L640-L1500)
   exercise this; pick one and run it in isolation.
2. **Show the OVK separation.** Construct two outputs to the same address with
   the same memo but different ovks. Confirm that the two
   [`out_ciphertext`][out_ciphertext] blobs differ (because `ock` derives from
   `ovk`), while the [`enc_ciphertext`][enc_ciphertext] blobs also differ
   (because they have different fresh trapdoors).
3. **Add a `Display` impl for [`Zip212Enforcement`][Zip212Enforcement].** Useful
   when debugging an ambiguous chain configuration. Lowercase `"off"`,
   `"grace_period"`, `"on"`. Add a unit test that round-trips through `format!`.

**Answers in the code.** For exercise 1, the test vectors are in the
[`test_vectors::note_encryption::make_test_vectors`][make_test_vectors] helper.
For exercise 2, the
[`prf_ock`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L38-L58)
function takes `ovk` as the first byte input, so two distinct `ovk`s give two
distinct `ock`s with overwhelming probability.

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[rcm]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L34
[rseed]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L96
[Note]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note.rs#L46
[derive_esk]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L147
[ka_derive_public]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L159
[ka_agree_enc]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L166
[ka_agree_dec]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L173
[kdf]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L183
[KDF_SAPLING_PERSONALIZATION]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L32
[plaintext_version_is_valid]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L399
[Zip212Enforcement]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L63
[SaplingDomain]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L116
[try_sapling_note_decryption]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L407
[try_sapling_output_recovery_with_ock]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L435
[try_sapling_output_recovery]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/note_encryption.rs#L452
[out_ciphertext]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L363
[enc_ciphertext]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/bundle.rs#L358
[make_test_vectors]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/test_vectors/note_encryption.rs#L24
