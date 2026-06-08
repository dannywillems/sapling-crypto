---
sidebar_position: 11
title: The Spend and Output Circuits
description:
  "The two bellman/Groth16 R1CS circuits: their public and private wires, exact
  constraint counts, and what each section enforces."
---

# The Spend and Output Circuits

## 1. Why this chapter exists

Sapling's privacy guarantees rest on two Groth16 R1CS circuits over BLS12-381: a
**Spend** circuit ($\approx$ 99k constraints) and an **Output** circuit
($\approx$ 8k constraints). Every spend description on chain is one Spend proof;
every output description is one Output proof. The Spend circuit is the largest
single artefact in the crate and the one whose correctness Zcash consensus most
depends on.

This chapter walks through the two circuits gate by gate, lists the exact
public-input slots and constraint counts asserted by the tests, and explains the
role of each major block (the value commitment exposure, the ivk derivation, the
Merkle ascent, the nullifier computation). It also clarifies that Groth16 is
R1CS, not Plonkish, and that R1CS has no notion of "selectors".

### 1.1 Spend vs Output at a glance

The two circuits are near mirror images. A shielded transaction destroys some
existing notes and creates some new ones: it carries **one Spend proof per note
consumed** and **one Output proof per note created**. The Spend circuit proves
you own an existing note in the tree and are authorised to destroy it; the
Output circuit proves a new note is well-formed for its recipient. The only
thing linking the two is the value commitment `cv`, and that link is checked
outside both circuits by the binding signature (see
[Value commitments](./value-commitments)).

| Aspect              | Spend                                           | Output                                                |
| ------------------- | ----------------------------------------------- | ----------------------------------------------------- |
| Note lifecycle      | consumes an existing note                       | creates a new note                                    |
| Merkle tree         | proves membership (auth path to `anchor`)       | no tree interaction                                   |
| Nullifier `nf`      | derives and reveals it                          | none                                                  |
| Note commitment     | already a leaf; re-derived to bind the proof    | computed and exposed as `cmu` (a future leaf)         |
| Authorisation       | proves knowledge of the spend key; exposes `rk` | none                                                  |
| Ephemeral key `epk` | not used                                        | proves `epk = [esk] g_d` so the recipient can decrypt |
| Shared clause       | value commitment `cv`                           | value commitment `cv`                                 |
| Size                | $\approx$ 99k constraints                       | $\approx$ 8k constraints                              |

The size gap follows from the clause lists below: $R_{\mathsf{Spend}}$
(Definition 11.1) has ten clauses including a 32-level Merkle ascent, while
$R_{\mathsf{Output}}$ (Definition 11.2) has four and never touches the tree.
That is why a Spend proof costs roughly 12x an Output proof.

## 2. Definitions

**Definition 11.1 (the Spend relation $R_{\mathsf{Spend}}$).** Public input

$$
x = (\mathsf{rk}, \mathsf{cv}, \mathsf{anchor}, \mathsf{nf}) \in
  \mathbb{F}_q^2 \times \mathbb{F}_q^2 \times \mathbb{F}_q
  \times \mathbb{F}_q^2.
$$

Witness

$$
w = (\mathsf{ak}, \mathsf{nsk}, \mathsf{g_d}, v, \mathsf{rcv},
  \mathsf{rcm}, \mathsf{ar}, \mathsf{auth\_path}).
$$

The relation $R_{\mathsf{Spend}}(x, w) = 1$ iff all of:

1. $\mathsf{ak}$ is on Jubjub and not small order.
2. $\mathsf{rk} = \mathsf{ak} + [\mathsf{ar}]
   G_{\mathsf{spendingKey}}$.
3. $\mathsf{nk} = [\mathsf{nsk}] G_{\mathsf{proofGenKey}}$.
4. $\mathsf{ivk} = \mathsf{BLAKE2s}_{\mathsf{Zcashivk}}(
     \mathsf{repr}(\mathsf{ak}) \mathbin{\|} \mathsf{repr}(\mathsf{nk}))$,
   with the top 5 bits zeroed.
5. $\mathsf{g_d}$ is on Jubjub and not small order.
6. $\mathsf{pk_d} = [\mathsf{ivk}] \mathsf{g_d}$.
7. $\mathsf{cv} = [v] G_{\mathsf{cv,v}} + [\mathsf{rcv}]
   G_{\mathsf{cv,r}}$.
8. $\mathsf{cm} = \mathsf{NoteCommit}(v, \mathsf{g_d}, \mathsf{pk_d},
   \mathsf{rcm})$.
9. The authentication path $\mathsf{auth\_path}$ from $\mathsf{cmu}$ to
   $\mathsf{anchor}$ verifies. Modulo: if $v = 0$ the path is unconstrained
   (zero-value bypass, Invariant 6.5).
10. The nullifier matches:

    $$
    \mathsf{nf} = \mathsf{BLAKE2s}_{\mathsf{Zcash\_nf}}\bigl(
      \mathsf{repr}(\mathsf{nk}) \mathbin{\|} \mathsf{repr}(\mathsf{cm}
      - [\mathsf{pos}] \, G_{\mathsf{nf}})\bigr),
    $$

    where $\mathsf{pos}$ is inferred from the `auth_path` position bits.

**Definition 11.2 (the Output relation $R_{\mathsf{Output}}$).** Public input

$$
x = (\mathsf{cv}, \mathsf{epk}, \mathsf{cmu}) \in \mathbb{F}_q^2
  \times \mathbb{F}_q^2 \times \mathbb{F}_q.
$$

Witness

$$
w = (v, \mathsf{rcv}, \mathsf{g_d}, \mathsf{pk_d}, \mathsf{rcm},
  \mathsf{esk}).
$$

$R_{\mathsf{Output}}(x, w) = 1$ iff all of:

1. $\mathsf{cv} = [v] G_{\mathsf{cv,v}} + [\mathsf{rcv}]
   G_{\mathsf{cv,r}}$.
2. $\mathsf{g_d}$ is on Jubjub and not small order.
3. $\mathsf{epk} = [\mathsf{esk}] \mathsf{g_d}$.
4. $\mathsf{cmu} = u\big(\mathsf{NoteCommit}(v, \mathsf{g_d},
   \mathsf{pk_d}, \mathsf{rcm})\big)$.

Notice the Output circuit witnesses $\mathsf{pk_d}$ as an unchecked field
element (it does not verify $\mathsf{pk_d}$ is on-curve or in the subgroup).
This is intentional: the recipient's ivk-decryption will discover any malformed
$\mathsf{pk_d}$ off-chain. See
[`circuit::Output::synthesize`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L486-L513).

**Theorem 11.3 (knowledge soundness, instantiated).** Under the $q$-power
knowledge of exponent assumption on BLS12-381's $\mathbb{G}_1$ and
$\mathbb{G}_2$, a verifier accepting a Groth16 proof for $R_{\mathsf{Spend}}$
(resp. $R_{\mathsf{Output}}$) implies an efficient extractor producing a witness
$w$ with $R(x, w) = 1$. Citation: Groth, EUROCRYPT 2016, Theorem 1. The
assumption is non-falsifiable but standard for SNARKs in this class.

## 3. Circuit size (the question to ask before optimising)

The Sapling protocol's most-cited number is "99k constraints per Spend, 8k per
Output." The exact numbers are asserted as test constants in this crate; they
are pinned, not derived, so a change that alters the constraint count fails CI
immediately.

**Spend circuit:**

| Quantity                         | Value                                                              | Source                                                                                                     |
| -------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| Public inputs (incl. `ONE` wire) | **8**                                                              | [`cs.num_inputs()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L762)      |
| Public inputs (user-facing)      | **7**                                                              | `rk_u, rk_v, cv_u, cv_v, anchor, nf[0], nf[1]`                                                             |
| R1CS constraints                 | **98,777**                                                         | [`cs.num_constraints()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L751) |
| R1CS hash                        | `d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89` | [`cs.hash()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L753-L755)       |

**Output circuit:**

| Quantity                         | Value                                                              | Source                                                                                                      |
| -------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Public inputs (incl. `ONE` wire) | **6**                                                              | [`cs.num_inputs()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L1049)      |
| Public inputs (user-facing)      | **5**                                                              | `cv_u, cv_v, epk_u, epk_v, cmu`                                                                             |
| R1CS constraints                 | **7,827**                                                          | [`cs.num_constraints()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L1025) |
| R1CS hash                        | `c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee` | [`cs.hash()` assertion](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L1027-L1029)      |

The **constant `ONE` wire** is a Groth16 / R1CS convention: the first public
input is reserved for a known-1 element so that linear combinations of variables
can include an additive constant. It is counted in `cs.num_inputs()` but is not
user-facing data.

### 3.1 R1CS has no selectors

A common confusion when reading Sapling alongside more recent zk-systems (Halo2,
Plonk, plonkish circuits in general): **Groth16 is R1CS, not Plonkish**, and
R1CS has only

- the constant `ONE` wire,
- "input" variables (public inputs, also called _instance_),
- "auxiliary" variables (private witness),
- and **constraints**, each a triple $(A_i, B_i, C_i) \in \mathbb{F}^{n+1}$ with
  $\langle A_i, \mathbf{w}\rangle \cdot \langle B_i, \mathbf{w}\rangle
   = \langle C_i, \mathbf{w}\rangle$.

There is no separate selector polynomial, no "advice" column, no custom gates.
Every "gate" you read about in this chapter is expressed as one or more R1CS
rows. The numbers in the table above are simply (a) the count of public-input
variables and (b) the count of constraint rows.

The number of **auxiliary** variables (the witness count, sometimes called
"private inputs" or "total wires minus public inputs") is not asserted in the
test as a fixed constant; it can be retrieved at runtime by calling
`cs.num_aux()` inside
[`test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L635-L782).
See Exercise 1.

## 4. The Spend circuit, section by section

The full implementation:

```rust reference title="src/circuit.rs (Spend::synthesize, header)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L152-L260
```

Section-by-section reading:

### 4.1 Witnessing `ak` and proving `rk = ak + [ar] G_{sk}`

Lines 157-182. The prover witnesses `ak` as an Edwards point (the
[`witness`][witness] gadget enforces "on the curve"). The
[`assert_not_small_order`][assert_not_small_order] call on line 166 performs
three doublings and checks $u \neq 0$; this rules out the eight small-order
points on the cofactor-8 Jubjub curve. Then
`rk = ak + [ar] * SPENDING_KEY_GENERATOR` is constructed and exposed as a public
input.

### 4.2 Witnessing `nsk` and proving `nk = [nsk] G_{pgk}`

Lines 184-204. `nsk` is witnessed as up to 256 bits (no field-element check);
only its bit-decomposition is needed for the in-circuit scalar multiplication.
The reason the spec does not require `nsk` to be in the field is documented in
the in-line comment on lines 193-197: any scalar congruent to a real `nsk` mod
$r_J$ would do, and the relation between $nk$ and $ak$ is still pinned down.

### 4.3 Computing `ivk = BLAKE2s(ak || nk)` then drop top 5 bits

Lines 207-235. `ivk_preimage` is built up from `repr(ak) || repr(nk)` (each
`repr` is 256 bits). The BLAKE2s output is truncated to 252 bits
([`jubjub::Fr`][jubjub::Fr]`::CAPACITY`), matching the out-of-circuit
[`crh_ivk`][crh_ivk] function which clears the top 5 bits.

### 4.4 Computing `pk_d = g_d^{ivk}` and the note hash

Lines 238-321. `g_d` is witnessed, small-order-checked, then `pk_d = [ivk] g_d`.
The note contents (`64 + 256 + 256 = 576` bits, value || g_d || pk_d) are
Pedersen-hashed in-circuit, then randomised by
`[rcm] * NOTE_COMMITMENT_RANDOMNESS_GENERATOR`. The result is the in-circuit
`cm`.

### 4.5 The Merkle ascent and the zero-value bypass

Lines 324-398. The `cur` variable is the u-coordinate of `cm` initially. The
loop at line 334 ascends one tree level at a time; at each level the sibling and
the position bit are witnessed, the two children are conditionally swapped, and
a Pedersen hash with `MerkleTree(i)` personalisation is computed. After 32
iterations, `cur` is the root.

The zero-value bypass is the constraint at line 389-394:

$$
(\mathsf{cur} - \mathsf{rt}) \cdot \mathsf{value} = 0.
$$

If `value = 0`, the path can lead anywhere; if `value != 0`, the path must hit
the public `rt`. This is what makes dummy spends free.

### 4.6 The nullifier computation

Lines 400-427. `rho = cm + [pos] * NULLIFIER_POSITION_GENERATOR`, where `pos` is
reconstructed from the path's position bits. Then `nf = BLAKE2s(nk || rho)` with
personalisation `Zcash_nf`, packed into 2 field elements (each field element
fits up to 254 bits, so 256 bits of nullifier need 2 of them).

## 5. The Output circuit

```rust reference title="src/circuit.rs (Output::synthesize)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L431-L554
```

The Output circuit is structurally simpler. It:

1. Exposes the value commitment (lines 440-445).
2. Witnesses `g_d`, asserts not-small-order, exposes `epk = [esk] g_d` (lines
   447-484).
3. Witnesses `pk_d`'s v-coordinate and a 1-bit u-sign (no on-curve check; lines
   486-512). The Output circuit deliberately trusts the prover here; the
   consequence is that an output to a malformed `pk_d` is unspendable but
   admissible.
4. Computes the note hash and exposes `cmu = u(cm)` (lines 514-551).

## 6. Circuit-side gadgets

The Edwards-point gadget library and the in-circuit Pedersen hash are in
[`src/circuit/ecc.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/ecc.rs)
and
[`src/circuit/pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/pedersen_hash.rs).
The [`fixed_base_multiplication`][fixed_base_multiplication] function is the
workhorse:

```rust reference title="src/circuit/ecc.rs (fixed_base_multiplication)"
https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/ecc.rs#L26-L74
```

3-bit windows, each yielding a table lookup (`lookup3_xy`) and an addition. This
is the same window size as the out-of-circuit Pedersen hash; the lookup tables
are the columnar arrangement of the
[`PEDERSEN_HASH_EXP_TABLE`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/constants.rs#L239-L243).

## 7. Failure modes

- **Constraint count drift.** Any change to the circuit alters
  `cs.num_constraints()`. The test
  [`test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L750-L756)
  asserts the count to the byte. A refactor that produces 98778 constraints
  fails CI. This is intentional: an unintended constraint addition is almost
  always a bug.
- **Public input order swap.** The public inputs are positional. A refactor that
  swaps `rk_u` and `rk_v` produces a circuit whose proofs pass the prover's
  check but fail any verifier built against the prior verification key. Caught
  by: the explicit `cs.get_input(i, name)` assertions in the test (lines
  763-779).
- **Missing not-small-order check.** `ak` and `g_d` must both be asserted
  not-small-order. If a refactor removed the check on `g_d` (e.g. because "the
  Output circuit already does it"), a malicious prover could craft a $g_d$ on a
  cofactor coset and bind one note to multiple ivk-decryptable readings. Caught
  by: the explicit lines 252-254 (for `g_d`) and 165-166 (for `ak`); their
  removal would change the constraint count and fail the assertion.
- **In-circuit / out-of-circuit Pedersen drift.** Already covered in
  [chapter 4](./group-hash-and-pedersen#5-failure-modes). The symptom in the
  circuit is `cs.hash()` mismatching the asserted value `d37c...6a89`.

## 8. Spec pointers

- [Zcash Protocol Specification, §4.17 (Sapling Spend Statement)](https://zips.z.cash/protocol/protocol.pdf#spendstatement)
  is the spec-level definition of $R_{\mathsf{Spend}}$. The bullet list of
  constraints there mirrors Definition 11.1.
- [Zcash Protocol Specification, §4.18 (Sapling Output Statement)](https://zips.z.cash/protocol/protocol.pdf#outputstatement)
  is the spec-level definition of $R_{\mathsf{Output}}$.
- [Groth, "On the Size of Pairing-Based Non-interactive Arguments", EUROCRYPT 2016](https://eprint.iacr.org/2016/260)
  is the proof system reference.
- [Bowe, "BLS12-381: New zk-SNARK Elliptic Curve Construction"](https://electriccoin.co/blog/new-snark-curve/)
  motivates the curve choice.

## 9. Exercises

1. **Print the auxiliary variable count.** Add
   `println!("num_aux = {}", cs.num_aux());` to
   [`test_input_circuit_with_bls12_381`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L750-L756)
   just before the `assert!(cs.is_satisfied())`. Run the test with
   `cargo test --all-features --release -- circuit::test_input_circuit_with_bls12_381 --nocapture`.
   Record the number. Together with the 8 public inputs and the 98,777
   constraints, this tells you the total wire count.
2. **Tighten a public-input assertion.** The test asserts the `ONE` input at
   index 0, then six named inputs. Add an assertion
   `assert_eq!(cs.num_inputs(), 1 + 7);` after the existing
   `assert_eq!(cs.num_inputs(), 8);` to make the distinction between `ONE` and
   the seven user-facing inputs explicit. Verify the test still passes.
3. **Make a constraint count change visible.** In
   [`circuit::Output::synthesize`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L431-L554),
   add a single dummy constraint
   (`cs.enforce(|| "dummy", |lc| lc, |lc| lc, |lc| lc);`). Run
   `cargo test --all-features --release -- circuit::test_output_circuit_with_bls12_381`.
   Observe the failure (`7827` becomes `7828`). Revert. The takeaway: the
   constraint count assertion is what makes any future circuit refactor visible.

**Answers in the code.** For exercise 1, on a fresh build at tag 0.7.0 the Spend
circuit reports `num_aux` in the ~75,000-80,000 range; the exact number is what
you should record. For exercise 3, the `cs.hash()` assertion will also fire
because the dummy constraint changes the constraint graph; that is the "defence
in depth" of having both a count and a hash.

## 10. Further reading

- The
  [`bellman` crate's groth16 module](https://docs.rs/bellman/latest/bellman/groth16/)
  is the proof-system implementation underneath. The
  [`Circuit` trait](https://docs.rs/bellman/latest/bellman/trait.Circuit.html)
  is what [`Spend::synthesize`][Spend::synthesize] and
  [`Output::synthesize`][Output::synthesize] implement.
- For the proof system's verifier internals, read the
  [`groth16::verify_proof`](https://docs.rs/bellman/latest/bellman/groth16/fn.verify_proof.html)
  source; it is the function called by
  [`SaplingVerificationContext::check_spend`](https://github.com/zcash/sapling-crypto/blob/0.7.0/src/verifier/single.rs#L46-L52).

<!-- Source links (zcash/sapling-crypto @ 0.7.0; jubjub via docs.rs) -->

[witness]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/ecc.rs#L132
[assert_not_small_order]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/ecc.rs#L86
[crh_ivk]: https://github.com/zcash/sapling-crypto/blob/0.7.0/src/spec.rs#L25
[fixed_base_multiplication]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit/ecc.rs#L28
[Spend::synthesize]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L153
[Output::synthesize]:
  https://github.com/zcash/sapling-crypto/blob/0.7.0/src/circuit.rs#L153
[jubjub::Fr]: https://docs.rs/jubjub/latest/jubjub/struct.Fr.html
