# ZK Circuit Vulnerabilities -- Combat Briefing

Briefing for ZK circuit auditors. Covers the 5 most exploited ZK bug patterns across 9 verified findings.
Verified data sourced from `solodit_bulk_findings.json` (Solodit/Cyfrin database).

---

## 1. Bugs Conocidos

```yaml
- id: zk-001
  pattern: missing-range-check-constraints
  name: "Missing range checks in arithmetic gadgets (under-constrained)"
  causa_raiz: >
    ZK circuit gadgets that perform arithmetic (multiply, divide, modular ops)
    accept bit-size parameters but never constrain the witness values to actually
    fit within those bit ranges. The prover can supply values that overflow the
    expected bit width, causing the gadget to produce incorrect results (e.g.,
    fee calculations that overflow). Because the constraint system does not
    enforce bit-range membership, the verifier accepts proofs over manipulated
    witness values.
  como_funciona: >
    1. Attacker identifies a gadget (e.g., MulDivGadget) that takes numBitsValue,
       numBitsNumerator, numBitsDenominator parameters.
    2. The gadget computes quotient = (value * numerator) / denominator but never
       range-checks that the quotient fits in the expected bit width.
    3. Attacker provides a witness where the quotient overflows the field capacity.
    4. The resulting fee/amount calculation wraps around, producing an incorrect
       (attacker-favorable) value.
    5. The proof verifies successfully because no constraint was violated.
  invariante: >
    For every arithmetic gadget: all intermediate and output values are
    range-constrained to their declared bit widths. Formally:
    assert(numBitsValue + numBitsNumerator <= NUM_BITS_FIELD_CAPACITY)
    AND quotient is range-checked to (numBitsValue + numBitsNumerator - numBitsDenominator) bits.
  que_mirar:
    - "Does the gadget accept bit-size parameters but skip range checks on outputs?"
    - "Are quotient/remainder values range-constrained after computation?"
    - "Is there an assert on bit capacity that can be bypassed by a malicious prover?"
    - "Are 'unchecked' variable names used (e.g., remainder_unchecked, quotient_unchecked)?"
    - "Does the gadget rely on caller to enforce range -- and does the caller actually do it?"
  como_se_arregla: >
    Add explicit range check constraints on all output values of arithmetic gadgets.
    For MulDiv: assert(numBitsValue + numBitsNumerator <= NUM_BITS_FIELD_CAPACITY)
    as a circuit constraint (not just a runtime assert). Range-check quotient to
    (numBitsValue + numBitsNumerator - numBitsDenominator) bits. Range-check
    remainder to numBitsDenominator bits.
  trampas:
    - "Runtime asserts (C++ assert, Rust debug_assert) are NOT circuit constraints -- prover can skip them"
    - "Comments saying 'range limit the remainder' may be aspirational, not enforced"
    - "The gadget may work correctly for honest provers but be exploitable by malicious ones"
    - "Nested gadget composition can hide missing range checks deep in call chains"
  incidentes:
    - nombre: "DeGate / Loopring V3 -- MulDivGadget"
      solodit_id: "17854"
      severidad: HIGH
      detalle: "MulDivGadget in SpotTradeCircuit and BatchOrderGadget missing range checks on quotient bit size, allowing fee overflow"
      auditor: "Trail of Bits"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "zkSync Era -- div opcode remainder"
      solodit_id: "30274"
      severidad: HIGH
      detalle: "Missing range constraint on subtraction_result_unchecked in div opcode allows forging remainder < divisor check, enabling manipulation of any smart contract using div"
      auditor: "Code4rena (ChainLight)"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [range-check, under-constrained, arithmetic, overflow, gadget, witness]
  relacionado_con: [zk-002, zk-004]

- id: zk-002
  pattern: unsafe-reduction-gates
  name: "Unsafe reduction gates allow forged operation results"
  causa_raiz: >
    When a circuit decomposes a composite lookup result into sub-results (e.g.,
    AND/OR/XOR from a single table lookup), the reduction gate constrains that
    composite = a + b*2^16 + c*2^32. However, if the individual components a, b, c
    are not independently range-checked to their expected bit widths (e.g., 8 bits
    for byte operations), the prover can supply values that satisfy the reduction
    equation but are not valid byte values. The sub-results are then wrapped in
    unsafe constructors (UInt8::from_variable_unchecked) without validation.
  como_funciona: >
    1. Circuit performs table lookup for composite AND/OR/XOR result.
    2. Reduction gate decomposes composite into three sub-results.
    3. Gate only enforces: composite = and + or*2^16 + xor*2^32.
    4. Attacker provides and_result and or_result as any value < 128 (not just 0-255 valid bytes).
    5. xor_result can overflow beyond 8 bits.
    6. Results are cast via unsafe UInt8::from_variable_unchecked, propagating invalid values.
    7. Attacker forges arbitrary AND/OR results for any bytewise operation.
  invariante: >
    Every sub-result from a reduction gate decomposition must be independently
    range-constrained to its declared type width. For UInt8: 0 <= value <= 255.
    Reduction equation alone is insufficient.
  que_mirar:
    - "ReductionGate usage -- are decomposed terms range-checked individually?"
    - "Any use of from_variable_unchecked or similar unsafe constructors after decomposition?"
    - "Table lookup results that are split into sub-components -- are all components constrained?"
    - "Composite encoding schemes (packing multiple values into one field element)"
  como_se_arregla: >
    Add independent range check constraints on each decomposed sub-result.
    For byte operations: constrain each result to [0, 255] via lookup or bit decomposition.
    Never use unsafe type constructors on unconstrained variables.
    Add range check gates after every reduction gate decomposition.
  trampas:
    - "The reduction equation is correct but insufficient -- it does not imply sub-result validity"
    - "unsafe/unchecked constructors in Rust ZK frameworks bypass type-level safety"
    - "Composite lookup tables give a false sense of security -- the decomposition is the weak point"
  incidentes:
    - nombre: "zkSync Era -- binop reduction gate"
      solodit_id: "30278"
      severidad: HIGH
      detalle: "Reduction gate in binop operation allows forging arbitrary AND/OR results and overflowing XOR results due to missing per-component range checks"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [reduction-gate, decomposition, unsafe-cast, binop, range-check, lookup-table]
  relacionado_con: [zk-001, zk-004]

- id: zk-003
  pattern: missing-subgroup-order-checks
  name: "Missing subgroup order checks on elliptic curve scalars"
  causa_raiz: >
    When a ZK circuit operates over an embedded curve (e.g., BabyJubJub inside
    BN254), the scalar field of the outer curve may be larger than the subgroup
    order of the inner curve's base point. If scalar inputs are not constrained
    to be less than the base point subgroup order, two different scalar values
    (s and s + base_point_order) produce identical curve points. This breaks
    uniqueness assumptions in encryption schemes like ElGamal, allowing an
    attacker to use equivalent scalars to bypass balance checks or forge transfers.
  como_funciona: >
    1. BabyJubJub base_point_order (2736030358...) < BN254 scalar_field (21888242871...).
    2. For any scalar s: s * BasePoint == (s + base_point_order) * BasePoint.
    3. ElGamal encryption of amount m produces same ciphertext as amount (m + base_point_order).
    4. Attacker encrypts a negative balance that wraps around modulo base_point_order.
    5. Homomorphic addition of encrypted balances produces incorrect totals.
    6. Attacker can mint tokens or transfer more than their balance.
  invariante: >
    All scalar values used in embedded curve operations must be constrained:
    scalar < base_point_order. This applies to private keys, plaintext messages,
    randomness values, and any input to scalar multiplication.
  que_mirar:
    - "Embedded curve usage (BabyJubJub in BN254, Ed25519 in BLS12-381, etc.)"
    - "Scalar multiplication inputs -- are they range-checked against subgroup order?"
    - "ElGamal or Pedersen commitment schemes -- are plaintexts bounded?"
    - "Homomorphic operations on encrypted values -- can overflow produce valid-looking results?"
    - "Circuit field size vs embedded curve subgroup order -- is there a gap?"
  como_se_arregla: >
    Add explicit constraint: scalar < base_point_order for every scalar input
    to embedded curve operations. Use range proof gadgets to enforce this bound.
    For ElGamal: constrain plaintext message to [0, base_point_order - 1].
    Consider using a curve where subgroup order equals or exceeds the circuit field.
  trampas:
    - "The gap between field sizes may seem small but is cryptographically exploitable"
    - "Honest provers naturally use small values, so tests may never trigger the overflow"
    - "Multiple embedded curves may have different subgroup orders -- check each one"
    - "The issue affects ALL operations using the embedded curve, not just specific gadgets"
  incidentes:
    - nombre: "Encrypted Token (ERC20) -- BabyJubJub scalar overflow"
      solodit_id: "56670"
      severidad: CRITICAL
      detalle: "Missing subgroup order check on BabyJubJub scalars in Gnark circuits for Mint/Transfer/Withdraw/Registration allows scalar wraparound, breaking ElGamal encryption uniqueness"
      auditor: "Ethereal (ETRP)"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [subgroup-order, elliptic-curve, babyjubjub, bn254, elgamal, scalar-multiplication, embedded-curve]
  relacionado_con: [zk-004, zk-005]

- id: zk-004
  pattern: incorrect-witness-validation
  name: "Witness hints not bound to circuit variables (under-constrained)"
  causa_raiz: >
    ZK frameworks (gnark, circom, etc.) separate hint computation from constraint
    enforcement. Hints compute witness values off-circuit, but the prover can
    supply arbitrary values for hint outputs. If the circuit does not add a
    recomposition constraint tying hint outputs back to the original variable
    (e.g., value == highLimb * 2^24 + lowLimb), the hint outputs float freely.
    Range checks on individual limbs are meaningless without binding them to the
    source variable, because the prover can pass limbs that satisfy bit checks
    but correspond to a completely different value.
  como_funciona: >
    1. Circuit calls SplitLimbsHint(value) to decompose value into highLimb and lowLimb.
    2. Hint function internally validates the split, but this is prover-side only.
    3. Circuit checks: highLimb fits in 7 bits, lowLimb fits in 24 bits.
    4. Circuit does NOT check: value == highLimb * 2^24 + lowLimb.
    5. Malicious prover provides arbitrary limbs satisfying bit checks but unrelated to value.
    6. The "range check" on value is completely ineffective -- any value passes.
    7. Applied broadly across all witness elements, this breaks the entire proof system.
  invariante: >
    For every hint-computed decomposition: a recomposition constraint must exist.
    value == sum(limb[i] * 2^(bitOffset[i])) for all limbs.
    Hint outputs without recomposition constraints are ALWAYS a critical bug.
  que_mirar:
    - "Hint functions that decompose values into limbs -- is there a recomposition constraint?"
    - "Pattern: SplitLimbs, decompose, toRadix followed by only per-limb range checks"
    - "Compare with correct implementations in same codebase (e.g., reduceWithMaxBits)"
    - "gnark: api.Add/api.Mul constraints after hint calls -- are they present?"
    - "circom: signal assignments from component outputs -- are they constrained to inputs?"
    - "How broadly is the broken helper used? (one gadget vs all witness validation)"
  como_se_arregla: >
    After every hint decomposition, add: api.AssertIsEqual(value, highLimb * 2^24 + lowLimb).
    Follow the pattern of correct implementations (e.g., reduceWithMaxBits in the same codebase).
    Audit ALL hint usage sites -- if one is wrong, others likely are too.
    Consider using api.ToBinary() which inherently constrains the decomposition.
  trampas:
    - "Hint functions contain validation logic that ONLY runs prover-side -- it is not a constraint"
    - "gnark hint errors (returning error) only affect honest provers, not malicious ones"
    - "A correct implementation may exist elsewhere in the codebase, masking the broken one"
    - "The bug may be in a low-level helper called thousands of times -- massive blast radius"
  incidentes:
    - nombre: "SP1 (Succinct) -- KoalaBearRangeCheck missing recomposition"
      solodit_id: "64925"
      severidad: HIGH
      detalle: "KoalaBearRangeCheck splits value into limbs via hint but never constrains value == highLimb * 2^24 + lowLimb, making all scalar range checks ineffective across the entire proof system"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [witness, hint, under-constrained, recomposition, gnark, limb-decomposition, soundness]
  relacionado_con: [zk-001, zk-002]

- id: zk-005
  pattern: insufficient-fiat-shamir-transcript
  name: "Incomplete Fiat-Shamir transcript allows challenge manipulation"
  causa_raiz: >
    The Fiat-Shamir heuristic makes interactive proofs non-interactive by
    deriving verifier challenges from a hash of the transcript. If the hash
    input does not include ALL values that the prover can influence AND the
    verifier uses, the prover gains degrees of freedom to manipulate the
    challenge. Common omissions: proof data, indices, chunk lengths, sample
    data, or protocol parameters. The prover can then search for inputs that
    produce favorable challenges, breaking soundness.
  como_funciona: >
    1. Verifier challenge randomFr is derived by hashing only commitments.
    2. Prover also controls: proof data, indices, chunk lengths, sample data.
    3. Prover searches for proof parameters that produce a favorable randomFr.
    4. With a favorable challenge, prover can forge batch verification or
       open commitments to wrong values.
    5. Verifier accepts the manipulated proof because the challenge looks valid.
  invariante: >
    Fiat-Shamir transcript must include ALL public inputs, ALL prover messages,
    and ALL protocol parameters. Specifically: commitments + proofs + indices +
    chunk lengths + sample data + any other verifier-consumed value.
    Alternatively, use cryptographic randomness (crypto/rand) instead of Fiat-Shamir.
  que_mirar:
    - "What is hashed to produce the verifier challenge? List ALL inputs."
    - "What does the verifier use that the prover can influence? Compare lists."
    - "Any prover-controlled value NOT in the hash? That is the vulnerability."
    - "Batch verification schemes -- are all batch elements in the transcript?"
    - "Multiple verification functions -- does each one hash sufficient inputs?"
    - "Deviations from reference specification -- are they security-justified?"
  como_se_arregla: >
    Include ALL prover-influenceable values in the Fiat-Shamir hash:
    commitments, proofs, indices, chunk lengths, sample data, and protocol parameters.
    Alternatively, use crypto/rand for challenge generation when interaction is possible.
    Follow the specification exactly; document and justify any deviations.
  trampas:
    - "Hashing 'enough' inputs feels secure but missing even one value can break soundness"
    - "Different verification functions may have different transcript requirements"
    - "Protocol modifications (e.g., squaring inputs, changing step counts) can silently break Fiat-Shamir"
    - "The attack requires a sophisticated prover but is fully exploitable in adversarial settings"
  incidentes:
    - nombre: "EigenDA -- BatchVerifyCommitEquivalence"
      solodit_id: "61704"
      severidad: HIGH
      detalle: "randomFr derived by hashing only commitments, not including proofs/indices/data that prover controls and verifier uses"
      auditor: "Sigma Prime"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "EigenDA -- UniversalVerify"
      solodit_id: "61705"
      severidad: HIGH
      detalle: "randomFr derived from only sample commitments, missing chunk length, sample data, proofs, and indices"
      auditor: "Sigma Prime"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Beam Network -- VDFVerifier"
      solodit_id: "11728"
      severidad: HIGH
      detalle: "Multiple undocumented deviations from VDF specification including modified Fiat-Shamir usage, input squaring instead of group membership testing, and altered termination condition"
      auditor: "Sigma Prime / Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [fiat-shamir, transcript, challenge, randomness, batch-verification, soundness, vdf]
  relacionado_con: [zk-003, zk-006]

- id: zk-006
  pattern: bus-argument-overflow
  name: "Field characteristic overflow in bus/permutation arguments"
  causa_raiz: >
    LogUp-style bus arguments connect chips/modules by tracking sent and received
    tuples via an accumulator: sum(m / (alpha + t)) = 0. This relies on the
    Schwartz-Zippel lemma, which requires that the number of bus sends with
    multiplicity 1 is less than the field characteristic p. If the framework
    does not enforce this bound, a malicious prover can send the same tuple
    p times (equivalent to 0 times in the field), effectively making any tuple
    "disappear" from the bus. This breaks inter-chip connectivity completely.
  como_funciona: >
    1. Framework uses BabyBear field (p = 2^31 - 2^27 + 1, roughly 2 billion).
    2. A chip sends tuple T to the bus with multiplicity 1.
    3. Malicious prover sends T a total of p times (multiplicity sums to 0 mod p).
    4. The bus argument sees zero net sends for T.
    5. The receiving chip can now claim any result for the operation T represents.
    6. Example: XOR lookup table receives wrong input/output pair, but bus balances.
    7. Any step of any computation can be forged.
  invariante: >
    The total number of bus sends (with multiplicity 1) across all chips in a
    segment must be strictly less than the field characteristic p.
    If using BabyBear: total_sends < 2^31 - 2^27 + 1.
  que_mirar:
    - "What field is the proof system over? (BabyBear, Goldilocks, BN254, etc.)"
    - "Is there a global limit on the number of bus interactions per segment?"
    - "Can the prover influence the number of rows/operations in a chip?"
    - "Are bus multiplicities constrained (e.g., to {0, 1} or {0, -1})?"
    - "LogUp accumulator -- does the soundness proof assume bounded interactions?"
  como_se_arregla: >
    Enforce that the number of bus sends per segment is bounded below field
    characteristic. Options: (a) limit segment size, (b) use extension field
    for accumulator, (c) add explicit row count constraints per chip.
    Document the bound in protocol specification.
  trampas:
    - "Small fields (BabyBear ~2B, Goldilocks ~2^64) make this attack practical"
    - "Large programs with many operations can naturally approach the field characteristic"
    - "The attack is invisible to honest execution -- only exploitable by malicious provers"
    - "Multiplicity constraints on receives may be loose (unconstrained negative values)"
  incidentes:
    - nombre: "OpenVM -- LogUp bus argument overflow"
      solodit_id: "53415"
      severidad: HIGH
      detalle: "BabyBear field characteristic allows malicious prover to send tuples p times, making them vanish from the bus argument and forging arbitrary computation results"
      auditor: "Cantina"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [bus-argument, logup, field-characteristic, overflow, babybear, permutation, soundness]
  relacionado_con: [zk-001, zk-005]

- id: zk-007
  pattern: under-constrained-vm-instruction-semantics
  name: "VM instruction AIR/chip missing read-write linkage constraints"
  causa_raiz: >
    In zkVM architectures (OpenVM, SP1, RISC Zero), each CPU instruction is
    proved by a dedicated AIR chip that constrains instruction semantics. If the
    chip's eval function only constrains opcode flags but omits the semantic
    constraint linking input values (reads) to output values (writes), a malicious
    prover can substitute arbitrary values for any instruction's result. Because
    VM instructions execute thousands of times per program, a single missing
    constraint in one instruction's AIR breaks soundness of the entire VM --
    the prover can forge the output of the recursive verifier itself.
  como_funciona: >
    1. Identify a VM instruction chip (e.g., LOADW, STOREW, ADD, MUL) in the AIR.
    2. The chip's eval function constrains opcode decoding flags correctly.
    3. However, it does NOT constrain that cols.data_write == cols.data_read
       (for LOAD/STORE) or that output == f(input1, input2) (for arithmetic).
    4. The adapter AIR also fails to enforce ctx.writes == f(ctx.reads).
    5. Malicious prover supplies arbitrary write values for that instruction.
    6. Since LOADW/STOREW execute hundreds of times in the recursive verifier,
       prover can change any intermediate value in proof verification.
    7. Prover falsely "verifies" an invalid inner proof, breaking recursion soundness.
  invariante: >
    For every VM instruction chip: the AIR must constrain output = f(inputs)
    where f is the instruction's semantic function. Specifically:
    - LOAD: data_write == memory[address] (the value read from memory)
    - STORE: memory[address] := data_read (the value written to memory)
    - ADD: output == input1 + input2
    - MUL: output == input1 * input2
    Every instruction in the ISA must have a semantic constraint, not just opcode flags.
  que_mirar:
    - "AIR eval functions for each instruction chip -- do they constrain MORE than just opcode flags?"
    - "Is there a constraint between data_read and data_write columns?"
    - "Adapter AIR: does it enforce a relationship between ctx.reads and ctx.writes?"
    - "How many times does this instruction execute? (blast radius assessment)"
    - "Is the instruction used in the recursive verifier program? (if yes, recursion is broken)"
    - "Compare with correctly constrained instructions in the same codebase"
  como_se_arregla: >
    Add explicit semantic constraints in every instruction chip's AIR eval:
    For LOADW: builder.assert_eq(cols.data_write, cols.data_read) or equivalent
    memory consistency check. For arithmetic: builder.assert_eq(output, op(in1, in2)).
    Audit ALL instruction chips systematically -- if one is missing, others likely are too.
    Add integration tests with a malicious witness that changes instruction outputs.
  trampas:
    - "The chip compiles and 'works' for honest provers -- the bug is only visible to malicious provers"
    - "Opcode flag constraints give the illusion of completeness but are only half the job"
    - "Adapter AIR and Core AIR share responsibility -- the gap may be between them"
    - "A single broken instruction in the recursive verifier ISA breaks the entire proof stack"
  incidentes:
    - nombre: "OpenVM -- LOADW/STOREW missing semantic constraints"
      solodit_id: "53430"
      severidad: HIGH
      detalle: "NativeLoadStoreCoreAir::eval and NativeLoadStoreAdapterAir do not constrain data_read vs data_write, letting malicious prover write arbitrary values for any LOADW/STOREW in the recursion VM"
      auditor: "Cantina"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [zkvm, air, instruction, under-constrained, load-store, recursion, soundness, openvm]
  relacionado_con: [zk-004, zk-008]

- id: zk-008
  pattern: untrusted-public-inputs-recursive-verification
  name: "Recursive proof verifier does not validate trust-critical public inputs"
  causa_raiz: >
    In recursive proving systems (SP1, Halo2, Nova), the final SNARK verifier
    (PLONK or Groth16) checks cryptographic proof validity but may not verify
    that certain public inputs match trusted reference values. The most dangerous
    omission is the recursion verification key (vk) root: if the verifier does
    not check that vk_root equals a trusted allowlist, a malicious prover can
    construct a recursion tree with unauthorized verification keys that omit
    critical constraints, then wrap it in a valid final proof. Similarly, if
    on-chain contracts skip ZK proof verification entirely (setting is_verified
    = true unconditionally for ZK-authenticated users), the entire ZK security
    model collapses.
  como_funciona: >
    1. SP1 final verifier (verify_plonk_bn254 / verify_groth16_bn254) parses
       vk_root from proof.public_inputs.
    2. It verifies the PLONK/Groth16 proof cryptographically (valid).
    3. It re-checks vkey_hash and public_values_hash (valid).
    4. It does NOT check: vk_root == self.recursion_prover.recursion_vk_root.
    5. Malicious prover builds a recursion Merkle tree with modified vk entries
       that skip constraint checks in inner recursion circuits.
    6. Wraps the weak inner proofs in a valid PLONK/Groth16 final proof.
    7. Verifier accepts because all checked fields are consistent.
    8. Variant: on-chain contract sets is_verified=true for scheme==ZK_WALLET
       without any proof check, trusting off-chain infrastructure entirely.
  invariante: >
    Every trust-critical public input in a recursive proof must be validated
    against a known-good reference value:
    - vk_root == trusted_recursion_vk_root (from prover config or on-chain registry)
    - proof_nonce is consistent across all shards
    - On-chain: ZK proofs MUST be verified on-chain or have cryptographic attestation
      of off-chain verification (not just a flag).
  que_mirar:
    - "Final verifier functions (verify_plonk, verify_groth16): which public inputs are re-validated?"
    - "Is vk_root compared against a trusted reference? Or just parsed and ignored?"
    - "Are there public inputs that the verifier consumes but does not validate?"
    - "On-chain contracts: does scheme==ZK skip actual proof verification?"
    - "Shard consistency: is proof_nonce identical across all shards? Can deferred accumulators clobber it?"
    - "Which fields are covered by the public_values_hash, and which are separate?"
  como_se_arregla: >
    Add explicit equality checks in the final verifier:
    assert(parsed_vk_root == self.trusted_recursion_vk_root).
    For on-chain contracts: verify ZK proofs on-chain using native verification
    precompiles or verified computation contracts. Never set is_verified=true
    without cryptographic proof. For shard nonces: propagate nonce from the real
    execution record to deferred accumulators before merging.
  trampas:
    - "The cryptographic proof IS valid -- the issue is WHAT it proves, not WHETHER it proves"
    - "public_values_hash may cover some inputs but not all (vk_root may be outside the hash)"
    - "Off-chain verification 'trust' is not a security property -- any off-chain bug becomes on-chain exploitable"
    - "Deferred accumulator default values (zeroed nonce) silently overwrite real values during shard packing"
  incidentes:
    - nombre: "SP1 (Succinct) -- PLONK/Groth16 accept untrusted recursion vk root"
      solodit_id: "64926"
      severidad: MEDIUM
      detalle: "verify_plonk_bn254 and verify_groth16_bn254 parse vk_root from public inputs but never check it against the trusted recursion_vk_root, allowing proofs built with unauthorized recursion circuits"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "SP1 (Succinct) -- Proof nonce clobbered by deferred accumulator"
      solodit_id: "64931"
      severidad: MEDIUM
      detalle: "Deferred accumulator initialized with default public_values overwrites last shard's proof_nonce with zeros during split, causing cross-shard nonce mismatch"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "On-chain ZK proof verification skipped (Move DEX)"
      solodit_id: "64744"
      severidad: HIGH
      detalle: "verify_signature sets is_verified=true for SIGNED_USING_ZK_WALLET without validating any zkLogin proof on-chain, trusting off-chain infrastructure entirely"
      auditor: "Zellic"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [recursive-verification, public-inputs, vk-root, trust-boundary, on-chain-verification, zklogin, soundness]
  relacionado_con: [zk-005, zk-007]

- id: zk-009
  pattern: verifier-dos-malformed-inputs
  name: "ZK verifier panics or stalls on malformed/unbounded prover inputs"
  causa_raiz: >
    ZK proof verifiers (both off-chain host verifiers and on-chain contracts)
    accept untrusted prover-supplied data: proof bytes, public inputs, and
    configuration parameters. If the verifier code uses unwrap(), unchecked
    array indexing, or unbounded parsing on these inputs, a malicious submitter
    can craft inputs that cause panics, out-of-bounds access, or resource
    exhaustion. This is especially dangerous for decentralized verifier networks
    where any participant can submit proofs, and for on-chain verifiers where
    gas waste from failed-but-expensive verification is borne by the operator.
  como_funciona: >
    1. Attacker submits a proof with truncated public_values (fewer elements
       than expected). Verifier indexes past the end and panics.
    2. Attacker submits a proof with malformed verifying key bytes. Verifier
       calls .unwrap() on deserialization and panics.
    3. Attacker submits public inputs as arbitrarily large decimal strings.
       Verifier parses them with big.Int, consuming unbounded memory/CPU.
    4. Attacker sets a configuration threshold to zero. Verifier calls
       chunks_exact(0) and panics on division by zero.
    5. In on-chain verifiers: each failed step still executes remaining steps
       instead of short-circuiting, wasting gas for the zkEVM operator.
  invariante: >
    Every verifier entry point must handle ALL possible inputs without panicking:
    - All deserializations return Result, never unwrap()
    - All array accesses are bounds-checked
    - All numeric inputs are bounded (reject oversized strings, zero divisors)
    - On-chain: short-circuit on first failure (do not continue wasting gas)
  que_mirar:
    - "Verifier functions: do they unwrap() on proof/vk/public-input deserialization?"
    - "Array indexing on public_values: is length checked before access?"
    - "Numeric parsing of public inputs: is input size bounded?"
    - "Configuration values (thresholds, chunk sizes): are zeros rejected?"
    - "On-chain verifier: does it short-circuit on step failure or continue executing?"
    - "What happens if proof.public_values.len() < expected?"
  como_se_arregla: >
    1. Replace all .unwrap() in verifier paths with proper error returns.
    2. Validate public_values.len() >= expected before any indexing.
    3. Bound decimal input string length before parsing (e.g., max 78 chars for BN254 field elements).
    4. Reject zero-valued configuration parameters at initialization.
    5. On-chain: add early return when any verification step fails (if !state_success) return false.
    6. Add fuzz tests that submit random/truncated/oversized inputs to verifier APIs.
  trampas:
    - "Rust's panic-on-unwrap is a silent DoS vector in verifier code"
    - "Honest provers always send well-formed inputs, so these bugs survive normal testing"
    - "On-chain gas waste from non-short-circuiting is a griefing vector, not just inefficiency"
    - "Multiple independent panic sites compound: attacker picks the cheapest one to trigger"
  incidentes:
    - nombre: "SP1 (Succinct) -- Truncated public_values panic"
      solodit_id: "64927"
      severidad: MEDIUM
      detalle: "Malformed proof with short public_values causes out-of-bounds panic in SP1Prover::verify and shard verifier"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "SP1 (Succinct) -- Zero config values crash prover"
      solodit_id: "64928"
      severidad: MEDIUM
      detalle: "Zero-valued SplitOpts thresholds cause chunks_exact(0) panic in ExecutionRecord::split, crashing or stalling prover indefinitely"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "SP1 (Succinct) -- PlonkVerifier panics on malformed inputs"
      solodit_id: "64929"
      severidad: MEDIUM
      detalle: "PlonkVerifier::verify_gnark_proof unwraps fallible decoding of vk, proof, and public inputs, enabling DoS via malformed submissions"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "SP1 (Succinct) -- Unbounded decimal public inputs DoS"
      solodit_id: "64932"
      severidad: MEDIUM
      detalle: "VerifyPlonk and VerifyGroth16 accept arbitrarily large decimal strings for public inputs, enabling memory/CPU exhaustion via oversized big.Int parsing"
      auditor: "Code4rena"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "zkEVM Verifier -- Gas waste on failed steps"
      solodit_id: "26830"
      severidad: MEDIUM
      detalle: "On-chain verifier continues executing all remaining steps after a failure instead of short-circuiting, wasting gas for the zkEVM operator"
      auditor: "Halborn"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [verifier, dos, panic, unwrap, malformed-input, gas-waste, short-circuit, input-validation]
  relacionado_con: [zk-008]

- id: zk-010
  pattern: zk-fiat-shamir-missing-observations
  name: "Recursive verifier omits polynomial evaluations from Fiat-Shamir transcript — proof forgery"
  causa_raiz: "The recursive verifier's FRI implementation observes extension field elements from the challenger but does not first observe each of the round polynomial evaluations into the transcript. This incorrect Fiat-Shamir ordering allows a malicious prover to manipulate opening arguments to cancel out, enabling complete proof forgery."
  como_funciona: |
    1. Recursive verifier processes FRI rounds.
    2. For each round, it should observe polynomial evaluations into challenger THEN sample challenge.
    3. Instead, it immediately observes the extension field element without per-round observations.
    4. Prover controls the opening values without them binding the challenge.
    5. Prover crafts openings that cancel out during batch check.
    6. Invalid execution proof accepted by the recursive verifier.
    7. Forged proof propagates through recursion pipeline.
  invariante: |
    // All polynomial evaluations must be observed into Fiat-Shamir transcript
    // before sampling the next challenge
    // for each round: observe(evaluations) THEN challenge = challenger.sample()
  que_mirar:
    - "Does the recursive verifier observe all round evaluations before sampling challenges?"
    - "Compare Fiat-Shamir observation order against reference implementation (e.g., SP1)"
    - "rg 'observe|challenger.*sample' — check ordering in FRI verification"
    - "Are there known CVEs in the reference codebase (e.g., GHSA-c873-wfhp-wx5m)?"
  como_se_arregla: "Observe each polynomial evaluation into the challenger transcript before sampling the next round's challenge. Follow the exact observation ordering from the reference implementation."
  trampas:
    - "Requires deep understanding of the PCS to verify — easy to miss in review"
    - "May only affect recursive verifier, not the native prover/verifier"
  incidentes:
    - "Brevis Pico ZKVM — polynomial evaluations not observed by recursive verifier, soundness completely bypassed (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, fiat-shamir, recursive-verifier, FRI, proof-forgery, soundness]

- id: zk-011
  pattern: zk-prover-controlled-quotient-domain
  name: "Prover controls quotient domain size — FRI PCS soundness broken"
  causa_raiz: "The verifier reads log_quotient_degrees from prover-supplied data instead of deriving it from the committed trace sizes. A malicious prover sets quotient domains to size 1, making FRI colinearity checks trivially satisfiable, completely bypassing the polynomial commitment scheme's soundness guarantees."
  como_funciona: |
    1. Honest verifier should compute quotient_degree from chip trace sizes.
    2. Verifier instead reads quotient_degree from prover-supplied proof metadata.
    3. Prover sets log_quotient_degrees to 0 for all chips.
    4. Quotient domain has size 1 — queries yield the same point.
    5. FRI colinearity check is trivially satisfied.
    6. Prover provides arbitrary polynomial evaluations.
    7. Invalid statements accepted by the verifier.
  invariante: |
    // Quotient domain size must be derived from trace length, not prover input
    // quotient_degree = trace_length * constraint_degree / domain_size
    assert(quotient_degree == derived_from_trace)
  que_mirar:
    - "Where does the verifier get quotient_degree? From proof metadata or trace?"
    - "Is chip_ordering prover-controlled or derived from preprocessed data?"
    - "Compare against reference implementation for domain size derivation"
    - "rg 'quotient_degree|log_quotient' — is it read from proof or computed?"
  como_se_arregla: "Derive quotient degrees from the committed trace sizes and chip constraint degrees. Never trust prover-supplied domain parameters. Validate all domain sizes against preprocessed circuit parameters."
  trampas:
    - "Only affects verifier implementations that read from proof metadata"
    - "Reference implementations (SP1) correctly derive from trace — diff carefully"
  incidentes:
    - "Brevis Pico ZKVM — quotient domain entirely prover-controlled, FRI soundness broken (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, quotient-domain, prover-controlled, FRI, soundness, domain-size]

- id: zk-012
  pattern: zk-global-cumulative-sum-unchecked
  name: "Global cumulative sum not checked to be zero on completion — lookup argument unsound"
  causa_raiz: "The global_cumulative_sum tracks the running sum of global lookup sends and receives across all shards. When all shards are combined (flag_complete = true), this sum must equal zero to prove all lookups are satisfied. The combine circuit computes and propagates the sum but never asserts it equals zero when complete."
  como_funciona: |
    1. Each shard contributes to global_cumulative_sum via lookup arguments.
    2. Shards combined in the combine recursion circuit.
    3. When flag_complete is true, deferred_proofs_digest is checked.
    4. global_cumulative_sum is NOT checked to equal zero.
    5. Prover can leave unresolved lookup arguments.
    6. Proof with unbalanced global lookups accepted as valid.
    7. Execution correctness not guaranteed.
  invariante: |
    // When all shards are combined, global cumulative sum must be zero
    // if flag_complete: assert(global_cumulative_sum == 0)
  que_mirar:
    - "rg 'global_cumulative_sum|cumulative_sum' — is it checked against zero?"
    - "Is there an assert when flag_complete is true?"
    - "Does assert_deferred_digest_complete also check cumulative_sum?"
    - "Compare combine circuit completeness checks against reference implementation"
  como_se_arregla: "Add an assertion in the combine circuit that when flag_complete is true, each element of global_cumulative_sum equals zero. This ensures all cross-shard lookup arguments are balanced."
  trampas:
    - "Requires understanding of the lookup argument protocol to verify"
    - "The sum is computed correctly — it's just not asserted"
  incidentes:
    - "Brevis Pico ZKVM — global_cumulative_sum not enforced zero when combine is complete, lookup argument unsound (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, cumulative-sum, lookup-argument, combine, completeness, soundness]

- id: zk-013
  pattern: zk-chip-ordering-prover-controlled
  name: "Prover-controlled chip ordering allows selective chip omission"
  causa_raiz: "The verifier uses a prover-supplied chip_ordering to determine which chips to verify. Instead of checking against preprocessed/expected chips, the verifier trusts the prover's ordering. A malicious prover includes only favorable chips and omits those with failing constraints."
  como_funciona: |
    1. verify_shard creates chip list from prover-supplied chip_ordering.
    2. chip_ordering should list all preprocessed chips.
    3. Prover omits chips with violated constraints from chip_ordering.
    4. Verifier only checks the chips the prover included.
    5. Missing chip constraints are never verified.
    6. Invalid execution accepted as valid proof.
  invariante: |
    // chip_ordering must exactly match the preprocessed chip set
    // assert(chip_ordering.keys() == preprocessed_chips.keys())
  que_mirar:
    - "Where does the verifier get the chip list? From proof or preprocessed data?"
    - "Is chip_ordering validated against a known set of expected chips?"
    - "rg 'chip_ordering|sorted_chips' — is it prover-supplied?"
    - "Does the verifier check that ALL expected chips are present?"
  como_se_arregla: "Validate chip_ordering against the preprocessed chip set. Require that every expected chip appears in the ordering. Reject proofs with missing or extra chips."
  trampas:
    - "Only relevant to zkVM implementations with configurable chip sets"
    - "If chip set is fixed at compile time, ordering is predetermined"
  incidentes:
    - "Brevis Pico ZKVM — chip ordering prover-controlled, allows selective opening of only favorable chips (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, chip-ordering, prover-controlled, selective-omission, soundness, verification]

- id: zk-014
  pattern: zk-compress-bypass-completeness
  name: "Compress circuit accepts single chunk as complete execution — completeness bypass"
  causa_raiz: "The recursion pipeline expects: convert -> combine (checks completeness) -> compress -> embed. However, the compress circuit also accepts converted proofs directly. A single chunk proof converted and then compressed bypasses the combine step's completeness checks, producing a 'complete' proof from a partial execution."
  como_funciona: |
    1. Normal pipeline: multiple chunks -> convert each -> combine (checks all shards present) -> compress.
    2. Compress circuit whitelists both combine and convert output vks.
    3. Prover converts a single chunk (not all chunks).
    4. Feeds single converted proof directly to compress (skipping combine).
    5. Compress does not re-check completeness — trusts input.
    6. Compressed proof appears complete but represents partial execution.
    7. On-chain verifier accepts the proof.
  invariante: |
    // Compress must only accept combine output, never raw convert output
    // assert(input_vk in allowed_combine_vks && input_vk not_in convert_vks)
  que_mirar:
    - "Which VKs does the compress circuit accept as valid inputs?"
    - "Can convert output be fed directly to compress?"
    - "Does compress re-verify completeness conditions?"
    - "Is the VK whitelist in the Merkle tree properly partitioned?"
  como_se_arregla: "Restrict compress circuit to only accept combine output VKs. Or re-check completeness conditions (contains_execution_chunk, all chunks present) in the compress circuit. Partition the VK Merkle tree so compress cannot accept convert-stage proofs."
  trampas:
    - "Requires understanding the full recursion pipeline to identify"
    - "If VK whitelisting is strict, this path may not exist"
  incidentes:
    - "Brevis Pico ZKVM — compress accepts convert output directly, bypassing combine completeness checks (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, compress, completeness, recursion-pipeline, bypass, vk-whitelist]

- id: zk-015
  pattern: zk-weak-fiat-shamir-challenge
  name: "Fiat-Shamir challenge hashes insufficient inputs — verifier accepts invalid proofs"
  causa_raiz: "When generating random challenges via Fiat-Shamir heuristic, the hash input includes only a subset of prover-influenceable data (e.g., only commitments but not proofs, indices, cells, or chunk length). A malicious prover manipulates the excluded inputs to produce proofs that pass batch verification but fail individual verification."
  como_funciona: |
    1. Batch verifier generates random challenge: hash(commitments).
    2. Challenge should bind: commitments, proofs, indices, cells, chunk_length.
    3. Prover manipulates proofs/indices (not in hash) to satisfy batch equation.
    4. Batch verification passes — random linear combination holds.
    5. Individual proof verification would fail for some proofs.
    6. Verifier accepts data column sidecars with arbitrary KZG commitments.
    7. Node accepts and rebroadcasts invalid data.
  invariante: |
    // Fiat-Shamir challenge must include ALL prover-influenceable inputs
    // challenge = hash(commitments || proofs || indices || cells || chunk_length)
  que_mirar:
    - "What inputs are included in the Fiat-Shamir hash for batch verification?"
    - "Are proofs, indices, and data cells included in the challenge?"
    - "Compare challenge generation against the specification or reference"
    - "rg 'compute.*challenge|hash.*commitments' — check inputs"
  como_se_arregla: "Include all prover-influenceable data in the Fiat-Shamir hash: commitments, proofs, cell indices, cells, chunk length, and any other prover-controlled parameters. Or use cryptographic randomness instead of Fiat-Shamir."
  trampas:
    - "If all relevant data is included, this pattern does not apply"
    - "Some optimizations intentionally exclude certain inputs — verify with spec"
  incidentes:
    - "EigenDA vCISO — UniversalVerify hashes only commitments, not proofs/indices/data; prover can forge batch proofs (High)"
    - "EigenDA vCISO — BatchVerifyCommitEquivalence hashes only commitments; insufficient for Fiat-Shamir security (High)"
    - "c-kzg-4844 (Fusaka Upgrade) — verify_cell_kzg_proof_batch passes deduplicated count but original array, challenge doesn't bind all commitments (High)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, fiat-shamir, challenge, batch-verification, KZG, soundness]

- id: zk-016
  pattern: zk-range-checker-zero-knowledge-violation
  name: "Range checker uses Pedersen commitments without blinding — zero-knowledge violated"
  causa_raiz: "The gnark library's RangeChecker.Check() internally uses Pedersen commitments without blinding factors (CVE-2024-45040). When used in Groth16 circuits, the commitment is included in the proof. For low-entropy private witnesses, a verifier can brute-force the commitment to recover private values, breaking the zero-knowledge property."
  como_funciona: |
    1. Circuit uses RangeChecker.Check() for field element range validation.
    2. gnark library generates Pedersen commitment of the checked value.
    3. Commitment has no blinding factor — same value always produces same commitment.
    4. Commitment embedded in the Groth16 proof (publicly visible).
    5. For small values (booleans, small integers), verifier brute-forces commitment.
    6. Verifier recovers the private witness value from the commitment.
    7. Zero-knowledge property broken for range-checked values.
  invariante: |
    // Range checking must not leak private witness information
    // Use api.ToBinary for Groth16, or patched gnark with blinding
  que_mirar:
    - "rg 'RangeChecker\\.Check|rangecheck' — used in Groth16 circuits?"
    - "Which version of gnark is used? Is CVE-2024-45040 patched?"
    - "Are range-checked values low-entropy (booleans, small fields)?"
    - "Is GROTH16 env flag set or default (unset = vulnerable path)?"
  como_se_arregla: "Update gnark to a version that patches CVE-2024-45040 (adds blinding to Pedersen commitments). Or use api.ToBinary() instead of RangeChecker.Check() for Groth16 circuits. Set GROTH16=1 environment variable to use the safe code path."
  trampas:
    - "Only affects Groth16 proving system, not PLONK or other backends"
    - "High-entropy witnesses are computationally infeasible to brute-force"
  incidentes:
    - "Brevis Pico ZKVM — RangeChecker.Check in BabyBear/KoalaBear chips uses unpatched gnark with CVE-2024-45040, verifier recovers private witnesses (Medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zk, range-checker, zero-knowledge, Groth16, Pedersen, CVE, gnark]

- id: zk-017
  pattern: zk-overconstraint-valid-proof-rejection
  name: "Circuito ZK overconstrainado rechaza pruebas válidas (DoS / fondos bloqueados)"
  causa_raiz: >
    Un circuito ZK puede ser soundly correcto (no acepta pruebas falsas) pero
    overconstrainedly restrictivo: rechaza pruebas válidas que representan statements
    correctos. Ocurre cuando el sistema de constraints es demasiado específico para
    transiciones de estado legítimas, o cuando valores intermedios están over-specified.
    El prover no puede construir un witness válido para un statement verdadero porque los
    constraints lo prohíben. Resultado: DoS permanente, fondos bloqueados, cuentas
    congeladas. DIFERENCIA CRÍTICA con zk-001 (missing constraints que aceptan pruebas
    inválidas) — aquí se PREVIENEN pruebas válidas.
  como_funciona: |
    1. Circuito define: path_selector IN {0, 1, 2, 3}
    2. Por transition rules underspecificadas, path válido 3 lleva a estado intermedio que
       viola constraint: assert(balance_after >= balance_before) — pero un burn legítimo
       reduce temporalmente el balance mid-proof
    3. Prover no puede construir witness satisfaciendo TODOS los constraints
    4. Transacción del usuario revierte: "proof rejected" aunque el statement sea verdadero
    5. Usuario no puede unstake, withdraw, ni recuperar fondos (bloqueo permanente)
    6. O: Range constraint sin upper_bound: assert(value >= 0) pero sin assert(value <= MAX)
       causa overflow del witness que rechaza valores correctos
    7. O: Gadget de signature requiere formato r,s exacto pero firmante usa high-S — firma
       válida rechazada permanentemente
  invariante: >
    Para todo statement válido en la spec del protocolo, el circuito DEBE
    aceptar al menos un witness correcto. Si canProve(validStatement) == false,
    el circuito está overconstrainado para ese statement.
  que_mirar:
    - "¿Los range checks tienen solo lower bound? Buscar assertions sin upper limit."
    - "¿Las constraint equations permiten solo UN path de estado intermedio específico?"
    - "Si un witness tiene múltiples representaciones válidas (e.g., firmas high-S/low-S), ¿acepta el circuito todas?"
    - "Cairo/Noir: ¿se usan felt values con constraints innecesariamente estrechos?"
    - "Transiciones: ¿puede una acción legítima (burn, vote, unstake) encontrar un witness path válido?"
    - "Lookup tables: ¿todos los inputs válidos tienen entradas en la tabla o faltan algunos?"
    - "Recursión: ¿los constraints de verificación recursiva bloquean accidentalmente sub-proofs válidas?"
  como_se_arregla: >
    Para cada transición de estado, enumerar TODOS los paths válidos (no solo happy path).
    Para cada transición, construir un test witness y verificar que el circuito lo acepta.
    Range constraints: usar BOTH lower y upper bounds, pero verificar que el dominio válido
    no sea estrechado accidentalmente. Signature gadgets: aceptar high-S y low-S.
    Witness decomposition: permitir flexibilidad en valores intermedios.
    Documentar en comentarios del circuito: qué paths statement→witness están soportados.
  trampas:
    - "Una constraint demasiado laxa (zk-001) falla en tests explícitos — overconstraint falla silenciosamente para el usuario en edge cases"
    - "NO es lo mismo que missing constraint (zk-001) que acepta pruebas falsas — este patrón PREVIENE pruebas verdaderas"
    - "Puede solo aparecer en edge cases (zero balance withdraw, valores máximos) — difícil de detectar en testnet"
    - "A veces el 'rechazo' no revierte el proof sino que produce un output incorrecto — más difícil de detectar"
  incidentes:
    - "Starknet bridge withdrawal path: valor > threshold rechazado por constraint too strict — withdrawals >1000 USDC bloqueados (HIGH, hipotético basado en análisis de constraints)"
    - "SP1 recursive prover: sub-proof format aceptado standalone pero rechazado en aggregated proof (CRITICAL potencial)"
    - "Circom circuits con componentes compartidos: intermediate signal asignado una vez pero reutilizado en dos templates con constraints incompatibles, bloqueando uno de los paths (HIGH)"
  severidad: high
  confianza: media
  verificado: false
  fuente: "ZK circuit audit best practices, overconstraint threat model 2026"
  tags: [zk-circuits, soundness, completeness, overconstraint, valid-proof-rejection, DoS, fund-lock, cairo, noir, circom, sp1]
  relacionado_con: [zk-001, zk-002, zk-004]
```

---

## 2. Invariantes Clave

Derived from 9 Solodit findings across ZK circuit audits.

### Range check completeness (zk-001, zk-002)

```
// CRITICAL: #1 ZK circuit bug pattern
// Every arithmetic gadget output must be range-constrained
For gadget with declared bit widths:
  assert(output fits in declared_bits)
  assert(intermediate values fit in field capacity)
  assert(decomposed sub-results are individually range-checked)
```

Historical hit rate: 3/9 findings (33%). Affects all ZK frameworks (libsnark, Boojum, gnark, Plonky2).

### Witness-constraint binding (zk-004)

```
// CRITICAL: Hints are NOT constraints
// Every hint decomposition must have a recomposition constraint
After hint: (highLimb, lowLimb) = SplitLimbs(value)
  assert(value == highLimb * 2^24 + lowLimb)  // THIS IS THE CONSTRAINT
  assert(highLimb fits in 7 bits)               // necessary but NOT sufficient alone
  assert(lowLimb fits in 24 bits)               // necessary but NOT sufficient alone
```

Historical hit rate: 1/9 findings but MASSIVE blast radius (affects all witness validation).

### Fiat-Shamir transcript completeness (zk-005)

```
// HIGH: Incomplete transcripts break non-interactive soundness
transcript = hash(
  ALL commitments +
  ALL proofs +
  ALL indices +
  ALL protocol parameters +
  ALL prover-influenceable data
)
// Missing ANY element = prover can manipulate challenge
```

Historical hit rate: 3/9 findings (33%). Affects batch verification and VDF schemes.

### Field characteristic bounds (zk-006)

```
// HIGH: Bus argument soundness requires bounded interactions
assert(total_bus_sends < field_characteristic)
// For BabyBear: total_bus_sends < 2^31 - 2^27 + 1
// For Goldilocks: total_bus_sends < 2^64 - 2^32 + 1
```

Historical hit rate: 1/9 findings but breaks entire proof system if violated.

### Subgroup order constraints (zk-003)

```
// CRITICAL: Embedded curve scalars must respect subgroup order
// BabyJubJub in BN254 example:
assert(scalar < base_point_order)
// where base_point_order = 2736030358979909402780800718157159386076813972158567259200215660948447373041
// and BN254_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Gap allows scalar wraparound: s * G == (s + order) * G
```

Historical hit rate: 1/9 findings. Affects all protocols using embedded curves with ElGamal/Pedersen.

---

## 3. Checklist Rapido

ZK circuit audit -- run through for every target:

```
RANGE CHECKS & CONSTRAINTS
[ ] Every arithmetic gadget: are outputs range-constrained to declared bit widths?
[ ] Every decomposition (reduction gate, split): are sub-results individually range-checked?
[ ] Any use of "unchecked" / "unsafe" constructors on decomposed values?
[ ] Runtime asserts vs circuit constraints -- are range checks actually in the constraint system?
[ ] Intermediate values: can they overflow field capacity?

WITNESS VALIDATION
[ ] Every hint/advice decomposition: is there a recomposition constraint?
[ ] Pattern: value == sum(limb[i] * 2^offset[i]) after every split
[ ] Compare broken helpers against correct implementations in same codebase
[ ] Hint error handling: does it only run prover-side? (not a constraint)
[ ] How broadly is each witness helper used? (blast radius assessment)

FIAT-SHAMIR TRANSCRIPT
[ ] What values are hashed for each verifier challenge?
[ ] What prover-controlled values does the verifier consume?
[ ] Are ALL prover-influenceable values in the transcript?
[ ] Batch verification: are all batch elements included?
[ ] Any deviations from reference specification? Security justification documented?

ELLIPTIC CURVE / GROUP THEORY
[ ] Embedded curve scalars: constrained to < subgroup order?
[ ] Field size gap between outer circuit and inner curve?
[ ] Homomorphic operations: can scalar wraparound produce valid-looking results?
[ ] Point validation: are curve points checked for subgroup membership?

BUS / PERMUTATION ARGUMENTS
[ ] What field is used? What is the characteristic?
[ ] Total bus interactions bounded below field characteristic?
[ ] Multiplicities constrained (send: {0,1}, receive: {0,-1})?
[ ] Can prover control number of rows/operations per chip?

CIRCUIT SOUNDNESS (GENERAL)
[ ] Every constraint needed for soundness is explicit (not implicit via honest prover behavior)
[ ] Specification deviations documented with security justification
[ ] Extension field elements properly constrained (not just base field)
[ ] Public inputs properly committed and verified
[ ] Recursion boundaries: are inner proof constraints complete?
```

### Audit patterns for fast triage

```bash
# Under-constrained variables (Rust ZK frameworks)
grep -rn "unchecked\|from_variable_unchecked\|unsafe" src/ --include="*.rs"

# Hint functions without recomposition (gnark)
grep -rn "Hint\|hint\|NewHint\|SplitLimbs" src/ --include="*.go"

# Missing range checks
grep -rn "range_check\|RangeCheck\|num_bits\|numBits" src/

# Fiat-Shamir transcript construction
grep -rn "transcript\|challenge\|hash.*commit\|Fiat.Shamir\|randomFr" src/

# Reduction gates and decomposition
grep -rn "ReductionGate\|decompos\|split.*limb" src/

# Embedded curve operations
grep -rn "BabyJubJub\|EdwardsPoint\|scalar_mul\|ScalarMul\|base_point" src/

# Bus/permutation arguments
grep -rn "bus_send\|bus_receive\|LogUp\|multiplicity\|accumulator" src/

# Field characteristic references
grep -rn "BabyBear\|Goldilocks\|BN254\|field_characteristic\|MODULUS" src/
```
