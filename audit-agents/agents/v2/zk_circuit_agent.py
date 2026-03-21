"""
ZK Circuit Vulnerability Hunting Agent System
=============================================

Specialized agent system for finding soundness bugs in ZK circuits and ZK-rollups.
Targets the $250K-$1.6M bounty tier where only 50-150 hunters operate globally.

Based on proven methodology (SP1 REMUW missing constraint term finding) and
systematic analysis of 141+ documented ZK vulnerabilities.

Key insight: 96% of documented ZK bugs are under-constrained circuit bugs.
"""

import os
import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# =============================================================================
# SECTION 1: ZK VULNERABILITY TAXONOMY
# =============================================================================

class ZKVulnClass(Enum):
    """Complete taxonomy of ZK circuit vulnerability classes."""

    # --- Under-Constrained (96% of all ZK bugs) ---
    MISSING_CONSTRAINT = "missing_constraint"              # Constraint term entirely absent
    INCOMPLETE_CONSTRAINT = "incomplete_constraint"        # Constraint exists but doesn't cover all cases
    MISSING_RANGE_CHECK = "missing_range_check"            # No bit-length enforcement on witness values
    UNCONSTRAINED_SIGNAL = "unconstrained_signal"          # Signal declared but never constrained
    UNCONSTRAINED_PUBLIC_INPUT = "unconstrained_public_input"  # Public input not used in constraints
    NONDETERMINISTIC_WITNESS = "nondeterministic_witness"  # Multiple valid witnesses for same statement
    REGISTER_CONFUSION = "register_confusion"              # zkVM: register values interchangeable (SP1 pattern)

    # --- Arithmetic Issues ---
    FIELD_OVERFLOW = "field_overflow"                       # Value wraps around field modulus
    FIELD_UNDERFLOW = "field_underflow"                     # Subtraction wraps to large field element
    MODULAR_REDUCTION = "modular_reduction"                 # Unexpected mod p behavior
    DIVISION_BY_ZERO = "division_by_zero"                   # Missing zero-check before field inverse
    INCORRECT_MODULAR_INVERSE = "incorrect_modular_inverse" # Wrong inverse computation

    # --- Over-Constrained (Completeness) ---
    OVER_CONSTRAINED = "over_constrained"                  # Valid inputs rejected
    IMPOSSIBLE_CONSTRAINT = "impossible_constraint"         # No valid witness exists for some inputs

    # --- Protocol-Level ---
    WEAK_FIAT_SHAMIR = "weak_fiat_shamir"                  # Incomplete transcript in Fiat-Shamir
    MISSING_PUBLIC_INPUT_BINDING = "missing_pi_binding"    # Public inputs not bound to proof
    PROOF_MALLEABILITY = "proof_malleability"               # Same statement, multiple valid proofs
    GROTH16_PROOF_FORGERY = "groth16_forgery"              # Groth16-specific proof manipulation

    # --- zkVM-Specific ---
    INSTRUCTION_CONFUSION = "instruction_confusion"        # Wrong opcode interpretation
    MEMORY_ACCESS_VIOLATION = "memory_access_violation"    # Unchecked memory bounds in VM circuit
    IMMEDIATE_MANIPULATION = "immediate_manipulation"      # Controllable instruction immediates
    LOOKUP_TABLE_BYPASS = "lookup_table_bypass"            # Lookup argument not fully enforced
    EXECUTION_FLAG_BYPASS = "execution_flag_bypass"        # Proof-completion flag not enforced

    # --- Privacy Leaks (less lucrative but still valid) ---
    SIGNAL_LEAKAGE = "signal_leakage"                      # Private data exposed via public signals
    TIMING_SIDE_CHANNEL = "timing_side_channel"            # Proof generation leaks witness info


@dataclass
class ZKVulnPattern:
    """A specific vulnerability pattern with detection methodology."""
    vuln_class: ZKVulnClass
    name: str
    description: str
    detection_method: str
    severity: str  # Critical, High, Medium, Low
    example_projects: list[str] = field(default_factory=list)
    payout_range: str = ""
    check_steps: list[str] = field(default_factory=list)


# Complete pattern database
ZK_VULN_PATTERNS: list[ZKVulnPattern] = [
    ZKVulnPattern(
        vuln_class=ZKVulnClass.MISSING_CONSTRAINT,
        name="Missing Constraint Term",
        description=(
            "A constraint equation is entirely absent from the circuit. "
            "The witness computation performs a check, but no corresponding "
            "constraint enforces it in the proof. This is the SP1 REMUW pattern."
        ),
        detection_method=(
            "Compare witness computation code line-by-line against constraint "
            "definitions. Every conditional branch, every arithmetic operation "
            "in the witness must have a matching constraint. Look for operations "
            "in eval() that lack corresponding constraint_transition() or "
            "constraint_first/last_row() entries."
        ),
        severity="Critical",
        example_projects=["SP1 (REMUW)", "RISC Zero rv32im", "Scroll modulo circuit"],
        payout_range="$100K-$1.6M",
        check_steps=[
            "1. Map every operation in witness generation code",
            "2. For each operation, find the corresponding constraint",
            "3. If constraint is missing -> CRITICAL vulnerability",
            "4. Verify constraint covers ALL registers/operands used",
            "5. Check edge cases: what if rs1==rs2? What if operand is 0?",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.MISSING_RANGE_CHECK,
        name="Missing Range Check on Witness Values",
        description=(
            "A witness value is used in constraints without enforcing its bit-length. "
            "The prover can choose values larger than expected, causing field arithmetic "
            "to produce valid-looking but incorrect results."
        ),
        detection_method=(
            "For every witness value, check if there is a range check (bit decomposition "
            "or lookup-based) that constrains it to the expected number of bits. "
            "Especially dangerous in comparator circuits (LessThan, GreaterThan)."
        ),
        severity="Critical",
        example_projects=["CircomLib LessThan", "Various Circom projects"],
        payout_range="$50K-$500K",
        check_steps=[
            "1. List all witness values in the circuit",
            "2. For each, determine expected bit-width",
            "3. Search for corresponding range check constraint",
            "4. Test: can a value > 2^n pass the constraints?",
            "5. Check if range check uses correct number of bits for the field",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.REGISTER_CONFUSION,
        name="Register/Operand Confusion in zkVM",
        description=(
            "In a zkVM circuit, register indices or operand sources are not properly "
            "constrained, allowing a malicious prover to confuse rs1 with rs2, or "
            "substitute one register's value for another."
        ),
        detection_method=(
            "For each instruction type, verify that ALL register operands are "
            "independently constrained. Check that the circuit does not assume "
            "register ordering or reuse constraints across different operand positions."
        ),
        severity="Critical",
        example_projects=["RISC Zero rv32im (CVE-2025-52484)", "SP1 register handling"],
        payout_range="$100K-$1M",
        check_steps=[
            "1. Identify all 3-register instructions (R-type in RISC-V)",
            "2. Trace how rs1, rs2, rd are constrained independently",
            "3. Check: can prover set rs1_val == rs2_val without constraint?",
            "4. Verify register index constraints are not shared/reused",
            "5. Test with adversarial instruction sequences",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.FIELD_OVERFLOW,
        name="Arithmetic Overflow via Field Modulus",
        description=(
            "Constraint arithmetic operates in a prime field (e.g., BN254). "
            "If the circuit does not account for modular reduction, a prover "
            "can use values that wrap around, producing valid constraints for "
            "invalid computations. Example: 0 - 1 === p - 1 in the field."
        ),
        detection_method=(
            "Identify all subtraction and addition operations. Check if the "
            "result could wrap around the field modulus. Look for missing "
            "checks that the result is within an expected range."
        ),
        severity="Critical",
        example_projects=["Multiple Circom projects", "Zcash 2018"],
        payout_range="$50K-$1M",
        check_steps=[
            "1. List all arithmetic operations in constraints",
            "2. For subtraction a-b, check: is there a range check on result?",
            "3. For addition a+b, check: can result exceed field modulus?",
            "4. Look for comparisons done without bit decomposition",
            "5. Test with values near field boundaries (0, 1, p-1, p-2)",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.WEAK_FIAT_SHAMIR,
        name="Weak Fiat-Shamir Transformation",
        description=(
            "The Fiat-Shamir heuristic converts interactive proofs to non-interactive "
            "by hashing the transcript. If the hash does not include all public inputs, "
            "common parameters, or prior proof elements, the prover can manipulate "
            "challenges. Known as 'Frozen Heart' vulnerability."
        ),
        detection_method=(
            "Trace the Fiat-Shamir transcript construction. Verify that EVERY "
            "public input, common reference string element, and prior commitment "
            "is included in the hash before challenges are derived."
        ),
        severity="Critical",
        example_projects=["Multiple SNARK implementations", "Frozen Heart (multiple libraries)"],
        payout_range="$100K-$500K",
        check_steps=[
            "1. Identify all Fiat-Shamir challenge derivations",
            "2. List all values that should be in the transcript",
            "3. Verify each value is actually hashed before challenge",
            "4. Check ordering: are commitments hashed before opening?",
            "5. Look for missing domain separators between protocol rounds",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.NONDETERMINISTIC_WITNESS,
        name="Nondeterministic Witness / Nullifier",
        description=(
            "Multiple valid witnesses exist for the same public statement. "
            "In privacy applications, this breaks nullifier uniqueness, allowing "
            "double-spending. In general circuits, it allows the prover to choose "
            "among multiple 'correct' computations."
        ),
        detection_method=(
            "For each witness value, ask: given fixed public inputs, is this value "
            "uniquely determined? Use Picus or manual analysis to check if the "
            "constraint system has a unique solution."
        ),
        severity="Critical",
        example_projects=["Tornado Cash nullifier issues", "Various mixer protocols"],
        payout_range="$50K-$1M",
        check_steps=[
            "1. Identify all witness values",
            "2. Fix all public inputs to concrete values",
            "3. Ask: does the constraint system have a unique solution?",
            "4. Focus on nullifiers, commitments, and hash preimages",
            "5. Check if any witness value has a degree of freedom",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.LOOKUP_TABLE_BYPASS,
        name="Lookup Table/Argument Bypass",
        description=(
            "Modern proof systems (Plonkish, AIR) use lookup arguments to enforce "
            "that values come from a predefined table. If the lookup argument is not "
            "properly enforced, a prover can use out-of-table values."
        ),
        detection_method=(
            "Verify that: (1) every value claimed to come from a lookup is actually "
            "constrained by the lookup argument, (2) the lookup table itself is "
            "correctly constructed, (3) multiplicity checks are enforced."
        ),
        severity="Critical",
        example_projects=["Plonky3 polynomial evaluation", "Various Plonkish circuits"],
        payout_range="$100K-$500K",
        check_steps=[
            "1. Identify all lookup tables in the circuit",
            "2. For each table, verify the lookup argument enforces membership",
            "3. Check: can a prover add entries to the table?",
            "4. Verify multiplicity (logup) polynomial is correctly constrained",
            "5. Test: does bypassing the lookup produce a valid proof?",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.EXECUTION_FLAG_BYPASS,
        name="Execution Completion Flag Bypass",
        description=(
            "In zkVMs, a flag indicates the program has completed execution. "
            "If this flag is not properly constrained, a prover can generate "
            "a proof for a partially executed program and claim arbitrary outputs."
        ),
        detection_method=(
            "Find the 'is_done' or 'halted' flag in the VM circuit. Verify it is "
            "constrained to be true at the last row and that the output is only "
            "read when this flag is set."
        ),
        severity="Critical",
        example_projects=["SP1 incomplete proof flag"],
        payout_range="$100K-$500K",
        check_steps=[
            "1. Find the execution completion flag in the circuit",
            "2. Verify it is constrained to true at the last step",
            "3. Check that outputs are gated behind this flag",
            "4. Test: can a proof be generated with is_done=false?",
            "5. Verify the flag transitions are monotonic (once done, stays done)",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.IMMEDIATE_MANIPULATION,
        name="Instruction Immediate Manipulation",
        description=(
            "In zkVM circuits, instruction immediates (constant operands encoded "
            "in the instruction) are not properly constrained, allowing a prover "
            "to substitute arbitrary values."
        ),
        detection_method=(
            "For each instruction that uses an immediate operand, verify that the "
            "immediate is constrained to match the program ROM. Check that the "
            "prover cannot modify the immediate after program loading."
        ),
        severity="Critical",
        example_projects=["JOLT v0.1.0 (lui instruction)"],
        payout_range="$50K-$500K",
        check_steps=[
            "1. List all instructions with immediate operands",
            "2. Trace how the immediate value enters the circuit",
            "3. Verify it is constrained to match the program ROM/memory",
            "4. Test: can prover substitute a different immediate?",
            "5. Check lui, addi, jalr, branch immediates specifically",
        ],
    ),
    ZKVulnPattern(
        vuln_class=ZKVulnClass.MEMORY_ACCESS_VIOLATION,
        name="Unchecked Memory Access in zkVM",
        description=(
            "The zkVM circuit does not properly constrain memory load/store "
            "addresses, allowing a prover to read from or write to arbitrary "
            "memory locations, including reserved registers."
        ),
        detection_method=(
            "Trace all memory access constraints. Verify address ranges are "
            "enforced. Check that reserved memory (register file, ROM) cannot "
            "be accessed via regular load/store instructions."
        ),
        severity="Critical",
        example_projects=["SP1 register 0 memory access"],
        payout_range="$100K-$500K",
        check_steps=[
            "1. Map the memory layout (registers, stack, heap, ROM)",
            "2. Find all load/store constraint implementations",
            "3. Verify address range checks exclude reserved regions",
            "4. Test: can a store overwrite register x0?",
            "5. Check memory consistency argument (read-after-write)",
        ],
    ),
]


# =============================================================================
# SECTION 2: TOP ZK BOUNTY TARGETS (Ranked by ROI)
# =============================================================================

@dataclass
class ZKBountyTarget:
    """A ZK bounty program worth targeting."""
    name: str
    platform: str
    max_payout: str
    min_payout: str
    scope: str
    tech_stack: str
    difficulty: str  # 1-5 (5 = hardest)
    competition: str  # Low, Medium, High
    our_edge: str
    priority_vulns: list[str]
    repo_url: str
    notes: str


TOP_ZK_BOUNTIES: list[ZKBountyTarget] = [
    ZKBountyTarget(
        name="ZKsync Era",
        platform="Immunefi",
        max_payout="$2,300,000",
        min_payout="$100,000",
        scope="ZK circuits, smart contracts, protocol",
        tech_stack="Boojum (custom STARK-based), Rust, Solidity",
        difficulty=5,
        competition="High",
        our_edge="Previous zkSync Era soundness bug by ChainLight shows circuit bugs exist. Boojum is complex and under-documented.",
        priority_vulns=["MISSING_CONSTRAINT", "LOOKUP_TABLE_BYPASS", "FIELD_OVERFLOW"],
        repo_url="https://github.com/matter-labs/zksync-era",
        notes="Highest payout in ZK. Their Airbender proof system is new attack surface.",
    ),
    ZKBountyTarget(
        name="Aztec Network",
        platform="Immunefi",
        max_payout="$1,000,000",
        min_payout="$40,000 (est.)",
        scope="Noir circuits, cryptography, smart contracts",
        tech_stack="Noir (custom DSL), Barretenberg (custom backend), Solidity",
        difficulty=5,
        competition="Medium",
        our_edge="Noir is newer with less audit coverage. Privacy-focused means nullifier/nondeterminism bugs are high-value.",
        priority_vulns=["NONDETERMINISTIC_WITNESS", "MISSING_CONSTRAINT", "WEAK_FIAT_SHAMIR"],
        repo_url="https://github.com/AztecProtocol/aztec-packages",
        notes="Total bounty pool $2M+. Privacy layer means completeness AND soundness matter.",
    ),
    ZKBountyTarget(
        name="DeGate",
        platform="Immunefi",
        max_payout="$1,110,000",
        min_payout="$100,000 (High)",
        scope="ZKP circuits, smart contracts, protocol",
        tech_stack="Circom, Groth16, Solidity",
        difficulty=3,
        competition="Low",
        our_edge="Circom is well-tooled (Circomspect, Picus, zkFuzz). ZK-rollup DEX with smaller security team.",
        priority_vulns=["MISSING_RANGE_CHECK", "MISSING_CONSTRAINT", "GROTH16_PROOF_FORGERY"],
        repo_url="https://github.com/degatedev",
        notes="Circom-based = we can use automated tooling. Lower difficulty, good ROI.",
    ),
    ZKBountyTarget(
        name="Polygon zkEVM",
        platform="Immunefi",
        max_payout="$1,000,000",
        min_payout="$50,000",
        scope="zkEVM circuits, bridge, smart contracts",
        tech_stack="PIL (Polynomial Identity Language), custom prover, Solidity",
        difficulty=5,
        competition="Medium",
        our_edge="Complex zkEVM with many opcodes = large constraint surface. PIL is less audited than Circom.",
        priority_vulns=["MISSING_CONSTRAINT", "INSTRUCTION_CONFUSION", "FIELD_OVERFLOW"],
        repo_url="https://github.com/0xPolygonHermez/zkevm-prover",
        notes="Full zkEVM = massive attack surface. Each EVM opcode is a potential bug.",
    ),
    ZKBountyTarget(
        name="Scroll",
        platform="Immunefi",
        max_payout="$1,000,000",
        min_payout="$50,000",
        scope="zkEVM circuits, bridge, rollup",
        tech_stack="Halo2 (PSE fork), Rust, Solidity",
        difficulty=4,
        competition="Medium",
        our_edge="Previous modulo circuit bug shows constraint gaps exist. Halo2 is complex.",
        priority_vulns=["MISSING_CONSTRAINT", "INCOMPLETE_CONSTRAINT", "LOOKUP_TABLE_BYPASS"],
        repo_url="https://github.com/scroll-tech/zkevm-circuits",
        notes="Already had a critical modulo constraint bug. Same class likely exists elsewhere.",
    ),
    ZKBountyTarget(
        name="StarkNet",
        platform="Immunefi",
        max_payout="$500,000",
        min_payout="$40,000",
        scope="STARK prover/verifier, Cairo VM, protocol",
        tech_stack="Cairo (custom language), STARK proofs, Rust/Python",
        difficulty=5,
        competition="Medium",
        our_edge="Cairo VM is a unique architecture. STARKs have different bug patterns than SNARKs.",
        priority_vulns=["MISSING_CONSTRAINT", "MEMORY_ACCESS_VIOLATION", "EXECUTION_FLAG_BYPASS"],
        repo_url="https://github.com/starkware-libs/cairo",
        notes="STARK-based = different proof system. Focus on Cairo VM circuit constraints.",
    ),
    ZKBountyTarget(
        name="Succinct SP1",
        platform="Code4rena",
        max_payout="$150,000",
        min_payout="N/A",
        scope="SP1 zkVM circuits, Plonky3",
        tech_stack="Plonky3 (STARK), Rust, RISC-V",
        difficulty=4,
        competition="Low",
        our_edge="WE ALREADY FOUND A BUG HERE (REMUW). We know the codebase. SP1 Hypercube is new attack surface.",
        priority_vulns=["MISSING_CONSTRAINT", "REGISTER_CONFUSION", "EXECUTION_FLAG_BYPASS"],
        repo_url="https://github.com/succinctlabs/sp1",
        notes="We have proven track record here. New versions = new bugs. Return to this regularly.",
    ),
    ZKBountyTarget(
        name="RISC Zero",
        platform="HackenProof",
        max_payout="$150,000",
        min_payout="N/A",
        scope="zkVM circuits, RISC-V",
        tech_stack="Custom STARK, Rust, RISC-V",
        difficulty=4,
        competition="Low",
        our_edge="CVE-2025-52484 shows missing constraints in rv32im. Same RISC-V architecture as SP1.",
        priority_vulns=["REGISTER_CONFUSION", "MISSING_CONSTRAINT", "IMMEDIATE_MANIPULATION"],
        repo_url="https://github.com/risc0/risc0",
        notes="RISC-V zkVM = similar attack surface to SP1. Skills transfer directly.",
    ),
    ZKBountyTarget(
        name="zkVerify",
        platform="Immunefi",
        max_payout="$50,000",
        min_payout="$15,000",
        scope="Proof verification layer",
        tech_stack="Substrate, Rust, various verifiers",
        difficulty=3,
        competition="Low",
        our_edge="Proof verification layer = single point of failure. Verifier bugs affect all proofs.",
        priority_vulns=["WEAK_FIAT_SHAMIR", "MISSING_CONSTRAINT", "PROOF_MALLEABILITY"],
        repo_url="https://github.com/zkVerify",
        notes="Lower payout but lower competition. Good for building track record.",
    ),
    ZKBountyTarget(
        name="Polygon (Main)",
        platform="Immunefi",
        max_payout="$1,000,000+",
        min_payout="$50,000",
        scope="Full Polygon ecosystem including ZK components",
        tech_stack="Various (Plonky2/3, custom provers)",
        difficulty=4,
        competition="High",
        our_edge="Broad scope means ZK components may get less attention from EVM-focused hunters.",
        priority_vulns=["MISSING_CONSTRAINT", "LOOKUP_TABLE_BYPASS", "FIELD_OVERFLOW"],
        repo_url="https://github.com/0xPolygon",
        notes="Parent program covers zkEVM and other ZK infrastructure.",
    ),
]


# =============================================================================
# SECTION 3: ZK-SPECIFIC VULNERABILITY CHECKLIST
# =============================================================================

ZK_AUDIT_CHECKLIST = """
================================================================================
ZK CIRCUIT VULNERABILITY CHECKLIST
================================================================================
Version: 1.0
Based on: 141+ documented ZK bugs, SP1 REMUW finding, 0xPARC bug tracker

NOTE: 96% of documented ZK bugs are under-constrained circuits. This checklist
is weighted accordingly.

================================================================================
PHASE 1: RECONNAISSANCE
================================================================================

[ ] 1.1 Identify the proof system (Groth16, Plonk, STARK/FRI, Halo2, etc.)
[ ] 1.2 Identify the DSL/framework (Circom, Noir, Halo2 API, Cairo, AIR/RAP)
[ ] 1.3 Map the circuit architecture (main circuit, sub-circuits, lookup tables)
[ ] 1.4 Identify all public inputs and their purpose
[ ] 1.5 Identify all witness (private) values and how they are computed
[ ] 1.6 Understand the protocol context (what is the circuit proving?)
[ ] 1.7 Read the specification/documentation for the computation being proved
[ ] 1.8 Identify recent changes (git diff) -- new code = new bugs

================================================================================
PHASE 2: CONSTRAINT COMPLETENESS (Primary Attack Surface)
================================================================================

UNDER-CONSTRAINED CHECKS:

[ ] 2.1 For EVERY witness computation, verify a matching constraint exists
    - Map witness code line-by-line to constraints
    - Any witness operation without a constraint = potential bug

[ ] 2.2 For EVERY conditional branch in witness code, verify constraint coverage
    - if/else in witness must have selector-based constraints
    - Missing branch = entire code path is unconstrained

[ ] 2.3 Check all signals/variables are constrained
    - Declared but unconstrained signals = free variables for prover
    - Use tools: Circomspect (Circom), Picus (formal verification)

[ ] 2.4 Verify all public inputs are used in constraints
    - Unused public input = proof is not bound to that value
    - Enables proof replay with different public inputs

[ ] 2.5 Check for missing range checks on ALL witness values
    - Every witness value needs an explicit bit-width constraint
    - Especially: values used in comparisons or as array indices

[ ] 2.6 For zkVMs: verify ALL register operands are independently constrained
    - rs1, rs2, rd must each have their own constraint
    - Shared/reused constraints = register confusion attack

[ ] 2.7 For zkVMs: verify instruction decoding is fully constrained
    - Each opcode must map to exactly one instruction behavior
    - Missing opcode constraint = instruction confusion

[ ] 2.8 Verify lookup table membership is enforced
    - Every claimed lookup must have a valid lookup argument
    - Check multiplicity polynomial is constrained

OVER-CONSTRAINED CHECKS:

[ ] 2.9 Verify valid inputs produce valid proofs
    - Test with edge cases (0, 1, max values, boundary values)
    - Over-constraining causes liveness failures

================================================================================
PHASE 3: ARITHMETIC CORRECTNESS
================================================================================

[ ] 3.1 Check all subtraction operations for underflow
    - a - b when b > a wraps to p + a - b (large field element)
    - Must have range check on result or guard condition

[ ] 3.2 Check all addition operations for overflow
    - a + b > p wraps to (a + b) mod p
    - Especially dangerous in sum-of-parts decompositions

[ ] 3.3 Check division/modular inverse for zero divisor
    - Field inverse of 0 is undefined but may silently produce 0
    - Missing zero-check before inverse = soundness bug

[ ] 3.4 Verify bit decomposition correctness
    - Sum of bits * powers of 2 must equal the original value
    - Each bit must be constrained to {0, 1}
    - Number of bits must match the expected range

[ ] 3.5 Check comparison operations use proper bit decomposition
    - a < b in a field requires converting to binary first
    - Direct field subtraction does NOT give correct ordering

[ ] 3.6 Verify modular arithmetic matches specification
    - a mod b in a field requires explicit constraint: a = b*q + r, r < b
    - Missing r < b constraint = Scroll modulo bug pattern

================================================================================
PHASE 4: PROTOCOL-LEVEL CHECKS
================================================================================

[ ] 4.1 Verify Fiat-Shamir transcript completeness
    - ALL public inputs must be in the hash
    - ALL commitments must be in the hash BEFORE challenge derivation
    - Common reference string must be included
    - Domain separators between rounds

[ ] 4.2 Check for proof malleability
    - Groth16: verify proof elements cannot be manipulated
    - Check for missing pairing checks

[ ] 4.3 Verify nullifier determinism (privacy circuits)
    - Same inputs must always produce same nullifier
    - Nondeterministic nullifier = double-spend

[ ] 4.4 Check trusted setup integrity (Groth16)
    - Toxic waste must be destroyed
    - Verify ceremony completeness

[ ] 4.5 Verify commitment scheme binding
    - Commitments must be computationally binding
    - Check for missing blinding factors

================================================================================
PHASE 5: zkVM-SPECIFIC CHECKS
================================================================================

[ ] 5.1 Verify program ROM is immutable
    - Prover must not be able to modify program after loading
    - Check program hash is constrained to public input

[ ] 5.2 Verify execution completion flag
    - Must be constrained to true at last row
    - Must be monotonic (once set, cannot be unset)
    - Outputs must be gated behind this flag

[ ] 5.3 Check memory consistency (read-after-write)
    - Memory reads must return the last written value
    - Address-timestamp ordering must be enforced
    - Check for aliasing between memory regions

[ ] 5.4 Verify register file constraints
    - x0 (zero register in RISC-V) must always be 0
    - Register writes must not affect reserved registers
    - Each register read must be constrained

[ ] 5.5 Check instruction immediate constraints
    - Immediates must match the program ROM
    - lui, addi, jalr, branch immediates are common targets

[ ] 5.6 Verify cross-chip/cross-AIR interactions
    - Data passed between sub-circuits must be consistent
    - Check bus arguments and permutation arguments

[ ] 5.7 Verify syscall/precompile constraints
    - External calls must have fully constrained I/O
    - Missing output constraints on precompiles = free outputs

================================================================================
PHASE 6: TOOLING-ASSISTED CHECKS
================================================================================

[ ] 6.1 Run Circomspect (if Circom)
    - Flags: unconstrained signals, unsafe <-- usage, unused variables
    - Note: high false positive rate, but catches real bugs

[ ] 6.2 Run Picus (if Circom)
    - Formal verification of uniqueness (under-constraint detection)
    - Slower but more precise than Circomspect

[ ] 6.3 Run zkFuzz (if Circom)
    - Mutation-based fuzzing for TCCT violations
    - Best current tool: outperforms Circomspect, ZKAP, Picus, ConsCS

[ ] 6.4 Run ARGUZZ (if zkVM)
    - Fuzzing for soundness and completeness bugs in zkVMs
    - Found bugs in 3 separate zkVMs

[ ] 6.5 Custom witness manipulation tests
    - Modify witness values and check if proof still verifies
    - Focus on: zero values, max values, negated values, swapped values

[ ] 6.6 Differential testing
    - Compare circuit output against reference implementation
    - Test with random inputs and edge cases
"""


# =============================================================================
# SECTION 4: AGENT PROMPTS FOR ZK CIRCUIT ANALYSIS
# =============================================================================

ZK_AGENT_PROMPTS = {
    "constraint_completeness_agent": {
        "name": "Constraint Completeness Agent",
        "description": "Systematically checks that every witness computation has a matching constraint",
        "prompt": """You are a specialized ZK circuit auditor focused on finding UNDER-CONSTRAINED bugs.
Your sole mission is to find witness computations that lack corresponding constraints.

## Context
96% of all documented ZK circuit bugs are under-constrained circuits. The most critical pattern
is a "missing constraint term" -- where the witness computation performs an operation but
no constraint enforces it in the proof system. This was the exact pattern in the SP1 REMUW finding
and the RISC Zero rv32im CVE-2025-52484.

## Your Methodology

### Step 1: Map Witness Computation
For the given circuit code, create a complete map of every operation performed during
witness generation (also called "trace generation" or "eval" in AIR-based systems):
- Every arithmetic operation (add, sub, mul, div, mod)
- Every conditional branch (if/else, match, select)
- Every value read from registers, memory, or lookup tables
- Every value written to output signals or state transitions

### Step 2: Map Constraints
Create a corresponding map of every constraint enforced by the circuit:
- Polynomial identity constraints (in AIR/STARK)
- R1CS constraints (in Circom/Groth16)
- PLONKish constraints (in Halo2)
- Lookup arguments
- Permutation arguments
- Range checks / bit decompositions

### Step 3: Cross-Reference
For EVERY witness operation from Step 1, find the EXACT constraint from Step 2
that enforces it. If you cannot find a matching constraint, flag it as:

**POTENTIAL UNDER-CONSTRAINED BUG: [operation description]**
- Witness code location: [file:line]
- Expected constraint: [what should exist]
- Impact: [what a malicious prover could do]
- Severity: CRITICAL (if soundness is broken)

### Step 4: Edge Case Analysis
For each constraint you DID find, check:
- Does it cover ALL branches of the corresponding witness code?
- Does it handle edge cases (zero values, maximum values, equal operands)?
- Are there off-by-one errors in range checks?
- Does it properly handle field arithmetic wraparound?

## Output Format
Provide a structured report with:
1. Total witness operations mapped
2. Total constraints mapped
3. UNMATCHED witness operations (potential bugs) -- with full details
4. WEAK constraints (exist but may be insufficient) -- with analysis
5. Confidence level for each finding (High/Medium/Low)

IMPORTANT: Be exhaustive. Missing even ONE constraint term can be a $1M+ vulnerability.
Do NOT assume any constraint exists unless you can point to the exact code that enforces it.
""",
    },

    "arithmetic_soundness_agent": {
        "name": "Arithmetic Soundness Agent",
        "description": "Hunts for field arithmetic bugs: overflow, underflow, modular reduction issues",
        "prompt": """You are a specialized ZK circuit auditor focused on FIELD ARITHMETIC vulnerabilities.
Your mission is to find places where arithmetic in a finite field produces unexpected results
that break the circuit's intended behavior.

## Context
ZK circuits operate over prime fields (e.g., BN254: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617).
Unlike normal integer arithmetic:
- Subtraction wraps: 0 - 1 = p - 1 (a huge number, not -1)
- Addition wraps: (p-1) + 2 = 1
- Multiplication wraps: large * large = (large * large) mod p
- Division is modular inverse: a / b = a * b^(p-2) mod p
- Comparison (a < b) has NO native meaning in a field

These properties create an entire class of bugs where constraints that look correct
actually allow invalid values.

## Your Methodology

### Step 1: Identify All Arithmetic Operations
For each operation, determine:
- What values are the operands? (witness, public input, constant)
- What is the expected range of the result in the "real" computation?
- Could the result wrap around the field modulus?

### Step 2: Check Each Operation Class

**Subtraction (a - b):**
- Is there a check that a >= b (or equivalently, result < p/2)?
- If b > a, the result is p + a - b, which is a valid field element but NOT the intended result
- Look for: balance checks, amount validations, fee computations

**Addition (a + b):**
- Can a + b exceed p? If so, the result wraps to (a + b - p)
- This is rare with typical values but critical in sum-of-parts checks
- Look for: total = sum of components assertions

**Comparison (a < b):**
- Is comparison done via bit decomposition? (correct)
- Or via field subtraction? (INCORRECT and exploitable)
- CircomLib LessThan bug: missing range check on inputs allows bypassing comparison

**Division / Modular Inverse:**
- Is there a zero-check before computing inverse?
- field_inverse(0) is undefined but may silently produce 0 or a random value
- Look for: division operations, modulo operations

**Bit Decomposition:**
- Are all bits constrained to {0, 1}? (each bit * (1 - bit) == 0)
- Does the number of bits match the expected range?
- Does the reconstruction (sum of bits * 2^i) equal the original value?
- Is there an extra bit needed to prevent overflow?

### Step 3: Test with Adversarial Values
For each identified risk, construct specific adversarial values:
- What happens if the prover uses (p - x) instead of x?
- What happens with value = 0?
- What happens with value = p - 1?
- What happens with value = 2^n (boundary of range check)?

## Output Format
For each finding:
1. Operation type and location in code
2. Expected behavior vs. actual field arithmetic behavior
3. Specific adversarial witness values that break the constraint
4. Impact on the protocol (what false statement can be proved)
5. Severity: CRITICAL if funds at risk, HIGH if integrity compromised
""",
    },

    "zkvm_instruction_agent": {
        "name": "zkVM Instruction Verification Agent",
        "description": "Specialized for auditing zkVM instruction circuits (RISC-V, Cairo, custom ISAs)",
        "prompt": """You are a specialized auditor for ZERO-KNOWLEDGE VIRTUAL MACHINE circuits.
Your mission is to find bugs in how zkVM instructions are constrained, focusing on the
RISC-V ISA used by SP1, RISC Zero, Jolt, and similar zkVMs.

## Context
zkVMs prove correct execution of programs by encoding each CPU instruction as circuit
constraints. The attack surface is massive: each instruction type needs its own set of
constraints, and a single missing constraint can allow forging arbitrary execution proofs.

Known zkVM bugs follow clear patterns:
- SP1 REMUW: Missing constraint term for a specific instruction
- RISC Zero rv32im: Missing constraint allowing rs1/rs2 register confusion
- JOLT lui: Missing constraint on immediate operand manipulation
- SP1: Execution completion flag not properly enforced
- SP1: Reserved memory accessible via load/store

## Your Methodology

### Step 1: Instruction Set Inventory
For the given zkVM, enumerate EVERY instruction type and its circuit implementation:
- R-type (3 register): ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND
- R-type (multiply): MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
- I-type (immediate): ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI
- Load: LB, LH, LW, LBU, LHU
- Store: SB, SH, SW
- Branch: BEQ, BNE, BLT, BGE, BLTU, BGEU
- Jump: JAL, JALR
- Upper immediate: LUI, AUIPC
- System: ECALL, EBREAK
- Extensions: M (multiply/divide), C (compressed), F/D (floating point)

### Step 2: Per-Instruction Constraint Audit
For EACH instruction, verify:

**Operand Sourcing:**
- [ ] rs1 value is constrained to come from register file at index rs1
- [ ] rs2 value is constrained to come from register file at index rs2 (R-type)
- [ ] Immediate is constrained to match program ROM (I-type, S-type, B-type, U-type, J-type)
- [ ] rs1 and rs2 are INDEPENDENTLY constrained (not shared/aliased)

**Computation:**
- [ ] The arithmetic/logic operation matches the ISA specification EXACTLY
- [ ] Edge cases handled: division by zero, shift amounts >= 32, overflow
- [ ] Signed vs unsigned operations use correct field arithmetic
- [ ] Result bit-width matches ISA spec (32-bit for RV32, 64-bit for RV64)

**Result Writing:**
- [ ] rd write is constrained to the correct register index
- [ ] Writing to x0 is properly handled (value must remain 0)
- [ ] PC update is correct (PC+4 for sequential, target for branch/jump)

**Memory Operations (Load/Store):**
- [ ] Address computation is constrained (base + offset)
- [ ] Address alignment checks (if required by ISA)
- [ ] Memory consistency: read returns last written value at that address
- [ ] Byte/halfword/word access size is properly constrained
- [ ] Sign extension (LB, LH) vs zero extension (LBU, LHU) is correct

### Step 3: Cross-Instruction Checks
- [ ] Can a prover make one instruction behave as another? (opcode confusion)
- [ ] Are instruction selectors mutually exclusive? (exactly one active per step)
- [ ] Is the instruction decoder fully constrained? (no undefined opcodes accepted)
- [ ] Are multi-cycle instructions properly chained?

### Step 4: VM-Level Checks
- [ ] Program counter transitions are constrained
- [ ] Execution trace length is bounded and enforced
- [ ] Halting condition is properly constrained
- [ ] Initial state (registers, memory) is constrained to public input
- [ ] Final state (output) is constrained to public output

## Output Format
Provide a per-instruction audit matrix:
| Instruction | Operand Sourcing | Computation | Result Writing | Edge Cases | Status |
Then detailed findings for any FAIL or WARN entries.

CRITICAL: Pay special attention to:
1. REMU/DIVU/REM/DIV -- these are where SP1 and RISC Zero bugs were found
2. Signed operations (SRA, SLT, BGE, BLT) -- sign handling is complex
3. Memory operations -- address range validation
4. Branch instructions -- condition evaluation and target computation
""",
    },

    "lookup_argument_agent": {
        "name": "Lookup Argument & Permutation Agent",
        "description": "Verifies correctness of lookup arguments, permutation arguments, and bus interactions",
        "prompt": """You are a specialized auditor for LOOKUP ARGUMENTS and PERMUTATION ARGUMENTS
in ZK circuits. These are critical components in modern proof systems (Plonk, AIR/STARK, Halo2)
that enforce set membership and cross-table consistency.

## Context
Modern ZK circuits use lookup arguments to efficiently prove that values come from
predefined tables (e.g., range checks, boolean tables, opcode tables). Permutation
arguments prove that two multisets are equal (used for memory consistency, wiring).
Bugs in these components can break the entire proof system.

Known lookup/permutation bugs:
- Plonky3 polynomial evaluation: incomplete verification before confirming proof validity
- Various Plonkish circuits: lookup table membership not properly enforced
- Bus argument failures: data passed between sub-circuits loses consistency

## Your Methodology

### Step 1: Inventory All Arguments
For the given circuit, list every:
- Lookup table: what values it contains, what queries it
- Lookup argument: which protocol (LogUp, Plookup, Halo2 lookup, etc.)
- Permutation argument: what columns/signals it connects
- Bus argument: what data flows between sub-circuits

### Step 2: Lookup Argument Verification
For EACH lookup:
- [ ] The table is correctly constructed (all valid entries, no extra entries)
- [ ] The table is immutable (prover cannot add/modify entries)
- [ ] Every query value is actually constrained by the lookup argument
- [ ] The multiplicity polynomial (LogUp) is correctly constrained
- [ ] The accumulator/running sum is initialized and finalized correctly
- [ ] Random challenges are properly derived (Fiat-Shamir)

### Step 3: Permutation Argument Verification
For EACH permutation:
- [ ] All column pairs in the permutation are correctly specified
- [ ] The grand product argument is initialized to 1
- [ ] The grand product argument finalizes to 1 (or the expected value)
- [ ] Random challenges for the permutation are properly derived
- [ ] The permutation actually includes ALL relevant columns

### Step 4: Bus / Cross-Table Interaction Verification
For EACH bus interaction (data flow between sub-circuits):
- [ ] Sending side constraints match receiving side constraints
- [ ] All fields in the bus message are constrained on both sides
- [ ] The bus argument enforces multiset equality (sends == receives)
- [ ] No bus messages can be dropped or duplicated without detection

### Step 5: Attack Scenarios
For each argument, consider:
- Can the prover construct a valid proof with an out-of-table value?
- Can the prover duplicate or drop a lookup/permutation entry?
- Can the prover reorder entries in a way that changes semantics?
- Is there a boundary condition where the argument fails?

## Output Format
1. Complete inventory of all lookup/permutation/bus arguments
2. Per-argument verification status (PASS/FAIL/WARN)
3. Detailed attack scenarios for any FAIL/WARN
4. Cross-references to specific code locations
""",
    },

    "protocol_integration_agent": {
        "name": "Protocol Integration & Fiat-Shamir Agent",
        "description": "Checks how the ZK proof integrates with the broader protocol, including Fiat-Shamir",
        "prompt": """You are a specialized auditor for ZK PROOF PROTOCOL INTEGRATION.
Your mission is to find bugs in how ZK proofs are constructed, verified, and used
within the broader protocol -- NOT in the circuit constraints themselves, but in
the cryptographic protocol layer.

## Context
Even a perfectly constrained circuit can be broken by:
- Weak Fiat-Shamir transformation (allows prover to manipulate challenges)
- Missing public input binding (proof is not tied to the claimed statement)
- Proof malleability (same statement can have multiple valid proofs)
- Verifier bugs (accepts invalid proofs)
- Integration bugs (proof is valid but used incorrectly by the protocol)

The "Frozen Heart" vulnerability affected multiple ZK libraries due to incomplete
Fiat-Shamir transcript construction.

## Your Methodology

### Step 1: Fiat-Shamir Transcript Analysis
Trace the COMPLETE transcript construction:
- [ ] List every value that should be in the transcript
- [ ] Verify each value IS hashed before the next challenge is derived
- [ ] Check ordering: commitments before challenges, challenges before openings
- [ ] Verify domain separators between protocol rounds
- [ ] Check that the verifier reconstructs the same transcript as the prover

Specifically verify these are in the transcript:
- All public inputs
- All polynomial commitments (in order)
- The common reference string / verification key
- Any auxiliary data needed for verification
- Protocol version / domain separator

### Step 2: Public Input Binding
- [ ] All public inputs declared by the circuit are passed to the verifier
- [ ] The verifier uses the correct public inputs (not attacker-controlled)
- [ ] Public inputs are included in the Fiat-Shamir transcript
- [ ] On-chain verifiers: public inputs come from trusted sources

### Step 3: Proof Verification Completeness
- [ ] All verification equations are checked (no skipped checks)
- [ ] Pairing checks (Groth16) include all required pairings
- [ ] FRI verification (STARK) checks all required queries
- [ ] Polynomial evaluation checks verify at all claimed points
- [ ] Batch verification (if used) does not introduce unsoundness

### Step 4: On-Chain Integration (if applicable)
- [ ] Verifier contract correctly deserializes the proof
- [ ] Public inputs are ABI-encoded correctly
- [ ] The verifier contract cannot be called with stale/replayed proofs
- [ ] Proof verification failure causes the transaction to revert
- [ ] Gas limits cannot cause partial verification (all-or-nothing)

### Step 5: Proof Malleability
- [ ] Groth16: check for known proof malleability vectors
- [ ] Check if the proof can be re-randomized by a third party
- [ ] Verify that proof uniqueness is enforced where needed
- [ ] Check for missing subgroup checks on curve points

## Output Format
1. Complete Fiat-Shamir transcript reconstruction
2. List of all values that should be in transcript vs. what IS in transcript
3. Any MISSING values = Frozen Heart vulnerability
4. Public input binding analysis
5. On-chain integration analysis (if applicable)
6. Severity and impact for each finding
""",
}
}


# =============================================================================
# SECTION 5: AUDIT METHODOLOGY
# =============================================================================

ZK_AUDIT_METHODOLOGY = """
================================================================================
SYSTEMATIC ZK CIRCUIT AUDIT METHODOLOGY
================================================================================

This methodology is designed for bug bounty hunters targeting ZK circuits.
It prioritizes the highest-ROI vulnerability classes first.

================================================================================
STAGE 0: TARGET SELECTION (1-2 hours)
================================================================================

1. Check the bounty program scope:
   - Is the ZK circuit / proof system in scope?
   - What is the maximum payout for circuit-level bugs?
   - Are there any exclusions?

2. Assess the target:
   - When was the circuit code last modified? (recent changes = fresh bugs)
   - How many prior audits? (check audit reports)
   - What proof system / DSL? (determines tooling availability)
   - How complex is the circuit? (more constraints = more attack surface)

3. Quick viability check:
   - Can you build and run the project locally?
   - Is the code readable and well-structured?
   - Is there documentation for the computation being proved?

================================================================================
STAGE 1: UNDERSTAND THE COMPUTATION (2-4 hours)
================================================================================

Before looking at constraints, you MUST understand what the circuit is supposed
to prove. This is the most important step.

1. Read the specification / documentation
2. Understand the inputs (public and private)
3. Understand the outputs and what constitutes a valid proof
4. Map the high-level computation flow
5. Identify the critical invariants (what MUST be true for soundness)

Example for a zkVM:
  - Inputs: program binary (public), initial state (public)
  - Output: final state (public)
  - Computation: sequential execution of RISC-V instructions
  - Critical invariant: the final state is the ONLY valid result of
    executing the program on the initial state

================================================================================
STAGE 2: MAP WITNESS vs. CONSTRAINTS (4-8 hours)
================================================================================

This is where bugs hide. Create two parallel maps:

MAP A: Witness Generation
  - Read the code that generates witness values (trace, assignment, eval)
  - List every operation: arithmetic, conditionals, memory access, etc.
  - Note the data dependencies between witness values

MAP B: Constraint Enforcement
  - Read the code that defines constraints
  - List every constraint equation / polynomial identity
  - Note which witness values each constraint references

CROSS-REFERENCE:
  - For every item in Map A, find the corresponding item in Map B
  - Items in Map A with no match in Map B = UNDER-CONSTRAINED (soundness bug)
  - Items in Map B with no match in Map A = OVER-CONSTRAINED (completeness bug)

This is the SP1 REMUW methodology: the witness code computed REMUW correctly,
but the constraint system was missing the term that enforced it.

================================================================================
STAGE 3: ARITHMETIC DEEP DIVE (2-4 hours)
================================================================================

For each constraint found in Stage 2:

1. Verify the arithmetic is correct in the prime field
   - Does subtraction handle underflow?
   - Does addition handle overflow?
   - Are comparisons done via bit decomposition?

2. Check range constraints
   - Is every witness value range-checked?
   - Is the range correct for the intended computation?
   - Does the range check use the right number of bits?

3. Test with adversarial values
   - Field boundary values (0, 1, p-1, p-2)
   - Values that cause wraparound
   - Maximum and minimum allowed values

================================================================================
STAGE 4: STRUCTURAL CHECKS (2-4 hours)
================================================================================

1. Lookup tables
   - Are all lookups enforced by the argument?
   - Can the prover modify the table?
   - Is the accumulator properly constrained?

2. Permutation arguments
   - Do permutations cover all required columns?
   - Is the grand product properly initialized and finalized?

3. Cross-circuit interactions (buses)
   - Are all bus messages fully constrained on both ends?
   - Can messages be dropped or duplicated?

4. Fiat-Shamir transcript
   - Are all public inputs in the transcript?
   - Are all commitments in the transcript?
   - Is the ordering correct?

================================================================================
STAGE 5: EDGE CASE TESTING (2-4 hours)
================================================================================

Using knowledge from Stages 1-4, construct specific test cases:

1. Zero-value attacks: What if a witness value is 0 when it shouldn't be?
2. Equality attacks: What if two values that should differ are equal?
3. Boundary attacks: Values at the edge of range checks
4. Negation attacks: Using p-x instead of x
5. Overflow attacks: Values that cause field wraparound

For zkVMs specifically:
6. Register x0 attacks: Can x0 be written to?
7. Empty execution: Can a proof show zero instructions?
8. Immediate substitution: Can instruction immediates be changed?
9. Memory aliasing: Can two addresses point to the same cell?
10. Partial execution: Can the proof cover only part of execution?

================================================================================
STAGE 6: TOOL-ASSISTED VERIFICATION (1-4 hours)
================================================================================

Run all available automated tools:

For Circom circuits:
  $ circomspect circuit.circom    # Static analysis
  $ picus verify circuit.r1cs     # Formal uniqueness verification
  $ zkfuzz fuzz circuit.circom    # Mutation-based fuzzing

For zkVMs:
  $ arguzz test target_zkvm       # Soundness/completeness fuzzing

For any circuit:
  - Write custom witness manipulation tests
  - Differential test against reference implementation
  - Fuzz with random inputs

================================================================================
STAGE 7: REPORT WRITING (2-4 hours)
================================================================================

For each finding:
1. Clear title describing the vulnerability
2. Severity classification with justification
3. Affected component (exact file and line numbers)
4. Root cause analysis
5. Step-by-step proof of concept
6. Impact assessment (what false statement can be proved)
7. Recommended fix with specific constraint equations

Total estimated time per target: 15-30 hours for a focused audit
Expected hit rate: 1 critical finding per 3-5 targets (based on industry data)
Expected value per hour: $1,500 - $10,000 (at $250K-$1.6M payouts)
"""


# =============================================================================
# SECTION 6: ZK SECURITY TOOLS REFERENCE
# =============================================================================

ZK_TOOLS = {
    "circomspect": {
        "description": "Static analysis tool for Circom circuits",
        "capabilities": [
            "Detects unconstrained signals",
            "Flags unsafe <-- operator usage",
            "Identifies unused variables",
            "Basic pattern matching for common bugs",
        ],
        "limitations": [
            "High false positive rate",
            "Only works with Circom",
            "Pattern-based, cannot reason about semantics",
        ],
        "install": "cargo install circomspect",
        "usage": "circomspect --input circuit.circom",
        "url": "https://github.com/trailofbits/circomspect",
    },
    "picus": {
        "description": "Formal verification of uniqueness property for Circom circuits",
        "capabilities": [
            "Proves circuits are not under-constrained",
            "Uses SMT solver for formal verification",
            "Can verify specific signals are uniquely determined",
        ],
        "limitations": [
            "Performance bottlenecks on large circuits",
            "Limited support for finite field arithmetic in SMT",
            "Only works with Circom (R1CS output)",
        ],
        "install": "See https://github.com/Veridise/Picus",
        "usage": "picus verify --r1cs circuit.r1cs --sym circuit.sym",
        "url": "https://github.com/Veridise/Picus",
    },
    "zkfuzz": {
        "description": "Mutation-based fuzzing for ZK circuits (IEEE S&P 2026)",
        "capabilities": [
            "Detects under-constrained and over-constrained bugs",
            "Uses Trace-Constraint Consistency Test (TCCT)",
            "Outperforms Circomspect, ZKAP, Picus, and ConsCS",
            "Program mutation-based approach",
        ],
        "limitations": [
            "Currently focused on Circom",
            "Requires executable circuit",
            "Probabilistic (may miss bugs)",
        ],
        "install": "See https://github.com/Koukyosyumei/zkFuzz",
        "usage": "zkfuzz fuzz --circuit circuit.circom --iterations 10000",
        "url": "https://github.com/Koukyosyumei/zkFuzz",
    },
    "arguzz": {
        "description": "Fuzzer for testing zkVMs for soundness and completeness bugs",
        "capabilities": [
            "Tests zkVMs specifically",
            "Found previously unknown bugs in 3 zkVMs",
            "Tests both soundness and completeness",
        ],
        "limitations": [
            "Requires zkVM integration",
            "Research prototype",
        ],
        "install": "See arxiv.org/pdf/2509.10819",
        "usage": "Custom integration required",
        "url": "https://arxiv.org/pdf/2509.10819",
    },
    "zk_vanguard": {
        "description": "Veridise's commercial ZK static analyzer",
        "capabilities": [
            "Detects under-constrained bugs",
            "Detects private input leaks",
            "Detects non-deterministic witness code",
            "Supports multiple ZK frameworks",
        ],
        "limitations": [
            "Commercial tool (not freely available)",
            "May require Veridise engagement",
        ],
        "install": "Contact Veridise",
        "usage": "Commercial tool",
        "url": "https://veridise.com/security/tools/zk-static-analyzer/",
    },
    "ecne": {
        "description": "0xPARC's formal verification for Circom uniqueness",
        "capabilities": [
            "Formal verification of circuit uniqueness",
            "Complementary to Picus",
        ],
        "limitations": [
            "Research tool",
            "Circom only",
        ],
        "install": "See 0xPARC GitHub",
        "usage": "Research prototype",
        "url": "https://github.com/0xPARC",
    },
    "ac4": {
        "description": "Algebraic Computation Checker for Circuit Constraints",
        "capabilities": [
            "Encodes circuit constraints as polynomial equation systems",
            "Solves over finite fields using algebraic computation",
            "Categorizes constraint problems by maximal degree",
        ],
        "limitations": [
            "Research tool",
            "May not scale to production circuits",
        ],
        "install": "See arxiv.org/html/2403.15676v1",
        "usage": "Research prototype",
        "url": "https://arxiv.org/html/2403.15676v1",
    },
}


# =============================================================================
# SECTION 7: REFERENCE - KNOWN ZK BUGS DATABASE
# =============================================================================

KNOWN_ZK_BUGS = [
    {
        "project": "SP1 (Succinct)",
        "vuln": "Missing REMUW constraint term",
        "class": "MISSING_CONSTRAINT",
        "impact": "Malicious prover could forge execution proofs",
        "discovery": "Our team",
        "payout": "N/A (responsible disclosure)",
    },
    {
        "project": "SP1 (Succinct)",
        "vuln": "Register 0 memory access not restricted",
        "class": "MEMORY_ACCESS_VIOLATION",
        "impact": "Prover can prove false statements via register manipulation",
        "discovery": "LambdaClass / 3Mi Labs / Aligned",
        "payout": "N/A",
    },
    {
        "project": "SP1 (Succinct)",
        "vuln": "Execution completion flag not enforced",
        "class": "EXECUTION_FLAG_BYPASS",
        "impact": "Proof for partially executed program accepted",
        "discovery": "LambdaClass",
        "payout": "N/A",
    },
    {
        "project": "RISC Zero",
        "vuln": "rv32im missing constraint (CVE-2025-52484)",
        "class": "REGISTER_CONFUSION",
        "impact": "rs1 treated as rs2 in 3-register instructions",
        "discovery": "Christoph Hochrainer via HackenProof",
        "payout": "Critical bounty paid",
    },
    {
        "project": "JOLT",
        "vuln": "lui instruction immediate manipulation",
        "class": "IMMEDIATE_MANIPULATION",
        "impact": "Prover can control lui instruction output",
        "discovery": "Security researcher",
        "payout": "N/A",
    },
    {
        "project": "zkSync Era",
        "vuln": "ZK-EVM soundness bug in circuits",
        "class": "MISSING_CONSTRAINT",
        "impact": "Malicious prover could produce proofs for invalid blocks",
        "discovery": "ChainLight (Sept 2023)",
        "payout": "$50,000 (at the time)",
    },
    {
        "project": "Scroll / PSE zkEVM",
        "vuln": "Modulo circuit missing constraint",
        "class": "INCOMPLETE_CONSTRAINT",
        "impact": "Prover could prove false modulo operations",
        "discovery": "Security audit",
        "payout": "N/A (audit finding)",
    },
    {
        "project": "Zcash",
        "vuln": "Under-constrained circuit allowing token counterfeiting",
        "class": "MISSING_CONSTRAINT",
        "impact": "Unlimited token counterfeiting",
        "discovery": "Zcash team (2018)",
        "payout": "N/A (internal)",
    },
    {
        "project": "CircomLib",
        "vuln": "LessThan missing range check on inputs",
        "class": "MISSING_RANGE_CHECK",
        "impact": "Comparison bypass with large numbers",
        "discovery": "Community",
        "payout": "N/A",
    },
    {
        "project": "ZK Email",
        "vuln": "Under-constrained circuit for email address spoofing",
        "class": "UNCONSTRAINED_SIGNAL",
        "impact": "Email address spoofing via forged proofs",
        "discovery": "Security audit",
        "payout": "N/A",
    },
    {
        "project": "Plonky3",
        "vuln": "Polynomial evaluation incomplete verification",
        "class": "LOOKUP_TABLE_BYPASS",
        "impact": "Proof accepted without full calculation verification",
        "discovery": "LambdaClass",
        "payout": "N/A",
    },
    {
        "project": "Multiple SNARK libraries",
        "vuln": "Frozen Heart (weak Fiat-Shamir)",
        "class": "WEAK_FIAT_SHAMIR",
        "impact": "Prover can manipulate verifier challenges",
        "discovery": "Trail of Bits",
        "payout": "N/A",
    },
]


# =============================================================================
# SECTION 8: UTILITY FUNCTIONS
# =============================================================================

def get_priority_targets(max_count: int = 5) -> list[ZKBountyTarget]:
    """Return the top bounty targets ranked by ROI (payout / difficulty / competition)."""
    def score(target: ZKBountyTarget) -> float:
        payout = float(target.max_payout.replace("$", "").replace(",", "").replace("+", ""))
        difficulty_penalty = target.difficulty
        competition_map = {"Low": 1, "Medium": 2, "High": 3}
        competition_penalty = competition_map.get(target.competition, 2)
        return payout / (difficulty_penalty * competition_penalty)

    ranked = sorted(TOP_ZK_BOUNTIES, key=score, reverse=True)
    return ranked[:max_count]


def get_patterns_for_target(target_name: str) -> list[ZKVulnPattern]:
    """Get the most relevant vulnerability patterns for a given target."""
    target = next((t for t in TOP_ZK_BOUNTIES if t.name.lower() in target_name.lower()), None)
    if not target:
        return ZK_VULN_PATTERNS  # Return all if target not found

    # Map string names to enum members (priority_vulns uses enum names like "MISSING_CONSTRAINT")
    priority_classes = set()
    for v in target.priority_vulns:
        try:
            priority_classes.add(ZKVulnClass[v])
        except KeyError:
            try:
                priority_classes.add(ZKVulnClass(v))
            except ValueError:
                pass
    return [p for p in ZK_VULN_PATTERNS if p.vuln_class in priority_classes]


def print_checklist():
    """Print the full audit checklist."""
    print(ZK_AUDIT_CHECKLIST)


def print_methodology():
    """Print the full audit methodology."""
    print(ZK_AUDIT_METHODOLOGY)


def print_top_targets():
    """Print ranked bounty targets."""
    targets = get_priority_targets(10)
    print("\n=== TOP ZK BOUNTY TARGETS (Ranked by ROI) ===\n")
    for i, t in enumerate(targets, 1):
        print(f"{i}. {t.name}")
        print(f"   Platform: {t.platform}")
        print(f"   Max Payout: {t.max_payout}")
        print(f"   Difficulty: {'*' * t.difficulty} ({t.difficulty}/5)")
        print(f"   Competition: {t.competition}")
        print(f"   Our Edge: {t.our_edge}")
        print(f"   Priority Vulns: {', '.join(t.priority_vulns)}")
        print(f"   Repo: {t.repo_url}")
        print()


if __name__ == "__main__":
    print("=" * 80)
    print("ZK CIRCUIT VULNERABILITY HUNTING SYSTEM")
    print("=" * 80)
    print()
    print_top_targets()
    print()
    print_checklist()
    print()
    print_methodology()
