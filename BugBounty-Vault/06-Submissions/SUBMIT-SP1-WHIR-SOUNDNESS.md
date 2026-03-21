# SP1 Bug Bounty Submission: Whir Verifier Uses Prover-Supplied Config for All Security Parameters (Critical Soundness Bug)

## Summary

The native Whir PCS verifier in `slop/crates/whir/src/verifier.rs` uses `proof.config` (prover-supplied) instead of `self.config` (verifier-trusted) for all security-critical parameters. A malicious prover can supply a config with zero OOD samples, zero FRI queries, and zero proof-of-work bits, completely bypassing all proximity and evaluation checks. This reduces the Whir PCS soundness guarantee to zero, allowing the prover to forge proofs for arbitrary false statements.

## Severity

**Critical** — Complete soundness break when Whir is used as the PCS. A malicious prover can prove any false statement.

## Vulnerability Details

### Root Cause

In `slop/crates/whir/src/verifier.rs`, the `verify()` function at **line 169** assigns:

```rust
let config = &proof.config; // BUG: uses prover-supplied config
```

The `Verifier` struct holds a trusted config in `self.config` (set during construction via `Verifier::new()` at line 139-146), but `verify()` shadows it with the prover-supplied `proof.config` for **all** security-critical parameters:

| Parameter | Line | Purpose | Controlled by |
|-----------|------|---------|---------------|
| `round_parameters` | 265 | Queries, OOD, PoW per round | Prover ✗ |
| `starting_ood_samples` | 196 | Out-of-domain evaluation samples | Prover ✗ |
| `starting_folding_pow_bits` | 243 | Proof-of-work difficulty | Prover ✗ |
| `starting_log_inv_rate` | 257 | Reed-Solomon code rate | Prover ✗ |
| `domain_generator` | 258 | Evaluation domain generator | Prover ✗ |
| `final_poly_log_degree` | 418, 481 | Final polynomial degree bound | Prover ✗ |
| `final_queries` | 427 | Number of final FRI queries | Prover ✗ |
| `final_pow_bits` | 473 | Final proof-of-work difficulty | Prover ✗ |
| `final_folding_pow_bits` | 482 | Final sumcheck PoW | Prover ✗ |

The verifier's own `self.config` is only used in **two** places:
- Line 184: shape check (`self.config.starting_interleaved_log_height`)
- Line 585: point splitting in `verify_trusted_evaluation`

### How the WHIR Protocol Works

WHIR is a polynomial commitment scheme where soundness relies on three pillars:

1. **OOD (Out-of-Domain) samples**: Verify that the committed polynomial evaluates correctly at random points outside the evaluation domain.
2. **FRI/STIR queries**: Verify that the committed data forms a valid low-degree codeword (proximity testing).
3. **Proof-of-Work**: Adds computational cost to forgery attempts.

The sumcheck protocol provides algebraic consistency but does NOT substitute for OOD/query checks — it only proves that the prover's messages are internally consistent, without verifying they correspond to the committed polynomial.

### Evidence: Recursive Verifier Is Correct

The recursive (in-circuit) Whir verifier at `crates/recursion/circuit/src/basefold/whir.rs` correctly uses `self.config`:

```rust
// Line 95 — CORRECT: uses self.config (trusted)
let n_rounds = self.config.round_parameters.len();

// Line 98 — CORRECT
(0..self.config.starting_ood_samples)

// Line 138 — CORRECT
num_variables - self.config.starting_interleaved_log_height,
```

This confirms the native verifier's use of `proof.config` is a bug, not a design choice.

### Whir Is Used in SP1 Hypercube Verification

The Whir verifier is integrated into SP1's shard verification path:

```rust
// crates/hypercube/src/verifier/shard.rs:6
use slop_whir::{Verifier, WhirProofShape};

// crates/hypercube/src/verifier/shard.rs:770-784
pub fn from_config(
    config: &WhirProofShape<GC::F>,
    max_log_row_count: usize,
    machine: Machine<GC::F, A>,
    num_expected_commitments: usize,
) -> Self {
    let merkle_verifier = MerkleTreeTcs::default();
    let verifier = Verifier::<GC>::new(merkle_verifier, config.clone(), num_expected_commitments);
    let jagged_verifier = JaggedPcsVerifier::<GC, Verifier<GC>>::new(verifier, max_log_row_count);
    Self { jagged_pcs_verifier: jagged_verifier, machine }
}
```

## Attack Scenario

### Preconditions
- SP1 is configured to use Whir as the PCS (via `ShardVerifier::from_config` with `WhirProofShape`)
- The attacker is a malicious prover who wants to prove a false statement

### Step-by-Step Attack

1. **Construct malicious config**: The prover includes the following in `proof.config`:
   ```
   WhirProofShape {
       starting_ood_samples: 0,          // Skip ALL OOD checks
       starting_interleaved_log_height: H, // Must match self.config
       starting_log_inv_rate: 1,
       starting_folding_pow_bits: [0.0; N-H],
       domain_generator: <any valid generator>,
       round_parameters: [RoundParameters {
           num_queries: 0,              // Skip ALL proximity queries
           ood_samples: 0,              // Skip round OOD
           folding_factor: 0,           // No folding in this round
           pow_bits: [],
           queries_pow_bits: 0.0,       // Skip PoW
           evaluation_domain_log_size: <valid>,
       }],
       final_poly_log_degree: H,
       final_queries: 0,                // Skip ALL final queries
       final_pow_bits: 0.0,             // Skip final PoW
       final_folding_pow_bits: [0.0; H],
   }
   ```

2. **Bypass initial OOD** (line 196): With `starting_ood_samples = 0`, no OOD points are sampled. The check at line 207 (`ood_points != commitment.ood_points`) passes because both are empty.

3. **Bypass round queries** (line 297): With `num_queries = 0`, no STIR query indices are sampled. `verify_tensor_openings` at line 323-330 is called with empty `id_query_indices` — the function checks `indices.len() == proof.paths.dimensions.sizes()[0]` (both 0), and the verification loop (tcs.rs line 116) iterates 0 times.

4. **Pass final commitment shape** (line 436): After 1 round, `prev_commitment = proof.commitments[1]` (prover-controlled with `commitment.len() == 1`). The `assert_eq!(prev_commitment.commitment.len(), 1)` passes.

5. **Bypass final queries** (line 427): With `final_queries = 0`, no final Merkle openings are verified.

6. **Bypass all PoW** (lines 307, 473): With `queries_pow_bits = 0.0` and `final_pow_bits = 0.0`, `check_witness(0, ...)` accepts any witness.

7. **Forge sumcheck messages**: The prover constructs sumcheck messages for a polynomial `g ≠ f` (where `f` is the committed polynomial) such that `g` satisfies the false evaluation claim. The sumcheck is sound — it correctly verifies that `g` evaluates as claimed. But without OOD samples or FRI queries, there is **no check** that `g` matches the committed `f`.

8. **Pass final evaluation** (line 591): The prover chooses `proof.final_polynomial` and sumcheck messages such that `Mle::full_lagrange_eval(&randomness, &point) == claimed_value`. Since the prover controls the polynomial g through the sumcheck messages, they can satisfy this check for any false claim.

### Result

The verifier accepts a proof for a false statement. The committed polynomial `f` satisfies `f(point) ≠ claimed_value`, but the prover proved `f(point) = claimed_value` by constructing consistent messages for a different polynomial `g` where `g(point) = claimed_value`, bypassing all proximity checks that would detect `g ≠ f`.

## Proof of Concept

The following demonstrates the vulnerability by contrasting the legitimate config (stored in `self.config`) with the malicious config a prover would embed in `proof.config`:

```rust
// ============================================================
// LEGITIMATE CONFIG (from WhirProofShape::default_whir_config())
// This is what self.config contains after Verifier::new()
// ============================================================
WhirProofShape {
    starting_ood_samples: 1,           // 1 OOD evaluation check
    starting_interleaved_log_height: 12,
    starting_log_inv_rate: 1,
    starting_domain_log_size: 13,
    domain_generator: F::two_adic_generator(13),
    starting_folding_pow_bits: vec![10.0; 4],  // 10 bits PoW per fold
    round_parameters: vec![
        RoundConfig {
            num_queries: 90,           // 90 FRI proximity queries
            ood_samples: 1,            // 1 OOD check per round
            queries_pow_bits: 10.0,    // 10 bits PoW
            pow_bits: vec![10.0; 4],   // 10 bits PoW per fold
            folding_factor: 4,
            evaluation_domain_log_size: 12,
            log_inv_rate: 4,
        },
        RoundConfig {
            num_queries: 15,           // 15 FRI proximity queries
            ood_samples: 1,
            queries_pow_bits: 10.0,
            pow_bits: vec![10.0; 4],
            folding_factor: 4,
            evaluation_domain_log_size: 11,
            log_inv_rate: 7,
        },
    ],
    final_queries: 10,                 // 10 final FRI queries
    final_pow_bits: 10.0,              // 10 bits PoW
    final_poly_log_degree: 4,
    final_folding_pow_bits: vec![10.0; 8],
}

// ============================================================
// MALICIOUS CONFIG (embedded in proof.config by attacker)
// This is what the verifier ACTUALLY uses due to the bug
// ============================================================
WhirProofShape {
    starting_ood_samples: 0,           // ZERO OOD checks — no evaluation verification
    starting_interleaved_log_height: 12, // Must match self.config (line 184, 585)
    starting_log_inv_rate: 1,
    starting_domain_log_size: 13,
    domain_generator: F::two_adic_generator(13),
    starting_folding_pow_bits: vec![0.0; 1],  // ZERO PoW
    round_parameters: vec![
        RoundConfig {
            num_queries: 0,            // ZERO queries — no proximity testing
            ood_samples: 0,            // ZERO OOD — no evaluation checks
            queries_pow_bits: 0.0,     // ZERO PoW
            pow_bits: vec![],          // ZERO PoW
            folding_factor: 0,         // No folding (just pass through)
            evaluation_domain_log_size: 13,
            log_inv_rate: 1,
        },
    ],
    final_queries: 0,                  // ZERO final queries — no Merkle verification
    final_pow_bits: 0.0,              // ZERO final PoW
    final_poly_log_degree: 12,        // = starting_interleaved_log_height (dimension match)
    final_folding_pow_bits: vec![0.0; 12],  // ZERO PoW
}
```

### Why the malicious config is accepted

The `verify()` function at line 169 assigns `let config = &proof.config`, then uses this malicious config throughout:

1. **Line 196**: `(0..config.starting_ood_samples)` → iterates 0 times → no OOD points sampled
2. **Line 265**: `config.round_parameters[0]` → single round with all zeros
3. **Line 297**: `(0..round_params.num_queries)` → iterates 0 times → no query indices
4. **Line 307**: `check_witness(0, ...)` → accepts any witness (0 bits PoW)
5. **Line 320-330**: `verify_tensor_openings` called with empty indices → `tcs.rs:116` loop iterates 0 times
6. **Line 427**: `(0..config.final_queries)` → iterates 0 times → no final verification
7. **Line 473**: `check_witness(0, ...)` → trivially passes

The **only** constraint the attacker must satisfy: `proof.config.starting_interleaved_log_height` must match `self.config.starting_interleaved_log_height` (enforced at lines 184 and 585). All other parameters are freely chosen by the attacker.

### Why the sumcheck alone cannot prevent the attack

The sumcheck protocol (lines 238-246, 379-387, 477-485) IS algebraically sound — it correctly verifies that the prover's polynomial evaluates as claimed. However, soundness of the PCS requires that the prover's polynomial matches the **committed** polynomial. This binding is established by:

- **OOD evaluation checks**: Verify committed polynomial at random out-of-domain points
- **FRI/STIR proximity queries**: Verify committed data forms a valid low-degree codeword

With both set to 0, the prover can construct sumcheck messages for an arbitrary polynomial `g ≠ f` that satisfies any false evaluation claim. The verifier has no way to detect that `g` differs from the committed `f`.

## Impact

- **Complete soundness break**: Any statement can be proven when Whir is used as the PCS
- **Affects**: Native Whir verifier (Rust). The recursive (in-circuit) verifier is NOT affected (uses `self.config` correctly)
- **SP1 Integration**: Whir is available as a PCS option via `ShardVerifier::from_config` in `crates/hypercube/src/verifier/shard.rs`
- **Note**: SP1's default PCS is `StackedPcsVerifier` (BaseFold), not Whir. The default configuration is NOT affected.

## Recommended Fix

Replace `proof.config` with `self.config` in `verify()`:

```diff
--- a/slop/crates/whir/src/verifier.rs
+++ b/slop/crates/whir/src/verifier.rs
@@ -166,7 +166,7 @@
         proof: &WhirProof<GC>,
         challenger: &mut GC::Challenger,
     ) -> Result<(Point<GC::EF>, GC::EF), WhirProofError> {
-        let config = &proof.config;
+        let config = &self.config;
         let n_rounds = config.round_parameters.len();
```

Additionally, either remove `config` from `WhirProof` entirely, or add an explicit equality check:

```rust
if proof.config != self.config {
    return Err(WhirProofError::ConfigMismatch);
}
```

## References

- **Vulnerable file**: `slop/crates/whir/src/verifier.rs` line 169
- **Correct implementation**: `crates/recursion/circuit/src/basefold/whir.rs` line 95 (uses `self.config`)
- **SP1 integration**: `crates/hypercube/src/verifier/shard.rs` lines 6, 770-784
- **SP1 version**: v6.0.0 (commit f87f8d6)
