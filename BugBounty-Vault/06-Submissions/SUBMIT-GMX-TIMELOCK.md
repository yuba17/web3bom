## Summary

The `initialize_executor` instruction in the GMX-Solana Timelock program has no access control, unlike every other instruction in the program which requires role-based authorization. Any user can front-run executor creation for any role/store combination, preventing the legitimate admin from initializing executors and potentially blocking the entire timelock governance system.

## Vulnerability Detail

In [`programs/timelock/src/lib.rs`](https://github.com/gmsol-labs/gmx-solana/blob/main/programs/timelock/src/lib.rs), every instruction has `#[access_control(CpiAuthenticate::only(...))]` except `initialize_executor`:

```rust
// ALL other instructions have access control:
#[access_control(internal::Authenticate::only_admin(&ctx))]
pub fn initialize_config(...) -> Result<()> { ... }

#[access_control(internal::Authenticate::only_admin(&ctx))]
pub fn increase_delay(...) -> Result<()> { ... }

#[access_control(internal::Authenticate::only_timelock_keeper(&ctx))]
pub fn create_instruction_buffer(...) -> Result<()> { ... }

// BUT initialize_executor has NONE:
pub fn initialize_executor(ctx: Context<InitializeExecutor>, role: String) -> Result<()> {
    instructions::initialize_executor(ctx, &role)
}
```

The `InitializeExecutor` accounts struct in `instructions/executor.rs` also performs no role check — it only requires a `payer: Signer` (anyone who pays rent). The executor PDA is derived from `[b"timelock_executor", store_key, role_bytes]`.

Additionally, the `store` account in `InitializeExecutor` is declared as `UncheckedAccount` with `/// CHECK: check by CPI.` — but there is NO CPI call in `initialize_executor`, unlike other instructions where this comment is accurate. The store key is used in PDA seed derivation and stored without verifying it is a valid Store account.

## Proof of Concept

Attack steps:
1. Attacker monitors for new GMX-Solana deployments or role additions
2. For each expected role (e.g., "TIMELOCK_KEEPER", "TIMELOCKED_ADMIN", "TIMELOCKED_MARKET_KEEPER"), attacker calls `initialize_executor` with the target `store` and `role`
3. Since executor PDAs are derived from `[seed, store, role]` and use Anchor's `init`, each (store, role) pair can only be initialized ONCE
4. When the legitimate admin tries to initialize the same executor, the transaction fails because the PDA already exists
5. The attacker-created executor has the correct PDA address but was initialized by the attacker's payer account

The attacker can also pass any arbitrary pubkey as `store` (since it's `UncheckedAccount`), creating executor PDAs for non-existent or malicious store addresses.

```rust
// Pseudocode for the attack
let executor_pda = find_pda(["timelock_executor", store_key, "TIMELOCK_KEEPER"]);
// Anyone can call this — no role check
initialize_executor(store: any_pubkey, role: "TIMELOCK_KEEPER", payer: attacker);
// Now the legitimate admin CANNOT initialize this executor
// The PDA is taken, and Anchor's `init` constraint prevents re-initialization
```

## Impact

- **Timelock system DoS**: An attacker can pre-create all executor PDAs for all expected roles, blocking the admin from initializing the timelock governance system
- **Applies to new deployments**: Every new store deployment is vulnerable during the setup phase
- **No recovery without program upgrade**: Once an executor PDA is created at a given (store, role) address, it cannot be re-created. The admin would need to use different role names or upgrade the program
- **UncheckedAccount store**: Executors can be created pointing to invalid store addresses, cluttering the state
- **Inconsistency with all other instructions**: This is clearly an oversight — every other instruction in the Timelock program has explicit access control

## Recommended Mitigation

Add the same access control pattern used by other instructions:

```rust
#[access_control(internal::Authenticate::only_admin(&ctx))]
pub fn initialize_executor(ctx: Context<InitializeExecutor>, role: String) -> Result<()> {
    instructions::initialize_executor(ctx, &role)
}
```

Also validate the `store` account in `InitializeExecutor`:

```rust
/// Store.
pub store: AccountLoader<'info, gmsol_store::states::Store>,
// Instead of: pub store: UncheckedAccount<'info>,
```
