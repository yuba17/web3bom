# IAR-DD-03: CommitmentReadIsm Does Not Validate ICA Address — CCIP Redirect Attack

## Bug Description

`CommitmentReadIsm.verify()` (line 52-78) extracts the ICA address from `_metadata[:20]`, which is provided by the off-chain CCIP-read service. The function verifies that `keccak256(_metadata[20:])` matches the commitment in the message, but **never validates that the ICA address corresponds to the message's origin/sender/ISM fields**.

```solidity
// CommitmentReadIsm.sol:52-78
function verify(bytes calldata _metadata, bytes calldata _message) external returns (bool) {
    bytes32 revealedHash = keccak256(_metadata[20:]);
    bytes32 msgCommitment = _message.body().revealCommitment();
    require(revealedHash == msgCommitment, "Commitment ISM: Revealed Hash Invalid");

    // BUG: ICA address from metadata, NOT validated against message
    address _ica = address(bytes20(_metadata[:20]));  // Line 65
    OwnableMulticall ica = OwnableMulticall(payable(_ica));

    ica.revealAndExecute(calls, salt);  // Executes on unvalidated ICA
    return true;
}
```

## Impact

**A compromised or malicious CCIP-read service can redirect execution to the wrong ICA.**

If two ICAs have pending commitments with the same hash (same salt + same calls), the CCIP service can return metadata pointing to ICA_B instead of ICA_A. The `verify()` function will:
1. Accept the metadata (hash matches the message commitment)
2. Execute the calls on ICA_B (wrong account)
3. ICA_A's commitment remains stuck permanently (DoS)

This breaks the security model where only ISM validators should be trusted — the CCIP service becomes an additional trusted party that can redirect cross-chain execution without validator collusion.

## Risk Breakdown

- **Difficulty**: Requires compromised CCIP service (external trust assumption)
- **On-chain**: `callRemoteCommitReveal` confirmed in deployed Polygon router
- **Severity**: High — breaks security model, enables execution redirect + permanent DoS of legitimate commitment
- **Fix**: Derive expected ICA address from message fields and require it matches `_metadata[:20]`

## Recommendation

```solidity
function verify(bytes calldata _metadata, bytes calldata _message) external returns (bool) {
    bytes32 revealedHash = keccak256(_metadata[20:]);
    bytes32 msgCommitment = _message.body().revealCommitment();
    require(revealedHash == msgCommitment, "Commitment ISM: Revealed Hash Invalid");

    address _ica = address(bytes20(_metadata[:20]));

    // FIX: Validate ICA address against message fields
    address expectedIca = router.getDeployedInterchainAccount(
        _message.origin(), _message.sender(), _message.recipient(), /* ISM from body */
    );
    require(_ica == expectedIca, "Commitment ISM: ICA address mismatch");

    // ... rest unchanged
}
```

## Proof of Concept

Test demonstrates two ICAs with same commitment, metadata redirected to wrong ICA. 2/2 tests PASS.

### Running

```bash
cd hyperlane-monorepo/solidity
source ../../.env && export ETH_RPC_URL
forge test --match-contract IAR_DD_03 -vvv
```
