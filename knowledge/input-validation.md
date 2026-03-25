# Input Validation Vulnerabilities -- Combat Briefing

> **Scope**: Missing or insufficient parameter validation in Solidity smart contracts.
> **Sources**: Halborn Top 100 DeFi Hacks (34.6% of cases), OWASP SC05, Solodit findings.
> **Last updated**: 2026-03-23

---

## Why This Matters

Input validation is the #1 vulnerability class by frequency (Halborn 2025: 34.6% of all DeFi hacks).
It's often overlooked because it seems "too simple" — but missing a single bounds check can be critical.
Unlike reentrancy or oracle bugs, these are often missed by automated tools because the "correct" range
depends on business logic context.

---

## Bug Patterns

```yaml
- id: input-001
  pattern: unbounded-array-length
  name: "Unbounded array parameter causes DoS or gas griefing"
  causa_raiz: "Function accepts an array parameter without checking its length. An attacker passes an extremely large array, causing the function to exceed the block gas limit, revert, or become prohibitively expensive."
  como_funciona: "1. Attacker identifies function that iterates over user-supplied array. 2. Calls it with array of thousands of elements. 3. Transaction exceeds block gas limit. 4. If this function is on a critical path (liquidation, withdrawal), it becomes permanently blocked."
  invariante: "Every function that iterates over a user-supplied array must have a maximum length check. Critical-path functions must never iterate over unbounded arrays."
  que_mirar:
    - "Functions with array[] parameters -- especially in loops"
    - "batch operations (batchTransfer, multicall, executeBatch)"
    - "Functions on critical paths (withdraw, liquidate, repay) that take arrays"
    - "Arrays that grow over time via push() without a cap"
    - "Loops over storage arrays that users can add to"
  como_se_arregla: "require(array.length <= MAX_BATCH_SIZE, 'too many'); Use pagination for read-heavy operations."
  trampas:
    - "Some arrays are admin-only or bounded by other logic -- verify the array source"
    - "The gas limit issue depends on the chain (Ethereum vs L2 with higher gas limits)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Halborn Top 100 DeFi Hacks 2025"
  tags: [dos, gas-griefing, array, batch, unbounded-loop]
  incidentes:
    - "Althea Liquid Infrastructure 2024 (C4) -- holders array grows unbounded, distribution function becomes uncallable (HIGH)"
    - "Telcoin 2024 -- unbounded loop in claim function blocked all claims after enough users (HIGH)"
```

```yaml
- id: input-002
  pattern: zero-address-not-checked
  name: "address(0) accepted for critical parameter"
  causa_raiz: "Function that sets an important address (owner, token, oracle, fee recipient) does not reject address(0). Once set to zero address, funds are sent to a black hole or access control breaks permanently."
  como_funciona: "1. Admin accidentally or maliciously sets critical address to address(0). 2. Funds transferred to address(0) are permanently lost. 3. Or access control that compares against address(0) becomes permissionless."
  invariante: "Every function that sets a critical address (owner, admin, token, oracle, feeRecipient, treasury) must revert if the new value is address(0)."
  que_mirar:
    - "Constructor parameters for critical addresses"
    - "Setter functions (setOracle, setTreasury, setFeeRecipient, transferOwnership)"
    - "Initialize functions in upgradeable contracts"
    - "Token addresses passed to approve/transfer"
  como_se_arregla: "require(newAddress != address(0), 'zero address');"
  trampas:
    - "Some protocols intentionally use address(0) to disable a feature (fee=0 means no fee recipient) -- check if by design"
    - "OpenZeppelin's Ownable already checks for zero in transferOwnership -- only flag custom implementations"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "OWASP SC05, Solodit"
  tags: [zero-address, initialization, admin-config]
```

```yaml
- id: input-003
  pattern: slippage-parameter-no-bounds
  name: "Slippage/deadline parameter without reasonable bounds"
  causa_raiz: "User-supplied slippage tolerance or deadline parameter is not bounded. Attacker can pass slippage=100% (accepting any price) or deadline=type(uint256).max (never expires), making sandwich attacks trivially profitable."
  como_funciona: "1. Protocol trusts user-supplied minAmountOut without sanity check. 2. Frontend or integration sets minAmountOut=0 for 'guaranteed execution'. 3. MEV bot sandwiches the transaction for maximum extractable value. 4. User receives far less than market price."
  invariante: "Slippage parameters must be bounded (e.g., maxSlippage <= 5%). Deadline parameters must be within a reasonable future window."
  que_mirar:
    - "Functions with minAmountOut, minOut, amountOutMin set to 0 or not validated"
    - "Deadline parameters compared with block.timestamp (always passes if deadline = block.timestamp)"
    - "Hardcoded slippage = 0 in internal calls to routers"
    - "Swap calls where the caller decides slippage but protocol doesn't cap it"
    - "block.timestamp used AS the deadline (always current, no protection)"
  como_se_arregla: "Enforce minimum output > 0 and deadline > block.timestamp. Consider protocol-level max slippage caps."
  trampas:
    - "Some protocols intentionally allow 100% slippage for emergency withdrawals -- verify context"
    - "On-chain slippage checks may be redundant if there's an off-chain oracle check"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit, MEV research"
  tags: [slippage, sandwich, mev, deadline, minAmountOut]
  incidentes:
    - "Multiple DEX integrations -- hardcoded minAmountOut=0 in swap calls (HIGH, recurring pattern)"
    - "Velodrome integrations -- deadline set to block.timestamp, providing zero protection (MEDIUM)"
    - "SushiSwap RouterV3 -- legacy adapters pass 0 slippage to Uniswap router (HIGH)"
```

```yaml
- id: input-004
  pattern: amount-zero-not-handled
  name: "Zero amount accepted causing unexpected behavior"
  causa_raiz: "Function does not reject amount=0. Zero-amount operations can mint shares for free, trigger events without real activity, bypass cooldowns, or cause division by zero."
  como_funciona: "1. Attacker calls deposit(0) or stake(0). 2. Function proceeds, possibly minting 0 shares but still updating timestamp/checkpoint. 3. Attacker uses the updated checkpoint to bypass time-based restrictions. 4. Or: division by zero in subsequent calculation causes revert on critical path."
  invariante: "State-changing functions with amount parameters should either revert on amount=0 or handle it as a no-op without side effects."
  que_mirar:
    - "deposit(0), withdraw(0), stake(0), transfer(0) -- what side effects occur?"
    - "Does amount=0 bypass cooldown by updating lastAction timestamp?"
    - "Does amount=0 create a position with 0 shares that still has state (mapping entry)?"
    - "Division by amount later in the flow (amount=0 → revert or infinity)"
    - "Events emitted for 0-amount operations (can pollute indexers)"
  como_se_arregla: "require(amount > 0, 'zero amount'); or early return without side effects."
  trampas:
    - "Some protocols use 0-amount calls intentionally to trigger harvest/checkpoint"
    - "ERC-20 spec technically allows transfer(0) -- only flag if there are side effects"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit, C4 findings"
  tags: [zero-amount, checkpoint-bypass, division-by-zero, cooldown]
```

```yaml
- id: input-005
  pattern: type-confusion-downcasting
  name: "Unsafe downcasting truncates value silently"
  causa_raiz: "A uint256 is cast to uint128, uint96, uint64, or smaller type without checking that the value fits. Solidity <0.8 silently truncates; Solidity >=0.8 reverts for arithmetic but NOT for explicit casting."
  como_funciona: "1. Function accepts uint256 but stores as uint128 via explicit cast. 2. Attacker passes value > type(uint128).max. 3. Value is silently truncated (even in Solidity >=0.8 with explicit casts). 4. Stored amount is much smaller than intended, breaking accounting."
  invariante: "Every explicit downcast must be preceded by a bounds check, or use SafeCast library. uint256(type(uint128).max) >= value must hold before casting to uint128."
  que_mirar:
    - "Explicit casts: uint128(x), uint96(x), uint64(x), int128(x)"
    - "Assembly blocks that truncate via and(x, 0xFFFF...)"
    - "Packed storage slots using smaller types"
    - "Casting in libraries (FullMath, TickMath) without caller validation"
    - "Timestamp casts to uint32/uint48 (Y2038/Y2106 problem)"
  como_se_arregla: "Use OpenZeppelin SafeCast or manual check: require(value <= type(uint128).max);"
  trampas:
    - "Solidity >=0.8 only auto-reverts on arithmetic overflow, NOT on explicit casts"
    - "Some truncation is intentional (e.g., extracting lower bits of a hash)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit, Trail of Bits"
  tags: [downcast, truncation, overflow, safecast, packed-storage]
  incidentes:
    - "Morpho -- unsafe uint128 cast on supply/borrow amounts, values > 2^128 silently truncated (CRITICAL)"
    - "Uniswap V3 -- tick calculations using int24 cast from larger types, edge cases at boundaries (MEDIUM)"
```

```yaml
- id: input-006
  pattern: missing-return-value-check
  name: "External call return value not checked"
  causa_raiz: "Function makes an external call (transfer, approve, low-level call) but does not check the return value. The call can fail silently, leaving the contract in an inconsistent state."
  como_funciona: "1. Contract calls token.transfer(to, amount). 2. Transfer fails (e.g., blocklisted recipient, insufficient balance in token). 3. Return value (false) is not checked. 4. Contract proceeds as if transfer succeeded, updating internal accounting. 5. User is credited but funds never moved."
  invariante: "Every external call's return value must be checked. Use SafeERC20.safeTransfer for token operations."
  que_mirar:
    - "ERC20.transfer() / .approve() without return value check"
    - "Low-level call() where success bool is not checked"
    - "IERC20(token).transfer() on non-standard tokens (USDT returns void)"
    - "Multicall/batch patterns where individual call failures are swallowed"
    - "try/catch blocks that catch but don't properly handle the failure"
  como_se_arregla: "Use SafeERC20 library. For low-level calls: require(success, 'call failed');"
  trampas:
    - "Some tokens (USDT) don't return bool -- SafeERC20 handles this correctly"
    - "Some protocols intentionally ignore return values for non-critical calls (logging, optional hooks)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "SWC-104, OWASP SC06"
  tags: [return-value, safeTransfer, unchecked-call, USDT]
  incidentes:
    - "Defrost Finance 2022 -- unchecked transferFrom allowed fake token deposits (CRITICAL, $12M)"
    - "Multiple Compound forks -- cToken.mint() return value not checked, failed deposits credited (HIGH)"
```

```yaml
- id: input-007
  pattern: reentrancy-via-callback-parameter
  name: "User-supplied callback address or data enables reentrancy"
  causa_raiz: "Function accepts a callback address, hook contract, or arbitrary bytes calldata from the user. The callback executes in the middle of state changes, enabling reentrancy or arbitrary code execution."
  como_funciona: "1. Function accepts a 'receiver' or 'callback' parameter. 2. Calls receiver.onAction() mid-execution, before state is finalized. 3. Callback re-enters the contract via another function. 4. State is inconsistent during re-entry, enabling double-spend or manipulation."
  invariante: "Functions that execute user-supplied callbacks must either: (a) complete ALL state changes before the callback (CEI pattern), or (b) use reentrancy guards."
  que_mirar:
    - "Parameters of type address that receive .call(), .delegatecall(), or interface calls"
    - "bytes calldata parameters decoded and executed"
    - "IFlashLoanReceiver, IERC3156FlashBorrower, ISwapCallback patterns"
    - "Arbitrary function selectors passed as parameters"
    - "onERC721Received, onERC1155Received callbacks on user-controlled receivers"
  como_se_arregla: "Apply CEI pattern strictly. Add nonReentrant modifier. Validate callback addresses against allowlist if possible."
  trampas:
    - "Not all callbacks are dangerous -- check if state is fully committed before callback"
    - "Some callbacks are from trusted protocols (Uniswap, Aave flash loans) -- only flag if receiver is user-controlled"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "samczsun, ChainSecurity, pcaversaccio"
  tags: [callback, reentrancy, arbitrary-call, flash-loan, receiver]
```

```yaml
- id: input-008
  pattern: fee-percentage-no-cap
  name: "Fee/rate parameter without maximum cap"
  causa_raiz: "Admin or governance can set a fee parameter to any value including 100% or above. This enables rug pull via excessive fees or breaks protocol math."
  como_funciona: "1. Fee parameter (protocolFee, performanceFee, withdrawFee) has no upper bound. 2. Malicious admin sets fee to 100%. 3. All user withdrawals/swaps lose 100% to fees. 4. Or: fee > 100% causes underflow in (amount - fee), reverting all operations."
  invariante: "Every fee/rate parameter must have a hardcoded maximum (e.g., fee <= 10%). The cap must be enforced in the setter function, not just in the constructor."
  que_mirar:
    - "setFee(), updateFee(), setProtocolFee() without require(fee <= MAX_FEE)"
    - "Fee parameters that can be changed after deployment"
    - "Fees applied as basis points -- is 10000 (100%) or higher accepted?"
    - "Multiple fees that stack (protocol + LP + performance) -- can they sum > 100%?"
    - "Fee-on-transfer tokens where external fee stacks with protocol fee"
  como_se_arregla: "require(newFee <= MAX_FEE, 'fee too high'); where MAX_FEE is a constant, not a variable."
  trampas:
    - "Many bounty programs exclude admin-controlled parameters as 'trusted admin' -- check exclusions"
    - "Some protocols use timelocks for fee changes, which mitigates the instant rug vector"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit, Cyfrin checklist"
  tags: [fee, admin-rug, basis-points, cap, governance]
```

```yaml
- id: input-009
  pattern: timestamp-block-number-manipulation
  name: "Reliance on block.timestamp or block.number for critical logic"
  causa_raiz: "Contract uses block.timestamp for time-sensitive operations (vesting, auctions, cooldowns). Miners/validators can manipulate timestamp within limits (~15 seconds on Ethereum, more on some L2s)."
  como_funciona: "1. Contract uses block.timestamp to determine auction end, vesting cliff, or lock period. 2. Validator manipulates timestamp to end auction early or release locked funds prematurely. 3. Or: block.timestamp is used as a source of randomness (fully predictable)."
  invariante: "block.timestamp must not be the sole source for critical time-sensitive logic with margins < 15 minutes. block.timestamp must never be used as randomness source."
  que_mirar:
    - "Comparisons like require(block.timestamp >= deadline) with tight deadlines"
    - "Auction end times where ±15 seconds matters"
    - "block.timestamp used in modular arithmetic for randomness"
    - "block.number assumptions about time (varies across chains and after merge)"
    - "L2 chains where block.timestamp has different properties (Arbitrum uses L1 timestamp)"
  como_se_arregla: "Accept ±15s variance in designs. Use Chainlink VRF for randomness. Don't assume fixed block times."
  trampas:
    - "Post-merge Ethereum has exact 12s block times -- but L2s vary significantly"
    - "Most time-based bugs are Low/QA unless the window is very tight (<1 minute)"
  severidad: low
  confianza: media
  verificado: true
  fuente: "SWC-116, Solodit"
  tags: [timestamp, block-number, randomness, miner-manipulation, L2]
```

```yaml
- id: input-010
  pattern: external-input-as-storage-key
  name: "User-supplied value used as mapping key without validation"
  causa_raiz: "Function uses a user-supplied parameter as a key into a critical mapping or array index without bounds checking. Attacker can access or overwrite arbitrary storage slots."
  como_funciona: "1. Function takes user-supplied 'id' or 'index' parameter. 2. Uses it directly as mapping key or array index. 3. Attacker passes a crafted value that collides with another user's position. 4. Or: array index out of bounds causes revert on critical path."
  invariante: "User-supplied indices must be bounds-checked against array length. User-supplied IDs must be validated as belonging to the caller."
  que_mirar:
    - "Array access with user-supplied index without bounds check"
    - "tokenId parameters -- does caller own the token?"
    - "poolId or vaultId -- is it a valid, existing pool?"
    - "position IDs that map to state -- can user manipulate another user's position?"
  como_se_arregla: "require(index < array.length); require(ownerOf[id] == msg.sender);"
  trampas:
    - "Solidity >=0.8 auto-reverts on array out-of-bounds -- but this DoS may itself be the bug"
    - "Mapping access with invalid keys returns default (0) -- this may be exploitable"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [array-bounds, mapping-key, position-id, ownership-check]
```

```yaml
- id: input-011
  pattern: calldata-length-mismatch
  name: "Calldata/bytes parameter length not validated"
  causa_raiz: "Function accepts bytes calldata without validating its length matches the expected format. Malformed input can cause abi.decode to read garbage data or truncated parameters."
  como_funciona: "1. Function expects bytes parameter containing encoded struct (e.g., swap path, multicall data). 2. Attacker passes shorter/longer bytes than expected. 3. abi.decode reads beyond actual data, or data is truncated mid-parameter. 4. Results in wrong addresses, wrong amounts, or skipped validation."
  invariante: "Every bytes parameter must be validated for minimum expected length before decoding."
  que_mirar:
    - "abi.decode on user-supplied bytes without length check"
    - "Swap path bytes (Uniswap V3 paths encoded as bytes)"
    - "Multicall payloads where individual call data is not validated"
    - "Custom encoding/decoding that assumes fixed-length fields"
    - "Assembly that reads from calldata at arbitrary offsets"
  como_se_arregla: "require(data.length >= MIN_EXPECTED_LENGTH); Validate encoded data structure before use."
  trampas:
    - "abi.decode itself reverts on malformed data in most cases -- but assembly decoding does NOT"
    - "Some protocols accept variable-length data by design"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Trail of Bits, Solodit"
  tags: [calldata, bytes, abi-decode, assembly, length-check]
```

```yaml
- id: input-012
  pattern: enum-out-of-range
  name: "Enum parameter accepts invalid value"
  causa_raiz: "Function uses a uint8 that represents an enum but does not validate the range. Values beyond the enum's max create undefined behavior."
  como_funciona: "1. Function takes uint8 parameter meant to represent an enum (e.g., action type, pool type). 2. Attacker passes value outside enum range. 3. In Solidity >=0.8, this reverts (DoS if on critical path). 4. In Solidity <0.8, undefined behavior occurs."
  invariante: "Every uint parameter representing an enum must be bounds-checked: require(value <= uint8(type(MyEnum).max))."
  que_mirar:
    - "uint8 parameters used in if/else chains or switch-like patterns"
    - "Functions where enum value routes to different logic paths -- what if none match?"
    - "Default case in if/else that does nothing (silent no-op)"
    - "Cross-contract calls that pass enum as uint"
  como_se_arregla: "Use the actual enum type in the function signature, or validate explicitly."
  trampas:
    - "Solidity >=0.8.0 with actual enum type auto-reverts on invalid cast from uint"
    - "This is usually Low unless the revert blocks a critical operation"
  severidad: low
  confianza: media
  verificado: true
  fuente: "SWC Registry"
  tags: [enum, type-safety, bounds-check, undefined-behavior]
```

---

## 3. Invariant Checklist

- [ ] Every array parameter has a maximum length check
- [ ] Every critical address setter rejects address(0)
- [ ] Slippage parameters (minAmountOut) are never hardcoded to 0
- [ ] Deadline parameters are always > block.timestamp, never == block.timestamp
- [ ] Fee/rate parameters have hardcoded maximum caps
- [ ] Every explicit downcast (uint128, uint96, uint64) is bounds-checked or uses SafeCast
- [ ] Every external call return value is checked (or uses SafeERC20)
- [ ] User-supplied callback addresses don't enable reentrancy
- [ ] Array indices are bounds-checked before access
- [ ] Bytes/calldata parameters are length-validated before decoding
- [ ] uint parameters representing enums are range-checked
- [ ] Amount parameters of 0 don't cause unexpected side effects

---

## 4. Quick Grep Targets

```bash
# Unbounded loops over user input
grep -rn "for.*\.length" src/ --include="*.sol"
grep -rn "while.*length" src/ --include="*.sol"

# Missing zero-address checks
grep -rn "function set\|function update\|function change" src/ --include="*.sol" | grep -i "address"

# Hardcoded zero slippage
grep -rn "amountOutMin.*=.*0\|minAmountOut.*=.*0\|minOut.*=.*0" src/ --include="*.sol"

# Deadline == block.timestamp (no protection)
grep -rn "block.timestamp" src/ --include="*.sol" | grep -i "deadline"

# Unsafe downcasts
grep -rn "uint128(\|uint96(\|uint64(\|uint48(\|uint32(\|int128(\|int96(" src/ --include="*.sol"

# Unchecked return values
grep -rn "\.transfer(\|\.approve(\|\.call(" src/ --include="*.sol" | grep -v "safe\|Safe\|require\|assert"

# Fee setters without caps
grep -rn "function.*[Ff]ee\|function.*[Rr]ate" src/ --include="*.sol"
```

---

## 5. Real-World Incidents

| Protocol | Year | Loss | Root Cause |
|----------|------|------|-----------|
| Defrost Finance | 2022 | $12M | Unchecked transferFrom return value |
| Althea Liquid Infra | 2024 | DoS | Unbounded holders array in distribution |
| Telcoin | 2024 | DoS | Unbounded loop in claim function |
| Morpho | 2024 | Critical | Unsafe uint128 cast on supply amounts |
| Multiple DEXs | 2023-25 | MEV | Hardcoded minAmountOut=0 in router calls |
| Multiple Compound forks | 2023-24 | Various | cToken.mint() return value not checked |
