# Access Control Vulnerabilities -- Combat Briefing

> **Scope**: Solidity access control bugs for bug bounty hunting.
> **Sources**: invariant-registry (ownership, timelock, exploit_derived).
> **Last updated**: 2026-03-19

---

## Bug Patterns

```yaml
- id: access-001
  pattern: missing-access-control
  name: "Missing access control on critical function"
  causa_raiz: "External/public function that moves funds, upgrades, or changes critical state has no modifier or sender check."
  como_funciona: "1. Attacker identifies unprotected external function (e.g., migrate, upgrade, withdraw). 2. Calls it directly from arbitrary EOA. 3. Drains funds, takes ownership, or corrupts state."
  invariante: "Every state-changing function that moves funds or modifies critical parameters must revert when called by an unauthorized address."
  que_mirar:
    - "All external/public functions -- enumerate them exhaustively"
    - "Functions with no modifier (onlyOwner, onlyRole, etc.)"
    - "Functions where access control exists but is checked in a branch that can be skipped"
    - "Internal functions exposed via a public wrapper without a guard"
    - "Functions added in upgrades that forgot to copy modifiers from the original"
  como_se_arregla: "Add explicit access control modifier. Prefer OpenZeppelin AccessControl over hand-rolled require(msg.sender == owner)."
  trampas:
    - "Some functions are intentionally permissionless (liquidation, keeper calls) -- verify it SHOULD be restricted"
    - "Access control may be enforced deeper in the call stack via an internal function"
  incidentes:
    - "Subsquid (tSQD) -- registerTokenOnL2 had no access control; attacker could front-run and set wrong L2 token address, permanently breaking the bridge (high)"
    - "Burve (SimplexDiamond) -- diamondCut function unrestricted; anyone could add/remove/replace facets and take full control (critical)"
    - "Union Finance (VouchFaucet) -- claimTokens never updated claimedTokens mapping; anyone could drain entire faucet balance (high)"
    - "RabbitHole (Erc20Quest) -- onlyAdminWithdrawAfterEnd modifier only checked timestamp, not caller identity; anyone could call withdrawFee repeatedly draining funds (high)"
    - "RabbitHole (RabbitHoleReceipt) -- onlyMinter modifier had bare comparison without require; anyone could mint receipts and steal quest rewards (critical)"
    - "Connext (DiamondInit) -- acceptanceDelay could be changed by anyone after init; no caller check for critical config fields (high)"
    - "Olympus DAO -- governance proposals passable with 0 votes before first VOTES mint; anyone could take over kernel (critical)"
    - "Boot Finance (Vesting) -- vest() had no beneficiary check; attacker could spam timelocks to DoS all claimable vestments via gas limit (high)"
    - "Winnables Raffles -- admin could self-grant role(1) on WinnablesTicket to mint unlimited tickets and rig raffle outcomes (medium)"
    - "Alchemix -- EmissionScheduler.epochEmission() lacks access control; anyone could cause epoch to mint zero emissions, disrupting reward distribution (high)"
    - "Kakarot zkEVM -- exec_precompile checked caller's code address but delegatecall preserved code address while changing context; unauthorized contracts accessed privileged precompiles (high)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-003 (defihacklabs), INV-OWN-002"
  verificado: true
  tags: [authorization, privilege-escalation, unprotected-function]
  relacionado_con: [access-003, access-006, access-008]
  incidentes_verificados:
    - nombre: "SafeMoon"
      fecha: "Mar 2023"
      perdida: "$8.9M"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "LeetSwap"
      fecha: "Aug 2023"
      perdida: "$630K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MEVBot"
      fecha: "Nov 2023"
      perdida: "$2M"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MEVBot_0x8c2d"
      fecha: "Nov 2023"
      perdida: "$365K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MEVBot_0xa247"
      fecha: "Nov 2023"
      perdida: "$150K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "AIS"
      fecha: "Nov 2023"
      perdida: "$61K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CEXISWAP"
      fecha: "Sep 2023"
      perdida: "$30K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CIVNFT"
      fecha: "Jul 2023"
      perdida: "$180K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Civfund"
      fecha: "Jul 2023"
      perdida: "$165K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "USDTStakingContract28"
      fecha: "Jul 2023"
      perdida: "$20,999"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "DEPUSDT_LEVUSDC"
      fecha: "Jun 2023"
      perdida: "$105K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Melo"
      fecha: "May 2023"
      perdida: "$90K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "LocalTrade"
      fecha: "May 2023"
      perdida: "384 BNB"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "LaunchZone"
      fecha: "Feb 2023"
      perdida: "$320K"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "SwapX"
      fecha: "Feb 2023"
      perdida: "$1M"
      tipo: "Access Control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "VeloCore"
      fecha: "Jun 2024"
      perdida: "$6.88M"
      tipo: "Lack of access control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Shezmu"
      fecha: "Sep 2024"
      perdida: "$4.9M"
      tipo: "Access control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "HedgeyFinance"
      fecha: "Apr 2024"
      perdida: "$48M"
      tipo: "Logic flaw - access related"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Lifiprotocol"
      fecha: "Jul 2024"
      perdida: "$10M"
      tipo: "Incorrect input validation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "GFOX"
      fecha: "May 2024"
      perdida: "$330K"
      tipo: "Lack of access control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "PLN"
      fecha: "Sep 2024"
      perdida: "$400K"
      tipo: "Access control"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MetaPoint"
      fecha: "Apr 2023"
      perdida: "$820K"
      tipo: "Unrestricted Approval"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "SocketGateway"
      fecha: "Jan 2024"
      perdida: "$3.3M"
      tipo: "Lack of calldata validation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
```

```yaml
- id: access-002
  pattern: single-step-ownership-transfer
  name: "Ownership transfer without 2-step confirmation"
  causa_raiz: "transferOwnership(address) changes owner in one transaction. A typo in the new address permanently locks all admin functions."
  como_funciona: "1. Owner calls transferOwnership(wrongAddress). 2. Ownership transfers immediately. 3. No way to recover -- all onlyOwner functions are permanently locked."
  invariante: "After transferOwnership(newOwner), owner() must still equal oldOwner until newOwner calls acceptOwnership()."
  que_mirar:
    - "Contract imports Ownable instead of Ownable2Step"
    - "Custom ownership logic with no pendingOwner pattern"
    - "Protocols where ownership controls fund withdrawal or upgrades (high impact if lost)"
  como_se_arregla: "Use Ownable2Step (OpenZeppelin). transferOwnership sets pendingOwner; acceptOwnership completes the transfer."
  trampas:
    - "Not always exploitable by attacker -- more of a governance risk"
    - "Some protocols intentionally use single-step for simplicity (low value contracts)"
  incidentes:
    - "Velodrome (CLGaugeFactory) -- setEmissionAdmin/setNotifyAdmin transferred roles in single step; mistyped address permanently locks admin (low)"
    - "Clober (MarketFactory) -- handOverHost single-step transfer; typo could disrupt fee collection (medium)"
    - "Liquid Collective (LibOwnable) -- _setAdmin allowed setting address(0) as admin, locking all admin functions across 4 contracts (medium)"
  severidad: high
  confianza: alta
  fuente: "INV-OWN-003"
  verificado: true
  tags: [owner, two-step, governance-risk]
  relacionado_con: [access-001]
```

```yaml
- id: access-003
  pattern: uninitialized-proxy-implementation
  name: "Uninitialized proxy implementation"
  causa_raiz: "Implementation contract behind a proxy was never initialized. Attacker calls initialize() on the implementation directly, becoming its owner, then uses that to compromise the proxy."
  como_funciona: "1. Protocol deploys proxy + implementation. Proxy is initialized, implementation is not. 2. Attacker calls initialize() on the implementation contract directly. 3. Attacker becomes owner of implementation. 4. In UUPS pattern, attacker calls upgradeTo() on implementation to point to malicious contract. 5. Proxy now delegates to attacker-controlled logic."
  invariante: "The initialize function must revert on any call after the first successful execution. Implementation contracts must be initialized or have their initializers disabled in the constructor."
  que_mirar:
    - "Implementation contracts without _disableInitializers() in constructor"
    - "UUPS implementations where upgradeTo is on the logic contract"
    - "Multiple initialize functions (initialize, initializeV2) where only one is protected"
    - "reinitializer(version) with a version that has not been consumed"
  como_se_arregla: "Call _disableInitializers() in the implementation constructor. Use initializer modifier on all init functions."
  trampas:
    - "reinitializer(version) is legitimate for upgrade migrations -- only flag if version is re-callable"
  incidentes:
    - "Saffron (RestrictedVaultFactory) -- initializeVault not overridden; previous owner could initialize vaults with arbitrary params after ownership transfer (low)"
    - "Covalent (DelegatedStaking) -- used non-upgradeable Ownable in upgradeable proxy; constructor never ran, owner stuck at address(0), all onlyOwner functions bricked (critical)"
  severidad: critical
  confianza: alta
  fuente: "INV-OWN-005, INV-EXPLOIT-009"
  verificado: true
  tags: [proxy, initializer, upgradeable]
  relacionado_con: [access-004]
```

```yaml
- id: access-004
  pattern: proxy-storage-collision
  name: "Storage collision in proxy upgrade"
  causa_raiz: "Proxy and implementation use overlapping storage slots, or a new implementation changes the storage layout, corrupting existing state."
  como_funciona: "1. Proxy stores admin/implementation in non-EIP-1967 slots that overlap with implementation variables. 2. Implementation writes to slot 0 (e.g., owner), which is also the proxy's admin slot. 3. State corruption: proxy admin is overwritten, or implementation logic reads garbage. 4. In worst case, attacker gains control of upgrade mechanism."
  invariante: "Storage layouts of proxy and implementation must not overlap. EIP-1967 storage slots must be used for admin, implementation, and beacon addresses."
  que_mirar:
    - "Custom proxy contracts NOT using EIP-1967 slots"
    - "Implementation contracts that inherit differently between versions (changed inheritance order)"
    - "Missing storage gaps (__gap) in base contracts of upgradeable hierarchies"
    - "delegatecall targets that write to fixed storage slots"
  como_se_arregla: "Use EIP-1967 storage slots. Maintain __gap arrays. Use OpenZeppelin storage checker or foundry storage layout diff between upgrades."
  trampas:
    - "Standard OpenZeppelin TransparentUpgradeableProxy and UUPS are safe by default"
    - "Focus on custom proxy implementations"
  incidentes:
    - "LI.FI -- Diamond facets used global variable appStorage on slot 0 instead of getStorage/NAMESPACE pattern; any new facet with a global variable would corrupt access control storage (high)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-009, INV-OWN-004"
  verificado: true
  tags: [proxy, storage-collision, delegatecall, EIP-1967]
  relacionado_con: [access-003, access-008]
```

```yaml
- id: access-005
  pattern: timelock-bypass
  name: "Timelock bypass"
  causa_raiz: "Timelocked operation can be executed without waiting the required delay, or the timelock can be reduced to zero, defeating its purpose."
  como_funciona: "1. Governance action requires a timelock (e.g., 48h delay). 2. Attacker finds a path to execute the action immediately: direct function without timelock check, or ability to set timelock to 0. 3. Malicious parameter change takes effect before users can react (e.g., fee set to 100%, collateral factor changed)."
  invariante: "Active delay must always be within [MIN_TIMELOCK, MAX_TIMELOCK]. A pending delay change (queued but not executed) can legitimately be LARGER than the current delay. The vulnerability is setting delay to 0 or below MIN_TIMELOCK — NOT proposing a larger delay. Queued operation timestamps must be monotonically increasing (no reset-the-clock attacks)."
  que_mirar:
    - "Functions that bypass the timelock path for the same parameter change"
    - "Ability to set timelock to 0 or below MIN_TIMELOCK"
    - "Pending timelock that can be overwritten before expiry to reset the clock"
    - "Emergency functions that skip timelock without proper multi-sig"
    - "Cap increases or fee changes that skip the queue mechanism"
  como_se_arregla: "Enforce MIN_TIMELOCK constant. All parameter changes must go through queue -> wait -> execute. No backdoor functions."
  trampas:
    - "Emergency pause mechanisms intentionally skip timelock -- this is expected"
    - "Cap decreases are often instant by design (reducing exposure is safe)"
  incidentes:
    - "Connext (RootManager/SpokeConnector) -- setDelayBlocks had no minimum; owner could set delayBlocks to 0, collapsing entire fraud protection mechanism (medium)"
    - "Forgeries (VRFNFTRandomDraw) -- recoverTimelock set at initialize, not updated per draw; admin could claim NFT immediately after initialization period, bypassing intended post-draw delay (high)"
    - "Sense (Divider) -- admin could toggle adapter off/on to backfill arbitrary lscales values, bypassing timelock-like protections on user data (medium)"
  severidad: critical
  confianza: alta
  fuente: "INV-TLOCK-009, INV-TLOCK-011, INV-TLOCK-012, INV-TLOCK-015, INV-TLOCK-016"
  verificado: true
  tags: [timelock, governance, delay-bypass]
  relacionado_con: [access-006]
```

```yaml
- id: access-006
  pattern: role-misconfiguration
  name: "Role misconfiguration (wrong role assigned to wrong address)"
  causa_raiz: "AccessControl roles are granted too broadly, or a critical role is granted to an address that should not have it (e.g., external contract granted DEFAULT_ADMIN_ROLE)."
  como_funciona: "1. Protocol uses role-based access (AccessControl). 2. During deployment or governance, wrong address gets a powerful role. 3. That address (or its compromise) allows unauthorized critical operations: upgrade, pause, drain. 4. Alternatively: a role intended to be single-holder can be granted to multiple addresses."
  invariante: "Each privileged role must be held only by the intended addresses. DEFAULT_ADMIN_ROLE holders must be minimized. Role grants must go through timelock or multi-sig."
  que_mirar:
    - "DEFAULT_ADMIN_ROLE granted to EOA instead of timelock/multi-sig"
    - "Role admin for a role is set to a less-trusted role"
    - "grantRole called in constructor with hardcoded addresses -- verify them on-chain"
    - "Missing renounceRole after initial setup"
    - "Roles that overlap in permissions (one role can do everything another can)"
  como_se_arregla: "Principle of least privilege. DEFAULT_ADMIN_ROLE to timelock only. Separate roles for separate functions. Verify on-chain role holders."
  trampas:
    - "Centralization concerns are often out of scope for bug bounties unless the bounty explicitly covers governance"
    - "Multi-sig is considered trusted in most bounty programs"
  incidentes:
    - "AI Arena (Neuron) -- DEFAULT_ADMIN_ROLE never granted; MINTER/STAKER/SPENDER roles irrevocable once granted (medium)"
    - "Escher -- CREATOR_ROLE bypass: malicious creator could grant DEFAULT_ADMIN_ROLE to non-creators, undermining the creator-only edition system (medium)"
    - "Sense (Trust.sol) -- blanket trust authority to all trusted accounts; any single compromised account could lock out all others (medium)"
    - "KelpDAO -- MANAGER role had excessive rights: could add tokens, set oracles, swap assets to drain all deposits (high)"
    - "SeaDrop -- owner could choose themselves as admin in constructor, bypassing protocol fee requirements (medium)"
    - "SeaDrop -- onlyOwnerOrAdministrator modifier let owner override admin's merkle root and set feeBps to 0, circumventing protocol fees (high)"
    - "Party Protocol -- 51% majority could use ArbitraryCallsProposal to mint governance NFTs, then bypass unanimous vote requirement for precious token transfer (high)"
  severidad: high
  confianza: media
  fuente: "INV-OWN-002, INV-TLOCK-010"
  verificado: true
  tags: [access-control, roles, governance, centralization]
  relacionado_con: [access-001, access-005]
```

```yaml
- id: access-007
  pattern: tx-origin-auth
  name: "tx.origin used for authentication"
  causa_raiz: "Contract uses tx.origin instead of msg.sender for authorization. tx.origin is the EOA that initiated the transaction, not the immediate caller."
  como_funciona: "1. Contract checks require(tx.origin == owner). 2. Attacker deploys a malicious contract and tricks the owner into calling it (phishing, malicious dApp). 3. Malicious contract calls the target. tx.origin is the owner, msg.sender is the malicious contract. 4. Authorization passes, attacker executes privileged operation through the owner's transaction."
  invariante: "tx.origin must never be used for authorization. All access control must use msg.sender."
  que_mirar:
    - "Any use of tx.origin in require/if statements"
    - "tx.origin == msg.sender used as a 'no contract' check (different bug, but related)"
    - "Modifier chains where tx.origin is checked instead of msg.sender"
  como_se_arregla: "Replace tx.origin with msg.sender for all authorization checks. If anti-contract check is needed, use code size or EIP-4337 patterns instead."
  trampas:
    - "tx.origin == msg.sender as an anti-contract guard is a different pattern (not auth bypass, but can be bypassed via constructor calls)"
    - "Rare in modern Solidity -- most audited codebases have eliminated this"
  severidad: high
  confianza: alta
  fuente: "Solidity documentation, universal pattern"
  verificado: true
  tags: [tx-origin, phishing, authorization]
  relacionado_con: [access-001]
```

```yaml
- id: access-008
  pattern: delegatecall-untrusted-target
  name: "Delegatecall to untrusted or user-controlled target"
  causa_raiz: "Contract performs delegatecall where the target address is derived from user input or insufficiently validated. delegatecall executes foreign code in the caller's storage context."
  como_funciona: "1. Contract has a function that delegatecalls to an address parameter or a stored address that can be changed. 2. Attacker supplies a malicious contract address. 3. Malicious code executes in the context of the victim contract -- same storage, same balance, same msg.sender. 4. Attacker overwrites owner, drains funds, or self-destructs the contract."
  invariante: "delegatecall target must be immutable or restricted to a hardcoded whitelist. No user-supplied address may be used as a delegatecall target."
  que_mirar:
    - "Any delegatecall where the target is a function parameter"
    - "Stored implementation addresses that can be changed without proper access control"
    - "Proxy patterns where fallback delegates to a mutable implementation"
    - "Multicall/batch patterns that include delegatecall"
    - "Library contracts that use delegatecall internally"
  como_se_arregla: "Hardcode delegatecall targets or restrict to immutable/constant addresses. If upgradeable, protect the upgrade function with strict access control and timelock."
  trampas:
    - "Standard proxy patterns (TransparentProxy, UUPS) use delegatecall by design -- the issue is when the target is changeable without auth"
    - "Solidity libraries use delegatecall internally -- this is safe"
  incidentes:
    - "Sudoswap -- factory owner could whitelist router contracts by first removing them as routers; pair owner could then use call() to invoke pairTransferERC20From and steal approved user funds (high)"
    - "Sudoswap -- clone verification checked only first 54 bytes of bytecode; attacker could deploy malicious clone with valid preamble, pass isPair check, and drain router-approved funds (critical)"
    - "Hats Protocol -- HatsSignerGateBase did not check owner changes post-execution; colluding signers could use delegatecall to swap valid signers with malicious ones, bypassing hat-wearing requirement (medium)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-009, INV-EXPLOIT-003"
  verificado: true
  tags: [delegatecall, proxy, arbitrary-code-execution]
  relacionado_con: [access-001, access-004]
  incidentes_verificados:
    - nombre: "Phoenix"
      fecha: "Mar 2023"
      perdida: "$100K"
      tipo: "Access Control/Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "SushiSwap"
      fecha: "Apr 2023"
      perdida: "$3.3M+"
      tipo: "Input Validation - arbitrary call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Dexible"
      fecha: "Feb 2023"
      perdida: "$1.5M"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CowSwap"
      fecha: "Feb 2023"
      perdida: "$120K"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "RevertFinance"
      fecha: "Feb 2023"
      perdida: "$30K"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MIMSpell"
      fecha: "Jun 2023"
      perdida: "$17K"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "UniBotRouter"
      fecha: "Oct 2023"
      perdida: "$83,944"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MaestroRouter2"
      fecha: "Oct 2023"
      perdida: "280 ETH"
      tipo: "Arbitrary Call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Seneca"
      fecha: "Feb 2024"
      perdida: "$6M"
      tipo: "Arbitrary external call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "ChaingeFinance"
      fecha: "Apr 2024"
      perdida: "$560K"
      tipo: "Arbitrary external call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "BmiZapper"
      fecha: "Jan 2024"
      perdida: "$114K"
      tipo: "Arbitrary external call"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"

- id: access-009
  pattern: broken-modifier-no-revert
  name: "Access control modifier that does not revert"
  causa_raiz: "Modifier performs a comparison (e.g., msg.sender == admin) but lacks require/revert, so the check evaluates to false silently and execution continues, granting access to anyone."
  como_funciona: |
    1. Developer writes modifier with a bare comparison: `msg.sender == minterAddress;` (no require).
    2. Solidity evaluates the expression, discards the boolean result, and falls through to `_;`.
    3. Any address can call the 'protected' function and execute privileged logic (mint, burn, transfer).
    4. Attacker mints unlimited tokens or drains rewards.
  invariante: |
    // For every function with an access modifier:
    // assert(tx reverts when called by unauthorized address)
  que_mirar:
    - "modifier.*\\{[^r]*\\}"
    - "Modifiers with bare comparisons (no require, revert, if+revert)"
    - "msg.sender == .* without require() wrapping"
    - "Custom modifiers (not OZ) on mint, burn, transfer functions"
  como_se_arregla: "Wrap comparison in require(): `require(msg.sender == minterAddress, 'not minter');` or use OZ AccessControl."
  trampas:
    - "Some modifiers delegate the check to an internal function that does revert -- trace the full call"
  incidentes:
    - "RabbitHole -- onlyMinter modifier had bare comparison, anyone could mint receipts and steal all quest rewards (critical)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, modifier, silent-fail, mint]

- id: access-010
  pattern: irrevocable-role-grant
  name: "Roles that cannot be revoked once granted"
  causa_raiz: "Contract uses AccessControl but never grants DEFAULT_ADMIN_ROLE to any address, or uses deprecated _setupRole instead of _grantRole, making it impossible to revoke roles via revokeRole()."
  como_funciona: |
    1. Contract defines MINTER_ROLE, BURNER_ROLE etc. and grants them via addMinter() using _setupRole().
    2. DEFAULT_ADMIN_ROLE (0x00) is never granted to the owner or governance.
    3. revokeRole() requires the caller to have the admin role for the target role.
    4. Since no one holds DEFAULT_ADMIN_ROLE, no one can revoke any role -- compromised role holders retain permanent access.
  invariante: |
    // assert(getRoleAdmin(MINTER_ROLE) != bytes32(0) || hasRole(DEFAULT_ADMIN_ROLE, expectedAdmin))
    // For every role R: there exists an address that can call revokeRole(R, holder)
  que_mirar:
    - "_setupRole"
    - "DEFAULT_ADMIN_ROLE"
    - "grantRole.*without.*DEFAULT_ADMIN"
    - "Missing renounceRole or revokeRole functions"
    - "addMinter|addBurner|addStaker.*_setupRole"
  como_se_arregla: "Grant DEFAULT_ADMIN_ROLE to a timelock/multisig in constructor. Use _grantRole instead of deprecated _setupRole. Implement emergency role revocation."
  trampas:
    - "If the owner has a separate custom revocation mechanism outside AccessControl"
    - "Some protocols intentionally make roles permanent (verify design docs)"
  incidentes:
    - "AI Arena -- MINTER/STAKER/SPENDER roles could never be revoked; _setupRole used instead of _grantRole, DEFAULT_ADMIN_ROLE never granted (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, roles, revocation, AccessControl]

- id: access-011
  pattern: renounce-ownership-lockout
  name: "Dangerous renounceOwnership permanently bricks contract"
  causa_raiz: "Contract inherits Ownable/Ownable2Step but does not override renounceOwnership(). Calling it sets owner to address(0), permanently locking all onlyOwner functions including pause, upgrade, fee withdrawal, and emergency recovery."
  como_funciona: |
    1. Contract inherits OZ Ownable without overriding renounceOwnership().
    2. Owner (or attacker via social engineering) calls renounceOwnership().
    3. Owner is set to address(0) permanently -- no recovery mechanism.
    4. All onlyOwner functions become uncallable: pause, unpause, upgrade, withdraw fees, add/remove trusted addresses.
    5. If contract is paused before renounce, it stays paused forever, bricking all user funds.
  invariante: |
    // assert(owner() != address(0) || contract has no onlyOwner functions)
  que_mirar:
    - "Ownable.*renounceOwnership"
    - "Contracts inheriting Ownable without overriding renounceOwnership"
    - "Contracts with Pausable + Ownable (paused + renounced = bricked)"
    - "renounceOwnership.*revert|renounceOwnership.*override"
  como_se_arregla: "Override renounceOwnership() to revert: `function renounceOwnership() public override onlyOwner { revert('not allowed'); }`"
  trampas:
    - "Some protocols intentionally want owner renunciation (fully decentralized after launch)"
    - "Check if other roles (admin, guardian) can perform the critical functions"
  incidentes:
    - "BOB -- OfframpRegistry inherits Ownable2Step without overriding renounceOwnership; renouncing while paused would permanently brick the contract (medium)"
    - "Connext -- Multiple contracts (WatcherClient, WatchManager, RootManager, ConnextPriceOracle) could have ownership renounced, breaking fraud protection and fee withdrawal permanently (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, ownership, renounce, permanent-lock]

- id: access-012
  pattern: contradictory-access-logic
  name: "Contradictory access control conditions cause permanent DoS"
  causa_raiz: "Function has two access checks (modifier + inline require) that contradict each other, making the function always revert regardless of caller."
  como_funciona: |
    1. Function has modifier: onlyGovernance checks `require(rolesManager.isGovernance(msg.sender))`.
    2. Function body has inline check: `if (rolesManager.isGovernance(msg.sender)) revert ONLY_GOVERNANCE()`.
    3. If caller IS governance: modifier passes, but body reverts.
    4. If caller is NOT governance: modifier reverts.
    5. No one can ever call the function -- critical admin operation permanently bricked.
  invariante: |
    // For every function with access control:
    // assert(there exists at least one address that can call it successfully)
  que_mirar:
    - "Functions with both a modifier AND an inline require/if that reference the same condition"
    - "onlyOwner.*require.*owner|onlyGovernance.*isGovernance"
    - "Copy-paste errors where negation was forgotten"
    - "Functions that always revert in testing"
  como_se_arregla: "Remove the contradictory inline check. Use only the modifier OR only the inline check, not both."
  trampas:
    - "Sometimes the inline check is for a DIFFERENT condition than the modifier -- read carefully"
  incidentes:
    - "Atlendis Labs -- updateRolesManager() had contradictory onlyGovernance modifier and inline isGovernance check; roles manager could never be updated (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, logic-error, permanent-dos, governance]

- id: access-013
  pattern: admin-can-rug-via-parameter-change
  name: "Trusted admin can drain funds via unrestricted parameter changes"
  causa_raiz: "Admin/owner can change critical parameters (oracle, controller, fee recipient, transfer manager) without timelock, enabling immediate fund extraction via parameter manipulation even when admin is supposed to be restricted."
  como_funciona: |
    1. Admin calls setOracle()/setController()/updateWrapper() to point to a malicious contract.
    2. Malicious oracle returns extreme price (e.g., 1 wei per ETH) triggering mass liquidations.
    3. OR malicious controller receives all vault funds via utilize()/migrate() function.
    4. OR admin sets fee to 100% and extracts all value.
    5. Funds are drained in a single transaction with no user reaction time.
  invariante: |
    // Critical parameter changes must go through timelock:
    // assert(block.timestamp >= proposalTime + MIN_DELAY) for oracle/controller/fee changes
  que_mirar:
    - "setOracle|setController|updateWrapper|setFee.*onlyOwner"
    - "Parameter changes that affect fund flows with no timelock"
    - "Admin-changeable addresses that receive transferFrom/safeTransfer"
    - "Functions that move all balance to an admin-controlled address"
    - "Contest README saying admin is RESTRICTED but code has no restrictions"
  como_se_arregla: "Add timelock to all parameter changes that affect fund flows. Use bounded ranges for fees. Make oracle/controller changes go through 2-step process with delay."
  trampas:
    - "Many bug bounties exclude admin/centralization risks -- check scope first"
    - "If admin is a timelock/multisig, the risk is lower but still valid if README says RESTRICTED"
  incidentes:
    - "Taurus -- admin could update price oracle without timelock, set malicious oracle to liquidate all positions (medium)"
    - "InsureDAO -- Vault owner could setController to malicious contract and drain all funds via utilize() (high)"
    - "LooksRare -- owner could add malicious transfer manager and drain all approved user currency tokens (critical)"
    - "KelpDAO -- MANAGER role could add fake token + oracle + swap to drain all deposits (high)"
    - "Napier -- restricted admin could set rebalancer + targetBufferPercentage to block all withdrawals (medium)"
    - "Tigris Trade -- owner could freeze withdrawals via oracle then use timelock to steal funds (medium)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [access-control, admin-rug, parameter-change, timelock-missing, centralization]

- id: access-014
  pattern: missing-state-update-in-access-check
  name: "Access control state not updated, allowing repeated privileged action"
  causa_raiz: "Function checks a state variable for authorization but never updates it after the action, allowing the same privileged operation to be repeated indefinitely."
  como_funciona: |
    1. Function checks `require(claimedTokens[token][msg.sender] <= maxClaimable[token])` for authorization.
    2. Function transfers tokens to caller.
    3. claimedTokens mapping is NEVER incremented after transfer.
    4. Attacker calls function repeatedly, draining contract balance in single tx or multiple txs.
    5. Each call passes the authorization check because state was never updated.
  invariante: |
    // After every privileged action that should be one-time or bounded:
    // assert(stateVariable was updated to reflect the action)
  que_mirar:
    - "require.*<=.*mapping.*transfer|safeTransfer"
    - "State checks before transfer without corresponding state update after"
    - "Missing ++ or += after a claim/withdraw check"
    - "withdrawFee|claimTokens|claimReward without reentrancy guard or claimed flag"
  como_se_arregla: "Update the state variable BEFORE the transfer (checks-effects-interactions). Add `claimedTokens[token][msg.sender] += amount;` before transfer."
  trampas:
    - "The check might be in a modifier while the update is expected in the function body"
    - "Some functions intentionally allow repeated claims (e.g., streaming rewards)"
  incidentes:
    - "Union Finance -- claimTokens() checked claimedTokens mapping but never updated it, allowing anyone to drain entire contract balance (high)"
    - "RabbitHole -- withdrawFee() had no protection against repeated calls, anyone could drain quest funds after end time (high)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, state-update, repeated-action, drain]

- id: access-015
  pattern: access-control-bypass-via-alternate-path
  name: "Access control bypassed via alternate code path to same state change"
  causa_raiz: "Function A restricts access to a state change, but function B (or an alternate entry point like a callback, different contract, or public wrapper) performs the same state change without the restriction."
  como_funciona: |
    1. Function A (e.g., addRewardToken) is protected by `require(msg.sender == gauge)`.
    2. Function B (e.g., notifyRewardAmount) calls the same internal _addRewardToken without access check.
    3. Attacker calls function B directly, bypassing the intended access control of function A.
    4. Attacker adds unauthorized reward tokens, bypasses pause state, or performs restricted operations.
  invariante: |
    // For every restricted state change S:
    // assert(ALL code paths that reach S enforce the same access control)
  que_mirar:
    - "Internal functions called from both restricted and unrestricted external functions"
    - "Same storage variable written by multiple external functions with different access levels"
    - "Callback functions (onReceive, fallback) that bypass whenNotPaused"
    - "Peripheral contracts that bypass main contract's access checks"
    - "burn|removeFollower.*without.*whenNotPaused"
  como_se_arregla: "Apply access control at the internal function level, not just the external wrapper. Or ensure all external entry points have consistent access control."
  trampas:
    - "Some alternate paths are intentionally permissionless (e.g., liquidation)"
    - "The access check might be enforced deeper in the call stack"
  incidentes:
    - "Alchemix -- addRewardToken restricted to gauge but notifyRewardAmount bypassed it to add any whitelisted token (medium)"
    - "Lens Protocol -- unfollow restricted via whenNotPaused on LensHub but FollowNFT.removeFollower/burn had no pause check (medium)"
    - "Ondo Finance -- BURNER_ROLE blocked by _beforeTokenTransfer KYC check, preventing burn of non-KYC accounts as designed (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, bypass, alternate-path, inconsistent-checks]

- id: access-016
  pattern: counterfactual-address-hijack
  name: "CREATE2 address hijack via missing salt parameters"
  causa_raiz: "CREATE2 deployment salt does not include all security-critical parameters (e.g., entrypoint, curator, initialization params). Attacker front-runs deployment with same salt but malicious parameters, landing at the pre-computed address."
  como_funciona: |
    1. User pre-computes a CREATE2 address using getAddressForCounterfactual(owner, index).
    2. User sends funds to the pre-computed address, expecting to deploy their wallet/vault there later.
    3. Attacker calls deployCounterFactualWallet with same (owner, index) but malicious entrypoint/curator.
    4. Contract deploys at the expected address because salt only depends on owner + index, NOT entrypoint.
    5. Attacker controls the entrypoint/curator of the deployed contract and can drain all pre-sent funds.
  invariante: |
    // CREATE2 salt must include ALL parameters that affect security:
    // assert(salt == keccak256(abi.encodePacked(owner, entrypoint, handler, index)))
  que_mirar:
    - "create2|CREATE2|deployCounterFactual|deployProxy"
    - "Salt computation that omits security-critical parameters"
    - "Factory functions callable by anyone (no access control on deploy)"
    - "Initialization parameters not part of salt/initHash"
  como_se_arregla: "Include ALL security-critical parameters in the CREATE2 salt (entrypoint, admin, curator, etc.). Or restrict deployment to the owner only."
  trampas:
    - "If deploy function has onlyOwner or requires a signature, frontrunning is not possible"
    - "Some factory patterns intentionally allow anyone to deploy with deterministic addresses"
  incidentes:
    - "Biconomy -- deployCounterFactualWallet salt excluded entrypoint; attacker could front-run with malicious entrypoint and control the wallet (critical)"
    - "Term Structure -- VaultFactory createVault salt excluded curator/timelock; attacker could front-run and hijack curator role (medium)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, CREATE2, salt, front-running, address-hijack]

- id: access-017
  pattern: governance-zero-supply-takeover
  name: "Governance takeover when token supply is zero"
  causa_raiz: "Governance proposal/voting thresholds are calculated as percentage of totalSupply. When totalSupply is 0 (before first mint or after burn), the threshold is 0, allowing anyone to pass arbitrary proposals with zero votes."
  como_funciona: |
    1. Governance contract calculates proposalThreshold as (totalSupply * numerator / denominator).
    2. Before any tokens are minted, totalSupply == 0, so threshold == 0.
    3. Attacker creates a proposal with 0 voting power (or front-runs the first mint).
    4. Quorum check also passes because 0 votes >= 0 required.
    5. Attacker executes proposal to change kernel admin/executor, drain treasury, or upgrade to malicious implementation.
  invariante: |
    // assert(proposalThreshold() > 0 || totalSupply() > 0)
    // assert(quorum > MIN_QUORUM_ABSOLUTE)
  que_mirar:
    - "proposalThreshold.*totalSupply|getPastTotalSupply"
    - "quorum.*totalSupply"
    - "Division by totalSupply without zero check"
    - "Governor deployment before token distribution"
  como_se_arregla: "Add minimum absolute threshold: `require(proposalThreshold() >= MIN_ABSOLUTE_THRESHOLD)`. Deploy governance AFTER initial token distribution. Or pre-mint a small amount to the protocol."
  trampas:
    - "If governance is deployed simultaneously with token and tokens are pre-minted in constructor"
    - "Some protocols use off-chain governance for initial setup"
  incidentes:
    - "Olympus DAO -- anyone could pass any proposal with 0 votes before first VOTES mint, taking over kernel admin/executor (critical)"
    - "Alchemix -- proposalThreshold was 0 before first veALCX lock, enabling proposal spam/griefing (medium)"
    - "Nouns Builder -- MerkleReserveMinter could mint many tokens instantly, manipulating quorum calculations for governance hijack (medium)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, governance, zero-supply, proposal-threshold, takeover]

- id: access-018
  pattern: upgradeable-wrong-ownable-version
  name: "Upgradeable proxy uses non-upgradeable Ownable, leaving owner unset"
  causa_raiz: "Contract is designed as upgradeable proxy (uses initializer) but imports regular Ownable instead of OwnableUpgradeable. Regular Ownable sets owner in constructor, which never executes for proxy implementations."
  como_funciona: |
    1. Developer creates upgradeable contract importing @openzeppelin/contracts/access/Ownable.sol.
    2. Regular Ownable sets owner = msg.sender in constructor().
    3. Proxy pattern bypasses constructors -- constructor never runs on the proxy.
    4. Owner remains address(0) permanently.
    5. All onlyOwner functions revert, OR if implementation has no zero-check, anyone with address(0) quirks can exploit.
  invariante: |
    // For all upgradeable contracts:
    // assert(imports OwnableUpgradeable, NOT Ownable)
    // assert(initialize() calls __Ownable_init())
  que_mirar:
    - "initializer.*import.*Ownable[^U]"
    - "Upgradeable contracts importing non-upgradeable Ownable"
    - "Missing __Ownable_init() in initialize()"
    - "proxy|upgradeable.*import.*@openzeppelin/contracts/access"
  como_se_arregla: "Use @openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol. Call __Ownable_init() in initialize()."
  trampas:
    - "If the contract is not actually deployed behind a proxy (just has initializer for other reasons)"
  incidentes:
    - "Covalent -- DelegatedStaking used non-upgradeable Ownable with initializer pattern; all onlyOwner functions inaccessible after proxy deployment (critical)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, proxy, upgradeable, ownable, constructor]

- id: access-019
  pattern: diamond-unprotected-diamondcut
  name: "Unrestricted diamondCut allows anyone to modify facets"
  causa_raiz: "Diamond proxy (EIP-2535) includes diamondCut selector in initial facets without access control, allowing any address to add/remove/replace facets and take full control of the diamond."
  como_funciona: |
    1. Diamond deploys with DiamondCutFacet.diamondCut as one of its initial selectors.
    2. diamondCut function has no onlyOwner/access check (or check was omitted during deployment).
    3. Attacker calls diamondCut to replace any facet with malicious code.
    4. Attacker gains full control: can drain funds, change owner, add backdoors.
  invariante: |
    // assert(diamondCut can only be called by diamond owner or authorized governance)
  que_mirar:
    - "diamondCut|DiamondCutFacet"
    - "Diamond constructors -- check if LibDiamond.enforceIsContractOwner() is called"
    - "Facet functions without access control that modify diamond storage"
    - "delegatecall targets in Diamond context without owner checks"
  como_se_arregla: "Add LibDiamond.enforceIsContractOwner() at the start of diamondCut. Verify all facet functions that modify critical state have proper access control."
  trampas:
    - "Standard Diamond implementations (diamond-3) include the check by default -- focus on custom implementations"
  incidentes:
    - "Burve -- SimplexDiamond included diamondCut selector without access restriction; any user could remove/replace facets (critical)"
    - "Connext -- DiamondInit.init() allowed anyone to change acceptanceDelay after first init, enabling DOS or instant governance changes (high)"
    - "LI.FI -- Diamond storage collision between facets using global variables instead of getStorage pattern, potentially corrupting access control (high)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, diamond, EIP-2535, facet, proxy]

- id: access-020
  pattern: function-selector-role-collision
  name: "Function selector collision with role identifiers"
  causa_raiz: "AccessControl uses msg.sig (4-byte function selector) as role identifier. An attacker can craft a function whose selector collides with ROOT role (0x00000000) or other privileged role, gaining unauthorized access."
  como_funciona: |
    1. AccessControl system maps function selectors (msg.sig) to required roles.
    2. ROOT/admin role is defined as bytes4(0x00000000).
    3. Attacker finds or brute-forces a function name whose selector equals 0x00000000 (e.g., `left_branch_block(uint32)`).
    4. Attacker gets authorized for this 'innocent' function via a module addition.
    5. Authorization for selector 0x00000000 grants ROOT access to the entire system.
  invariante: |
    // assert(no user-defined function selector == ROOT_ROLE or any admin role)
    // assert(grantRole explicitly prevents granting ROOT via normal flow)
  que_mirar:
    - "msg.sig.*role|auth.*msg.sig"
    - "Role definitions that use function selectors as identifiers"
    - "Module systems where third parties can propose new function selectors"
    - "ROOT.*bytes4(0)|0x00000000"
  como_se_arregla: "Separate grantRoot() from grantRole(). Check new module function selectors for collisions with existing roles. Use longer role identifiers (bytes32) instead of bytes4."
  trampas:
    - "Only exploitable if the system allows external module additions"
    - "Standard OZ AccessControl uses bytes32 roles, not msg.sig -- this is a custom pattern"
  incidentes:
    - "Yield -- AccessControl used msg.sig as role ID; function selector collision with ROOT (0x00000000) could grant full system access via innocent-looking module function (high)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [access-control, selector-collision, role, msg-sig, brute-force]

- id: access-021
  pattern: external-call-changes-msg-sender
  name: "External self-call via this.func() changes msg.sender context"
  causa_raiz: "Contract calls its own function via `this.functionName()` (external call) instead of internal call. This changes msg.sender from the original caller to the contract address, breaking access control checks that rely on msg.sender."
  como_funciona: |
    1. Function A calls `this.functionB(tokenId)` (external call syntax).
    2. Inside functionB, msg.sender is now the CONTRACT address, not the original caller.
    3. functionB has `require(ownerOf(tokenId) == msg.sender)` -- checks against contract address.
    4. Since the contract is not the token owner, the call reverts.
    5. Core functionality (transfer, merge, withdraw) is permanently broken.
  invariante: |
    // No function should use `this.func()` when func() has msg.sender-based access control
  que_mirar:
    - "this\\."
    - "External self-calls (this.functionName) in contracts with access control"
    - "Functions that change from external to internal call context"
  como_se_arregla: "Change `this.functionB()` to internal call `_functionB()` or make functionB public instead of external and call directly."
  trampas:
    - "this.func() is sometimes intentional for reentrancy or ABI encoding purposes"
  incidentes:
    - "Golom -- _transferFrom called this.removeDelegation() which changed msg.sender to contract address, breaking all NFT transfers (critical)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, msg-sender, external-call, this-keyword, context-change]

- id: access-022
  pattern: overly-strict-access-locks-protocol-funds
  name: "Overly strict access control locks protocol/DAO funds permanently"
  causa_raiz: "Function that distributes funds to multiple parties (including DAO/protocol) is restricted to a single role (e.g., only host). If that role is compromised or lost, funds for ALL parties are permanently locked."
  como_funciona: |
    1. collectFees() is restricted to host only: `require(msg.sender == host)`.
    2. Function distributes fees to both host AND DAO treasury.
    3. If host wallet is lost/compromised/blacklisted, no one can trigger fee distribution.
    4. DAO fees accumulate in the contract with no recovery path.
    5. Funds are permanently locked.
  invariante: |
    // For functions distributing to fixed addresses:
    // assert(function can be called by ANY address, OR has fallback mechanism)
  que_mirar:
    - "collectFees|distributeRewards|claimToTreasury.*onlyOwner|onlyHost"
    - "Functions that transfer to hardcoded/immutable addresses but have access control"
    - "Missing fallback/emergency withdrawal for protocol funds"
    - "Single-key dependency for multi-party fund distribution"
  como_se_arregla: "Remove access control from functions that distribute to fixed addresses (anyone can trigger, funds go to predetermined recipients). Or add DAO-level fallback."
  trampas:
    - "Some access control is needed to prevent griefing (e.g., gas costs, timing)"
  incidentes:
    - "Clober -- collectFees restricted to host only, but also distributed DAO fees; lost host key would lock DAO fees permanently (medium)"
    - "Morpho -- claimToTreasury could send to address(0) if treasuryVault not set, burning tokens instead of distributing (medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, fund-lock, overly-strict, single-point-failure]

- id: access-023
  pattern: clone-verification-incomplete
  name: "Minimal proxy clone verified by partial bytecode check"
  causa_raiz: "Clone/proxy verification function only checks first N bytes of deployed bytecode (proxy preamble) but ignores the rest, allowing attacker to deploy a contract with valid preamble but malicious trailing code that passes isPair/isClone checks."
  como_funciona: |
    1. Factory verifies clones by checking first 54 bytes match expected proxy bytecode.
    2. Attacker deploys contract with valid 54-byte proxy preamble + malicious payload (factory, bondingCurve, nft stored in immutable extradata).
    3. isPair/isValidClone returns true for the malicious contract.
    4. Attacker uses the 'valid' clone to call router functions (pairTransferERC20From) that trust isPair check.
    5. Attacker drains user funds approved to the router.
  invariante: |
    // Clone verification must check ENTIRE deployed bytecode, not just prefix
    // assert(verifyClone checks all bytes including immutable args)
  que_mirar:
    - "isClone|isPair|isValidPair|verifyClone"
    - "Bytecode comparison that uses < full length"
    - "Clone factories with immutable args in extradata"
    - "Router functions that trust clone verification for fund transfers"
  como_se_arregla: "Verify full bytecode including all immutable arguments. Or use a registry pattern: only factory-deployed addresses are marked as valid in a mapping."
  trampas:
    - "Standard OZ Clones library verification is complete -- focus on custom clone implementations"
  incidentes:
    - "Sudoswap -- isPair only checked first 54 bytes; attacker deployed contract with valid preamble + malicious factory/nft params, could drain all router-approved user funds (critical)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, clone, proxy, bytecode-verification, router]

- id: access-024
  pattern: repeatable-action-missing-epoch-guard
  name: "Privileged action repeatable within epoch due to missing rate-limit on sibling function"
  causa_raiz: "Protocol rate-limits a privileged action (vote, reset) with an onlyNewEpoch or lastVoted check, but a sibling function (poke, pokeTokens, carryVoteForward) that calls the same internal reward-accruing logic lacks the same guard, allowing unlimited calls per epoch."
  como_funciona: |
    1. vote() and reset() are gated by onlyNewEpoch(_tokenId) modifier: one call per epoch.
    2. Both call internal _vote() which calls FluxToken.accrueFlux(_tokenId), increasing unclaimed reward balance.
    3. poke(_tokenId) also calls _vote() internally but has NO onlyNewEpoch guard.
    4. Attacker calls poke() hundreds of times in a single transaction within one epoch.
    5. Each call accrues FLUX tokens proportional to the veNFT's voting power.
    6. Attacker calls claimFlux() to mint unlimited FLUX, then uses it to boost governance votes or sell.
    7. Variant: merge() + reset() loop across tokenIds also bypasses the per-token epoch guard.
  invariante: |
    // For every function that triggers reward accrual:
    // assert(lastAccrued[tokenId] >= currentEpochStart)
    // assert(totalAccrued[tokenId][epoch] <= maxAccrualPerEpoch)
  que_mirar:
    - "poke|pokeTokens|carryVoteForward — functions that repeat previous votes"
    - "Functions calling the same internal _vote/_reset without onlyNewEpoch"
    - "accrueFlux|accrueReward called from multiple entry points with different guards"
    - "merge + reset loops that allow cross-token epoch bypass"
    - "onlyNewEpoch modifier — check which functions use it and which don't"
  como_se_arregla: "Add the same onlyNewEpoch or lastVoted guard to poke() and all sibling functions. Or move the accrual guard into the internal function itself."
  trampas:
    - "Admin-only poke functions (pokeTokens) may be intentionally unguarded for keeper automation"
    - "Some protocols intentionally allow poke without epoch limits for UX reasons — verify reward accrual is separated from vote refresh"
  incidentes:
    - "Alchemix — Voter.poke() lacked onlyNewEpoch modifier, allowing unlimited FLUX minting per epoch; 20+ duplicate reports on Immunefi (critical)"
    - "Alchemix — VotingEscrow.merge() + Voter.reset() loop allowed cross-token epoch bypass for unlimited FLUX (critical)"
    - "Alchemix — Voter.carryVoteForward() permissionless, anyone could trigger vote carry and disrupt bribe accounting (high)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, epoch-guard, rate-limit, poke, reward-accrual, veToken]

- id: access-025
  pattern: timelock-storage-slot-collision-cancel
  name: "Timelock takeover via cancel(bytes32(0)) storage slot collision"
  causa_raiz: "Timelock contract uses XOR-based storage slot derivation for operation tracking. Cancelling bytes32(0) computes a slot that collides with the contract's minimum delay or initialization slot, allowing the attacker to zero out critical configuration and reinitialize the timelock."
  como_funciona: |
    1. Timelock uses assembly: slot = xor(shl(72, id), _TIMELOCK_SLOT) to map operation IDs to storage.
    2. cancel(bytes32(0)) computes a slot that happens to be the same as the minDelay or initialized flag slot.
    3. cancel() calls sstore(slot, 0), zeroing out the minimum delay.
    4. With minDelay = 0, attacker can propose + execute operations instantly.
    5. Attacker grants themselves all roles (PROPOSER, EXECUTOR, ADMIN) and takes over the timelock.
    6. Variant: collision with other config slots can disable different protections.
  invariante: |
    // assert(cancel(id) only clears slots for valid pending operations)
    // assert(minDelay > 0 after any cancel operation)
    // assert(initialized flag cannot be cleared by cancel)
  que_mirar:
    - "Timelock contracts using assembly XOR for storage slot derivation"
    - "cancel() function that accepts arbitrary bytes32 without validating it maps to a real operation"
    - "Storage layout of timelock config vs operation slots — check for overlap"
    - "Solady Timelock, custom timelocks with packed storage"
  como_se_arregla: "Validate that the id being cancelled corresponds to an actual pending operation (sload(slot) must be nonzero and in valid state range). Ensure config slots cannot collide with operation slots by using separate storage namespaces."
  trampas:
    - "Only exploitable if the attacker holds CANCELLER_ROLE"
    - "OZ TimelockController uses mappings, not assembly XOR — this is specific to optimized implementations"
  incidentes:
    - "Coinbase/Solady — cancel(bytes32(0)) zeroed out minDelay slot via XOR collision, enabling instant execution and full timelock takeover (critical)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, timelock, storage-collision, assembly, cancel, bytes32-zero]

- id: access-026
  pattern: erc6492-signature-verification-arbitrary-execution
  name: "ERC-6492 counterfactual signature path enables arbitrary call execution"
  causa_raiz: "ERC-6492 signature verification deploys a contract at a counterfactual address as part of validation. If the permission manager trusts this verification path, an attacker can craft a signature that triggers arbitrary contract deployment and call execution during the isValidSignature check, draining wallet funds."
  como_funciona: |
    1. SpendPermissionManager validates signatures via isValidSignature, supporting ERC-6492.
    2. ERC-6492 path: if no contract at signer address, deploy one first, then verify signature.
    3. Attacker crafts signature with 0x6492 magic wrapper containing: (a) factory address, (b) deployment calldata with malicious payload, (c) a signature that the newly deployed contract will accept.
    4. During verification, the factory deploys a contract that returns true for isValidSignature.
    5. The verification passes, granting the attacker a valid spend permission.
    6. Attacker uses the permission to drain the victim's SmartWallet via executeBatch.
  invariante: |
    // ERC-6492 deployment during signature verification must NOT have side effects on caller state
    // assert(no state changes to permission manager during isValidSignature)
    // assert(deployed contract address matches expected signer)
  que_mirar:
    - "ERC-6492|0x6492|magicWrapper in signature verification"
    - "isValidSignature paths that deploy contracts as side effect"
    - "SpendPermissionManager or similar that trusts ERC-6492 verified signatures"
    - "Account abstraction wallets with modular signature verification"
  como_se_arregla: "Do not allow ERC-6492 counterfactual deployment path in spend permission contexts. Restrict signature verification to already-deployed contracts. If ERC-6492 is needed, ensure the deployment cannot alter authorization state."
  trampas:
    - "Only exploitable when SpendPermissionManager is an owner on the SmartWallet"
    - "Standard EOA signature verification is unaffected"
  incidentes:
    - "Coinbase SmartWallet — ERC-6492 path in SpendPermissionManager allowed attacker to deploy arbitrary contract during signature check, drain any wallet with SPM as owner (critical)"
    - "Coinbase SmartWallet — ownerIndex manipulation via ERC-6492 path allowed same drain attack with different vector (critical)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, ERC-6492, signature, counterfactual, account-abstraction, wallet-drain]

- id: access-027
  pattern: blacklist-bypass-via-preexisting-approval
  name: "Blacklisted address transfers tokens via pre-existing ERC-20 approval"
  causa_raiz: "Blacklist check in transferFrom only validates msg.sender (the spender), not the from address (the token holder). A blacklisted user who previously approved a non-blacklisted address can still move tokens through that approved spender."
  como_funciona: |
    1. User A approves User B to spend their tokens (approve(B, amount)).
    2. User A gets blacklisted: blacklisted[A] = true.
    3. User A cannot call transfer() directly (blocked by blacklist check on msg.sender).
    4. But User B calls transferFrom(A, C, amount) — blacklist only checks msg.sender == B, which is not blacklisted.
    5. Tokens move from blacklisted A to C, bypassing the blacklist entirely.
    6. Variant: blacklisted user approves a fresh address after blacklisting if approve() also only checks msg.sender.
  invariante: |
    // For every transfer/transferFrom:
    // assert(!blacklisted[from] && !blacklisted[to] && !blacklisted[msg.sender])
  que_mirar:
    - "transferFrom.*blacklist|notBlacklisted.*msg.sender"
    - "Blacklist modifier that only checks msg.sender, not from/to"
    - "approve() function — can blacklisted addresses still approve new spenders?"
    - "Token contracts with OFAC/sanctions compliance that use blacklists"
  como_se_arregla: "Check all three addresses in transferFrom: from, to, and msg.sender. Also block approve() for blacklisted addresses to prevent future bypass setup."
  trampas:
    - "Some tokens intentionally only block the sender (different design choice)"
    - "If approval was granted before blacklisting, revoking approvals may require a separate admin function"
  incidentes:
    - "TerPlayer BeraBTC — transferFrom only checked msg.sender blacklist, allowing blacklisted users to transfer via approved addresses (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, blacklist, transferFrom, approval, compliance, sanctions]

- id: access-028
  pattern: session-key-scope-escape
  name: "Session key escapes intended scope via missing ownership or cross-key validation"
  causa_raiz: "Account abstraction session key modules validate that the signer holds A session key but not that the specific session key being consumed belongs to that signer. Alternatively, enableSessionKey does not check if the key is already registered to another wallet, allowing takeover."
  como_funciona: |
    1. Smart wallet enables multiple concurrent session keys, each with token allowances and time limits.
    2. Session key A is authorized for 100 USDC. Session key B is authorized for 1000 USDC.
    3. Signer of key A signs a claim() for key B's allowance — validation only checks signer is a valid session key owner for this wallet, not that they own key B specifically.
    4. Signer A drains 1000 USDC using key B's limits.
    5. Variant: attacker calls enableSessionKey with an already-active key from another wallet, overwriting sessionKeyToWallet mapping and hijacking the key.
    6. Variant: disableSessionKey uses wrong wallet context (msg.sender vs target wallet), skipping token claim validation.
  invariante: |
    // assert(recoveredSigner == sessionKeyToWallet[consumedSessionKey].authorizedSigner)
    // assert(enableSessionKey reverts if key already registered to different wallet)
    // assert(disableSessionKey validates against target session's wallet, not caller's)
  que_mirar:
    - "SessionKey|CredibleAccount|sessionData — session key modules"
    - "validateUserOp that recovers signer but doesn't bind signer to specific session key"
    - "enableSessionKey without checking existing registration"
    - "disableSessionKey with msg.sender context confusion"
    - "Account abstraction modules (ERC-4337, ERC-7579)"
  como_se_arregla: "Bind session key consumption to the specific signer: require(recoveredSigner == authorizedSignerForThisKey). Check key uniqueness across wallets in enableSessionKey. Use target wallet context in disableSessionKey."
  trampas:
    - "Some session key implementations use the key itself as the signer — verify the authorization model"
    - "ERC-4337 entrypoint handles some validation externally"
  incidentes:
    - "Etherspot — SessionKey owner could consume another key's allowance for same wallet; no binding between signer and specific key (critical)"
    - "Etherspot — enableSessionKey allowed overwriting sessionKeyToWallet for active keys from other wallets (critical)"
    - "Etherspot — disableSessionKey checked msg.sender's session data instead of target session, skipping claim validation (critical)"
    - "Etherspot — Session key consumed by unauthorized SCW due to missing wallet binding in validateUserOp (high)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, session-key, account-abstraction, ERC-4337, scope-escape, wallet]

- id: access-029
  pattern: buggy-data-structure-breaks-role-revocation
  name: "Custom data structure bug silently fails role revocation"
  causa_raiz: "Protocol uses a custom set/array library for role membership tracking instead of OZ EnumerableSet. A bug in the remove() function (e.g., not resetting the index mapping) causes hasRole() to return true for revoked accounts, making revokeRole a no-op."
  como_funciona: |
    1. Protocol implements custom AsSequentialSet or similar for tracking role members.
    2. remove(account) swaps the last element into the removed slot and pops, BUT does not reset the index mapping for the removed account.
    3. hasRole(role, account) checks if index[account] < set.length — since index was never reset, it still points to a valid position.
    4. Revoked account retains full role privileges despite appearing removed.
    5. Admin believes they revoked the compromised account, but it still has DEFAULT_ADMIN_ROLE.
    6. Compromised account continues to execute privileged operations.
  invariante: |
    // After revokeRole(role, account):
    // assert(hasRole(role, account) == false)
    // assert(getRoleMemberCount(role) decreased by 1)
  que_mirar:
    - "Custom set libraries (not OZ EnumerableSet) for role tracking"
    - "remove() function in custom set — does it reset the index mapping?"
    - "AsSequentialSet|OrderedSet|CustomSet — any non-standard set implementation"
    - "revokeRole that calls custom remove() instead of OZ"
  como_se_arregla: "Use OpenZeppelin EnumerableSet. If custom implementation is required, ensure remove() resets index[removed] = 0 and handles the swap-and-pop correctly for both index and value arrays."
  trampas:
    - "The bug may only manifest when removing non-last elements (last element removal might work correctly)"
    - "Test with at least 3 members and remove the middle one to detect"
  incidentes:
    - "Astrolab — Custom AsSequentialSet.remove() did not reset index mapping; revoked accounts retained DEFAULT_ADMIN_ROLE permanently (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, data-structure, role-revocation, enumerable-set, custom-library]

- id: access-030
  pattern: deployment-script-ownership-not-transferred
  name: "Deployment script fails to transfer ownership from deployer to intended admin"
  causa_raiz: "Forge/Hardhat deployment script creates contracts with deployer as initial owner (Ownable(msg.sender)) but never calls transferOwnership() to the intended admin/multisig. The deployer EOA retains permanent control of critical contracts."
  como_funciona: |
    1. Deployment script runs vm.startBroadcast(deployerPrivateKey).
    2. Contract constructor sets owner = msg.sender (the deployer EOA).
    3. Script deploys contract successfully but never calls transferOwnership(admin).
    4. Deployer EOA (hot wallet used for deployment) retains ownership of production contracts.
    5. If deployer key is compromised, attacker has full admin control.
    6. Variant: proxy initialized with deployer as admin, but proxyAdmin ownership never transferred.
    7. Variant: multiple contracts deployed, ownership transferred for some but missed for others.
  invariante: |
    // Post-deployment: for every Ownable contract:
    // assert(owner() == expectedAdmin && owner() != deployer)
  que_mirar:
    - "Deployment scripts (script/*.sol, deploy/*.js) — check every new Contract() for subsequent transferOwnership"
    - "Ownable(msg.sender) in constructors — trace msg.sender during deployment"
    - "initialize(deployer) calls without subsequent ownership transfer"
    - "Multiple contract deployments — verify ALL contracts, not just the main one"
    - "ProxyAdmin ownership separate from proxy implementation ownership"
  como_se_arregla: "Add transferOwnership(admin) for every Ownable contract in the deployment script. Add post-deployment verification assertions. Use Ownable2Step so the admin must accept."
  trampas:
    - "Some protocols intentionally keep deployer as owner during initial setup phase"
    - "Verify the admin address is correct (not zero, not the deployer)"
  incidentes:
    - "HypurrFi — DeployCapAutomator.run() deployed CapAutomator with deployer as owner, never transferred to admin (high)"
    - "HypurrFi — _deployUsdxl() initialized proxy with deployer as owner, never transferred usdxlToken ownership to admin (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, deployment, ownership-transfer, deployer, script, forge]

- id: access-031
  pattern: governance-cancel-state-desync
  name: "Governance cancel does not propagate to timelock, enabling ghost execution"
  causa_raiz: "Governance.cancel() marks a proposal as cancelled in governance state but does not call TimelockController.cancel() to remove the operation from the timelock queue. The operation remains executable in the timelock despite being cancelled in governance."
  como_funciona: |
    1. Proposer creates proposal, it passes voting and gets queued in TimelockController.
    2. Governance.cancel(proposalId) sets proposal state to Cancelled in governance storage.
    3. But cancel() does NOT call timelockController.cancel(operationId) to remove the queued operation.
    4. After the timelock delay passes, anyone with EXECUTOR_ROLE calls timelockController.execute().
    5. The cancelled proposal executes successfully because the timelock still has it queued.
    6. Variant: cancel() is overly permissive, allowing proposals to be cancelled even in Succeeded/Queued state.
  invariante: |
    // After Governance.cancel(proposalId):
    // assert(timelockController.isOperation(operationId) == false)
    // assert(proposal cannot be executed through any path)
  que_mirar:
    - "Governance.cancel() — does it call timelockController.cancel()?"
    - "State transitions: Queued -> Cancelled — is the timelock operation also removed?"
    - "Custom governance implementations (not using OZ Governor directly)"
    - "EXECUTOR_ROLE — can it execute operations that governance considers cancelled?"
    - "cancel() permissions — who can cancel, and in which states?"
  como_se_arregla: "Governance.cancel() must call timelockController.cancel(operationId) to remove the queued operation. Add a state check: cancelled proposals must not be executable through any path."
  trampas:
    - "OZ Governor.cancel() properly propagates to timelock — this bug affects custom implementations"
    - "Some protocols use separate cancellation mechanisms for governance vs timelock"
  incidentes:
    - "RAAC — Governance.cancel() did not propagate to TimelockController; cancelled proposals remained executable via timelock (medium)"
    - "RAAC — Unrestricted proposal cancellation allowed cancelling Succeeded/Queued proposals, disrupting governance (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [access-control, governance, timelock, cancel, state-desync, ghost-execution]

- id: access-032
  pattern: frontrunnable-initializer
  name: "Permissionless initialize() — anyone can front-run deployment to seize admin"
  causa_raiz: >
    Proxy contracts and upgradeable contracts use an `initialize()` function instead
    of a constructor. If this function has no `initializer` modifier (Initializable) or
    no access control on who can call it, any attacker who sees the deployment transaction
    in the mempool can front-run it with their own `initialize(attackerAddress)` — setting
    themselves as owner/admin before the legitimate deployer does.
  como_funciona: |
    1. Team deploys proxy contract. Implementation has initialize(owner) function.
    2. Team's initialization tx hits the mempool before execution.
    3. Attacker frontruns: calls initialize(attacker).
    4. Contract is now initialized with attacker as owner.
    5. Team's tx reverts ("already initialized") or silently fails.
    6. Attacker has full admin rights: can withdraw, upgrade, disable.
  invariante: "initialize() must revert on second call AND must revert if called by non-deployer (or use CREATE2 + atomic deployment)"
  que_mirar:
    - "Does initialize() have the `initializer` modifier from OpenZeppelin Initializable?"
    - "If using a custom initializer flag, is it set atomically with the initialization logic?"
    - "Is the contract deployed via CREATE2 with initialization in the same tx?"
    - "Are there re-initialization vectors (proxy upgrade that calls initialize again)?"
    - "Does initialize() call other contracts before setting owner? (reentrancy window)"
  como_se_arregla: "Use OpenZeppelin `Initializable` with `initializer` modifier. Or deploy + initialize atomically in a factory contract. Consider `_disableInitializers()` in implementation constructor."
  trampas:
    - "If the contract is deployed via a factory that atomically initializes, the front-run window doesn't exist"
    - "EIP-1167 minimal proxies initialized at deploy time are safe — check the deployment tx"
    - "OpenZeppelin v4+ `_disableInitializers()` in implementation constructor prevents this even if proxy init is delayed"
    - "Severity depends heavily on whether the contract holds funds at init time vs later"
  severidad: high
  confianza: alta
  fuente: "Solodit: Hubble (L-03 frontrunnable initializers), Enclave 2025 (L-04), Onre Re-Audit-2, general proxy pattern"
  verificado: false
  tags: [initialize, proxy, front-run, admin, ownership, Initializable]
  relacionado_con: [access-001, access-003]

- id: access-033
  pattern: single-step-ownership-transfer
  name: "Single-step transferOwnership — typo or wrong address causes permanent lockout"
  causa_raiz: >
    `transferOwnership(newOwner)` takes effect immediately with no confirmation step.
    If `newOwner` is a typo, a burn address, a contract that can't call `acceptOwnership`,
    or an address the team no longer controls, ownership is permanently lost. There is no
    recourse because the original owner is already stripped of privileges in the same tx.
  como_funciona: |
    1. Team calls transferOwnership(0x1234...typo).
    2. Contract sets owner = 0x1234...typo immediately.
    3. Original owner no longer has onlyOwner access.
    4. New "owner" cannot sign transactions (address doesn't exist or is wrong).
    5. Admin functions locked permanently — protocol cannot be upgraded, paused, or fixed.
  invariante: "Ownership transfer requires explicit acceptance from the new address (two-step)"
  que_mirar:
    - "Does transferOwnership() immediately set owner = newOwner?"
    - "Is OpenZeppelin Ownable2Step used instead of Ownable?"
    - "Are there other roles (ADMIN_ROLE, DEFAULT_ADMIN_ROLE) with the same single-step pattern?"
    - "Can the deployer's EOA be compromised? (recovery path needed)"
    - "Is there a timelock before the transfer takes effect? (better than two-step for large protocols)"
  como_se_arregla: "Use Ownable2Step: pendingOwner = newOwner, then require newOwner.acceptOwnership(). Add validation: require(newOwner != address(0) && newOwner != address(this)). Consider a timelock for protocol-wide ownership."
  trampas:
    - "Ownable2Step prevents typo lockout but NOT compromise of newOwner before acceptance"
    - "For Gnosis Safe multisigs, single-step may be acceptable (signing requires multiple keys)"
    - "This is consistently Low in competitive audits but HIGH in bug bounties if owner has fund-access"
    - "If the contract has no owner-privileged functions that move funds, severity drops to informational"
  severidad: low
  confianza: alta
  fuente: "Solodit: Arkham Intel (critical role transfer two-step), API3 (Ownable pattern), BMX (wBltOracle admin risk), Cyfrin checklist item"
  verificado: false
  tags: [ownership, transferOwnership, Ownable2Step, admin, lockout, two-step]
  relacionado_con: [access-001, access-003]

- id: access-034
  pattern: role-removal-grants-instead-of-revokes
  name: "Bitmask RBAC: role removal logic uses OR instead of AND-NOT — grants all roles"
  causa_raiz: >
    Custom role-based access control using bitmasks can have an inverted removal logic.
    To remove role R from user U: correct is `roles[U] &= ~R` (bit-AND with complement).
    A common bug is `roles[U] |= ~R` (bit-OR with complement) or `roles[U] = roles[U] | ~R`,
    which sets ALL bits EXCEPT R to 1 — granting every other role to the user instead of
    removing one role. A revoke call silently becomes a grant-all call.
  como_funciona: |
    1. roles[alice] = 0b0001 (has DEPOSITOR role, bit 0).
    2. Admin calls revokeRole(alice, DEPOSITOR_ROLE).
    3. Bug: roles[alice] |= ~DEPOSITOR_ROLE = 0b1111...1110.
    4. Alice now has ALL roles: ADMIN, WITHDRAWER, UPGRADER, etc.
    5. Alice drains the protocol using roles she never should have had.
  invariante: "revokeRole(user, role) must result in hasRole(user, role) == false without granting any other role"
  que_mirar:
    - "Custom bitmask RBAC: look for `roles[user] |=` in a revoke/remove function (should be `&= ~`)"
    - "OpenZeppelin AccessControl is safe — only flag custom implementations"
    - "Any role update using bitwise OR where the intent is to remove"
    - "Symmetric issue in grant: `roles[user] &= role` removes all other roles (should be `|= role`)"
  como_se_arregla: "Revoke: `roles[user] &= ~role`. Grant: `roles[user] |= role`. Always use OpenZeppelin AccessControl unless there's a compelling gas reason not to."
  trampas:
    - "OpenZeppelin AccessControl and EnumerableSet-based RBAC are not vulnerable — this is custom code only"
    - "Audit 507 M-02: this exact bug was found in a custom RBAC implementation"
    - "The inverse bug (grant using AND) removes all other roles — separate but related issue"
    - "Unit tests often test grant/revoke in isolation and miss the compound effect on bitmask state"
  severidad: critical
  confianza: alta
  fuente: "Solodit: Audit 507 M-02 (role removal logic incorrectly grants unauthorized), general RBAC pattern"
  verificado: false
  tags: [RBAC, bitmask, role, grant, revoke, access-control, bitwise]
  relacionado_con: [access-001, access-002, access-003]

- id: access-035
  pattern: flash-loan-governance-early-execution
  name: "Flash loan para manipular voting power en modo EarlyExecution de DAO"
  causa_raiz: >
    Protocolos de governance que permiten ejecutar una propuesta anticipadamente cuando
    el soporte supera el quorum (modo "EarlyExecution") son vulnerables si el token de
    votación es flash-loaneable o flash-minteable. Un atacante puede tomar prestado un
    gran número de tokens en un bloque, votar con todo ese poder, ejecutar la propuesta
    anticipadamente y devolver el préstamo en la misma transacción, sin necesidad de
    mantener tokens.
  como_funciona: |
    1. Protocolo tiene propuestas con modo EarlyExecution: si votos_a_favor >= quorum, se
       ejecuta inmediatamente sin esperar el período de votación.
    2. El token de gobernanza puede ser flash-loaneado (no hay check de bloque anterior).
    3. Atacante en una sola tx: toma flashloan del token, delega al propio atacante,
       vota en la propuesta maliciosa, la propuesta alcanza quorum y se ejecuta (earlyExecute),
       desdelega, devuelve el flashloan.
    4. Propuesta ejecutada: puede draining del treasury, cambio de parámetros críticos,
       o upgrade del contrato.
  invariante: |
    // Voting power debe ser tomada de snapshot ANTERIOR al bloque de la transacción de voto
    // require(block.number > proposal.snapshotBlock)
    // getPastVotes(voter, proposal.snapshotBlock) — no getCurrentVotes()
  que_mirar:
    - "Modo EarlyExecution o similar (execute antes de que termine el período de votación)"
    - "Uso de balanceOf() o getCurrentVotes() en lugar de getPastVotes(snapshotBlock)"
    - "Token de governanza con función flashLoan() o flashMint()"
    - "LockManager.getVotes() sin snapshot — devuelve balance actual"
    - "Token sin delegate checkpoint: el balance actual cuenta directamente como voto"
  como_se_arregla: "Snapshot de voting power en el bloque de creación de la propuesta (getPastVotes). Modo EarlyExecution requiere espera adicional post-quorum antes de ejecutar. Alternativamente, añadir bloqueo de transferencia durante el período de votación."
  trampas:
    - "Si el protocolo usa getPastVotes() correctamente con snapshot, el flash loan no funciona"
    - "Flash loan solo es posible si el token es flash-loaneable O si la plataforma permite préstamos del mismo"
    - "Governance que requiere staking/lockeo previo (con tiempo mínimo) no es vulnerable"
    - "El ataque requiere que la propuesta ya esté creada — el atacante no puede crear y ejecutar en una sola tx si hay voting delay"
  incidentes:
    - "Aragon DAO Gov Plugin — propuestas con EarlyExecution vulnerables a flash loan attack si el token del LockManager es flash-loaneable; attacker puede vote y execute en una transacción (High, Spearbit)"
    - "Curve DAO / Frax Finance — veFXS via Aragon: sin mitigación de flash loan en voting, sin snapshot, sin bloqueo de transferencia post-voto (High, Trail of Bits)"
    - "Beanstalk — $180M explotado via flash loan de BEAN tokens para pasar propuesta de governance maliciosa y drenar el protocolo (Critical, real exploit 2022)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Aragon DAO Gov Plugin (Spearbit), Frax Finance (Trail of Bits); DeFiHackLabs: Beanstalk exploit"
  tags: [governance, flash-loan, voting-power, EarlyExecution, DAO, snapshot, flash-mint]
  relacionado_con: [access-017, access-022]

- id: access-036
  pattern: governance-voting-power-no-snapshot
  name: "Voting power calculada sobre balance actual en lugar de snapshot — double vote y flash loan"
  causa_raiz: >
    La función castVote() calcula el poder de voto del usuario usando su balance actual
    (balanceOf o getCurrentVotes) en lugar del balance en el bloque de creación de la
    propuesta (getPastVotes). Esto permite: (1) votar, transferir tokens a otra cuenta
    y votar de nuevo (double-vote); (2) adquirir tokens flash-loaned, votar, y devolver.
    El invariante fundamental de governance — "una unidad de token = un voto, una vez" —
    se rompe.
  como_funciona: |
    1. Usuario A tiene 1000 tokens. Vota en propuesta P.
    2. Transfiere 1000 tokens a Usuario B.
    3. Usuario B vota en propuesta P con los mismos 1000 tokens.
    4. Propuesta P tiene 2000 votos sobre una base real de 1000 tokens.
    5. Alternativamente: atacante hace flash loan de todos los tokens, vota, devuelve.
    6. Minority actor puede pasar cualquier propuesta manipulando el conteo.
  invariante: |
    // votingPower DEBE ser getPastVotes(voter, proposal.voteStart)
    // NUNCA balanceOf(voter) ni getCurrentVotes(voter) en castVote()
    require(block.number > proposal.voteStart, "snapshot not yet taken");
  que_mirar:
    - "castVote() que llama balanceOf() o getCurrentVotes() en lugar de getPastVotes()"
    - "snapshotBlock no definido o no almacenado en la propuesta"
    - "Transferencia de tokens NO bloqueada durante período de votación"
    - "Contratos que forean OZ Governor pero sobreescriben _getVotes()"
    - "Falta de evento Checkpoint actualizado al crear la propuesta"
  como_se_arregla: "Usar ERC20Votes / ERC721Votes de OpenZeppelin con getPastVotes(account, proposalSnapshot()). Almacenar el bloque de snapshot al crear la propuesta y usarlo en todas las consultas de voto. Nunca leer balance actual durante votación."
  trampas:
    - "SnapshotERC20Guild de DXdao implementa snapshot pero con un bug distinto (double-vote via transfer dentro del mismo snapshot)"
    - "La mayoría de formas de OZ Governor sí implementan snapshot correctamente — flag solo en custom governance"
    - "veToken (locked) governance suele ser inmune al flash loan pero puede ser vulnerable a double-vote via NFT transfer si no hay check"
  incidentes:
    - "Regnum Aurum Core Contracts — castVote() usa balance actual, no snapshot; double-vote y flash loan posibles (High, Codehawks)"
    - "DXdao BaseERC20Guild — doble voto via lockTokens + transfer antes de snapshot; attacker puede votar dos veces con los mismos tokens (High, Sigmaprime)"
    - "DXdao SnapshotERC20Guild — snapshot implementado pero double-vote aún posible via NFT transfer dentro del mismo período (High, Sigmaprime)"
    - "EYWA EscrowManager — moveVotes() no verifica si el token ya votó (s_hasVotedByTokenId), permitiendo inflación de voto (High, MixBytes)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Regnum Aurum (Codehawks H), DXdao (Sigmaprime H), EYWA (MixBytes H)"
  tags: [governance, voting-power, snapshot, double-vote, flash-loan, DAO, ERC20Votes]
  relacionado_con: [access-017, access-035]

- id: access-037
  pattern: governance-quorum-numerator-denominator-misconfiguration
  name: "Quorum mal configurado: numerador/denominador permiten pasar propuestas con minoría pequeña"
  causa_raiz: >
    El quorum de governance se calcula como (totalSupply * quorumNumerator) / quorumDenominator.
    Un bug frecuente: el numerador se confunde con el denominador esperado, o las constantes
    están invertidas. Ejemplo: quorumNumerator=250, quorumDenominator=10000 da 2.5%
    cuando el intent era 25%. Attackers con minority stake pueden pasar propuestas que
    el diseño debería rechazar. Variante: el quorum puede ser actualizado por governance
    y una propuesta existente (pre-quorum-change) ahora cumple el nuevo quorum reducido.
  como_funciona: |
    1. Protocolo establece quorum como 25% del totalSupply.
    2. Bug: quorumNumerator=25, quorumDenominator=10000 → real quorum = 0.25%.
    3. Atacante con 4% del supply puede pasar cualquier propuesta.
    4. Variante temporal: governance reduce quorum via nueva propuesta → propuestas
       anteriores que no tenían quorum ahora sí lo tienen y pueden ejecutarse.
  invariante: |
    // assert(quorumNumerator * 100 / quorumDenominator >= MIN_QUORUM_PERCENT)
    // quorumNumerator < quorumDenominator always
    // Cambio de quorum no debe activar propuestas históricas pendientes
  que_mirar:
    - "quorumNumerator y quorumDenominator: verificar la proporción resultante con valores reales"
    - "Funciones que permiten reducir quorum vía governance: ¿afectan propuestas históricas?"
    - "quorum() que usa getPastTotalSupply() vs totalSupply() (diferencia en timing)"
    - "Constantes hardcodeadas como PROPOSAL_NUMERATOR o QUORUM_NUMERATOR — validar escala"
  como_se_arregla: "Añadir MIN_QUORUM_PERCENT como constante y assert en el setter. Documentar la escala explícitamente (e.g., '25% = numerator 2500, denominator 10000'). Aplicar cambios de quorum solo a propuestas FUTURAS, no retroactivamente."
  trampas:
    - "Quorum bajo (2-5%) es normal en muchos protocolos reales (AAVE: 3%, COMP: 5%) — verificar la INTENCIÓN del protocolo antes de reportar"
    - "Reducción de quorum que afecta propuestas pasadas puede ser deliberada en emergencias"
    - "El fallo de quorum-reached() en DeFi no siempre es por numerador/denominador — puede ser bug en totalVoteWeight (e.g., Dexe)"
  incidentes:
    - "IQ AI TokenGovernor — quorum esperado del 25% pero atacante pasa propuestas con solo 4% debido a miscalculación de numerador/denominador (High, Code4rena 2025)"
    - "Velodrome Finance VeloGovernor — MAX_PROPOSAL_NUMERATOR en 0.5% cuando debía ser 5%; proposal numerator start value también incorrecto (Low, Spearbit)"
    - "Alchemix AlchemixGovernor — reducción de quorum via governance activa propuestas pasadas que antes fallaban por quorum (Low, Immunefi)"
    - "Dexe GovPool — totalPowerInTokens estático en denominador de quorum; minting de nuevos NFTs hace imposible alcanzar quorum (High, Cyfrin)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: IQ AI (Code4rena H-01), Velodrome Finance (Spearbit L), Alchemix (Immunefi L), Dexe (Cyfrin H)"
  tags: [governance, quorum, numerator, denominator, DAO, proposal, misconfiguration]
  relacionado_con: [access-017, access-036]

- id: access-038
  pattern: auto-execution-missing-access-control-arbitrary-trigger
  name: "Función de auto-ejecución sin control de acceso: cualquier dirección puede disparar la automatización para manipular el resultado"
  causa_raiz: >
    Contratos de automatización (AutoRedemption, AutoExit, AutoRange, AutoCompound) que exponen
    sus funciones de ejecución como públicas o accesibles por cualquier dirección, sin restricción
    a keepers autorizados. El llamante arbitrario puede controlar el timing exacto de la ejecución,
    eligiendo el momento más favorable para él (precio manipulado, condiciones de mercado extremas)
    en lugar del momento óptimo para el usuario. En casos extremos, el llamante puede pasar
    parámetros adversariales (swap paths, slippage) si la función los acepta como argumentos.
  como_funciona: |
    1. Protocolo tiene función execute() o triggerAutomation() que debería llamar solo un keeper autorizado.
    2. La función es pública (o el modifier solo verifica un estado flag, no el msg.sender).
    3. Atacante espera condición favorable: precio manipulado vía flash loan, pool en estado adversarial.
    4. Atacante llama execute() en el timing elegido por él → la ejecución usa el precio adversarial.
    5. Usuarios reciben ejecución sub-óptima (venden posición a precio bajo, liquidan colateral a pérdida).
    6. Variante The Standard: AutoRedemption.fulfillRequest() callable por cualquiera permite que el
       atacante elija qué vault se redime y en qué orden, priorizando el más favorable para él.
  invariante: >
    // Solo keepers autorizados deben poder llamar funciones de ejecución
    // assert(isAuthorizedKeeper[msg.sender] || msg.sender == owner)
    // Si la función tiene parámetros de swap, deben estar pre-aprobados por el usuario
    // assert(userApprovedParams[user][paramsHash])
  que_mirar:
    - "¿execute()/triggerAutomation()/fulfillRequest() tiene modifier de acceso o es pública?"
    - "¿El keeper puede pasar parámetros arbitrarios de swap/slippage o están hardcodeados por el usuario?"
    - "¿Hay una whitelist de keepers o cualquier EOA puede ejecutar?"
    - "¿La función verifica condiciones de mercado independientemente (oracle TWAP) o confía en el caller?"
    - "rg 'execute\\|trigger\\|fulfillRequest\\|performUpkeep' --type sol | rg -v 'onlyKeeper\\|onlyAuthorized\\|modifier'"
  como_se_arregla: >
    Implementar whitelist de keepers autorizada por el owner del protocolo o del vault.
    Para parámetros de swap: los usuarios pre-configuran sus propios parámetros de slippage/precio,
    el keeper solo puede ejecutar con esos parámetros pre-aprobados (no puede sobreescribirlos).
    Si se permite ejecución pública por diseño: usar precios TWAP en lugar de spot, añadir
    slippage máximo configurable por el usuario, y revertir si el precio spot se desvía del TWAP
    más de un umbral.
  trampas:
    - "The Standard H: el bug no es que la función sea pública — es que el caller controla CUÁL vault se redime (orden adversarial)"
    - "En Revert Lend, los keepers de AutoExit reciben un reward — verificar si la función de ejecución está restringida solo a keepers autorizados"
    - "Distinguir de dex-047: aquí el problema es WHO puede ejecutar, no cuánto pagan"
    - "Si el protocolo usa Gelato/Chainlink Automation: la restricción debe ser en el Upkeep contract, no solo en el backend"
  incidentes:
    - "The Standard Auto Redemption — Auto redemption logic can be abused by an attacker due to insufficient access control: cualquier dirección puede llamar fulfillRequest() y elegir qué vault redimir (High, Sherlock 2024) — solodit.xyz"
    - "The Standard Auto Redemption — Automation and redemption could be artificially manipulated due to use of instant price (Medium) — solodit.xyz"
    - "Brahma — TRST-H-2: Users can drain Gelato deposit at little cost: ejecuciones no restringidas drenan el depósito de gas (High) — solodit.xyz"
  severidad: high
  confianza: alta
  fuente: "Solodit: The Standard Auto Redemption (Sherlock H, 2024), The Standard (M, slippage), Brahma (TRST-H-2)"
  verificado: true
  tags: [access-control, keeper, automation, execute, trigger, public-function, autoexecution, the-standard, brahma, autoexit]
  relacionado_con: [access-001, dex-047]

- id: access-039
  pattern: gelato-keeper-deposit-drain-low-cost-execution
  name: "Depósito Gelato/keeper drainable a bajo costo: ejecutores o usuarios drenan el gas del protocolo mediante ejecuciones triviales"
  causa_raiz: >
    Protocolos que usan Gelato Network o Chainlink Automation para pagar el gas de sus keepers
    mantienen un depósito de ETH (o tokens nativos) en el contrato de Gelato/registry. Si las
    condiciones que activan la ejecución automática son demasiado laxas, o si usuarios/atacantes
    pueden forzar ejecuciones repetidas a bajo costo (pequeños depósitos, operaciones triviales),
    el depósito del protocolo se vacía rápidamente. Cuando el depósito se agota, el protocolo
    queda sin keepers y las posiciones no se ejecutan (DoS funcional).
  como_funciona: |
    Variante A (Brahma H-2): Usuario crea strategy con condición de trigger barata → Gelato la ejecuta
    repetidamente → cada ejecución usa gas del depósito del protocolo. El costo para el atacante
    es solo el gas de crear las strategies; el protocolo paga todo el gas de ejecución.

    Variante B (Brahma H-4): Los executors internos del protocolo pueden llamar funciones de
    trabajo triviales (cero items a procesar) que aun así consumen gas del depósito Gelato y
    generan un pago de fee para el executor.

    Variante C (GMX M-5): Keepers pueden inflar el gas reportado en payExecutionFee() para cobrar
    más del depósito del usuario de lo que realmente gastaron.

    Resultado: depósito vaciado → keepers dejan de funcionar → DoS para todos los usuarios del protocolo.
  invariante: >
    // El depósito del protocolo no debe decrecer más de MAX_GAS_PER_EXECUTION por ejecución
    uint256 depositBefore = gelato.taskBalance(address(this));
    keeper.execute(params);
    uint256 depositAfter = gelato.taskBalance(address(this));
    uint256 gasUsed = depositBefore - depositAfter;
    assert(gasUsed <= MAX_GAS_PER_LEGITIMATE_EXECUTION);
    // Además: verificar que cada ejecución procesó trabajo real (no ejecución vacía)
  que_mirar:
    - "¿Quién paga el gas de los keepers Gelato/Chainlink? ¿Un depósito del protocolo o del usuario?"
    - "¿Las condiciones de trigger son lo suficientemente restrictivas para evitar ejecuciones triviales?"
    - "¿Hay un límite en cuántas veces un mismo usuario/strategy puede activar el keeper en un período?"
    - "¿Se verifica que la ejecución realizó trabajo real antes de pagar la fee?"
    - "rg 'gelato\\|IAutomate\\|performUpkeep\\|execTask' --type sol | rg 'deposit\\|fund\\|fee'"
  como_se_arregla: >
    Hacer que los USUARIOS depositen ETH para sus propias tareas Gelato (no el protocolo).
    Si el protocolo paga: añadir rate limiting por usuario/strategy (mínimo 1h entre ejecuciones).
    Validar que el trabajo realizado justifica el costo de gas antes de ejecutar.
    Implementar un techo de gas por tarea y revertir si se supera.
    Para la variante de fee inflation: usar `gasleft()` antes y después para medir gas real,
    no confiar en el gas reportado por el caller.
  trampas:
    - "Este es un bug de DoS económico, no de fund loss directo — algunos auditores lo downgradan injustamente"
    - "El impacto real es que todas las posiciones del protocolo dejan de ejecutarse si el depósito se agota"
    - "En Revert Lend, si los keepers de AutoExit/AutoRange son pagados por un depósito del protocolo, este bug aplica"
    - "Brahma tenía MÚLTIPLES variantes del mismo bug (H-2, H-4, M-1) — buscar en toda la superficie de pago de gas"
  incidentes:
    - "Brahma — TRST-H-2: Users can drain Gelato deposit at little cost: strategy creation barata permite drenar depósito de gas del protocolo (High, Trust Security 2023) — solodit.xyz"
    - "Brahma — TRST-H-4: Executors can drain the Gelato deposit while profiting from free gas (High, Trust Security 2023) — solodit.xyz"
    - "Brahma — TRST-M-1: When FeePayer is subsidizing, users can steal gas (Medium) — solodit.xyz"
    - "GMX Update — M-5: Keepers can steal additional execution fee from users (Medium, 2023) — solodit.xyz"
  severidad: high
  confianza: alta
  fuente: "Solodit: Brahma (Trust Security TRST-H-2, TRST-H-4, TRST-M-1), GMX Update (M-5)"
  verificado: true
  tags: [gelato, keeper, gas-deposit, drain, execution-fee, dos, brahma, gmx, chainlink-automation, automator]
  relacionado_con: [access-038, dex-043]

- id: access-040
  pattern: keeper-execution-fee-inflation-gas-manipulation
  name: "Keeper infla gas reportado en payExecutionFee() para extraer más fondos del depósito del usuario de los que realmente gastó"
  causa_raiz: >
    Protocolos que reembolsan a los keepers el gas gastado calculan el pago como
    `gasUsed * gasPrice + baseFee`. Si este cálculo se basa en valores reportados por el keeper
    (no en medición real del EVM), el keeper puede inflar el gasUsed, usar un gasPrice artificialmente
    alto, o incluir gastos no relacionados con la ejecución. El usuario que configuró la orden
    acaba pagando más de lo que debería, y el exceso va al keeper malicioso.
  como_funciona: |
    1. Usuario deposita ETH para pagar el gas de sus automaciones (AutoExit, AutoCompound, etc.).
    2. Keeper ejecuta la automatización y llama payExecutionFee(gasUsed, gasPrice, ...).
    3. Si gasUsed/gasPrice son parámetros del caller (no medidos internamente), el keeper los infla.
    4. El contrato paga gasUsed * gasPrice al keeper sin verificar que coincide con el gas real.
    5. Keeper obtiene 2-5x el gas real → extrae valor del depósito del usuario.
    6. Variante EIP-150: el cálculo no considera que las subcalls usan solo 63/64 del gas disponible,
       subestimando (o sobreestimando) el costo real de la cadena de llamadas.
  invariante: >
    // El pago al keeper no debe exceder el gas real gastado más un margen razonable
    uint256 gasBefore = gasleft();
    // ... ejecución ...
    uint256 gasUsedReal = gasBefore - gasleft() + GAS_OVERHEAD_CONSTANT;
    uint256 keeperPayment = gasUsedReal * tx.gasprice;
    // Pago no debe exceder el real en más de MAX_OVERHEAD_PERCENT
    assert(actualPayment <= keeperPayment * (100 + MAX_OVERHEAD_PERCENT) / 100);
  que_mirar:
    - "¿payExecutionFee() acepta gasUsed como parámetro del caller o lo mide internamente con gasleft()?"
    - "¿Se verifica que el gasPrice del pago no excede tx.gasprice actual?"
    - "¿El cálculo considera EIP-150 (63/64 gas forwarding en subcalls)?"
    - "¿Hay un techo máximo en el pago al keeper por ejecución?"
    - "rg 'payExecutionFee\\|keeperFee\\|gasReimburs\\|executionFee' --type sol | rg 'gasUsed\\|gasPrice\\|param'"
  como_se_arregla: >
    Medir el gas internamente: `uint256 gasStart = gasleft(); /* trabajo */ uint256 gasEnd = gasleft();
    uint256 gasUsed = gasStart - gasEnd + OVERHEAD`.
    No aceptar gasUsed como parámetro externo. Usar `tx.gasprice` para el precio, no un parámetro.
    Añadir techo máximo: `require(reimbursement <= MAX_KEEPER_FEE_WEI)`.
    Para EIP-150: añadir margen de 1/63 al overhead calculado.
  trampas:
    - "GMX M-5 fue clasificado Medium porque el exceso es limitado (no drenado total) — pero en protocolos con muchas ejecuciones el impacto acumula"
    - "Elfi M-9 es similar pero desde el ángulo opuesto: el protocolo SUBESTIMA el costo y el keeper no puede recuperar su gas real"
    - "Distinguir de access-039: aquí el keeper sí hace trabajo real, pero infla el cobro. En access-039 no hace trabajo"
    - "En Revert Lend: verificar la función que paga el reward al keeper en AutoExit/AutoCompound — cómo se calcula exactamente"
  incidentes:
    - "GMX Update — M-5: Keepers can steal additional execution fee from users: gasUsed manipulable por el keeper (Medium, 2023) — solodit.xyz"
    - "Elfi — M-9: The implementation of payExecutionFee() didn't take EIP-150 into consideration (Medium, 2024) — solodit.xyz"
    - "Primex Finance — Gas Manipulation for High Rewards: keepers manipulan gas para maximizar reward (Low, 2023) — solodit.xyz"
  severidad: medium
  confianza: alta
  fuente: "Solodit: GMX Update (M-5, 2023), Elfi (M-9, EIP-150), Primex Finance (L, gas manipulation)"
  verificado: true
  tags: [keeper, execution-fee, gas-inflation, eip-150, reimbursement, gmx, elfi, primex, automator, autoexit]
  relacionado_con: [access-039, access-038, dex-043]
```

---

## Quick-Scan Grep Patterns

Use these to triage a new codebase fast:

```bash
# Missing access control candidates
grep -rn "external\|public" --include="*.sol" | grep -v "view\|pure\|onlyOwner\|onlyRole\|onlyAdmin\|modifier\|interface\|abstract"

# tx.origin usage
grep -rn "tx\.origin" --include="*.sol"

# delegatecall sites
grep -rn "delegatecall" --include="*.sol"

# Unprotected initialize
grep -rn "function initialize" --include="*.sol" | grep -v "initializer\|onlyInitializing"

# Proxy storage (non-EIP-1967)
grep -rn "assembly.*sload\|assembly.*sstore" --include="*.sol"

# Timelock references
grep -rn "timelock\|delay\|MIN_DELAY\|MAX_DELAY" --include="*.sol"

# Role grants
grep -rn "grantRole\|_setupRole\|DEFAULT_ADMIN" --include="*.sol"
```

---

## Severity Decision Tree

1. **Can an arbitrary address drain funds?** -> Critical (access-001, access-008)
2. **Can an arbitrary address upgrade the contract?** -> Critical (access-003, access-004)
3. **Can a governance action bypass its timelock?** -> Critical (access-005)
4. **Can ownership be irrecoverably lost?** -> High (access-002)
5. **Can a phishing attack escalate privileges?** -> High (access-007)
6. **Is a role over-permissioned?** -> High if exploitable, Medium if centralization-only (access-006)

---

## DeFiHackLabs Verified Incident Summary

> **Source**: DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)
> **Total verified access control incidents**: 34
> **Combined losses**: $90M+ (access-001: ~$80M+, access-008: ~$12M+)

**Key takeaway**: Missing access control (access-001) remains the single most exploited vulnerability class by frequency and total loss. Arbitrary call/delegatecall (access-008) is the second most common, with router/aggregator contracts being the primary targets. MEV bots are disproportionately affected -- 3 separate MEVBot incidents in Nov 2023 alone.

**Highest single-incident losses**:
1. HedgeyFinance (Apr 2024) -- $48M (logic flaw, access related)
2. Lifiprotocol (Jul 2024) -- $10M (input validation)
3. SafeMoon (Mar 2023) -- $8.9M (access control)
4. VeloCore (Jun 2024) -- $6.88M (lack of access control)
5. Seneca (Feb 2024) -- $6M (arbitrary external call)
6. Shezmu (Sep 2024) -- $4.9M (access control)

---

## Cross-References

| Pattern | Invariant Registry IDs | DeFiHackLabs Verified Incidents |
|---|---|---|
| access-001 | INV-EXPLOIT-003, INV-OWN-002 | 22 incidents (SafeMoon, HedgeyFinance, VeloCore, Shezmu, Lifiprotocol, etc.) |
| access-002 | INV-OWN-003 | -- |
| access-003 | INV-OWN-005, INV-EXPLOIT-009 | -- |
| access-004 | INV-EXPLOIT-009, INV-OWN-004 | -- |
| access-005 | INV-TLOCK-009, INV-TLOCK-011, INV-TLOCK-012 | -- |
| access-006 | INV-OWN-002, INV-TLOCK-010 | -- |
| access-007 | (universal pattern) | -- |
| access-008 | INV-EXPLOIT-009, INV-EXPLOIT-003 | 11 incidents (Seneca, SushiSwap, Dexible, ChaingeFinance, Phoenix, etc.) |

---

## Solodit Verified Findings

> Source: Solodit audit database. Only findings adding new information beyond DeFiHackLabs incidents are included.

### Maps to access-001 (Missing Access Control on Critical Function)

- **[HIGH] One World Project has unilateral control over all DAOs** — EXTERNAL_CALLER role granted at deployment gives project owner ability to update tier configs, mint/burn membership tokens, steal profits, and abuse approvals on MembershipFactory and MembershipERC1155 proxy contracts. Key insight: role granted during deployment is overly broad and covers both DAO management AND fund extraction.
- **[HIGH] DAO creator can inflate privileges to mint/burn membership tokens and steal profits** — During DAO creation, MembershipFactory is granted blanket permissions on the DAO's ERC1155; the DAO creator can escalate through the factory to mint/burn tokens and extract funds. Key insight: factory contract acts as a privilege amplifier for the creator.

### Maps to access-008 (Delegatecall to Untrusted Target)

- **[HIGH] CM can delegatecall to any address and bypass all restrictions** — GuardCM contract designed to restrict Community Multisig actions can be bypassed via delegatecall; the guard checks function selectors on direct calls but delegatecall executes arbitrary code in the multisig's context, bypassing all selector-based restrictions. Key insight: transaction guards that filter by selector are ineffective against delegatecall since the target code is arbitrary.

### New patterns not in existing bugs

- **(No new patterns identified)** — All 3 Solodit access control findings map to existing patterns (access-001 and access-008). The findings reinforce that role over-granting during deployment (access-001/access-006 overlap) and delegatecall guard bypasses (access-008) remain the most common audit findings in this category.
