# Proxy & Upgrade Vulnerabilities -- Combat Briefing

> **Scope**: Solidity proxy and upgrade bugs for bug bounty hunting.
> **Sources**: solodit_bulk_findings.json (proxy category, 20 findings), invariant-registry, DeFiHackLabs.
> **Last updated**: 2026-03-19

---

## Bug Patterns

```yaml
- id: proxy-001
  pattern: storage-collision-on-upgrade
  name: "Storage collision between proxy and implementation"
  causa_raiz: "Proxy and implementation share the same storage space via delegatecall. If the proxy stores admin/implementation addresses in slots that overlap with the implementation's variables, or if a new implementation version changes the inheritance order or inserts new base contracts, storage gets corrupted."
  como_funciona: "1. Proxy stores its admin address at storage slot 0 (non-EIP-1967). 2. Implementation also uses slot 0 for its first state variable (e.g., owner or totalSupply). 3. When the implementation writes to its first variable, it overwrites the proxy admin. 4. Attacker can become proxy admin and upgrade to malicious implementation, draining all funds."
  invariante: "Storage layouts of proxy and implementation must never overlap. All proxy-specific slots (admin, implementation, beacon) must use EIP-1967 pseudo-random slots. Between upgrades, the storage layout of the implementation must be append-only."
  que_mirar:
    - "Custom proxy contracts NOT using EIP-1967 slots (bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1))"
    - "Implementation contracts that changed inheritance order between V1 and V2"
    - "New base contracts inserted in the middle of the inheritance chain"
    - "Missing __gap arrays in upgradeable base contracts"
    - "Structs or mappings that shifted position between versions"
    - "Use of assembly sload/sstore on hardcoded slot numbers"
  como_se_arregla: "Use EIP-1967 storage slots for all proxy metadata. Maintain uint256[50] __gap arrays in every base contract. Use OpenZeppelin upgrade-safety tooling (forge inspect --storage-layout, oz upgrades plugin) to diff layouts between versions."
  trampas:
    - "Standard OpenZeppelin TransparentUpgradeableProxy and UUPS are safe for proxy-vs-implementation overlap -- focus on CUSTOM proxies"
    - "The real danger is between V1 and V2 of the IMPLEMENTATION, not proxy vs implementation"
    - "Enums and small types packed together can shift unexpectedly"
  incidentes:
    - "Brink Protocol -- ProxyStorage._implementation and _owner at slots 0-1 overlap with verifier contract storage; attacker could overwrite implementation address via delegatecall to crafted verifier (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "INV-EXPLOIT-009, INV-OWN-004, solodit proxy category"
  tags: [proxy, storage-collision, delegatecall, EIP-1967, upgrade]
  relacionado_con: [proxy-002, proxy-006]
  incidentes_verificados:
    - nombre: "Audius"
      fecha: "Jul 2022"
      perdida: "$6M"
      tipo: "Storage collision -- proxy admin overwritten via uninitialized implementation"
      verificado: true
      fuente: "DeFiHackLabs, Rekt News"
    - nombre: "Furucombo"
      fecha: "Feb 2021"
      perdida: "$14M"
      tipo: "Proxy-related delegatecall to attacker-controlled implementation"
      verificado: true
      fuente: "DeFiHackLabs, Rekt News"
```

```yaml
- id: proxy-002
  pattern: uninitialized-implementation
  name: "Uninitialized implementation behind proxy (delegatecall to uninitialized)"
  causa_raiz: "Implementation contract deployed behind a proxy was never initialized. The proxy's initialize() was called, but the implementation contract itself sits at its own address with no initialization. An attacker calls initialize() directly on the implementation, becoming its owner."
  como_funciona: "1. Protocol deploys TransparentProxy pointing to ImplementationV1. Proxy is initialized via delegatecall. 2. ImplementationV1 at its own address has never had initialize() called on it directly. 3. Attacker calls ImplementationV1.initialize() at the implementation address, becoming its owner. 4. For UUPS: attacker calls upgradeTo(maliciousImpl) on the implementation. Since UUPS upgrade logic lives in the implementation, this succeeds. 5. Attacker then calls selfdestruct via the malicious implementation, bricking the proxy forever. 6. For TransparentProxy: direct ownership of the implementation is less dangerous but can still be exploited if the implementation has selfdestruct or other destructive functions."
  invariante: "The initialize function must revert on any call after the first successful execution. Implementation contracts must call _disableInitializers() in their constructor to prevent direct initialization."
  que_mirar:
    - "Implementation constructors missing _disableInitializers()"
    - "UUPS implementations where upgradeToAndCall is on the logic contract -- highest risk"
    - "Multiple initialize functions (initialize, initializeV2, __ContractName_init) where only some are protected"
    - "reinitializer(version) with a version that has not been consumed yet"
    - "Implementation contracts deployed without being immediately proxied"
  como_se_arregla: "Add constructor() { _disableInitializers(); } to every implementation contract. Use the initializer modifier on all init functions. For UUPS, ensure _authorizeUpgrade has proper access control."
  trampas:
    - "reinitializer(version) is legitimate for V2 migration -- only flag if the version number allows re-calling"
    - "On TransparentProxy, the impact is lower because upgrade logic is in the proxy, not implementation"
    - "Some protocols intentionally leave implementation uninitialized if it has no selfdestruct path"
  incidentes:
    - "Zap Protocol (Vesting, TokenSale, Admin) -- Three proxy contracts missing _disableInitializers in constructor; implementation contracts directly initializable (MEDIUM)"
    - "Ethos Network -- All EthosContracts missing _disableInitializers in constructor and inheriting non-upgradeable OZ contracts (MEDIUM)"
    - "Lyra Finance (GMXAdapter) -- Implementation missing _disableInitializers; attacker can take ownership of implementation (MEDIUM)"
    - "Soulsclub Wheel -- UUPS Wheel contract missing _disableInitializers; attacker could initialize implementation as admin (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "INV-OWN-005, INV-EXPLOIT-009, solodit proxy category (finding #7 -- selfdestruct vector)"
  tags: [proxy, initializer, upgradeable, UUPS, delegatecall]
  relacionado_con: [proxy-003, proxy-004, proxy-005]
  incidentes_verificados:
    - nombre: "Audius"
      fecha: "Jul 2022"
      perdida: "$6M"
      tipo: "Uninitialized implementation -- attacker took ownership and upgraded"
      verificado: true
      fuente: "DeFiHackLabs, Rekt News"
    - nombre: "Wormhole (near miss)"
      fecha: "Feb 2022"
      perdida: "$0 (whitehat)"
      tipo: "Uninitialized UUPS implementation on Ethereum"
      verificado: true
      fuente: "Immunefi bug report, public disclosure"
```

```yaml
- id: proxy-003
  pattern: uups-missing-upgrade-authorization
  name: "UUPS missing authorization on upgradeToAndCall"
  causa_raiz: "In UUPS proxies, the upgrade logic (upgradeToAndCall) lives in the implementation contract, not the proxy. If _authorizeUpgrade() is not properly overridden with access control, anyone can upgrade the implementation to arbitrary code."
  como_funciona: "1. UUPS implementation inherits UUPSUpgradeable but does not override _authorizeUpgrade() with onlyOwner or equivalent. 2. Attacker deploys malicious implementation contract. 3. Attacker calls upgradeToAndCall(maliciousImpl, '') on the proxy. 4. The proxy now delegates all calls to attacker-controlled code. 5. Attacker drains all funds, changes all state, or selfdestructs."
  invariante: "_authorizeUpgrade must revert for any caller that is not the authorized upgrader (owner, governance, timelock). upgradeToAndCall must only be callable through the proxy (not directly on implementation)."
  que_mirar:
    - "_authorizeUpgrade function body -- is it empty? Does it have onlyOwner?"
    - "UUPS contracts where _authorizeUpgrade is inherited but never overridden"
    - "Contracts using custom UUPS that skip the OpenZeppelin _authorizeUpgrade pattern"
    - "Implementation contracts where upgradeToAndCall can be called directly (not through proxy)"
    - "After upgrade: does new implementation still have _authorizeUpgrade protected?"
  como_se_arregla: "Always override _authorizeUpgrade with onlyOwner or equivalent role check. Use OpenZeppelin UUPSUpgradeable which forces the override. Verify after every upgrade that the new implementation still has auth."
  trampas:
    - "OpenZeppelin v5 UUPSUpgradeable forces you to override _authorizeUpgrade (compile error if you don't) -- but the override can still be empty"
    - "The auth check might be present but bypass-able (e.g., checks a role that was not properly set up)"
    - "Transparent proxies are NOT affected -- upgrade logic is in the proxy admin"
  incidentes:
    - "MorpheusAI (DistributionV2) -- _authorizeUpgrade() has empty body with no access control; anyone can upgrade implementation and selfdestruct proxy (MEDIUM)"
    - "Ithaca Finance (Registry) -- Registry._authorizeUpgrade() has no access control; any user can upgrade to arbitrary implementation (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "solodit proxy category, OpenZeppelin security advisories"
  tags: [UUPS, upgrade, access-control, authorization]
  relacionado_con: [proxy-002, proxy-005]
  incidentes_verificados:
    - nombre: "OpenZeppelin UUPS vulnerability"
      fecha: "Sep 2021"
      perdida: "$0 (pre-emptive fix)"
      tipo: "Missing selfdestruct protection in UUPS -- could brick proxies"
      verificado: true
      fuente: "OpenZeppelin security advisory GHSA-5vp3-v4hc-gx76"
```

```yaml
- id: proxy-004
  pattern: initializer-frontrunning
  name: "Initializer front-running on deploy"
  causa_raiz: "Proxy deployment and initialization happen in separate transactions. An attacker front-runs the initialize() call, setting themselves as owner or injecting malicious parameters before the legitimate deployer."
  como_funciona: "1. Deployer sends tx1: deploy proxy pointing to implementation. 2. Deployer sends tx2: call initialize(owner, params) on proxy. 3. Attacker sees tx2 in mempool, front-runs with their own initialize(attackerAddr, maliciousParams). 4. Attacker becomes owner. Deployer's tx2 reverts (already initialized). 5. Attacker controls the proxy -- can upgrade, drain, or brick."
  invariante: "Proxy deployment and initialization must be atomic (single transaction). If not atomic, the initialize function must validate the caller or have a trusted deployer check."
  que_mirar:
    - "Deployment scripts that deploy proxy in one tx and call initialize in another"
    - "Factory contracts that deploy + initialize atomically (SAFE) vs ones that don't"
    - "CREATE2 deployments where the address is known in advance -- attacker can pre-compute and front-run"
    - "Contracts with multiple initializer functions where only the first is called atomically"
    - "Deployment scripts on chains with public mempools (mainnet, BSC) vs private ordering (Flashbots)"
  como_se_arregla: "Use factory patterns that deploy and initialize atomically in a single transaction. OpenZeppelin TransparentUpgradeableProxy constructor accepts _data parameter for atomic init. For CREATE2, include initialization in the constructor or use CREATE3."
  trampas:
    - "On L2s with sequencer-ordered transactions (Optimism, Arbitrum), front-running is harder but not impossible"
    - "Some protocols use a two-phase deploy intentionally with a deployer whitelist -- verify the whitelist is enforced"
    - "This is often reported as Medium, not Critical, because it requires monitoring the mempool at deploy time"
  incidentes:
    - "reNFT (modules) -- Both proxy modules missing atomic initialization; initializers can be front-run during deployment, attacker sets owner to themselves (LOW, Code4rena)"
    - "Soonaverse -- Deployment script deploys proxy then calls initialize in separate tx; attacker front-runs initialize to take ownership and force re-deployment (HIGH, AuditOne)"
    - "Advanced Blockchain / CrosslayerPortal -- Multiple contracts with front-runnable initializers via delegatecall proxy; attacker can incorrectly initialize cross-layer configuration (HIGH, Trail of Bits)"
    - "Immutable Smart Contracts -- Several implementation contracts with front-runnable initialization functions across the codebase (LOW, Trail of Bits)"
    - "CompliFi Vault -- Vault.initialize() can be front-run; difficulty rated HIGH because protocol relies on private mempool for deploy (LOW post-context, Trail of Bits)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit proxy category (findings #0, #5 -- front-running on initialization), universal pattern"
  tags: [proxy, initializer, front-running, deployment, atomic]
  relacionado_con: [proxy-002, proxy-003]
```

```yaml
- id: proxy-005
  pattern: selfdestruct-on-implementation
  name: "selfdestruct called on implementation contract bricks proxy"
  causa_raiz: "If an attacker gains control of the implementation contract (via uninitialized state, missing auth on upgrade, or direct call), they can call selfdestruct. Since the proxy delegates all calls to the implementation address, and that address now has no code, the proxy becomes permanently bricked. All funds in the proxy are locked forever."
  como_funciona: "1. Attacker initializes the unprotected implementation contract directly (proxy-002). 2. Attacker upgrades the implementation to a contract containing selfdestruct (UUPS) or calls a function that triggers selfdestruct. 3. selfdestruct destroys the code at the implementation address. 4. Proxy's fallback still delegates to that address, but there is no code -- all calls return empty/success with no effect. 5. All funds in the proxy are permanently locked. No recovery possible."
  invariante: "Implementation contracts must never contain selfdestruct or delegatecall to arbitrary targets. The implementation address must always contain code (EXTCODESIZE > 0)."
  que_mirar:
    - "Any selfdestruct or SELFDESTRUCT opcode in implementation contracts"
    - "delegatecall to user-supplied addresses within the implementation (indirect selfdestruct)"
    - "Implementation contracts that can call arbitrary targets via low-level call/delegatecall"
    - "Post-Dencun: selfdestruct only sends ETH, does not destroy code UNLESS called in the same tx as creation -- still check for pre-Dencun deployments"
    - "UUPS implementations where attacker can chain: initialize -> upgradeTo(selfdestructContract) -> selfdestruct"
  como_se_arregla: "Never include selfdestruct in implementation contracts. Call _disableInitializers() in constructor (prevents proxy-002 -> proxy-005 chain). After Dencun (EIP-6780), selfdestruct only works in creation tx, but pre-Dencun deployments remain at risk."
  trampas:
    - "Post-Dencun (Mar 2024), selfdestruct no longer destroys code except in same-tx-as-creation -- but many contracts were deployed pre-Dencun"
    - "Some chains (L2s) may not have adopted EIP-6780"
    - "The selfdestruct may be hidden behind an assembly block or in a library"
  incidentes:
    - "Biconomy SmartAccount -- Uninitialized SmartAccount implementation allows attacker to initialize, then delegatecall to Destructor, executing selfdestruct and bricking all wallets pointing to implementation (MEDIUM)"
    - "Brink Protocol (Account.sol) -- Account.sol delegateCall() allows owner to delegatecall arbitrary target; if access control compromised, selfdestruct bricks all user wallets (MEDIUM)"
    - "Escher (FixedPrice/OpenEdition) -- After selfdestruct, buy() calls to empty address succeed silently; msg.value locked forever at destroyed contract address (HIGH)"
    - "Mimo DeFi (MIMOProxy) -- User delegatecalls to selfdestruct target, destroying proxy; registry still has destroyed proxy address, user cannot deploy new proxy from same EOA (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "solodit proxy category (finding #7 -- selfdestruct/forceful ETH send vector), OpenZeppelin UUPS advisory"
  tags: [proxy, selfdestruct, UUPS, brick, permanent-lock]
  relacionado_con: [proxy-002, proxy-003]
  incidentes_verificados:
    - nombre: "Parity Wallet"
      fecha: "Nov 2017"
      perdida: "$280M (permanently locked)"
      tipo: "selfdestruct on uninitialized library/implementation"
      verificado: true
      fuente: "Public incident, Parity post-mortem"
```

```yaml
- id: proxy-006
  pattern: storage-layout-gap-missing
  name: "Missing storage gaps between upgrade versions"
  causa_raiz: "Upgradeable base contracts do not reserve storage slots via __gap arrays. When a new version adds state variables to a base contract, all derived contract variables shift down, corrupting storage for the entire inheritance tree."
  como_funciona: "1. BaseV1 has 2 state variables (slots 0-1). DerivedV1 inherits BaseV1 and adds 3 variables (slots 2-4). 2. Upgrade: BaseV2 adds 1 new variable. Now BaseV2 uses slots 0-2. 3. DerivedV2 inherits BaseV2. Its variables now start at slot 3 instead of slot 2. 4. All of DerivedV2's storage reads return wrong data. Balances, mappings, addresses -- all corrupted. 5. Funds may become inaccessible or transferable to wrong addresses."
  invariante: "Every upgradeable base contract must have a uint256[N] __gap array where N ensures total slots = constant across versions. Adding a variable to base must decrease __gap by the same number of slots."
  que_mirar:
    - "Upgradeable contracts missing __gap arrays in any base contract"
    - "__gap that was not decreased when new variables were added"
    - "Multiple inheritance where two bases both have (or lack) __gap"
    - "Contracts using OpenZeppelin upgradeable libs mixed with non-upgradeable libs"
    - "Structs added to base contracts (they consume multiple slots)"
    - "forge inspect ContractName storage-layout -- diff V1 vs V2"
  como_se_arregla: "Add uint256[50] __gap (or appropriate size) to every base contract. When adding N new state variables, reduce __gap by N. Use OpenZeppelin's upgrade safety checks or foundry storage layout inspection."
  trampas:
    - "OpenZeppelin upgradeable contracts already include __gap -- but custom base contracts often don't"
    - "Constants and immutables do NOT consume storage slots -- no gap needed for them"
    - "Mappings and dynamic arrays each consume exactly 1 slot for the root -- gap math still applies"
  incidentes:
    - "Biconomy SmartAccount (ModuleManager) -- ModuleManager has storage but no __gap; future base contract changes shift all derived storage slots (MEDIUM)"
    - "Connext Protocol -- All __GAP arrays set to 49 regardless of contract storage variable count; incorrect gap sizes make future upgrades unsafe (MEDIUM)"
    - "Rubicon (ExpiringMarket/SimpleMarket) -- SimpleMarket and ExpiringMarket have no storage gaps; adding variables to base shifts RubiconMarket storage (MEDIUM)"
    - "Ethos Network -- Custom AccessControl and SignatureControl have storage but no gaps, plus inherit non-upgradeable OZ contracts (MEDIUM)"
    - "Strata Protocol -- Upgradeable contracts missing both ERC-7201 namespaced storage and __gap arrays (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit proxy category, OpenZeppelin upgrade documentation"
  tags: [proxy, storage-gap, upgrade, inheritance, layout]
  relacionado_con: [proxy-001]
```

```yaml
- id: proxy-007
  pattern: transparent-proxy-function-clashing
  name: "Function selector clashing between proxy and implementation"
  causa_raiz: "In a transparent proxy, if the proxy admin calls a function that exists on the implementation, the proxy intercepts it instead of forwarding. But if a non-admin caller tries to call a proxy-level function (like upgradeTo), it gets forwarded to the implementation where it may match a different function with the same 4-byte selector."
  como_funciona: "1. Proxy has function upgradeTo(address). Implementation has a different function with the same 4-byte selector (e.g., collate_propagate_storage(bytes16)). 2. Non-admin user calls the clashing selector on the proxy. 3. Proxy forwards to implementation (user is not admin). 4. Implementation executes the wrong function. 5. Depending on the function, this can cause state corruption or unauthorized actions."
  invariante: "No function selector in the implementation should collide with proxy admin functions. TransparentProxy must route admin calls exclusively to proxy logic and user calls exclusively to implementation."
  que_mirar:
    - "Custom proxy contracts that do not use the transparent proxy admin pattern"
    - "Proxy contracts with many admin functions beyond just upgradeTo"
    - "Diamond/EIP-2535 proxies where facet function selectors could collide"
    - "Minimal proxies (EIP-1167) that add extra functions beyond clone forwarding"
  como_se_arregla: "Use OpenZeppelin TransparentUpgradeableProxy which enforces strict admin/non-admin routing. For Diamond proxies, check for selector collisions in the facet registry. Use tools like solidity-function-selector-collision-checker."
  trampas:
    - "OpenZeppelin TransparentProxy fully prevents this by design -- focus on custom proxies"
    - "4-byte collision probability is low but not zero, especially with auto-generated getters"
    - "This is more of a DoS/UX issue than a fund-loss issue in most cases"
  incidentes:
    - "Ironblocks Onchain Firewall -- ifAdmin modifier deprecated in OZ v4.9.3 due to function signature clash risk; FirewallTransparentUpgradeableProxy inherits deprecated pattern (LOW, OpenZeppelin)"
    - "ink! / cargo-contract -- Custom hardcoded selectors in ink! contracts can produce 4-byte collisions with proxy admin functions; attacker crafts function name to match proxy selector (HIGH, OpenZeppelin)"
    - "Compound III -- TransparentUpgradeableConfiguratorProxy._beforeCallback override creates potential clash between proxy and configurator function selectors (LOW, OpenZeppelin)"
    - "Venus Protocol Diamond Comptroller -- Multiple Diamond facets risk 4-byte selector collisions across facets; OZ audit flags systematic collision risk (LOW, OpenZeppelin)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Nomic Labs original transparent proxy research, solodit proxy category"
  tags: [proxy, selector-clash, transparent-proxy, diamond]
  relacionado_con: [proxy-001, proxy-003]
```

```yaml
- id: proxy-008
  pattern: beacon-proxy-compromise
  name: "Beacon proxy -- single point of failure for all clones"
  causa_raiz: "Beacon proxies share a single beacon contract that returns the implementation address. If the beacon is compromised (ownership taken, upgrade function unprotected), ALL proxies pointing to that beacon are simultaneously compromised."
  como_funciona: "1. Protocol deploys BeaconProxy pattern: 1 beacon + N proxy clones. 2. Beacon has an upgradeTo function protected by owner. 3. Attacker compromises the beacon owner (phishing, key leak, uninitialized -- same vectors as proxy-002/003). 4. Attacker calls beacon.upgradeTo(maliciousImpl). 5. ALL N proxy clones now delegate to the malicious implementation. 6. Attacker drains funds from all clones in a single transaction."
  invariante: "Beacon ownership must be held by a timelock or multi-sig. Beacon upgrade function must have the same auth protections as any proxy upgrade. All beacon proxies are exactly as secure as the beacon itself."
  que_mirar:
    - "Who owns the beacon? EOA vs multi-sig vs timelock"
    - "Is the beacon's upgradeTo protected by access control?"
    - "How many proxies point to this beacon? (blast radius assessment)"
    - "Can the beacon be initialized/re-initialized?"
    - "Is there a way to decouple a single proxy from the beacon in an emergency?"
  como_se_arregla: "Beacon owner must be a timelock with minimum delay. Consider adding per-proxy emergency override. Monitor beacon upgrade events. Use multi-sig for beacon ownership."
  trampas:
    - "The blast radius is the key differentiator -- a single beacon compromise affects ALL clones"
    - "Beacon proxies are legitimate and useful (gas-efficient mass upgrades) -- the issue is auth, not the pattern"
  incidentes:
    - "Primex Finance -- Factory-deployed beacon proxies owned by deployer EOA (not PrimexProxyAdmin); any deployer can upgrade all factory clones without going through governance (MEDIUM, Quantstamp)"
    - "AriaIPVault -- Contract inherits UUPS AND sits behind BeaconProxy; UUPS _authorizeUpgrade is unreachable because beacon controls upgrades; redundant UUPS adds confusion about actual upgrade path (LOW, Pashov Audit Group)"
    - "Solv Protocol SolvBTC -- Mismatch between beacon contract stored in factory vs beacon used by proxies; factory cannot verify which beacon proxies actually point to, creating split-brain upgrade risk (LOW, Quantstamp)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "solodit proxy category, OpenZeppelin BeaconProxy documentation"
  tags: [proxy, beacon, mass-compromise, upgrade, access-control]
  relacionado_con: [proxy-002, proxy-003]

- id: proxy-009
  pattern: notDelegated-kills-upgradeability
  name: "UUPS functions marked notDelegated make contract non-upgradeable"
  causa_raiz: "UUPS upgradeable contracts use the notDelegated modifier on initialize() or _authorizeUpgrade(). This modifier requires msg.sender == address(this), which is false when called through a proxy via delegatecall. The contract compiles and deploys, but can never actually be upgraded because upgradeToAndCall() internally calls _authorizeUpgrade() which reverts."
  como_funciona: |
    1. Protocol deploys AssetFactory behind a UUPS proxy.
    2. AssetFactory.initialize() has the notDelegated modifier.
    3. Proxy calls initialize() via delegatecall -- notDelegated checks address(this) != deploymentAddress, reverts.
    4. Even if initialize succeeds via workaround, _authorizeUpgrade() also has notDelegated.
    5. Admin calls upgradeToAndCall() on proxy -- internally calls _authorizeUpgrade() via delegatecall -- reverts.
    6. Contract is permanently non-upgradeable. If a critical bug is found, no fix is possible.
    7. Ownership may also be stuck in a contract (e.g., ModuleCore) that cannot call upgradeToAndCall().
  invariante: "UUPS initialize() and _authorizeUpgrade() must never use the notDelegated modifier. upgradeToAndCall() must be callable through the proxy by the authorized upgrader."
  que_mirar:
    - "grep -rn 'notDelegated' --include='*.sol' -- look for it on initialize or _authorizeUpgrade"
    - "UUPS contracts where ownership is set to a contract that lacks upgradeToAndCall() capability"
    - "Contracts inheriting UUPSUpgradeable but deployed without a proxy (notDelegated is a hint)"
    - "Check deploy scripts: is the contract actually deployed behind a proxy or standalone?"
  como_se_arregla: "Remove notDelegated from initialize() and _authorizeUpgrade(). Ensure the owner contract can call upgradeToAndCall(). If standalone deployment is intended, do not inherit UUPSUpgradeable."
  trampas:
    - "notDelegated is legitimate for functions that should ONLY run on the implementation directly (rare)"
    - "The contract compiles fine -- this only manifests at runtime when upgrade is attempted"
    - "If the owner is set to a contract (e.g., ModuleCore), verify that contract exposes upgrade functionality"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "solodit #41488 (Cork Protocol, Sherlock), #41486 (Cork Protocol, Sherlock)"
  tags: [UUPS, notDelegated, upgrade, broken-upgradeability]
  relacionado_con: [proxy-003]
  incidentes_verificados:
    - nombre: "Cork Protocol"
      fecha: "Aug 2024"
      perdida: "N/A (broken functionality)"
      tipo: "AssetFactory and FlashSwapRouter marked notDelegated on initialize and _authorizeUpgrade -- permanently non-upgradeable"
      verificado: true
      fuente: "Sherlock audit 2024-08-cork-protocol, issues #185 and #47"

- id: proxy-010
  pattern: constructor-config-behind-proxy
  name: "Constructor-only configuration does not apply to proxy"
  causa_raiz: "Developer places chain-specific or protocol configuration logic in the constructor of an upgradeable implementation contract. Constructors run during deployment and affect the implementation contract's own storage/state. But the proxy -- which holds all user funds and real state -- never executes the constructor. The configuration is applied to the wrong contract."
  como_funciona: |
    1. ParticlePositionManager has constructor that calls Blast.configure() to set yield mode to claimable.
    2. Contract is deployed behind a UUPS proxy. Constructor runs on the implementation address.
    3. Blast yield/gas configuration is set on the implementation contract, not the proxy.
    4. The proxy contract (where all ETH, WETHB, USDB balances live) has default void/disabled yield mode.
    5. All yield and gas refunds that should accrue to the protocol are permanently lost.
    6. No setter function exists to change the mode after deployment.
  invariante: "Any configuration that affects contract state (yield modes, gas modes, rebasing token config, chain-specific setup) must be in initialize(), not the constructor. Constructor should only contain _disableInitializers() and immutable assignments."
  que_mirar:
    - "Constructors in upgradeable contracts that do more than _disableInitializers() and set immutables"
    - "Blast-specific: grep for 'configureClaimableYield|configureClaimableGas|configure(' in constructors"
    - "Any external call in a constructor of a proxied contract"
    - "Chain-specific config (Blast yield, Optimism gas, etc.) that must apply to the proxy address"
  como_se_arregla: "Move all configuration logic from constructor to initialize(). Constructor should only set immutables and call _disableInitializers(). For Blast: call Blast.configure() inside initialize()."
  trampas:
    - "immutable variables ARE set correctly in constructors (they live in bytecode, not storage) -- do not flag these"
    - "_disableInitializers() in constructor is correct and expected"
    - "This is Blast/L2-specific in many cases but the general pattern applies to any chain-specific setup"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit #40716 (Particle, Cantina)"
  tags: [proxy, constructor, blast, yield, configuration, initialize]
  relacionado_con: [proxy-002]
  incidentes_verificados:
    - nombre: "Particle Protocol"
      fecha: "2024"
      perdida: "Permanent yield loss (all Blast yield/gas on proxy)"
      tipo: "Blast.configure() in constructor only affected implementation, not proxy -- zero yield accrual"
      verificado: true
      fuente: "Cantina audit of Particle"

- id: proxy-011
  pattern: upgrade-drops-interface
  name: "V2 implementation is not a strict superset of V1 interface"
  causa_raiz: "When upgrading a UUPS proxy, the new implementation must contain ALL functions from V1 plus any new ones. If V2 is written as a standalone contract that only adds new features without inheriting V1, all V1 function selectors disappear. Calls to those functions (from scripts, other contracts, or users) silently succeed with empty return data or revert."
  como_funciona: |
    1. RewardsEngineV1 has distribute(), epoch config, claim functions.
    2. RewardsEngineV1_1 is written as a new standalone contract inheriting only OZ base contracts.
    3. V1_1 only adds claimFor() and batchClaimFor() -- does NOT inherit V1.
    4. After proxy upgrade to V1_1, calls to distribute() revert (selector not found).
    5. Migration runbook calls distribute() after upgrade -- entire migration breaks.
    6. Protocol is stuck: cannot distribute rewards, must deploy another upgrade to fix.
  invariante: "After upgrade, every function selector present in V(N) must also be present in V(N+1). V(N+1) implementation must be a strict superset of V(N) interface."
  que_mirar:
    - "V2 contracts that do NOT inherit from V1 -- instead written from scratch"
    - "Compare function selectors: forge inspect V1 abi vs forge inspect V2 abi"
    - "Upgrade runbooks/scripts that call functions -- verify those functions exist in new impl"
    - "Contracts that remove or rename public/external functions between versions"
    - "New implementation inheriting different base contracts than V1"
  como_se_arregla: "V2 should inherit V1 and add new functionality. If rewrite is necessary, ensure all V1 external function selectors are preserved. Run fork test: upgrade proxy, then execute full V1 interface + migration script."
  trampas:
    - "Some functions are intentionally removed (deprecated) -- but callers must be updated first"
    - "Even if the function body changes, the selector must remain callable"
    - "Internal functions don't matter -- only public/external selectors"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit #64790 (Buck Labs, Spearbit)"
  tags: [proxy, upgrade, interface, ABI, migration, UUPS]
  relacionado_con: [proxy-003, proxy-006]
  incidentes_verificados:
    - nombre: "Buck Labs RewardsEngine"
      fecha: "2025"
      perdida: "N/A (caught in audit)"
      tipo: "RewardsEngineV1_1 did not inherit V1 -- distribute() missing after upgrade, blocking migration"
      verificado: true
      fuente: "Spearbit audit of Buck Labs"

- id: proxy-012
  pattern: initializer-vs-onlyInitializing-misuse
  name: "Base contract uses initializer modifier instead of onlyInitializing"
  causa_raiz: "In OpenZeppelin's upgradeable pattern, base/parent contracts must use onlyInitializing on their __init functions (called during child initialization). If a base contract uses the initializer modifier instead, calling it from a child's initialize() (which also has initializer) causes a revert due to reentrancy protection in the Initializable contract -- the initializer modifier does not allow nested calls."
  como_funciona: |
    1. EIP712MetaTransaction has initializeEIP712() with the initializer modifier.
    2. QuantProtocol has initialize() with the initializer modifier.
    3. initialize() calls initializeEIP712() internally.
    4. OpenZeppelin's initializer modifier sets _initializing = true on first call.
    5. Second nested initializer call checks _initializing -- in Solidity >= 0.8 with OZ v4.x, this reverts.
    6. Contract cannot be initialized through the proxy. Deployment fails silently or requires workaround.
    7. Exception: if called inside a constructor context (e.g., via deployProxy), nested initializer may succeed due to special constructor handling -- but this is fragile.
  invariante: "Base/parent upgradeable contracts must use onlyInitializing modifier on their internal init functions. Only the top-level child contract's initialize() should use initializer."
  que_mirar:
    - "grep -rn 'initializer' --include='*.sol' -- look for base contracts using initializer instead of onlyInitializing"
    - "Internal init functions (__ContractName_init) with public visibility and initializer modifier"
    - "Inheritance chains where multiple contracts each have initializer-modified functions"
    - "Contracts marked public instead of internal on their init helpers"
  como_se_arregla: "Change base contract init functions to use onlyInitializing modifier and internal visibility. Only the final child contract's initialize() should use initializer. Follow OZ pattern: __Base_init() is internal onlyInitializing."
  trampas:
    - "In constructor context (deployProxy), nested initializer calls may succeed -- bug only appears on redeployment or upgrade"
    - "OZ v5 changed some behavior around reentrancy in initializers -- check the specific version"
    - "reinitializer(N) has different nesting rules than initializer"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit #1684 (Rolla, Code4rena)"
  tags: [proxy, initializer, onlyInitializing, OpenZeppelin, upgradeable]
  relacionado_con: [proxy-002, proxy-004]
  incidentes_verificados:
    - nombre: "Rolla / Quant Protocol"
      fecha: "Mar 2022"
      perdida: "N/A (broken initialization)"
      tipo: "EIP712MetaTransaction used initializer instead of onlyInitializing -- nested init reverts"
      verificado: true
      fuente: "Code4rena 2022-03-rolla contest"

- id: proxy-013
  pattern: missing-state-migration-on-upgrade
  name: "V2 replaces storage variables without migration function"
  causa_raiz: "When upgrading, V2 replaces V1's global state variables with a new structure (e.g., single variable to per-vault mapping). The old storage slot values are not migrated to the new structure. After upgrade, the new mapping/struct reads default zero values instead of the intended V1 values. Critical protocol parameters silently become zero."
  como_funciona: |
    1. LiquidationManagerV1 has global liquidatorRewardBps = 25% and bufferRewardsBps = 25%.
    2. V2 replaces these with mapping(uint8 => LiquidationConfiguration) per vault.
    3. Upgrade to V2 occurs. No reinitializer or migration function is called.
    4. liquidationConfiguration[vaultId] returns zero for all vaults (mapping default).
    5. Liquidation reward calculations use zero values -- liquidators get zero reward.
    6. Nobody liquidates because there is no incentive. Protocol accumulates bad debt.
  invariante: "After upgrade, all V1 state must be accessible through V2's interface with correct values. Any structural change to storage variables requires a reinitializer that migrates V1 values to V2 format."
  que_mirar:
    - "V2 contracts that replace variables with mappings or structs but have no reinitializer(N)"
    - "reinitializer functions that set new variables but don't copy from old ones"
    - "Upgrade scripts that don't call any migration function after upgradeToAndCall"
    - "Default-zero values in new mappings/structs that replace non-zero V1 globals"
    - "Compare V1 storage layout to V2 -- any renamed or restructured slots need migration"
  como_se_arregla: "Implement reinitializer(N) that reads old values and writes them into new structure. Test on fork: upgrade, then verify all V1 parameter values are accessible through V2 interface. Include migration in upgradeToAndCall data parameter."
  trampas:
    - "If V2 storage is append-only (new slots after V1 slots), old values survive -- only structural changes need migration"
    - "reinitializer version must be incremented correctly (2 for first upgrade, 3 for second, etc.)"
    - "TimelockUpgradeableProxy patterns may not clear upgrade state after execution (solodit #63531) -- separate issue but related"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit #63444 (Hyperstable, Pashov Audit Group)"
  tags: [proxy, upgrade, migration, reinitializer, state, storage]
  relacionado_con: [proxy-001, proxy-006]
  incidentes_verificados:
    - nombre: "Hyperstable LiquidationManager"
      fecha: "Jun 2025"
      perdida: "N/A (caught in audit)"
      tipo: "V2 replaced global reward params with per-vault mapping -- zero rewards for all vaults post-upgrade"
      verificado: true
      fuente: "Pashov Audit Group audit of Hyperstable_2025-06-03"

- id: proxy-014
  pattern: unsafe-downgrade-storage-reorder
  name: "Rollback to V1 after V2 corrupts storage due to slot reordering"
  causa_raiz: "V2 implementation reorders storage slots compared to V1. After the proxy runs V2, those slots hold V2 values. If the proxy is downgraded back to V1 (emergency rollback), V1 interprets the same slots as different fields. Addresses, amounts, and access control state get cross-contaminated."
  como_funciona: |
    1. V1 storage: slot0=buck, slot1=liquidityReserve, slot2=policyManager, slot3=usdc.
    2. V2 storage: slot0=buck, slot1=policyManager, slot2=oracleAdapter, slot3=liquidityReserve.
    3. Proxy upgraded to V2. V2 writes policyManager address to slot1, oracleAdapter to slot2.
    4. Emergency: proxy rolled back to V1.
    5. V1 reads slot1 as liquidityReserve -- but it contains policyManager address from V2.
    6. Funds sent to liquidityReserve go to policyManager contract instead.
    7. Access checks using wrong addresses may grant unauthorized access or lock out admins.
  invariante: "Storage slot assignments must be identical between V1 and V2 for all shared variables. If V2 reorders slots, rollback to V1 must be explicitly forbidden or a migration contract must be used."
  que_mirar:
    - "Upgrade runbooks with 'rollback' or 'downgrade' steps"
    - "V2 contracts that reorder existing V1 storage variables (not just append)"
    - "forge inspect V1 storage-layout vs forge inspect V2 storage-layout -- any reordered slots"
    - "Emergency procedures that point proxy back to old implementation"
    - "Proxy admin timelocks with rollback capabilities"
  como_se_arregla: "Never reorder existing storage slots between versions (append-only). Remove rollback-to-V1 from runbooks if V2 reorders storage. If rollback is required, deploy fresh proxy with clean V1 state. Alternatively, create a dedicated rollback implementation that migrates V2 layout back to V1."
  trampas:
    - "Append-only storage changes ARE safe to rollback (V1 simply ignores new trailing slots)"
    - "ERC-7201 namespaced storage makes reordering within a namespace safe but cross-namespace changes still matter"
    - "This is an operational/runbook issue as much as a code issue -- auditors should review upgrade procedures"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "solodit #64799 (Buck Labs, Spearbit)"
  tags: [proxy, upgrade, rollback, storage, downgrade, migration]
  relacionado_con: [proxy-001, proxy-006, proxy-013]
  incidentes_verificados:
    - nombre: "Buck Labs LiquidityWindow"
      fecha: "2025"
      perdida: "N/A (caught in audit)"
      tipo: "V2 reordered storage slots -- runbook suggested rollback to V1 which would corrupt addresses and misroute funds"
      verificado: true
      fuente: "Spearbit audit of Buck Labs"

- id: proxy-015
  pattern: proxy-reuse-outdated-implementation
  name: "Reused clone proxy delegates to outdated/vulnerable implementation"
  causa_raiz: "Protocol pools proxies (EIP-1167 clones) for reuse. When the admin updates the implementation address, existing proxies in the pool still embed the old implementation in their bytecode. Reusing a pooled proxy silently delegates to the old (possibly vulnerable) logic instead of the current implementation."
  como_funciona: |
    1. Owner sets implementations[token] = ImplV1.
    2. Alice creates two proxies — both cloned from ImplV1.
    3. Owner calls setImplementations(token, ImplV2).
    4. Alice's old proxies return to the reuse pool.
    5. New transfer pops a proxy from the pool — still delegates to ImplV1.
    6. User operates through outdated logic with potential bugs or incompatibilities.
  invariante: |
    // Reused proxy implementation must match current implementation
    // assert(proxy.implementation() == implementations[token])
  que_mirar:
    - "rg 'proxiesPool|proxyPool|clonePool' --type sol"
    - "Are EIP-1167 clones reused after implementation updates?"
    - "Does the reuse path verify the proxy's embedded implementation?"
    - "rg 'setImplementation' --type sol — can implementation change while proxies exist?"
  como_se_arregla: "When reusing a proxy, verify its implementation matches the current one. If mismatched, discard the old proxy and create a new clone with the current implementation."
  trampas:
    - "If implementation is immutable (never updated), not exploitable"
    - "If proxies are UUPS (not minimal clones), implementation can be updated in-place"
  incidentes:
    - "Strata Tranches UnstakeCooldown — reuses old clone proxies with outdated implementation after setImplementations update (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, clone, EIP-1167, implementation, reuse, outdated]

- id: proxy-016
  pattern: upgrade-authority-too-broad
  name: "Non-admin role granted upgrade authority — excessive privilege"
  causa_raiz: "_authorizeUpgrade allows multiple roles (e.g., ROLE_MANAGER_ROLE alongside SUPER_ADMIN_ROLE) to perform contract upgrades. Upgrade is the most sensitive operation in a proxy system. Granting it to roles not designed for that trust level increases attack surface and violates least-privilege principle."
  como_funciona: |
    1. _authorizeUpgrade uses onlySuperAdminOrRoleManager modifier.
    2. ROLE_MANAGER_ROLE is designed for managing user roles, not upgrades.
    3. Attacker compromises ROLE_MANAGER_ROLE account.
    4. Attacker calls upgradeToAndCall with malicious implementation.
    5. All proxy state is now controlled by attacker's logic.
    6. Funds drained or backdoor installed.
  invariante: |
    // Only a single, clearly defined admin role should authorize upgrades
    // assert(msg.sender == superAdmin)
  que_mirar:
    - "rg '_authorizeUpgrade' --type sol — which roles can call it?"
    - "Is there more than one role that can trigger upgrades?"
    - "Are the upgrade-authorized roles consistent across all contracts?"
    - "Does the protocol use timelock for upgrades?"
  como_se_arregla: "Restrict _authorizeUpgrade to a single highly-trusted role (e.g., SUPER_ADMIN_ROLE only). Use a timelock for upgrade operations. Remove upgrade capability from operational roles."
  trampas:
    - "If both roles are controlled by the same multisig, lower practical risk"
    - "If the protocol is intended to be admin-upgradeable by design, may be accepted"
  incidentes:
    - "RipIt RoleBasedAccessControl — _authorizeUpgrade allows both SUPER_ADMIN_ROLE and ROLE_MANAGER_ROLE, excessive upgrade privilege (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, upgrade, access-control, UUPS, privilege-escalation]

- id: proxy-017
  pattern: upgrade-config-not-persisted-to-storage
  name: "Upgrade process computes new config but does not persist it to storage"
  causa_raiz: "Multi-step upgrade process computes a new_upgrade_config variable (containing updated version numbers and cleaned-up fields) but never writes it back to storage. The upgrade appears to succeed but version tracking, user code updates, and cleanup fields remain stale, causing the next upgrade to malfunction or fail."
  como_funciona: |
    1. Admin initiates upgrade: init_upgrade_process sets new code and starts timer.
    2. Admin calls submit_upgrade_process to finalize.
    3. Function creates new_upgrade_config with updated versions and cleared fields.
    4. new_upgrade_config is used only for the log event, never saved to storage.
    5. Storage retains old master_version, user_version, user_code values.
    6. Next upgrade reads stale values — version mismatch or double-upgrade possible.
  invariante: |
    // After upgrade submission, storage must reflect the new config
    // assert(storage.master_version == new_config.master_version)
    // assert(storage.user_code == new_config.user_code)
  que_mirar:
    - "Is there a multi-step upgrade process (init, disable, submit)?"
    - "Does submit_upgrade write computed values back to persistent storage?"
    - "Are version numbers updated in storage after upgrade completes?"
    - "rg 'upgrade_config|set_data|save.*config' — check persistence"
  como_se_arregla: "Persist new_upgrade_config to storage after computing it. Add assertions that verify storage state matches expected post-upgrade values. Test the full upgrade lifecycle including subsequent upgrades."
  trampas:
    - "If the platform uses a different upgrade mechanism for subsequent upgrades, may be mitigated"
    - "May only manifest on the second upgrade cycle"
  incidentes:
    - "EVAA Finance — submit_upgrade_process generates new_upgrade_config but never saves to storage, version tracking broken (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, upgrade, storage, persistence, version, multi-step]

- id: proxy-018
  pattern: reinitializer-frontrun-after-upgrade
  name: "Reinitializer function callable by anyone after proxy upgrade"
  causa_raiz: "Contract implements reinitializer(N) for upgrade-time initialization but does not restrict who can call it. After an upgrade deploys new implementation, there is a window where anyone can front-run the admin's reinitialization call, potentially setting critical parameters (roles, addresses) to attacker-controlled values."
  como_funciona: |
    1. Contract has initialize() with initializer and initializeV2() with reinitializer(2).
    2. Admin upgrades proxy to new implementation.
    3. reinitializer(2) becomes callable (version 1 was already used).
    4. Attacker front-runs admin's upgradeAndCall or separate reinitialize tx.
    5. Attacker calls initializeV2() with their own parameters.
    6. Attacker gains admin roles or sets malicious addresses.
    7. With UUPS, attacker can then upgrade again to fully control the proxy.
  invariante: |
    // Reinitialization must be atomic with upgrade or access-restricted
    // assert(reinitialize.caller == admin || calledViaUpgradeAndCall)
  que_mirar:
    - "rg 'reinitializer' --type sol — is it access-restricted?"
    - "Is reinitializer called atomically via upgradeAndCall?"
    - "Can reinitializer be called separately from upgrade?"
    - "Does the reinitializer set any privileged roles or critical addresses?"
  como_se_arregla: "Always call reinitializer atomically via upgradeAndCall in the same transaction as the upgrade. Or add access control (onlyOwner/onlyAdmin) to the reinitializer function. Never leave reinitialization as a separate unprotected step."
  trampas:
    - "If using Transparent Proxy (not UUPS), attacker cannot upgrade further even if they front-run"
    - "If reinitializer only sets non-critical parameters, impact is low"
  incidentes:
    - "Linea RollupRevenueVault — reinitializer(2) available immediately after initialize, front-runnable before admin calls upgradeAndCall (Medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, reinitializer, frontrun, upgrade, access-control, initialization]

- id: proxy-019
  pattern: diamond-storage-slot-zero-collision
  name: "Diamond facet uses standard ReentrancyGuard — slot 0 collision across facets"
  causa_raiz: "Diamond proxy facets inherit standard (non-upgradeable) OpenZeppelin ReentrancyGuard which uses storage slot 0 for its status variable. In a Diamond pattern, all facets share the same storage. If multiple facets use slot 0 for different purposes, storage corruption disables reentrancy protection or corrupts state."
  como_funciona: |
    1. Diamond plugin A inherits standard ReentrancyGuard (uses slot 0).
    2. Diamond plugin B also uses slot 0 for a different variable.
    3. Plugin A sets reentrancy lock: slot 0 = 2.
    4. Plugin B reads slot 0, interprets 2 as its own variable's value.
    5. Either reentrancy protection is bypassed or plugin B's state is corrupted.
    6. In worst case, reentrancy guard is permanently locked, DoSing all guarded functions.
  invariante: |
    // Diamond facets must use namespaced storage, not slot 0
    // assert(facet.storageSlot != 0 || facet == onlySlotZeroOwner)
  que_mirar:
    - "Does the Diamond facet inherit standard (non-upgradeable) OpenZeppelin contracts?"
    - "rg 'ReentrancyGuard' --type sol — is it the standard or upgradeable version?"
    - "Do multiple facets share slot 0 or low-numbered slots?"
    - "Is ERC-7201 namespaced storage used for Diamond facets?"
  como_se_arregla: "Use ReentrancyGuardUpgradeable or Diamond-specific storage patterns (ERC-7201 namespaced storage). Ensure all facets use distinct storage namespaces. Call __ReentrancyGuard_init in the Diamond's initialization."
  trampas:
    - "If Diamond has only one facet using slot 0, no collision currently"
    - "Future facet additions may introduce the collision"
  incidentes:
    - "CryptoLegacy — Diamond plugins inherit standard ReentrancyGuard using slot 0, collision risk across facets (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, diamond, storage-collision, ReentrancyGuard, slot-zero, ERC-7201]

- id: proxy-020
  pattern: selfdestruct-breaks-contract-balance-invariant
  name: "SELFDESTRUCT forces native tokens into contract, breaking balance-based invariants"
  causa_raiz: "Contract uses address(this).balance for critical accounting (totalSupply, staking invariants) and blocks normal receive() deposits. An attacker uses SELFDESTRUCT from another contract to force native tokens in, breaking the invariant that balance equals tracked deposits. On chains where SELFDESTRUCT still deletes code (pre-EIP-6780), this inflates balance-derived calculations."
  como_funciona: |
    1. Contract tracks totalSupply = address(this).balance (e.g., wrapped token).
    2. Contract has no payable functions — assumes balance only changes via deposit/withdraw.
    3. Attacker creates a contract with native tokens and calls SELFDESTRUCT(target).
    4. Native tokens force-sent to target contract.
    5. address(this).balance increases without corresponding deposit tracking.
    6. totalSupply() returns inflated value. Accounting invariants break.
    7. For staking contracts: balance != tracked stakes, blocking operations.
  invariante: |
    // Internal tracking must not rely on address(this).balance
    // Use a separate state variable for deposits
    assert(internalBalance == trackedDeposits)
  que_mirar:
    - "rg 'address.*this.*balance|this\\.balance' --type sol — used for accounting?"
    - "Does totalSupply or any critical value derive from contract balance?"
    - "Can balance be manipulated via SELFDESTRUCT or coinbase reward?"
    - "Is the chain pre-EIP-6780 (SELFDESTRUCT still works)?"
  como_se_arregla: "Track deposits and withdrawals in a separate state variable instead of relying on address(this).balance. Add a recoverExtraTokens() function for the difference. Use internal accounting for all critical calculations."
  trampas:
    - "Post-EIP-6780 chains: SELFDESTRUCT only works in same-creation-tx, limiting attack"
    - "If contract has payable functions, balance manipulation is expected"
  incidentes:
    - "VeChain DPoS Staker — SELFDESTRUCT sends VET to Staker contract, breaks balance == staked invariant, blocks block production (High)"
    - "Camp WrappedCAMP — SELFDESTRUCT inflates totalSupply derived from balance (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [proxy, selfdestruct, balance-invariant, forced-ether, accounting, EIP-6780]

- id: proxy-021
  pattern: unrestricted-diamondcut
  name: "Unrestricted diamondCut allows anyone to modify or replace all facets"
  causa_raiz: "Diamond proxy (EIP-2535) exposes diamondCut() -- the function that adds, replaces, or removes facets. If this function has no access control, any caller can replace all facets with malicious implementations or remove all selectors (bricking the diamond). Because all proxy functionality routes through facets, this is equivalent to an unprotected upgradeToAndCall on UUPS."
  como_funciona: |
    1. SimplexDiamond includes DiamondCutFacet.diamondCut.selector in its public facet list.
    2. DiamondCutFacet.diamondCut() has no onlyOwner or role check.
    3. Attacker calls diamond.diamondCut([{facet: maliciousImpl, action: Replace, selectors: [...]}], ...).
    4. All critical facets (swap, liquidity, access control) replaced with attacker-controlled code.
    5. Attacker drains all funds or bricks the diamond permanently.
  invariante: |
    // diamondCut must be callable only by authorized admin
    // assert(msg.sender == diamondOwner || hasRole(DIAMOND_CUT_ROLE, msg.sender))
  que_mirar:
    - "rg 'diamondCut' --type sol -- check access control on the DiamondCutFacet"
    - "Is diamondCut.selector included in the public facet selector list?"
    - "Does the DiamondCutFacet enforce onlyOwner or equivalent before modifying facets?"
    - "Can diamondCut be called without a timelock delay?"
    - "rg 'FacetCutAction' --type sol -- look for where diamondCut is invoked"
  como_se_arregla: "Add access control to diamondCut (onlyOwner or role-gated). Consider adding a timelock delay for diamond upgrades (as Connext does with 7-day proposal window). Do NOT expose diamondCut.selector in public-facing facet listings."
  trampas:
    - "If diamond is intended to be immutable post-deploy, diamondCut should be removed entirely from facets"
    - "Some diamonds use a governance proposal + timelock flow -- check whether execution step also requires the delay"
    - "LiFi's Diamond uses owner-only diamondCut with no timelock -- owner key compromise is the remaining risk"
  incidentes:
    - "Burve Protocol (SimplexDiamond) -- DiamondCutFacet.diamondCut exposed with no access control; any caller can replace all facets, drain all liquidity positions (CRITICAL, Pashov Audit Group)"
    - "LI.FI Diamond -- diamondCut callable by owner with no timelock delay; Connext requires 7-day proposal window for same operation (LOW, Spearbit)"
    - "Connext Diamond -- diamondCut acceptance hash not reset after execution; old upgrades can be re-executed without waiting for delay again (MEDIUM, Spearbit)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (Burve_2025-01-29, LIFI, Connext)"
  tags: [proxy, diamond, diamondCut, access-control, upgrade, EIP-2535]
  relacionado_con: [proxy-003, proxy-007, proxy-019]

- id: proxy-022
  pattern: storage-slot-shift-loses-roles-on-upgrade
  name: "Proxy upgrade shifts accessControl mapping slot, permanently losing all roles"
  causa_raiz: "A Diamond or upgradeable proxy stores an access control mapping (e.g., mapping(address => mapping(bytes32 => bool)) accessControl) at a specific storage slot. When a new facet or module is added that inserts a variable before it in the storage layout, the slot number shifts. All previously-granted roles are now read from the wrong slot and appear ungranted. Protocol operations requiring those roles are instantly broken post-upgrade."
  como_funciona: |
    1. GNSMultiCollatDiamond stores accessControl mapping at slot 2 in the proxy.
    2. New upgrade adds a variable at slot 2 in a new facet, shifting accessControl to slot 3.
    3. After upgrade, hasRole(ROLE, addr) reads from new slot 3 -- all values are zero (empty).
    4. All admin functions, liquidations, and protocol operations that check roles revert.
    5. Protocol is operationally locked. New roles must be re-granted, but the role-granting function
       may also be broken if it too requires a role.
  invariante: |
    // After upgrade: all pre-upgrade role assignments must still return true
    // assert(accessControl[prevRoleHolder][LIQUIDATOR_ROLE] == true)
  que_mirar:
    - "forge inspect ContractV1 storage-layout vs forge inspect ContractV2 storage-layout -- any shifted slots?"
    - "Does the upgrade insert new variables before existing access control mappings?"
    - "Are roles re-granted via a reinitializer after the upgrade, or assumed to persist?"
    - "Does the role-granting function itself require a role that will be lost post-upgrade?"
    - "rg 'accessControl|hasRole|_roles' --type sol -- find where roles are stored"
  como_se_arregla: "Never insert new storage variables before existing ones (append-only). If restructuring is required, implement a reinitializer that re-grants all critical roles from a backup list. Test on fork: upgrade, then verify all pre-upgrade role holders still have their roles."
  trampas:
    - "Diamond storage with ERC-7201 namespaced structs avoids this if all access control is inside the same namespace"
    - "If the protocol has an off-chain role registry, re-granting may be feasible -- but it requires the grant function to work post-upgrade"
    - "Even immutable roles (DEFAULT_ADMIN_ROLE) stored in a shifted slot are lost"
  incidentes:
    - "GainsNetwork GNSMultiCollatDiamond -- Upgrade shifts accessControl mapping from slot 2 to slot 3; all grantee roles lost post-upgrade, all role-gated protocol functions broken (HIGH, Pashov Audit Group)"
    - "Realize TokenManager -- Roles granted in constructor apply only to implementation, not proxy; after upgrade implementation roles are lost and proxy has no DEFAULT_ADMIN_ROLE (INFO, Zokyo)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (GainsNetwork-February H-01, Realize)"
  tags: [proxy, upgrade, storage-slot, access-control, roles, diamond, mapping]
  relacionado_con: [proxy-001, proxy-006, proxy-013]

- id: proxy-023
  pattern: incorrect-role-constant-bypasses-upgrade-auth
  name: "UPGRADER_ROLE bytes32 constant has wrong value -- upgrade auth silently grants to wrong role"
  causa_raiz: "The UPGRADER_ROLE constant used in _authorizeUpgrade() is defined with the wrong keccak256 string (e.g., 'cbattestations.staticattester.upgrader' instead of 'cbattestations.indexer.upgrader'). AccessControl.hasRole() checks the exact bytes32 value. The role that actually grants upgrade capability is different from the role that admins believe they are managing. Either no one has upgrade authority (DoS) or the wrong role holders can upgrade (privilege escalation)."
  como_funciona: |
    1. AttestationIndexer defines UPGRADER_ROLE = keccak256("cbattestations.staticattester.upgrader").
    2. _authorizeUpgrade checks hasRole(UPGRADER_ROLE, msg.sender).
    3. Admin grants the role they believe is UPGRADER_ROLE via the role name in docs.
    4. But the actual bytes32 stored in UPGRADER_ROLE does not match what was granted.
    5. Either: (a) nobody can upgrade (DoS on upgrade path), or (b) wrong role holders
       (staticattester role) can trigger upgrades without intending to.
  invariante: |
    // UPGRADER_ROLE value must match the string documented and used in role grants
    // assert(UPGRADER_ROLE == keccak256("cbattestations.indexer.upgrader"))
  que_mirar:
    - "rg 'UPGRADER_ROLE|UPGRADE_ROLE' --type sol -- what string is hashed?"
    - "Does the hashed string match the role name in documentation and deploy scripts?"
    - "Are there multiple contracts with UPGRADER_ROLE? Do they all use the same bytes32?"
    - "Is the same keccak string used in grantRole() calls (deploy scripts, tests)?"
    - "Check for typos: 'upgrader' vs 'upgrade', 'Upgrader' vs 'upgrader', protocol name mismatches"
  como_se_arregla: "Audit all bytes32 role constants against their intended string values. Use a single shared constants file for role definitions. Write tests that assert keccak256(roleString) == ROLE_CONSTANT for every role. Verify deploy scripts use the same role values as the contracts."
  trampas:
    - "If the wrong role is empty (no holders), result is DoS on upgrades rather than privilege escalation"
    - "Role typos are especially dangerous if the 'wrong' role is held by a less-trusted account"
    - "This pattern appears in both UUPS and Diamond proxies -- anywhere hasRole gates upgrade"
  incidentes:
    - "Coinbase AttestationIndexer -- UPGRADER_ROLE value uses 'staticattester' string instead of 'indexer'; role check in _authorizeUpgrade silently gates wrong set of accounts, breaking upgrade access control (MEDIUM, Cantina)"
    - "Coinbase AttestationIndexer -- INDEXER_ROLE similarly incorrect ('cbattestations.staticattester.indexer' vs expected value); pattern shows systemic copy-paste of wrong protocol name in role constants (MEDIUM, Cantina)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (Coinbase Cantina audit)"
  tags: [proxy, UUPS, access-control, UPGRADER_ROLE, bytes32, role-constant, typo]
  relacionado_con: [proxy-003, proxy-016]

- id: proxy-024
  pattern: delegatecall-to-zero-code-silently-succeeds
  name: "delegatecall to non-existent or destructed address returns success with empty data"
  causa_raiz: >
    Solidity's low-level delegatecall returns (true, "") when the target address
    has no code (zero-length bytecode). This happens when: (1) the implementation
    address is set to a contract that hasn't been deployed yet, (2) the implementation
    was previously selfdestructed, or (3) the address was misconfigured to an EOA.
    The proxy treats success=true as a valid call, silently ignoring the empty return
    data. All proxy calls appear to succeed while executing nothing, corrupting protocol
    state silently or returning zero-value data that downstream logic misinterprets.
  como_funciona: |
    1. Proxy stores implementationAddress = 0xDEAD... (zero-code address).
    2. User calls proxy.someFunction().
    3. Proxy executes: (bool ok, bytes memory data) = implementationAddress.delegatecall(msg.data).
    4. EVM returns (true, "") because no code at target — no revert.
    5. Proxy interprets ok==true as success, returns empty data to caller.
    6. Caller's return data decoding produces zero values (0, false, address(0)).
    7. Critical state changes (balance debits, role grants) never execute but no error surfaced.
  invariante: >
    assert(implementationAddress.code.length > 0);
    // Check before every delegatecall, or in the upgrade setter
  que_mirar:
    - "rg 'delegatecall' --type sol -A 2 -- is return value checked AND is code.length checked?"
    - "Does the proxy setter for implementation address verify code.length > 0?"
    - "Are there any paths where the implementation could be selfdestructed?"
    - "rg '_implementation|implementation()' --type sol -- where is address stored and validated?"
    - "Does the fallback() function check code size before delegating?"
  como_se_arregla: >
    Add a code existence check before delegatecall: require(target.code.length > 0, "no code at target").
    Add the same check in the setImplementation / _authorizeUpgrade flow.
    OpenZeppelin's Address.functionDelegateCall() includes this check — prefer it over raw assembly.
  trampas:
    - "On chains where SELFDESTRUCT is post-EIP-6780 (same-tx only), implementation destruction is harder but still possible via CREATE2 address reuse"
    - "Foundry mocks often deploy implementation to valid addresses — fork testing is needed to catch this in prod deploys"
    - "The pattern is also triggered if a clone factory points to an implementation that was never deployed (deploy script bug)"
  incidentes:
    - "DeGate (Consensys) — delegatecall with no code existence check; if target is zero-code, call silently succeeds, breaking proxy logic (MEDIUM)"
    - "Frax Finance (Trail of Bits) — same delegatecall-no-code-check pattern; HIGH severity due to critical proxy paths affected"
    - "Rocket Pool (Sigma Prime) — delegatecall target validation missing; HIGH severity"
    - "Fuji Protocol — delegatecall to potentially empty address; HIGH severity in vault upgrade path"
    - "Op Enclave — missing contract size check on implementation results in silent proxy call failure (LOW)"
  severidad: high
  confianza: alta
  fuente: "Solodit: DeGate/Consensys, Frax/ToB, Rocket Pool/Sigma Prime, Fuji Protocol — multiple HIGH findings on same pattern"
  verificado: true
  tags: [proxy, delegatecall, code-existence, zero-code, selfdestruct, silent-failure]
  relacionado_con: [proxy-002, proxy-005]

- id: proxy-025
  pattern: uups-upgrade-path-broken-missing-authorize
  name: "UUPS proxy upgrade path permanently bricked — _authorizeUpgrade not implemented or wrong"
  causa_raiz: >
    UUPS proxies require the implementation contract to override _authorizeUpgrade()
    from OpenZeppelin's UUPSUpgradeable. If: (1) the function is not overridden
    (inheriting the default empty/unprotected version), (2) the implementation does
    not inherit UUPSUpgradeable at all while being treated as UUPS, or (3) the upgrade
    function is defined as public with no access control — then either anyone can upgrade
    the contract, or the upgrade path is silently broken (no one can upgrade).
    Both outcomes are critical: one enables takeover, the other permanently bricks upgradeability.
  como_funciona: |
    1a. [No override] Implementation inherits UUPSUpgradeable but never overrides _authorizeUpgrade.
        Default: function reverts with "not authorized". No one can upgrade. Protocol permanently stuck.
    1b. [Wrong override] Implementation overrides _authorizeUpgrade() with empty body or missing modifier.
        Anyone calls upgradeToAndCall(maliciousImpl, ""). No access check. Full takeover.
    2. Cork Protocol variant: contract marked as UUPS but core upgrade logic never wired up;
       admin tries to upgrade in emergency, all calls revert. Funds frozen in old bugged code.
    3. MorpheusAI variant: _authorizeUpgrade has no onlyOwner — any caller upgrades to malicious impl.
  invariante: |
    // _authorizeUpgrade must exist, revert for non-admin, and work on the deployed proxy
    // assert(proxy.owner() != address(0));
    // Test: non-owner call to upgradeTo() must revert
  que_mirar:
    - "rg '_authorizeUpgrade' --type sol -- does it exist in the implementation? Is it access-gated?"
    - "Does the contract inherit UUPSUpgradeable? Is it initialized via __UUPSUpgradeable_init()?"
    - "Can upgradeToAndCall be called by a non-owner on the deployed proxy?"
    - "Is there a test that verifies the upgrade path end-to-end (proxy.upgradeToAndCall works for owner, reverts for others)?"
    - "rg 'UUPSUpgradeable' --type sol -- list all contracts; do all of them override _authorizeUpgrade?"
  como_se_arregla: >
    Always override _authorizeUpgrade with onlyOwner (or equivalent role check).
    Write an integration test that: (a) upgrades successfully as owner, (b) reverts as non-owner.
    Use OpenZeppelin's upgrade-safe checker (openzeppelin-upgrades plugin) in CI.
    Consider Transparent Proxy for simpler access control semantics if UUPS complexity is a risk.
  trampas:
    - "Cork Protocol finding: contract compiles and deploys fine; the bug only manifests when upgrade is actually needed (emergency scenario)"
    - "If the protocol is 'intended to be non-upgradeable', removing upgrade logic entirely is safer than broken UUPS"
    - "Some audits flag this as Low/Info if the protocol claims upgrades are out-of-scope — but a bricked upgrade path is a real operational risk"
  incidentes:
    - "Cork Protocol — UUPS standard implemented incorrectly; admin cannot upgrade smart contracts, breaking core upgrade functionality (MEDIUM, audit 2024)"
    - "Cork Protocol M-3 — Admin will not be able to upgrade, blocking emergency response (MEDIUM)"
    - "MorpheusAI — _authorizeUpgrade() has no access control; anyone can change implementation to malicious contract (MEDIUM, Solodit)"
    - "Futaba — Protocol entirely missing upgradeability mechanism despite UUPS design intent; critical functions permanently locked (HIGH)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Cork Protocol (2x MEDIUM), MorpheusAI (MEDIUM), Futaba (HIGH)"
  verificado: true
  tags: [proxy, UUPS, upgrade, _authorizeUpgrade, bricked, access-control, initialization]
  relacionado_con: [proxy-003, proxy-016, proxy-023]

- id: proxy-026
  pattern: implementation-selfdestruct-via-uninitialized-takeover
  name: "Uninitialized implementation selfdestructs via attacker-controlled initialize + upgradeToAndCall"
  causa_raiz: >
    UUPS implementation contracts deployed without _disableInitializers() in their constructor
    can be initialized by anyone. Once an attacker calls initialize() on the bare implementation
    (not the proxy), they become owner of the implementation. They then call upgradeToAndCall
    on the implementation (not the proxy), upgrading it to a contract with selfdestruct.
    The selfdestruct executes in the context of the implementation, destroying its code.
    All proxies pointing to this implementation now delegate to dead code — every call returns
    empty data, effectively locking all user funds in the proxy permanently.
  como_funciona: |
    1. Implementation deployed without _disableInitializers().
    2. Attacker calls impl.initialize(attacker) — becomes owner of implementation.
    3. Attacker calls impl.upgradeTo(selfdestructContract) — impl is UUPS, attacker is owner.
    4. selfdestructContract.initialize() triggers selfdestruct(attacker).
    5. Implementation code deleted (pre-EIP-6780 chains).
    6. Proxy.fallback() delegatecalls to dead address — all calls silently succeed with no-op.
    7. User funds locked forever. No recovery path.
  invariante: |
    // Implementation constructor must call _disableInitializers()
    // assert: impl.owner() != address(0) before deployment to proxy
    // Test: direct call to impl.initialize() must revert post-deploy
  que_mirar:
    - "rg 'constructor' --type sol | grep -v '_disableInitializers' -- missing in UUPS implementations?"
    - "Can initialize() be called directly on the implementation address (not proxy)?"
    - "Is the implementation a UUPS contract? If so, can upgradeTo be called on the implementation itself?"
    - "rg 'selfdestruct|SELFDESTRUCT' --type sol -- any contract with this that could be upgrade target?"
    - "forge script -- is _disableInitializers() called in every upgradeable contract's constructor?"
  como_se_arregla: >
    Add _disableInitializers() in every UUPS implementation's constructor.
    Verify in deploy scripts that implementation.owner() == address(0) (disabled) before pointing proxy.
    Use OpenZeppelin's upgrades plugin which checks for this automatically.
    On chains where SELFDESTRUCT is post-EIP-6780, destruction risk is lower but initialization takeover still enables other attacks.
  trampas:
    - "Lido: DoS via uninitialized EasyTrack implementation — attacker doesn't destruct, just calls initialize to DoS upgrade path"
    - "Enso Finance: implementation destruction directly executed (HIGH, $0 loss caught in audit)"
    - "Biconomy SmartAccount: implementation destroyed in prod — all smart accounts bricked"
    - "This is different from proxy-002 (uninitialized proxy) — here the IMPLEMENTATION is taken over, not the proxy"
  incidentes:
    - "Enso Finance — EnsoWallet implementation can be destroyed; any proxy pointing to it loses all functionality (HIGH, Consensys)"
    - "Biconomy SmartAccount — implementation contract destroyed via uninitialized takeover; all wallets bricked (HIGH)"
    - "Fractional Art — Vault implementation destructible; all user vaults lose all assets (HIGH)"
    - "Lido — EasyTrack implementation uninitialized; attacker calls initialize to DoS (HIGH)"
    - "PoolTogether LootBox — unprotected selfdestruct in proxy implementation (HIGH)"
    - "Fuji Protocol — FujiVault implementation destructible if initialize not called atomically (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "Solodit: Enso Finance/Consensys (HIGH), Biconomy (HIGH), Fractional (HIGH), Lido (HIGH), Fuji Protocol (HIGH)"
  verificado: true
  tags: [proxy, UUPS, selfdestruct, uninitialized, initialize, implementation, _disableInitializers]
  relacionado_con: [proxy-002, proxy-003, proxy-005]

- id: proxy-027
  pattern: proxy-gas-reserve-manipulation-bricks-calls
  name: "Misconfigured gas reserve on proxy causes all forwarded calls to revert (DoS)"
  causa_raiz: >
    Some proxy designs (e.g., MIMOProxy, Sablier) maintain a minGasReserve parameter
    to ensure the proxy retains enough gas after a delegatecall to process cleanup logic.
    If minGasReserve can be set to an unreasonably high value by any caller (or misconfigured
    by admin), the condition gasleft() >= minGasReserve + gas_for_call fails for all normal
    transactions. Every forwarded call reverts at the gas check, effectively bricking the proxy
    for all users. No funds are lost directly, but the proxy is completely unusable (DoS).
  como_funciona: |
    1. MIMOProxy exposes setMinGasReserve(uint256 value) with no upper bound check.
    2. Attacker (or misconfigured admin script) sets minGasReserve = type(uint256).max.
    3. User calls proxy.execute(target, data) — proxy checks: gasleft() >= minGasReserve.
    4. gasleft() is always << type(uint256).max — check always fails.
    5. All proxy calls revert with "not enough gas". Proxy permanently bricked.
    6. Admin cannot call setMinGasReserve to fix it either, since that call also routes through proxy.
  invariante: |
    // minGasReserve must be bounded to a reasonable maximum
    // assert(minGasReserve <= 1_000_000); // practical gas limit
  que_mirar:
    - "rg 'minGasReserve|gasReserve|gasBuffer' --type sol -- is there an upper bound check on the setter?"
    - "Can a non-admin role set the gas reserve parameter?"
    - "If the proxy bricks, is there a recovery path (e.g., direct admin slot write)?"
    - "rg 'gasleft' --type sol -- used in a require/if that blocks all calls if too large?"
  como_se_arregla: >
    Add an upper bound to the gas reserve setter: require(value <= MAX_GAS_RESERVE, "too large").
    Use a reasonable maximum (e.g., 500_000 gas). Emit an event on change.
    Consider making the gas reserve immutable after deployment if dynamic adjustment isn't needed.
  trampas:
    - "Sablier finding is about plugin/target with selfdestruct enabled via proxy — adjacent but different vector"
    - "MIMO finding: the DoS is permanent unless proxy admin can call via a different code path to reset"
    - "Gas reserve DoS is rated HIGH in Sablier audit due to permanent bricking of all user flows"
  incidentes:
    - "MIMO DeFi (MIMOProxy) — setMinGasReserve() with no upper bound; attacker sets max value, all proxy calls revert permanently (HIGH, Spearbit)"
    - "MIMO DeFi — MIMOProxy owner destroys their proxy via selfdestruct-enabled plugin; cannot redeploy (MEDIUM, Spearbit)"
    - "Sablier — plugin or target with selfdestruct capability exploitable via proxy delegatecall (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "Solodit: MIMO DeFi/Spearbit (HIGH), Sablier (MEDIUM)"
  verificado: true
  tags: [proxy, gas-reserve, DoS, minGasReserve, bricked, delegatecall, bounds-check]
  relacionado_con: [proxy-003, proxy-007]

- id: proxy-028
  pattern: transparent-proxy-missing-ifAdmin-check-on-fallback
  name: "Transparent proxy missing admin-vs-user routing — admin calls routed to implementation"
  causa_raiz: >
    Transparent Proxy Pattern (OpenZeppelin TPP) requires that calls from the admin
    address are NEVER forwarded to the implementation — they always go to the proxy admin
    functions. If the ifAdmin() modifier is missing or incorrectly implemented, admin
    calls reach the implementation's fallback. If the implementation has a function
    with the same selector as the proxy admin function (selector clash, proxy-007),
    the admin can accidentally execute implementation logic instead of proxy admin logic,
    or vice versa. This can prevent upgrades, allow admin to interact with implementation
    in unintended ways, or silently do nothing.
  como_funciona: |
    1. Transparent proxy has admin address A, implementation contract I.
    2. I has a function foo() with selector 0xaabbccdd.
    3. Proxy's upgradeTo() also has selector 0xaabbccdd (selector clash, proxy-007).
    4. Admin calls proxy with 0xaabbccdd data, intending to upgrade.
    5. Missing ifAdmin check: proxy forwards to I.foo() instead of proxy.upgradeTo().
    6. Upgrade never happens. Admin believes protocol was upgraded when it wasn't.
    7. Or: admin cannot interact with implementation at all if check is too aggressive.
  invariante: |
    // Admin address must never reach implementation logic
    // assert(msg.sender != proxyAdmin || isAdminFunction(msg.sig))
  que_mirar:
    - "rg 'ifAdmin|_isAdmin|proxyAdmin|TransparentProxy' --type sol -- check routing logic"
    - "Does the proxy fallback() have explicit admin vs non-admin routing?"
    - "Are proxy admin selectors cross-checked against implementation selectors?"
    - "rg 'upgradeTo|changeAdmin|getProxyAdmin' --type sol -- selector: bytes4(keccak256(...))"
    - "Compute selectors: cast sig 'upgradeTo(address)' and compare to implementation functions"
  como_se_arregla: >
    Use OpenZeppelin's ProxyAdmin pattern where admin functions are in a separate ProxyAdmin
    contract — the proxy itself never has admin-callable functions, eliminating routing confusion.
    If implementing custom transparent proxy, always use the ifAdmin modifier from OZ's
    TransparentUpgradeableProxy and test all admin vs user paths explicitly.
  trampas:
    - "OpenZeppelin v5 ProxyAdmin moves admin functions out-of-proxy — this pattern only affects older OZ versions or custom proxies"
    - "If the proxy uses a dedicated ProxyAdmin contract (OZ standard), admin calls the ProxyAdmin, not the proxy directly — routing confusion doesn't apply"
    - "Selector clashes between proxy and impl are rare but 4-byte collisions do exist (proxy-007 documents known clashes)"
  incidentes:
    - "Infinigold — Inadequate proxy implementation preventing upgrades; transparent proxy routing misconfigured, admin cannot upgrade (HIGH)"
    - "Various — Selector clash between proxy admin functions and implementation causes silent misdirection (class of bugs, multiple audit findings)"
  severidad: medium
  confianza: media
  fuente: "Solodit: Infinigold (HIGH), proxy-007 selector clash class"
  verificado: true
  tags: [proxy, transparent-proxy, admin-routing, selector-clash, ifAdmin, OpenZeppelin]
  relacionado_con: [proxy-003, proxy-007, proxy-016]
```

---

## Solodit Findings Cross-Reference

The "proxy" category in `solodit_bulk_findings.json` contains 20 findings primarily focused on front-running and initialization vectors. Below maps each finding to the proxy patterns above where applicable:

| Solodit Finding | ID | Impact | Relevant Pattern |
|---|---|---|---|
| Initial Mint Front-Run Inflation Attack | 62659 | HIGH | proxy-004 (front-running initialization) |
| Front-running attacks on finalize | 7096 | MEDIUM | proxy-004 (front-running state transitions) |
| Ticket buyer front-runned by owner | 8905 | MEDIUM | proxy-004 (front-running claim) |
| ggAVAX share price inflation | 8826 | HIGH | proxy-004 (front-running first deposit) |
| Draw organizer can rig the draw | 6395 | HIGH | -- (randomness manipulation, not proxy) |
| Weak Address Salt in VaultFactory | 54903 | MEDIUM | proxy-004 (CREATE2 front-running deploy) |
| Unpredictable staking rewards | 13430 | HIGH | -- (reward timing, not proxy) |
| Freeze deposits with 1 wei + selfdestruct | 7008 | HIGH | proxy-005 (selfdestruct to force ETH) |
| Decrease allowance non-zero value | 7039 | HIGH | -- (ERC20 approval, not proxy) |
| Reward manipulation in StabilityPool | 57166 | HIGH | -- (reward calculation, not proxy) |
| Inflation Attack on Zero Total Stake | 53237 | MEDIUM | proxy-004 (first depositor front-running) |
| Plugin evasion of slashing | 6667 | MEDIUM | -- (slashing logic, not proxy) |
| First pool depositor front-run | 6949 | HIGH | proxy-004 (first depositor inflation) |
| Oracle front-running depletes reserves | 13645 | HIGH | -- (oracle MEV, not proxy) |
| Voting ignores lock period end | 36682 | HIGH | -- (governance logic, not proxy) |
| Cancel raffle before admin starts | 38403 | HIGH | proxy-004 (front-running admin setup) |
| Undermining fairness in swapSource | 8903 | MEDIUM | -- (randomness re-request, not proxy) |
| Drawing state extended period | 8904 | MEDIUM | -- (DoS on state machine, not proxy) |
| Filler state manipulation DoS | 58224 | MEDIUM | -- (state manipulation DoS, not proxy) |
| First Deposit Bug (CToken) | 6413 | MEDIUM | proxy-004 (first depositor inflation) |

---

## Quick-Scan Grep Patterns

Use these to triage a new codebase for proxy/upgrade vulnerabilities:

```bash
# Uninitialized implementation (missing _disableInitializers)
grep -rn "constructor" --include="*.sol" | xargs grep -L "_disableInitializers"

# Unprotected initialize functions
grep -rn "function initialize" --include="*.sol" | grep -v "initializer\|onlyInitializing\|reinitializer"

# UUPS _authorizeUpgrade check
grep -rn "_authorizeUpgrade" --include="*.sol" -A 3

# selfdestruct in implementation contracts
grep -rn "selfdestruct\|SELFDESTRUCT" --include="*.sol"

# Storage gaps
grep -rn "__gap" --include="*.sol"

# Custom proxy / non-EIP-1967 storage
grep -rn "assembly" --include="*.sol" | grep -i "sstore\|sload"

# EIP-1967 slot usage
grep -rn "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" --include="*.sol"

# delegatecall targets
grep -rn "delegatecall" --include="*.sol"

# Beacon proxy references
grep -rn "beacon\|Beacon" --include="*.sol"

# Proxy deployment scripts (check for atomic init)
grep -rn "deploy\|Deploy" --include="*.sol" --include="*.js" --include="*.ts" | grep -i "proxy"
```

---

## Severity Decision Tree

1. **Can anyone upgrade the implementation?** -> Critical (proxy-003)
2. **Can the implementation be selfdestructed?** -> Critical (proxy-005)
3. **Is the implementation uninitialized on a UUPS proxy?** -> Critical (proxy-002)
4. **Can storage be corrupted by an upgrade?** -> Critical (proxy-001, proxy-006)
5. **Can a beacon compromise affect all clones?** -> Critical (proxy-008)
6. **Can initialization be front-run?** -> High (proxy-004)
7. **Can function selectors clash?** -> Medium (proxy-007)

---

## Attack Chain: The Classic UUPS Kill

The most devastating proxy attack combines three patterns into one chain:

```
proxy-002 (uninitialized impl)
  -> attacker calls initialize() on implementation
  -> attacker becomes owner of implementation
  -> proxy-003 (missing upgrade auth on impl)
    -> attacker calls upgradeTo(selfdestructContract) on implementation
    -> proxy-005 (selfdestruct on implementation)
      -> implementation code destroyed
      -> ALL proxy calls return empty
      -> funds permanently locked
```

**This exact chain was used in the Parity Wallet hack ($280M locked) and nearly succeeded against Wormhole.**

---

## Pre-Upgrade Checklist (for auditing upgrades)

```
[ ] 1. forge inspect ContractV1 storage-layout > v1.txt
[ ] 2. forge inspect ContractV2 storage-layout > v2.txt
[ ] 3. diff v1.txt v2.txt -- NO slot shifts allowed
[ ] 4. All new variables added AFTER existing ones (append-only)
[ ] 5. __gap reduced by number of new slots added
[ ] 6. No inheritance order changes
[ ] 7. No new base contracts inserted before existing ones
[ ] 8. _disableInitializers() in V2 constructor
[ ] 9. reinitializer(N) used for V2 migration with correct version
[ ] 10. _authorizeUpgrade still protected in V2
```

---

## Cross-References

| Pattern | Invariant Registry IDs | Related Access-Control Patterns |
|---|---|---|
| proxy-001 | INV-EXPLOIT-009, INV-OWN-004 | access-004 (storage collision) |
| proxy-002 | INV-OWN-005, INV-EXPLOIT-009 | access-003 (uninitialized proxy) |
| proxy-003 | (UUPS-specific) | access-001 (missing access control) |
| proxy-004 | (deployment pattern) | -- |
| proxy-005 | INV-EXPLOIT-009 | access-008 (delegatecall to untrusted) |
| proxy-006 | INV-OWN-004 | access-004 (storage collision) |
| proxy-007 | (selector-specific) | -- |
| proxy-008 | (beacon-specific) | access-001, access-006 |
