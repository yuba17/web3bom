"""Cross-chain bridge vulnerability detection agent.

Specialized scanner for bridge-specific vulnerability patterns covering:
- Message verification and replay
- Signature/validator compromise surfaces
- Lock/mint/burn accounting invariants
- Cross-chain state synchronization
- Rate limiting and emergency controls
- Upgradability in bridge context
"""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class BridgeAgent(BaseAgent):
    name = "BridgeDetector"
    description = (
        "Detects cross-chain bridge vulnerabilities -- message verification, "
        "replay attacks, validator key management, accounting invariants, "
        "and bridge-specific logic flaws"
    )

    # ------------------------------------------------------------------ #
    #  Bridge-specific sensitive functions (beyond generic access control)
    # ------------------------------------------------------------------ #
    BRIDGE_SENSITIVE_FUNCTIONS = [
        'relayMessage', 'executeMessage', 'receiveMessage', 'processMessage',
        'submitMessage', 'verifyMessage', 'confirmMessage', 'deliverMessage',
        'receivePayload', 'lzReceive', '_nonblockingLzReceive',
        'processPacket', 'receivePacket', 'submitPacket',
        'mint', 'mintWrapped', 'unlock', 'release', 'withdraw',
        'lock', 'burn', 'burnWrapped', 'deposit',
        'setGuardian', 'setValidator', 'setRelayer', 'setOracle',
        'setTrustedRemote', 'setTrustedForwarder', 'setPeer',
        'updateChainConfig', 'addChain', 'removeChain',
        'pause', 'unpause', 'emergencyWithdraw', 'rescue',
        'updateQuorum', 'setThreshold', 'addSigner', 'removeSigner',
    ]

    # Bridge-specific modifiers/guards
    BRIDGE_GUARDS = [
        'onlyRelayer', 'onlyMessenger', 'onlyBridge', 'onlyOracle',
        'onlyValidator', 'onlyGuardian', 'onlyCrossChainSender',
        'onlyEndpoint', 'onlyRouter', 'onlyGateway',
        'onlyOwner', 'onlyAdmin', 'onlyRole',
        'whenNotPaused', 'nonReentrant',
    ]

    # Known bridge message structs/patterns
    BRIDGE_PATTERNS = [
        'chainId', 'srcChainId', 'dstChainId', 'sourceChain', 'destChain',
        'nonce', 'messageNonce', 'sequence',
        'trustedRemote', 'trustedForwarder', 'peer',
        'payload', 'message', 'packet',
        'guardian', 'validator', 'relayer', 'oracle',
        'quorum', 'threshold', 'signatures',
        'merkleRoot', 'merkleProof', 'stateRoot',
        'lockBox', 'vault', 'escrow',
    ]

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()

        if not self._is_bridge_contract(contract):
            return self.findings

        # --- Core bridge checks --- #
        self._check_message_verification(contract)
        self._check_replay_protection(contract)
        self._check_chain_id_validation(contract)
        self._check_source_sender_validation(contract)
        self._check_signature_verification(contract)
        self._check_merkle_proof_validation(contract)

        # --- Accounting invariants --- #
        self._check_mint_without_lock(contract)
        self._check_unlock_without_burn(contract)
        self._check_balance_accounting(contract)

        # --- Access control (bridge-specific) --- #
        self._check_unprotected_bridge_functions(contract)
        self._check_guardian_quorum(contract)
        self._check_single_signer_risk(contract)

        # --- Rate limiting and safety --- #
        self._check_missing_rate_limit(contract)
        self._check_missing_pause(contract)
        self._check_missing_amount_cap(contract)

        # --- Cross-chain state --- #
        self._check_hardcoded_chain_ids(contract)
        self._check_trusted_remote_validation(contract)
        self._check_message_ordering(contract)

        # --- Upgradability in bridge context --- #
        self._check_bridge_upgradeability(contract)
        self._check_token_decimals_mismatch(contract)

        return self.findings

    # ================================================================== #
    #  Detection: Is this a bridge contract?
    # ================================================================== #

    def _is_bridge_contract(self, contract: SolidityContract) -> bool:
        """Heuristic detection of bridge-related contracts."""
        bridge_keywords = [
            r'\bbridge\b', r'\bcross.?chain\b', r'\brelayer?\b',
            r'\bmessenger\b', r'\bgateway\b', r'\bendpoint\b',
            r'\blzReceive\b', r'\breceivePayload\b', r'\bprocessPacket\b',
            r'\btrustedRemote\b', r'\bsrcChainId\b', r'\bdstChainId\b',
            r'\bLayerZero\b', r'\bWormhole\b', r'\bAxelar\b',
            r'\bHyperlane\b', r'\bCCIP\b', r'\bcBridge\b',
            r'\bIMessageRecipient\b', r'\bILayerZeroReceiver\b',
            r'\blockAndMint\b', r'\bburnAndUnlock\b',
            r'\bmintWrapped\b', r'\bunlockTokens\b',
        ]
        source_lower = contract.source.lower()
        matches = sum(1 for kw in bridge_keywords if re.search(kw, source_lower, re.IGNORECASE))
        return matches >= 2  # At least 2 bridge-related keywords

    # ================================================================== #
    #  1. MESSAGE VERIFICATION
    # ================================================================== #

    def _check_message_verification(self, contract: SolidityContract):
        """Check if incoming cross-chain messages are properly verified."""
        for func in contract.functions:
            name_lower = func.name.lower()
            is_receive = any(kw in name_lower for kw in [
                'receive', 'relay', 'execute', 'process', 'deliver', 'submit',
                'lzreceive', 'handle',
            ])
            if not is_receive:
                continue
            if func.visibility in ('internal', 'private'):
                continue

            # Check for signature/proof verification in the function
            has_verification = bool(re.search(
                r'(verify|validate|check|require|assert|revert)'
                r'.*(signature|proof|hash|digest|guardian|validator|signer)',
                func.body, re.IGNORECASE | re.DOTALL
            ))

            # Also check for trusted source validation
            has_source_check = bool(re.search(
                r'(trustedRemote|trustedForwarder|peer|allowedSender|'
                r'msg\.sender\s*==\s*(endpoint|messenger|bridge|gateway|router))',
                func.body, re.IGNORECASE
            ))

            if not has_verification and not has_source_check:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Unverified Cross-Chain Message in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` appears to process incoming cross-chain "
                        f"messages but does not verify signatures, merkle proofs, or validate "
                        f"the message source. An attacker could forge arbitrary messages to "
                        f"mint tokens, unlock funds, or execute unauthorized actions. "
                        f"This is the #1 bridge exploit pattern (cf. Wormhole hack, $320M)."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=(
                        "Verify the message source (msg.sender == endpoint/gateway) AND "
                        "validate the origin chain/sender against a whitelist (trustedRemote). "
                        "Verify cryptographic proofs or guardian signatures before processing."
                    ),
                )

    # ================================================================== #
    #  2. REPLAY PROTECTION
    # ================================================================== #

    def _check_replay_protection(self, contract: SolidityContract):
        """Check for missing nonce/hash tracking to prevent message replay."""
        has_nonce_tracking = bool(re.search(
            r'(nonce|messageId|messageHash|processedMessages?|usedNonces?|'
            r'executed|consumed|claimed)\s*\[',
            contract.source, re.IGNORECASE
        ))

        has_receive_function = any(
            any(kw in func.name.lower() for kw in ['receive', 'relay', 'execute', 'process'])
            for func in contract.functions
            if func.visibility in ('external', 'public')
        )

        if has_receive_function and not has_nonce_tracking:
            self.add_finding(
                severity="CRITICAL",
                title="Missing Replay Protection for Cross-Chain Messages",
                description=(
                    "The contract processes cross-chain messages but does not track "
                    "processed message nonces or hashes. An attacker could replay "
                    "a valid message multiple times to drain funds. "
                    "Cf. the general class of replay attacks on bridges."
                ),
                location=contract.file_path,
                recommendation=(
                    "Track processed messages: `mapping(bytes32 => bool) public processedMessages;` "
                    "Check and set before processing: "
                    "`require(!processedMessages[hash]); processedMessages[hash] = true;`"
                ),
            )

    # ================================================================== #
    #  3. CHAIN ID VALIDATION
    # ================================================================== #

    def _check_chain_id_validation(self, contract: SolidityContract):
        """Check if source/destination chain IDs are validated."""
        has_chain_param = bool(re.search(
            r'(srcChainId|sourceChain|chainId|_srcEid|_dstEid|srcEid|dstEid)',
            contract.source
        ))

        if not has_chain_param:
            return

        # Check if chain ID is validated against allowed values
        has_chain_validation = bool(re.search(
            r'(supportedChain|allowedChain|validChain|chainConfig|'
            r'require.*chainId|if.*chainId.*revert)',
            contract.source, re.IGNORECASE
        ))

        if not has_chain_validation:
            self.add_finding(
                severity="HIGH",
                title="Unvalidated Source/Destination Chain ID",
                description=(
                    "The contract references chain IDs but does not appear to validate "
                    "them against a set of supported chains. An attacker could send "
                    "messages with spoofed chain IDs from unsupported or malicious chains."
                ),
                location=contract.file_path,
                recommendation=(
                    "Maintain a mapping of supported chain IDs and validate all incoming "
                    "messages against it. Reject messages from unknown chains."
                ),
            )

    # ================================================================== #
    #  4. SOURCE SENDER VALIDATION
    # ================================================================== #

    def _check_source_sender_validation(self, contract: SolidityContract):
        """Check if the source contract address is validated on receive."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['receive', 'lzreceive', 'handle', 'execute']):
                continue
            if func.visibility in ('internal', 'private'):
                continue

            # Check for source address validation
            has_source_validation = bool(re.search(
                r'(trustedRemote|peer|allowedSender|sourceSender|'
                r'_origin\.sender|_srcAddress)',
                func.body, re.IGNORECASE
            ))

            # Check in modifiers
            has_modifier_check = any(
                mod.lower() in ['onlyendpoint', 'onlygateway', 'onlyrouter', 'onlymessenger']
                for mod in func.modifiers
            )

            if not has_source_validation and not has_modifier_check:
                self.add_finding(
                    severity="HIGH",
                    title=f"Missing Source Sender Validation in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` processes incoming messages but does not "
                        f"validate the source contract address. An attacker could deploy "
                        f"a malicious contract on the source chain and send forged messages "
                        f"that appear legitimate."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=(
                        "Validate that the source sender matches the expected trusted remote "
                        "contract: `require(peer[srcChainId] == srcSender, 'untrusted source');`"
                    ),
                )

    # ================================================================== #
    #  5. SIGNATURE VERIFICATION
    # ================================================================== #

    def _check_signature_verification(self, contract: SolidityContract):
        """Check for weak signature verification patterns."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            # Check for ecrecover without zero-address check
            if 'ecrecover(' in stripped:
                # Look at surrounding lines for zero check
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                if not re.search(r'(!= address\(0\)|!= 0x0|== address\(0\))', context):
                    self.add_finding(
                        severity="CRITICAL",
                        title="ecrecover Without Zero-Address Check",
                        description=(
                            "ecrecover returns address(0) for invalid signatures. "
                            "Without checking the return value against address(0), "
                            "an attacker can bypass signature verification entirely. "
                            "This is the exact vulnerability that caused the Wormhole "
                            "hack ($320M loss)."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation=(
                            "Always check: `address signer = ecrecover(...); "
                            "require(signer != address(0), 'invalid signature');` "
                            "Better: use OpenZeppelin's ECDSA.recover() which reverts on invalid."
                        ),
                        code_snippet=stripped,
                    )

            # Check for deprecated verify_signatures patterns
            if re.search(r'(verify_signatures?|verifySig)', stripped, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                if re.search(r'(deprecated|legacy|old)', context, re.IGNORECASE):
                    self.add_finding(
                        severity="HIGH",
                        title="Deprecated Signature Verification Function",
                        description=(
                            "A signature verification function appears to be deprecated. "
                            "Using deprecated verification functions can introduce bypasses. "
                            "The Wormhole hack exploited a deprecated `verify_signatures` function."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation="Use the latest, audited signature verification implementation.",
                        code_snippet=stripped,
                    )

    # ================================================================== #
    #  6. MERKLE PROOF VALIDATION
    # ================================================================== #

    def _check_merkle_proof_validation(self, contract: SolidityContract):
        """Check for weak or missing merkle proof verification."""
        if 'merkle' not in contract.source.lower() and 'proof' not in contract.source.lower():
            return

        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # Check for merkle root set to zero or default value
            if re.search(r'(merkleRoot|root|trustedRoot)\s*=\s*(0x0+|bytes32\(0\))', stripped):
                self.add_finding(
                    severity="CRITICAL",
                    title="Merkle Root Initialized to Zero",
                    description=(
                        "A merkle/state root is initialized to zero (0x00). If incoming "
                        "messages default to the zero hash, any message would be accepted "
                        "as valid. This is the exact vulnerability exploited in the Nomad "
                        "bridge hack ($190M loss), where a zero-initialized trusted root "
                        "matched untrusted message hashes."
                    ),
                    location=f"{contract.file_path}:{i}",
                    recommendation=(
                        "Never initialize roots to zero. Require explicit setting of a "
                        "valid root. Add: `require(root != bytes32(0), 'invalid root');`"
                    ),
                    code_snippet=stripped,
                )

    # ================================================================== #
    #  7. MINT WITHOUT LOCK / UNLOCK WITHOUT BURN
    # ================================================================== #

    def _check_mint_without_lock(self, contract: SolidityContract):
        """Check if minting functions verify that tokens were locked on source chain."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['mint', 'minttoken', 'mintasset', 'release', 'unlock']):
                continue
            if func.visibility in ('internal', 'private'):
                continue

            # Should have message/proof verification before minting
            has_cross_chain_proof = bool(re.search(
                r'(proof|signature|message|guardian|validator|verify|confirmed)',
                func.body, re.IGNORECASE
            ))

            has_access_control = any(
                mod.lower() in [m.lower() for m in self.BRIDGE_GUARDS]
                for mod in func.modifiers
            )

            if not has_cross_chain_proof and not has_access_control:
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Unprotected Mint/Release in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` can mint/release tokens without verifying "
                        f"a cross-chain proof or message. An attacker could mint unlimited "
                        f"wrapped tokens without locking collateral on the source chain. "
                        f"This breaks the fundamental bridge invariant: "
                        f"minted_on_dst <= locked_on_src."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=(
                        "Only mint/release tokens after verifying a valid cross-chain "
                        "message that proves tokens were locked/burned on the source chain."
                    ),
                )

    def _check_unlock_without_burn(self, contract: SolidityContract):
        """Check if unlock functions verify that wrapped tokens were burned."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['unlock', 'release', 'withdraw', 'redeem']):
                continue
            if func.visibility in ('internal', 'private'):
                continue

            has_burn = bool(re.search(r'(burn|_burn)', func.body))
            has_proof = bool(re.search(
                r'(proof|message|signature|verify|confirmed)',
                func.body, re.IGNORECASE
            ))

            if not has_burn and not has_proof:
                # Only flag if it looks like a bridge unlock (not a generic withdraw)
                has_chain_ref = bool(re.search(
                    r'(chain|remote|cross|bridge|wrapped)',
                    func.body + func.name, re.IGNORECASE
                ))
                if has_chain_ref:
                    self.add_finding(
                        severity="HIGH",
                        title=f"Unlock Without Burn Verification in `{func.name}()`",
                        description=(
                            f"Function `{func.name}` releases locked tokens without "
                            f"verifying that wrapped tokens were burned on the remote chain. "
                            f"This could allow double-spending of bridged assets."
                        ),
                        location=f"{contract.file_path}:{func.line_start}",
                        recommendation=(
                            "Require proof that wrapped tokens were burned on the destination "
                            "chain before releasing locked tokens on the source chain."
                        ),
                    )

    # ================================================================== #
    #  8. BALANCE / ACCOUNTING CHECKS
    # ================================================================== #

    def _check_balance_accounting(self, contract: SolidityContract):
        """Check for balance-based accounting vs internal tracking."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # Using balanceOf(address(this)) as source of truth in bridge context
            if re.search(r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', stripped):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+5)])
                if re.search(r'(bridge|lock|mint|unlock|deposit|cross)', context, re.IGNORECASE):
                    self.add_finding(
                        severity="HIGH",
                        title="Bridge Uses balanceOf(this) for Accounting",
                        description=(
                            "The bridge uses balanceOf(address(this)) as its source of truth "
                            "instead of internal accounting. An attacker can manipulate the "
                            "actual balance (via direct token transfer or flash loan) to "
                            "create a discrepancy, potentially minting excess wrapped tokens "
                            "or unlocking more than was deposited."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation=(
                            "Track deposits/locks with internal state variables. Compare "
                            "actual balance against expected balance as an invariant check, "
                            "but do not use it as the authoritative accounting source."
                        ),
                        code_snippet=stripped,
                    )

    # ================================================================== #
    #  9. ACCESS CONTROL (BRIDGE-SPECIFIC)
    # ================================================================== #

    def _check_unprotected_bridge_functions(self, contract: SolidityContract):
        """Check if bridge-critical functions lack access control."""
        for func in contract.functions:
            if func.visibility in ('internal', 'private'):
                continue

            func_lower = func.name.lower()
            is_sensitive = any(
                s.lower() in func_lower
                for s in self.BRIDGE_SENSITIVE_FUNCTIONS
            )
            if not is_sensitive:
                continue

            has_guard = any(
                mod.lower() in [g.lower() for g in self.BRIDGE_GUARDS]
                for mod in func.modifiers
            )

            has_sender_check = bool(re.search(
                r'(require|if)\s*\(.*msg\.sender\s*==',
                func.body
            ))

            if not has_guard and not has_sender_check:
                severity = "CRITICAL" if any(
                    kw in func_lower for kw in [
                        'settrustedremote', 'setpeer', 'setguardian',
                        'setvalidator', 'updatequorum', 'setthreshold',
                    ]
                ) else "HIGH"

                self.add_finding(
                    severity=severity,
                    title=f"Unprotected Bridge Function: `{func.name}()`",
                    description=(
                        f"Bridge-sensitive function `{func.name}` ({func.visibility}) "
                        f"has no access control. If an attacker can call this function, "
                        f"they could reconfigure the bridge to point to malicious contracts, "
                        f"change validator sets, or drain locked funds."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=f"Add appropriate access control to `{func.name}()`.",
                )

    def _check_guardian_quorum(self, contract: SolidityContract):
        """Check for dangerously low guardian/validator quorum."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # Check for quorum/threshold values
            match = re.search(
                r'(quorum|threshold|requiredSignatures?|minValidators?)\s*=\s*(\d+)',
                stripped, re.IGNORECASE
            )
            if match:
                value = int(match.group(2))
                if value <= 2:
                    self.add_finding(
                        severity="HIGH",
                        title=f"Low Guardian/Validator Quorum: {match.group(1)} = {value}",
                        description=(
                            f"The bridge requires only {value} signatures/validators to approve "
                            f"cross-chain messages. The Harmony Horizon Bridge was hacked because "
                            f"only 2 of 5 validators needed to be compromised ($100M loss). "
                            f"The Ronin Bridge required 5 of 9 but 5 were compromised ($600M loss)."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation=(
                            "Use a higher quorum (e.g., 2/3+1 of total validators). "
                            "Ensure validators are independent entities with separate infrastructure. "
                            "Consider a decentralized validator network."
                        ),
                        code_snippet=stripped,
                    )

    def _check_single_signer_risk(self, contract: SolidityContract):
        """Check if bridge operations can be authorized by a single key."""
        # Look for single-signer patterns
        has_multisig = bool(re.search(
            r'(multisig|multiSig|multi.?sig|gnosis|safe|quorum|threshold|signaturesRequired)',
            contract.source, re.IGNORECASE
        ))

        has_single_signer = bool(re.search(
            r'(owner|admin|operator)\s*=\s*msg\.sender',
            contract.source
        ))

        # Check if critical functions use single-owner pattern
        for func in contract.functions:
            name_lower = func.name.lower()
            if any(kw in name_lower for kw in ['lock', 'unlock', 'mint', 'burn', 'relay']):
                if func.visibility in ('external', 'public'):
                    if 'onlyOwner' in func.modifiers and not has_multisig:
                        self.add_finding(
                            severity="MEDIUM",
                            title=f"Single-Key Authorization for `{func.name}()`",
                            description=(
                                f"Bridge function `{func.name}` is protected by onlyOwner "
                                f"(single key) without multisig. If this key is compromised, "
                                f"the bridge is fully compromised. The Multichain bridge lost "
                                f"$126M because all keys were controlled by a single person (the CEO)."
                            ),
                            location=f"{contract.file_path}:{func.line_start}",
                            recommendation=(
                                "Use a multisig wallet (Gnosis Safe) with a meaningful threshold "
                                "(e.g., 3/5 or 4/7) for all bridge admin operations. "
                                "Ensure signers are independent entities."
                            ),
                        )

    # ================================================================== #
    #  10. RATE LIMITING & SAFETY
    # ================================================================== #

    def _check_missing_rate_limit(self, contract: SolidityContract):
        """Check for missing rate limits on bridge transfers."""
        has_rate_limit = bool(re.search(
            r'(rateLimit|rateLimiter|maxTransfer|dailyLimit|hourlyLimit|'
            r'transferLimit|maxAmount|volumeLimit|cooldown|throttle)',
            contract.source, re.IGNORECASE
        ))

        has_transfer_function = any(
            any(kw in func.name.lower() for kw in [
                'lock', 'deposit', 'send', 'bridge', 'transfer', 'unlock', 'mint',
            ])
            for func in contract.functions
            if func.visibility in ('external', 'public')
        )

        if has_transfer_function and not has_rate_limit:
            self.add_finding(
                severity="MEDIUM",
                title="Missing Rate Limits on Bridge Transfers",
                description=(
                    "The bridge has no rate limiting mechanism. If any other security "
                    "control is bypassed, an attacker can drain the entire TVL in a "
                    "single transaction. Rate limits are the last line of defense. "
                    "Had the Ronin Bridge had rate limits, the $600M loss could have "
                    "been limited to the daily cap."
                ),
                location=contract.file_path,
                recommendation=(
                    "Implement per-chain and global rate limits: "
                    "- Per-transaction max amount "
                    "- Hourly/daily volume caps "
                    "- Automatic pause if anomalous volume is detected"
                ),
            )

    def _check_missing_pause(self, contract: SolidityContract):
        """Check if bridge has emergency pause capability."""
        has_pause = bool(re.search(
            r'(Pausable|pause|unpause|whenNotPaused|paused\(\)|_pause\(\)|emergencyStop)',
            contract.source
        ))

        if not has_pause:
            self.add_finding(
                severity="MEDIUM",
                title="Bridge Lacks Emergency Pause Mechanism",
                description=(
                    "The bridge contract has no pause functionality. During an active "
                    "exploit, there is no way to halt operations to prevent further "
                    "fund loss. The Ronin hack went undetected for 6 days -- a pause "
                    "mechanism with anomaly detection could have limited losses."
                ),
                location=contract.file_path,
                recommendation=(
                    "Implement OpenZeppelin's Pausable. Add `whenNotPaused` to all "
                    "external transfer functions. Implement a guardian role that can "
                    "trigger emergency pause with a lower threshold than normal operations."
                ),
            )

    def _check_missing_amount_cap(self, contract: SolidityContract):
        """Check if individual transfer amounts are capped."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['lock', 'deposit', 'send', 'bridge']):
                continue
            if func.visibility in ('internal', 'private'):
                continue

            has_amount_check = bool(re.search(
                r'(maxAmount|maxTransfer|MAX_TRANSFER|require.*amount\s*<=|'
                r'amount\s*>\s*max|if.*amount.*>)',
                func.body, re.IGNORECASE
            ))

            if not has_amount_check:
                self.add_finding(
                    severity="LOW",
                    title=f"No Maximum Transfer Amount in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` does not enforce a maximum transfer amount. "
                        f"This allows single transactions to move the entire TVL through "
                        f"the bridge, amplifying the impact of any exploit."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add a configurable maximum transfer amount per transaction.",
                )

    # ================================================================== #
    #  11. CROSS-CHAIN STATE
    # ================================================================== #

    def _check_hardcoded_chain_ids(self, contract: SolidityContract):
        """Check for hardcoded chain IDs that may be wrong after forks."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # Hardcoded chain ID
            if re.search(r'chainId\s*==\s*\d+', stripped):
                self.add_finding(
                    severity="LOW",
                    title="Hardcoded Chain ID",
                    description=(
                        "A chain ID is hardcoded. After chain forks (e.g., ETH/ETC split), "
                        "hardcoded chain IDs can cause messages to be replayed on the forked "
                        "chain. Use block.chainid at runtime instead."
                    ),
                    location=f"{contract.file_path}:{i}",
                    recommendation="Use `block.chainid` instead of hardcoded values for chain identification.",
                    code_snippet=stripped,
                )

    def _check_trusted_remote_validation(self, contract: SolidityContract):
        """Check if trustedRemote/peer can be set to zero or malicious address."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in [
                'settrustedremote', 'setpeer', 'settrusted', 'addremote',
            ]):
                continue

            has_zero_check = bool(re.search(
                r'(address\(0\)|!= 0x0|!= bytes32\(0\)|\.length\s*[>!])',
                func.body
            ))

            if not has_zero_check:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"Missing Validation in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` sets a trusted remote/peer address without "
                        f"validating against zero address. Setting to zero would disable "
                        f"the trust check, potentially accepting messages from any source."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Validate that the new trusted remote is not zero/empty.",
                )

    def _check_message_ordering(self, contract: SolidityContract):
        """Check for message ordering assumptions that could be exploited."""
        has_nonce_order = bool(re.search(
            r'(nonce\s*==|nonce\s*\+\+|nextNonce|expectedNonce|inboundNonce)',
            contract.source
        ))

        has_receive = any(
            'receive' in func.name.lower() or 'execute' in func.name.lower()
            for func in contract.functions
        )

        # If there are nonces, check for strict ordering issues
        if has_nonce_order and has_receive:
            # Check for the LayerZero-style blocking issue
            has_nonblocking = bool(re.search(
                r'(nonblocking|nonBlocking|try|catch|failedMessages)',
                contract.source
            ))
            if not has_nonblocking:
                self.add_finding(
                    severity="MEDIUM",
                    title="Strict Message Ordering Without Fallback",
                    description=(
                        "The bridge enforces strict nonce ordering without a non-blocking "
                        "fallback. If a single message fails to execute, all subsequent "
                        "messages are blocked (DoS). An attacker could intentionally craft "
                        "a failing message to halt the bridge."
                    ),
                    location=contract.file_path,
                    recommendation=(
                        "Implement a non-blocking receive pattern: store failed messages "
                        "and allow retrying them independently. See LayerZero's "
                        "NonblockingLzApp pattern."
                    ),
                )

    # ================================================================== #
    #  12. UPGRADE & DECIMAL CHECKS
    # ================================================================== #

    def _check_bridge_upgradeability(self, contract: SolidityContract):
        """Check for dangerous upgrade patterns in bridge context."""
        is_upgradeable = bool(re.search(
            r'(Upgradeable|UUPSUpgradeable|TransparentUpgradeable|Proxy|ERC1967)',
            contract.source
        ))

        if not is_upgradeable:
            return

        # Check for timelock on upgrades
        has_timelock = bool(re.search(
            r'(timelock|TimelockController|delay|UPGRADE_DELAY)',
            contract.source, re.IGNORECASE
        ))

        if not has_timelock:
            self.add_finding(
                severity="HIGH",
                title="Upgradeable Bridge Without Timelock",
                description=(
                    "The bridge contract is upgradeable but has no timelock on upgrades. "
                    "A compromised admin key could upgrade the implementation to a malicious "
                    "contract and drain all locked funds instantly. The ALEX Bridge hack "
                    "($4.3M) used exactly this attack vector -- a malicious upgrade by "
                    "a compromised deployer account."
                ),
                location=contract.file_path,
                recommendation=(
                    "Add a timelock (48-72 hours minimum) to all upgrade operations. "
                    "Use a multisig + timelock combination. Monitor for upgrade events."
                ),
            )

    def _check_token_decimals_mismatch(self, contract: SolidityContract):
        """Check for potential decimal mismatch between chains."""
        has_decimals = bool(re.search(r'decimals', contract.source, re.IGNORECASE))
        has_conversion = bool(re.search(
            r'(10\s*\*\*|1e\d+|DECIMALS|decimal_factor|scalingFactor)',
            contract.source, re.IGNORECASE
        ))

        if has_decimals and not has_conversion:
            self.add_finding(
                severity="MEDIUM",
                title="Potential Token Decimal Mismatch",
                description=(
                    "The contract references token decimals but does not appear to "
                    "perform decimal conversion. When bridging tokens between chains "
                    "with different decimal standards (e.g., USDC has 6 decimals on "
                    "Ethereum but could have 18 on another chain), incorrect conversion "
                    "can lead to massive over/under-minting."
                ),
                location=contract.file_path,
                recommendation=(
                    "Implement explicit decimal normalization: convert all amounts to a "
                    "canonical decimal representation before cross-chain messaging, then "
                    "convert back on the destination chain."
                ),
            )
