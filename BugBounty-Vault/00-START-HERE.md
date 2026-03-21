---
tags: [index, home]
---

# Web3 Bug Bounty Vault

## Quick Links
- [[01-Vulnerabilities/access-control|Access Control (SC01)]] — #1 vulnerability, $953M+ losses
- [[01-Vulnerabilities/reentrancy|Reentrancy (SC08)]] — The classic, still alive
- [[01-Vulnerabilities/flash-loan-attacks|Flash Loans & Oracles (SC03/04)]]
- [[01-Vulnerabilities/business-logic|Business Logic (SC02)]] — Hardest to find, biggest rewards

## Workflow
```
1. Pick target (Immunefi/Code4rena/Sherlock)
2. Study protocol → 02-Protocols-Studied/
3. Run audit agents → audit-agents/
4. Manual review (where the money is)
5. Write PoC in Foundry
6. Submit report → 06-Submissions/
7. Study past exploits → 03-Exploits-Studied/
```

## Templates
- [[Templates/vulnerability-template|Vulnerability Template]]
- [[Templates/protocol-study-template|Protocol Study Template]]
- [[Templates/bug-report-template|Bug Report Template]]
- [[Templates/exploit-study-template|Exploit Study Template]]

## Daily Practice
- Read 3 findings on [Solodit](https://solodit.xyz) → log in 07-Daily-Findings/
- Reproduce 1 exploit from [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) per week
- Participate in 1 Code4rena/Sherlock contest per month

## Resources
- [Cyfrin Updraft Security Course](https://updraft.cyfrin.io/courses/security) (free, 24h+)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [Immunefi Bug Bounties](https://immunefi.com/bug-bounty/)

## Audit Agent
Run the custom audit system:
```bash
cd ../audit-agents
python audit.py <contract.sol>
python audit.py <contract.sol> --report markdown -o reports/name.md
python audit.py contracts/ --recursive
```
