# Unverified Trampas — Pendientes de Revisión Humana

Estas entradas fueron generadas por hunters de IA y añadidas automáticamente a los briefings.
**NO están verificadas.** Moverlas aquí para revisión manual antes de promoverlas a briefings.

Para promover: copia la trampa al briefing correspondiente y bórrala de aquí.
Para descartar: bórrala directamente.

---

## De lending.md (fuente: hyp_V3Vault_*.yaml)

- "Revert Lend V3Vault uses exchange-rate-based ERC4626 -- NOT balance-based totalAssets for share pricing. First depositor inflation attack does not apply because donations go to reserves, not share price."
  - fuente: hyp/DomainHunter/V3Vault

- "V3Vault asset is immutable ERC20 — no ERC777 callback risk on deposit/withdraw unless the asset itself is ERC777-compatible."
  - fuente: hyp/FlowHunter/V3Vault

- "V3Vault exchange rate is time-based (IRM), not balance/supply-based. First depositor inflation attack does not apply. Donations go to reserves, not share price."
  - fuente: hyp/MathHunter/V3Vault

- "V3Vault rounding directions are correct: borrow UP, repay by assets DOWN. Cannot extract rounding dust via cycles."
  - fuente: hyp/MathHunter/V3Vault

- "V3Vault totalSupply cannot reach 0 while debt is outstanding — _withdraw enforces InsufficientLiquidity. Do not flag totalLent==0 socialization DoS as a real vector."
  - fuente: hyp/MathHunter/V3Vault

- "V3Oracle maxPoolPriceDifference check blocks ALL operations including liquidations when pool is manipulated. This is by design per comments at V3Oracle lines 522-524."
  - fuente: hyp/OracleHunter/V3Vault

---

## De staking.md (fuente: hyp_GaugeManager_*.yaml)

- "TWAP 60s en Aerodrome Base (2s bloques): 30 bloques para manipular. El check es TWAP distance, no TWAP price — amountOutMin viene del spot. Esta distinción es la vulnerabilidad real (spot puede estar manipulado dentro del TWAP window)."
  - fuente: hyp/OracleHunter/GaugeManager
  - ⚠ OJO: esta podría ser una vulnerabilidad real, no una trampa

- "setRewardBasePool verifica canonicidad del pool via factory.getPool. La restricción de owner y la verificación de tokens hacen que sea trusted role, no un vector explotable sin acceso privilegiado."
  - fuente: hyp/OracleHunter/GaugeManager

- "El rounding de 1 wei en rewardPerToken por epoch es esperado — no es bug"
  - fuente: hyp/MathHunter/ComponentName
