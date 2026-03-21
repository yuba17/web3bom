# PASO A PASO — Moonwell Bug Bounty

## ✅ PASO 1: Cuentas necesarias (10 min)

### 1.1 Code4rena
1. Ve a https://code4rena.com
2. "Connect Wallet" con MetaMask
3. Crea perfil de warden
4. Guarda tu username

### 1.2 Alchemy (RPC gratis para forkear Base)
1. Ve a https://www.alchemy.com/
2. Crea cuenta gratis
3. "Create App" → selecciona chain "Base"
4. Copia la API key
5. Crea otra app para "Optimism"
6. Copia esa key también
7. Edita el archivo: `audit-agents/.env`
   - Pega tu key de Base en `BASE_RPC_URL`
   - Pega tu key de Optimism en `OPTIMISM_RPC_URL`

### 1.3 BaseScan (opcional, para verificar contratos on-chain)
1. Ve a https://basescan.org/register
2. Crea cuenta gratuita
3. "API Keys" → crea una key
4. Pégala en `.env` → `BASESCAN_API_KEY`

---

## ✅ PASO 2: Verificar que el entorno funciona (5 min)

Abre una terminal en `C:\Users\Yuba\Documents\Web3\audit-agents` y ejecuta:

```bash
# Verificar Foundry
forge --version

# Verificar Slither
slither --version

# Verificar Python
python --version

# Test rápido del audit system
python audit.py contracts/VulnerableVault.sol
```

---

## ✅ PASO 3: Obtener API key de Alchemy y probar fork (5 min)

Una vez que tengas la key de Alchemy, prueba que puedes forkear Base:

```bash
cd foundry-workspace

# Forkear Base mainnet (reemplaza TU_KEY)
forge test --fork-url https://base-mainnet.g.alchemy.com/v2/TU_KEY --fork-block-number 25000000 -vv
```

Si ves output sin errores, el fork funciona.

---

## ✅ PASO 4: Ejecutar los PoC (esto lo hacemos juntos)

Dime cuando tengas las API keys de Alchemy configuradas y yo:
1. Escribo los PoC completos en Foundry
2. Los ejecutamos contra Base mainnet forkeado
3. Verificamos que los exploits funcionan

### PoCs a escribir (en orden de prioridad):

| # | Finding | Dificultad PoC |
|---|---------|---------------|
| F-01 | protocolSeizeShare freeze liquidations | Fácil |
| F-02 | Quorum retroactivo | Fácil |
| F-06 | OEVMorpho missing nonReentrant | Solo argumentar |
| F-03 | closeFactor sin bounds | Fácil |
| F-05 | OEV phase change bypass | Media |
| F-04 | OEV oracle DoS | Media |

---

## ✅ PASO 5: Preparar los reports para Code4rena

Cada report necesita:

```
# Título del Bug

## Summary
Descripción en 1-2 frases

## Vulnerability Detail
Explicación técnica completa con referencias al código

## Impact
Qué puede pasar: pérdida de fondos, DoS, etc.

## Proof of Concept
Código Foundry que demuestra el bug

## Recommended Mitigation
Cómo arreglarlo
```

Ya tenemos drafts para F-01 y F-02 en:
- `BugBounty-Vault/06-Submissions/moonwell-001-protocolSeizeShare.md`
- `BugBounty-Vault/06-Submissions/moonwell-002-quorum-retroactive.md`

---

## ✅ PASO 6: Submit en Code4rena

1. Ve a https://code4rena.com/bounties/moonwell
2. Click "Submit Finding"
3. Selecciona severity (Critical/High/Medium)
4. Pega el report completo
5. Adjunta el código del PoC
6. Submit

### Orden de envío recomendado:
1. **F-01** (protocolSeizeShare) — nuestro mejor finding
2. **F-02** (quorum retroactivo) — segundo mejor
3. **F-06** (nonReentrant missing) — fácil de argumentar sin PoC complejo
4. **F-03** (closeFactor bounds) — sólido
5. Resto de TIER 2 si hay tiempo

---

## ✅ PASO 7: Seguimiento

- Code4rena revisa en ~1-2 semanas
- Si aceptan → te piden KYC → pago en USDC
- Si rechazan → revisa el feedback, aprende para el siguiente

---

## CHECKLIST RÁPIDO

```
[ ] Cuenta en Code4rena creada
[ ] Wallet conectada a Code4rena
[ ] Cuenta en Alchemy creada
[ ] API key de Base obtenida
[ ] .env configurado con las keys
[ ] Fork de Base funciona (forge test --fork-url)
[ ] PoC F-01 ejecutado y funciona
[ ] PoC F-02 ejecutado y funciona
[ ] Report F-01 enviado a Code4rena
[ ] Report F-02 enviado a Code4rena
[ ] Reports F-03 a F-06 enviados
```
