# Restaking Protocols — Bug Patterns

## Quick Reference

```
grep_targets:
  - StrategyManager
  - DelegationManager
  - EigenPodManager
  - EigenPod
  - AVSDirectory
  - SlasherManager
  - Slasher
  - StrategyBase
  - depositIntoStrategy
  - depositIntoStrategyWithSignature
  - queueWithdrawals
  - completeQueuedWithdrawals
  - delegateTo
  - undelegate
  - registerAsOperator
  - registerOperatorToAVS
  - deregisterOperatorFromAVS
  - verifyWithdrawalCredentials
  - verifyBalanceUpdates
  - verifyAndProcessWithdrawals
  - withdrawNonBeaconChainETHBalanceWei
  - hasRestaked
  - eigenPodManager
  - withdrawableRestakedExecutionLayerGwei
  - podOwner
  - NativeVault
  - slashableStake
  - requestSlashing
  - cancelSlashing
  - SLASHING_WINDOW
  - SLASHING_VETO_WINDOW
  - operatorShares
  - stakerStrategyShares
  - withdrawalDelayBlocks
  - MIN_WITHDRAWAL_DELAY_BLOCKS
  - calculateWithdrawalRoot
  - pendingWithdrawals
  - cumulativeWithdrawalsQueued
  - beaconChainETHStrategy
  - maxMagnitude
  - allocationDelay
```

---

## 1. Share Inflation en Strategy Deposits (First Depositor Attack)

```yaml
- id: restake-001
  titulo: Primer depositante en Strategy puede inflar el share price y robar fondos de depositantes posteriores
  causa_raiz: |
    EigenLayer's StrategyBase (y forks como Karak Vault) usan el patron shares/totalShares
    para trackear depositos. Cuando totalShares == 0, el primer deposito define el ratio
    inicial. Un atacante puede: (1) depositar 1 wei para obtener 1 share, (2) donar tokens
    directamente al contrato Strategy para inflar totalAssets sin incrementar totalShares,
    (3) cuando el siguiente usuario deposita, recibe 0 shares por rounding-down.
    Este es el clasico ERC4626 vault inflation attack adaptado al contexto de restaking.
    EigenLayer mitigo con un deposito minimo y "virtual shares", pero forks y wrappers
    a menudo no implementan estas mitigaciones.
  como_funciona: |
    1. Atacante llama depositIntoStrategy() con 1 wei de token → recibe 1 share.
    2. Atacante transfiere directamente 1e18 tokens al contrato Strategy (donation).
    3. Ahora: totalShares = 1, totalAssets = 1e18 + 1.
    4. Victima deposita 0.9e18 tokens → shares = (0.9e18 * 1) / (1e18 + 1) = 0 shares (rounding down).
    5. Los tokens de la victima se suman a totalAssets pero no generan shares → fondos del atacante valen mas.
    6. Atacante retira su 1 share → recibe totalAssets completo.
  invariante: |
    // Primer deposito debe generar shares > 0 para todo depositante
    uint256 sharesBefore = strategy.shares(user);
    strategy.deposit(token, amount);
    uint256 sharesAfter = strategy.shares(user);
    assert(sharesAfter > sharesBefore); // Si deposito > 0, shares deben incrementar
    // O con virtual shares: assert(totalShares >= VIRTUAL_SHARE_OFFSET);
  que_mirar:
    - "StrategyBase.deposit() sin virtual shares (offset) o deposito minimo"
    - "totalShares == 0 como condicion especial sin proteccion"
    - "Vaults/NativeVaults que heredan de ERC4626 sin override de _decimalsOffset()"
    - "depositIntoStrategy() acepta amounts arbitrariamente pequenos (1 wei)"
    - "Ausencia de dead shares o shares quemadas al primer deposito"
  como_se_arregla: |
    Implementar virtual shares (ERC4626 con _decimalsOffset() >= 3).
    Deposito minimo: require(shares >= MIN_SHARES, "deposit too small").
    Quemar las primeras N shares a address(dead) en el primer deposito.
    EigenLayer lo resolvio con SHARES_OFFSET = 1e3 y BALANCE_OFFSET = 1e3 en StrategyBase.
  trampas:
    - "EigenLayer mainnet (post M2) YA tiene virtual shares — no es vulnerable en la version actual"
    - "El ataque requiere que la Strategy acepte depositos directos de tokens (transfer sin deposit)"
    - "Protocolos con whitelist de depositantes (onlyStrategyManager) no son vulnerables via donation directa"
    - "Karak Vault Low-03 fue reportado pero clasificado como Low por mitigaciones existentes"
  solodit_ids:
    - "h-03-the-price-of-rseth-could-be-manipulated-by-the-first-staker-code4rena-kelp-kelp-dao-rseth-git"
    - "h-3-early-depositors-to-bufferbinarypool-can-manipulate-exchange-rates-to-steal-funds-from-later-depositors-sherlock-buffer-finance-buffer-finance-git"
    - "exchangerate-can-be-manipulated-leading-to-inflation-attack-cantina-none-opalprotocol-pdf"
  incidentes:
    - "Kelp DAO rsETH (C4 H-03) — primer staker manipula precio de rsETH via donation attack"
    - "Karak (C4 Low-03) — First depositor attack posible en Vault sin virtual shares"
    - "Trail of Bits EigenLayer audit — TOB-EIGEN-003: Strategies vulnerable to inflation attacks (mitigado con SHARES_OFFSET)"
    - "OpalProtocol (Cantina) — exchangeRate manipulable via deposit → inflation attack clasico"
```

---

## 2. Slashing de Queued Withdrawals — Error en Loop de Exclusion

```yaml
- id: restake-002
  titulo: Slashing de withdrawals en cola falla por error en incremento del loop, permitiendo robo de fondos
  causa_raiz: |
    En EigenLayer v1 (StrategyManager), la funcion slashQueuedWithdrawal() permite
    al slasher penalizar retiros en cola de operadores maliciosos. Acepta un parametro
    indicesToSkip para excluir strategies que revertirian (e.g., strategies maliciosas).
    El bug: el incremento del loop counter (++i) esta dentro del bloque `else`, no despues
    del if/else completo. Cuando un indice coincide con indicesToSkip, se incrementa
    indicesToSkipIndex pero NO i, causando que la siguiente iteracion entre al else y
    slashee la strategy que deberia haberse saltado.
    Resultado: si una strategy maliciosa revierte en cualquier llamada, toda la operacion
    de slashing falla, y el operador puede completar el withdrawal impunemente.
  como_funciona: |
    1. Operador malicioso hace queueWithdrawal() incluyendo una StrategyMaliciosa que revierte en transferFrom().
    2. Slasher intenta slashQueuedWithdrawal() con indicesToSkip = [indice de la strategy maliciosa].
    3. El loop llega al indice malicioso, entra al if (indicesToSkip match), incrementa indicesToSkipIndex.
    4. Bug: i NO se incrementa → siguiente iteracion usa el mismo indice → entra al else → intenta slashear la strategy maliciosa.
    5. La strategy maliciosa revierte en la llamada → toda la tx de slashing revierte.
    6. El operador espera el withdrawal delay y ejecuta completeQueuedWithdrawal() sin penalidad.
    7. Resultado: fondos que deberian ser slasheados son robados exitosamente.
  invariante: |
    // Post-slashing: los shares del operador deben reducirse
    uint256 sharesBefore = strategyManager.stakerStrategyShares(operator, strategy);
    slasher.slashQueuedWithdrawal(operator, withdrawalRoot, strategies, indicesToSkip);
    uint256 sharesAfter = strategyManager.stakerStrategyShares(operator, strategy);
    assert(sharesAfter < sharesBefore); // Slashing DEBE reducir shares
    // Loop invariant: i siempre incrementa en cada iteracion
  que_mirar:
    - "Loop con indicesToSkip donde ++i esta dentro de un bloque condicional"
    - "slashQueuedWithdrawal o funciones similares que procesan arrays con skip logic"
    - "Strategies que pueden revertir en withdraw/transferFrom bloqueando slashing"
    - "Operadores que incluyen strategies arbitrarias en sus withdrawals"
  como_se_arregla: |
    Mover ++i fuera del if/else, en un bloque unchecked al final del loop body.
    Alternativamente, usar continue en vez de else para el skip case.
    EigenLayer fixeo esto moviendo unchecked { ++i; } fuera del condicional.
  trampas:
    - "Este bug fue fixeado en EigenLayer M2 — no existe en versiones actuales"
    - "Solo aplica a queued withdrawals, no a deposits activos"
    - "El slasher role tiene permisos especiales — verificar que slasher != address(0) en forks"
    - "Forks de EigenLayer que copian StrategyManager v1 sin el fix siguen vulnerables"
  solodit_ids:
    - "h-02-it-is-impossible-to-slash-queued-withdrawals-that-contain-a-malicious-strategy-due-to-a-misplacement-of-the-i-increment-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 H-02) — ++i misplacement en slashQueuedWithdrawal() impide slashing de withdrawals con strategies maliciosas"
    - "EigenLayer (Trail of Bits) — Corroborado en audit formal, fix implementado en M2"
```

---

## 3. Verificacion de Withdrawals sin Pruebas de Slot/Block — Retiros Multiples

```yaml
- id: restake-003
  titulo: Withdrawal proofs de beacon chain aceptan proofs vacios, permitiendo retiros duplicados
  causa_raiz: |
    En EigenLayer, los retiros nativos (EigenPod) requieren proofs Merkle de la beacon chain
    para verificar que un validator hizo un retiro. La libreria BeaconChainProofs.sol
    no valida longitudes minimas de slotProof y blockNumberProof. La libreria Merkle
    retorna true cuando se le da un proof vacio si leaf == root. Un atacante puede
    modificar withdrawal proofs validos sustituyendo slotProof/blockNumberProof con bytes
    vacios y manipulando slotRoot/blockNumberRoot, procesando el mismo retiro multiples
    veces con valores de slot distintos.
  como_funciona: |
    1. Validator legítimo hace un full withdrawal en la beacon chain.
    2. Pod owner obtiene un proof valido y llama a verifyAndProcessWithdrawals().
    3. El proof se procesa correctamente. El withdrawal queda registrado para ese slot.
    4. Atacante toma el mismo proof, reemplaza slotProof con bytes("") y slotRoot con blockHeaderRoot.
    5. Como Merkle.verify(emptyProof, root, leaf) == true cuando leaf == root, la verificacion pasa.
    6. El blockNumberRoot tambien se puede manipular para bypass el modifier proofIsForValidBlockNumber.
    7. El retiro se procesa de nuevo con un slot value distinto → doble retiro.
    8. Repetir N veces → drenar el pod.
  invariante: |
    // Proof lengths deben ser >= 32 bytes (al menos un nivel Merkle)
    assert(proofs.slotProof.length >= 32);
    assert(proofs.blockNumberProof.length >= 32);
    // Un withdrawal solo se procesa una vez
    bytes32 withdrawalKey = keccak256(abi.encode(validatorIndex, withdrawalIndex));
    assert(!processedWithdrawals[withdrawalKey]); // No duplicate processing
  que_mirar:
    - "Merkle.verify() que retorna true con proof de longitud 0"
    - "BeaconChainProofs sin require de longitud minima en proofs"
    - "verifyAndProcessWithdrawals() key de deduplicacion basada en slot (manipulable)"
    - "proofIsForValidBlockNumber con blockNumberRoot que viene del proof (circular)"
  como_se_arregla: |
    Agregar require(proofs.slotProof.length >= 32) y require(proofs.blockNumberProof.length >= 32).
    Usar (validatorIndex, withdrawalIndex) como key de deduplicacion en vez de slot number.
    EigenLayer fixeo con validaciones de longitud minima en BeaconChainProofs.
  trampas:
    - "Este bug fue corregido en EigenLayer — versiones post-audit no son vulnerables"
    - "Requiere que la libreria Merkle acepte proofs vacios — verificar la implementacion especifica"
    - "En la practica, el atacante necesita un withdrawal real previo para extraer el proof base"
    - "Solo aplica a native restaking (EigenPod), no a LST strategies"
  solodit_ids:
    - "h-01-slot-and-block-number-proofs-not-required-for-verification-of-withdrawal-multiple-withdrawals-possible-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 H-01) — Slot/block proofs no requeridos para verificacion de withdrawal, multiples withdrawals posibles"
```

---

## 4. Bypass de Slashing por Overcommitment del Staker

```yaml
- id: restake-004
  titulo: Staker con over-commitment verificado puede evadir slashing completamente via timing
  causa_raiz: |
    En EigenLayer, cuando un staker tiene mas ETH comprometido (restaked) del que realmente
    tiene en su validator, se llama "over-commitment". El protocolo tiene un mecanismo para
    verificar y penalizar esto. Sin embargo, un staker que sabe que va a ser slasheado puede
    manipular el timing: hacer un retiro parcial del validator antes de que el verifier
    publique la prueba de over-commitment. Al reducir su balance real, el over-commitment
    se vuelve mas severo, pero el staker ya ha extraido los fondos del EigenPod antes de
    que el slashing pueda aplicarse. La penalidad se aplica sobre shares que el staker
    ya no posee o que valen menos de lo que deberian.
  como_funciona: |
    1. Staker tiene 32 ETH en validator, restaked como 32 ETH en EigenLayer.
    2. Staker sabe que va a ser slasheado por un AVS.
    3. Staker hace voluntary exit del validator en beacon chain.
    4. Los 32 ETH llegan al EigenPod como retiro completo.
    5. Staker llama a withdrawNonBeaconChainETHBalanceWei() si los fondos no estan tracked como beacon chain ETH.
    6. Alternativamente, inicia queueWithdrawals() inmediatamente.
    7. Para cuando el slasher ejecuta, el staker ya tiene los fondos en proceso de withdrawal.
    8. El slashing reduce shares pero los fondos ya fueron extraidos.
  invariante: |
    // Los shares slasheados deben tener backing real (no pueden ser fantasma)
    uint256 operatorSlashableStake = delegation.getSlashableStake(operator, strategy);
    // Post-slashing, operador no debe poder completar withdrawals > remaining stake
    uint256 totalQueued = delegation.cumulativeWithdrawalsQueued(operator);
    assert(totalQueued <= operatorSlashableStake);
  que_mirar:
    - "Timing entre queueWithdrawals y ejecucion de slashing — race condition"
    - "withdrawNonBeaconChainETHBalanceWei() accesible antes de slashing"
    - "Over-commitment verification delay vs withdrawal completion delay"
    - "Operadores que pueden auto-undelegarse durante periodo de slashing pendiente"
  como_se_arregla: |
    Withdrawal delay >= slashing window (EigenLayer: withdrawal delay de 7+ dias).
    Congelar withdrawals del operador cuando hay slashing pendiente.
    Verificar balance real del validator al momento del slashing, no al momento del registro.
    EigenLayer M2+ implementa maxMagnitude y allocationDelay para esto.
  trampas:
    - "EigenLayer M2 agrega withdrawal delay suficiente para cubrir slashing window"
    - "El over-commitment solo aplica a native restaking (EigenPods), no LST strategies"
    - "El beacon chain tiene su propio delay para exits (~27h min) que limita este ataque"
    - "No confundir con slashing del beacon chain (Ethereum) vs slashing del AVS (EigenLayer)"
  solodit_ids:
    - "m-01-a-staker-with-verified-over-commitment-can-potentially-bypass-slashing-completely-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 M-01) — staker con over-commitment puede bypass slashing via timing de retiro"
    - "EigenLayer (Trail of Bits) — Varios findings sobre race conditions entre withdrawal y slashing"
```

---

## 5. Slashing de NativeVault Bloquea ETH de Usuarios

```yaml
- id: restake-005
  titulo: Slashing en NativeVault reduce shares pero ETH queda bloqueado sin mecanismo de redistribucion
  causa_raiz: |
    En protocolos como Karak, el NativeVault maneja staking nativo de ETH via validators.
    Cuando un DSS (Distributed Secure Service, analogo a AVS) solicita slashing de un operador,
    la funcion de slashing reduce los shares de los stakers pero no mueve ni redistribuye
    el ETH subyacente. El ETH queda en el validator o en el pod, pero las shares ya fueron
    quemadas. Los usuarios afectados pierden su representacion (shares) pero el ETH sigue
    locked sin que nadie pueda reclamarlo. Esto crea un mismatch permanente entre
    totalShares y el ETH real, causando que todo retiro posterior calcule montos incorrectos.
  como_funciona: |
    1. Stakers A y B depositan 16 ETH cada uno via NativeVault (total: 32 ETH, 32 shares).
    2. Operador es slasheado por el DSS: se queman 10 shares (de staker A).
    3. totalShares = 22, pero totalAssets (ETH en validator) sigue siendo ~32 ETH.
    4. El ETH que correspondia a las 10 shares quemadas queda locked en el validator.
    5. Staker B intenta retirar sus 16 shares → recibe (16/22) * 32 = 23.27 ETH (mas de lo que deposito).
    6. O peor: no hay mecanismo para mover ETH del validator a un slashingHandler.
    7. Resultado: ETH bloqueado permanentemente, accounting roto para todos los stakers.
  invariante: |
    // totalShares * pricePerShare == totalAssets (despues de slashing tambien)
    uint256 impliedAssets = vault.totalShares() * vault.pricePerShare() / 1e18;
    uint256 actualAssets = vault.totalAssets();
    assert(impliedAssets <= actualAssets + DUST_TOLERANCE);
    // Post-slashing: el ETH penalizado debe moverse, no solo quemar shares
    assert(postSlashTotalAssets == preSlashTotalAssets - slashedAmount);
  que_mirar:
    - "Funcion de slashing que reduce shares sin mover/quemar los assets subyacentes"
    - "NativeVault donde ETH esta en validators (no se puede transferir instantaneamente)"
    - "totalAssets() que no refleja el slashing hasta que el validator haga exit"
    - "changeSlashingHandler() que puede invalidar slashings pendientes"
  como_se_arregla: |
    Implementar mecanismo de withdrawal forzado del validator al momento del slashing.
    Trackear pendingSlashes como pasivo contra totalAssets.
    Usar un escrow para ETH slasheado hasta que el validator procese el exit.
    No permitir cambiar slashingHandler mientras haya slashings pendientes.
  trampas:
    - "El ETH en validators de beacon chain NO puede moverse instantaneamente — exit toma 27h+"
    - "El slashing puede aplicarse en shares pero el ETH real tarda dias en llegar"
    - "No confundir con slashing del propio validator (beacon chain) vs slashing del DSS/AVS"
    - "Karak M-01: cambiar slashingHandler para NativeVaults hace DoS en slashing futuro"
  solodit_ids:
    - "h-01-slashing-nativevault-will-lead-to-locked-eth-for-users-code4rena-karak-karak-git"
    - "m-01-changing-the-slashinghandler-for-nativevaults-will-dos-slashing-code4rena-karak-karak-git"
  incidentes:
    - "Karak (C4 H-01) — Slashing de NativeVault bloquea ETH permanentemente para stakers"
    - "Karak (C4 M-01) — Cambiar slashingHandler para NativeVaults causa DoS en slashing"
    - "Karak (C4 M-02) — Snapshot permanente DoS si slashing + penalizacion de validator ocurren juntos"
```

---

## 6. Operador Crea NativeVault Inslashable Silenciosamente

```yaml
- id: restake-006
  titulo: Operador puede crear un NativeVault cuya configuracion impide que el DSS lo slashee
  causa_raiz: |
    En Karak, los operadores deployean sus propios NativeVaults (via CREATE2 o factory).
    El operador controla los parametros de inicializacion del vault, incluyendo configuraciones
    que determinan como se ejecuta el slashing. Si el operador configura el vault de forma
    que slashing() siempre revierte (e.g., slashingHandler apuntando a un contrato que
    revierte, o parametros que causan division por zero), el vault opera normalmente para
    stakers pero es silenciosamente inslashable. Los DSS confian en que pueden slashear
    al operador, pero en la practica nunca podran.
  como_funciona: |
    1. Operador malicioso deployea NativeVault con slashingHandler = contrato que revierte.
    2. Operador registra el vault con un DSS, recibiendo delegaciones de stakers.
    3. DSS asume que el operador es slashable (el vault existe y esta registrado).
    4. Operador actua maliciosamente en el AVS/DSS.
    5. DSS intenta requestSlashing() → la tx llega al NativeVault → la ejecucion de slashing revierte.
    6. Los stakers han depositado sin saber que su operador es efectivamente inslashable.
    7. El mecanismo de seguridad del restaking queda completamente anulado.
  invariante: |
    // Todo vault registrado en un DSS debe ser slashable (dry-run)
    // Invariante: si requestSlashing() no revierte, slashVault() tampoco deberia
    (bool success,) = vault.slashingHandler().call(
        abi.encodeWithSignature("handleSlashing(address,uint256)", vault, testAmount)
    );
    assert(success); // Vault DEBE ser slashable
  que_mirar:
    - "Operadores que deployean sus propios vaults sin validacion de slashability"
    - "Factory/CREATE2 de vaults sin dry-run test de slashing en la inicializacion"
    - "slashingHandler configurable por el operador (no por el DSS o el protocolo)"
    - "Ausencia de validacion on-chain de que el vault puede ejecutar slashing"
  como_se_arregla: |
    Validar slashability del vault en el momento del registro con el DSS.
    Hacer dry-run de slashing con un monto de test durante la inicializacion.
    El protocolo (no el operador) debe controlar el slashingHandler.
    Implementar slashing via pull (DSS retira shares) en vez de push (vault ejecuta).
  trampas:
    - "El operador puede no ser malicioso inicialmente — puede cambiar el handler despues"
    - "La slashability no es solo sobre el handler: tambien depende del balance del validator"
    - "Un vault puede ser slashable para montos pequenos pero revertir para montos grandes"
    - "No confundir con operadores que legítimamente no tienen stake suficiente (eso es diferente)"
  solodit_ids:
    - "h-02-operator-can-create-nativevault-that-can-be-silently-unslashable-code4rena-karak-karak-git"
  incidentes:
    - "Karak (C4 H-02) — Operador crea NativeVault silenciosamente inslashable"
    - "Karak (C4 H-04) — Invariante violado: DSS puede slashear operadores no registrados (problema inverso)"
```

---

## 7. DoS en Snapshots por Error de Rounding en NativeVault

```yaml
- id: restake-007
  titulo: Error de redondeo en calculo de snapshot causa DoS permanente en NativeVault
  causa_raiz: |
    En Karak NativeVault, el mecanismo de snapshots captura el balance del validator
    en puntos especificos para calcular rewards y balances. El calculo de
    balanceDeltaWei (diferencia entre balance actual y anterior del validator) puede
    producir valores negativos pequenos por redondeo en la conversion gwei→wei.
    Cuando balanceDelta es negativo y se resta de las shares del staker, puede causar
    underflow si las shares son menores que el delta (por acumulacion de errores de
    rounding en multiples snapshots). El underflow hace revertir la transaccion,
    causando DoS permanente en el snapshot del staker.
  como_funciona: |
    1. Validator tiene 32.000000001 ETH → en gwei es 32000000001, en wei es 32000000001000000000.
    2. Snapshot N registra el balance.
    3. Validator pierde 1 gwei por gas/penalties → 32000000000 gwei.
    4. Snapshot N+1 calcula delta: 32000000000 - 32000000001 = -1 gwei = -1e9 wei.
    5. Si el staker tiene exactamente 32e18 shares y el delta se resta directamente: shares - 1e9 = OK.
    6. Pero si multiples redondeos acumulados causan que el delta negativo > shares restantes → underflow.
    7. La funcion de snapshot revierte → el staker no puede hacer mas snapshots → fondos bloqueados.
    8. Esto puede ser triggereado griefing: un tercero causa penalizaciones menores al validator.
  invariante: |
    // Snapshot delta nunca debe causar underflow en shares del staker
    int256 delta = int256(currentBalanceWei) - int256(previousBalanceWei);
    if (delta < 0) {
        uint256 reduction = uint256(-delta);
        assert(stakerShares[staker] >= reduction); // No underflow
    }
    // Snapshot siempre debe completarse (no revertir)
  que_mirar:
    - "Conversion gwei → wei con posible perdida de precision"
    - "Restas de shares sin checked underflow protection"
    - "Snapshots que usan int256 vs uint256 sin safe casting"
    - "Acumulacion de redondeos negativos en multiples snapshots consecutivos"
    - "Slash event durante snapshot — M-02 de Karak"
  como_se_arregla: |
    Usar SafeMath o checked arithmetic para la resta de shares.
    Implementar floor en 0: if (reduction > shares) reduction = shares.
    Trackear rounding dust por separado y no aplicarlo a shares del usuario.
    Validar que snapshot() nunca puede revertir (DoS-free).
  trampas:
    - "Un solo snapshot con rounding error es benigno — el problema es la ACUMULACION"
    - "En la practica, los balances de validators solo cambian en gwei (no wei) — la precision importa"
    - "No todos los rounding errors son bugs: algunos son inherentes al diseno gwei→wei"
    - "La solucion no es eliminar el rounding sino hacerlo tolerante a fallos (no revertir)"
  solodit_ids:
    - "h-03-dos-on-snapshots-due-to-rounding-error-in-calculations-code4rena-karak-karak-git"
    - "m-02-snapshot-may-face-permanent-dos-if-slashing-event-occurs-in-nativevault-and-stakers-validator-is-penalized-code4rena-karak-karak-git"
  incidentes:
    - "Karak (C4 H-03) — DoS en snapshots por rounding error en calculos"
    - "Karak (C4 M-02) — Snapshot DoS permanente si slashing + penalizacion del validator coinciden"
```

---

## 8. TVL Incorrecto por Queued Withdrawals — Manipulacion de Mint Rate de LRT

```yaml
- id: restake-008
  titulo: Calculo incorrecto de queued withdrawals deflacta TVL y permite mintear LRT a precio inflado
  causa_raiz: |
    En protocolos de Liquid Restaking (Renzo ezETH, Kelp rsETH, Puffer pufETH),
    el TVL (Total Value Locked) se usa para calcular el exchange rate del LRT.
    Si el calculo de TVL no incluye correctamente los fondos en cola de retiro
    (queued withdrawals de EigenLayer), el TVL se subestima. Un TVL mas bajo
    significa que el exchange rate es mas alto (cada LRT "vale" mas), pero en
    realidad hay mas fondos de los reportados. Nuevos depositantes reciben mas
    LRT de lo que deberian, diluyendo a los existentes.

    En Renzo, el calculo de calculateTVL() no contabilizaba correctamente
    los ETH en queued withdrawals de EigenLayer, causando que el TVL fuera
    menor que el real → ezETH se minteaba a ratio inflado.
  como_funciona: |
    1. Protocolo tiene 100 ETH en EigenLayer strategies + 20 ETH en queued withdrawals.
    2. TVL real = 120 ETH. Pero calculateTVL() solo cuenta strategies activas = 100 ETH.
    3. Si hay 100 ezETH en circulacion, el rate es 100/100 = 1:1 (correcto seria 120/100 = 1.2:1).
    4. Nuevo depositante deposita 10 ETH → recibe 10 ezETH (deberia recibir 10/1.2 = 8.33 ezETH).
    5. El depositante nuevo recibio 1.67 ezETH extra → dilucion para todos los holders existentes.
    6. Atacante puede amplificar esto: initiar muchos withdrawals para deflactar TVL artificialmente,
       depositar a rate favorable, cancelar withdrawals.
  invariante: |
    // TVL debe incluir TODOS los fondos: strategies + queued + buffer
    uint256 calculatedTVL = protocol.calculateTVL();
    uint256 realTVL = sumAllStrategies() + sumQueuedWithdrawals() + bufferBalance();
    assert(calculatedTVL >= realTVL * 99 / 100); // Max 1% deviation
    // Exchange rate no debe cambiar significativamente por una queue/dequeue operation
  que_mirar:
    - "calculateTVL() o totalAssets() que no incluyen queuedWithdrawals"
    - "Fondos en EigenLayer completeQueuedWithdrawals() pendientes de claim"
    - "Buffer/deposit pool no contabilizado en el TVL"
    - "Exchange rate del LRT calculado antes de actualizar TVL"
    - "Operaciones de queue/dequeue que no actualizan el TVL atomicamente"
  como_se_arregla: |
    Incluir queuedWithdrawals en calculateTVL() con su valor real.
    Trackear pendingWithdrawals como activo del protocolo (no como perdida).
    Actualizar TVL atomicamente en deposit/withdraw.
    Circuit breaker si TVL cambia > X% en un bloque.
  trampas:
    - "Los queued withdrawals tienen un valor incierto (depende del rate al completar)"
    - "Incluir withdrawals cancelados o ya completados infla el TVL (error opuesto)"
    - "El impacto depende del ratio queued/active — si queued es <1% del TVL, es dust"
    - "Renzo H-08 y H-02 son findings relacionados pero distintos: H-02 es calculo incorrecto, H-08 es no incluir balance"
  solodit_ids:
    - "h-02-incorrect-calculation-of-queued-withdrawals-can-deflate-tvl-and-increase-ezeth-mint-rate-code4rena-renzo-renzo-git"
    - "h-08-incorrect-withdraw-queue-balance-in-tvl-calculation-code4rena-renzo-renzo-git"
    - "h-04-aavevault-does-not-update-tvl-on-depositwithdraw-code4rena-mellow-protocol-mellow-protocol-contest-git"
  incidentes:
    - "Renzo (C4 H-02) — Calculo incorrecto de queued withdrawals deflacta TVL, inflando mint rate de ezETH"
    - "Renzo (C4 H-08) — Balance de withdraw queue no incluido en calculo de TVL"
    - "Mellow Protocol (C4 H-04) — AaveVault no actualiza TVL en deposit/withdraw"
    - "Kelp DAO (C4 H-02) — Protocol mints less rsETH than intended por calculo erroneo de TVL"
```

---

## 9. Withdrawal ETH Falla por receive() nonReentrant en OperatorDelegator

```yaml
- id: restake-009
  titulo: Retiros de ETH desde EigenLayer siempre fallan porque receive() del OperatorDelegator tiene nonReentrant
  causa_raiz: |
    En Renzo, cuando EigenLayer completa un queued withdrawal de ETH nativo (no ERC20),
    el ETH se envia al OperatorDelegator via una llamada que pasa por la funcion
    completeQueuedWithdrawal(). Esta funcion ya tiene el modifier nonReentrant.
    Cuando EigenLayer transfiere el ETH al OperatorDelegator, activa receive().
    Si receive() tambien tiene nonReentrant, la tx revierte porque el lock ya esta
    tomado por completeQueuedWithdrawal(). Resultado: todos los retiros de ETH nativo
    quedan permanentemente bloqueados.
  como_funciona: |
    1. Usuario solicita retiro de ETH via el protocolo LRT.
    2. Protocolo llama a EigenLayer.queueWithdrawals() para el beaconChainETHStrategy.
    3. Despues del delay, protocolo llama completeQueuedWithdrawals() (con nonReentrant).
    4. EigenLayer procesa el retiro y envia ETH al OperatorDelegator.
    5. OperatorDelegator.receive() se activa → tiene nonReentrant → ya esta locked → REVERT.
    6. Ningun retiro de ETH nativo puede completarse. Fondos bloqueados.
  invariante: |
    // Completar un queued withdrawal de ETH nunca debe revertir por reentrancy guard
    // Test: llamar completeQueuedWithdrawal() con receiveAsTokens=true para ETH
    vm.expectCall(address(operatorDelegator), withdrawAmount, "");
    eigenLayer.completeQueuedWithdrawals(withdrawal, tokens, middlewareTimesIndexes, receiveAsTokens);
    // Si revierte con "ReentrancyGuard: reentrant call" → bug confirmado
  que_mirar:
    - "receive() o fallback() con nonReentrant en contratos que reciben ETH de EigenLayer"
    - "completeQueuedWithdrawal con receiveAsTokens=true para ETH nativo"
    - "Cadena de llamadas: completeQueuedWithdrawal → transfer ETH → receive()"
    - "OperatorDelegator o contratos wrapper que heredan ReentrancyGuard"
  como_se_arregla: |
    Remover nonReentrant de receive()/fallback() cuando el contrato recibe ETH de fuentes confiables.
    Alternativamente, recibir ETH como WETH (wrap antes de transferir).
    Usar un patron pull (el contrato claim ETH) en vez de push (EigenLayer envia ETH).
  trampas:
    - "Solo aplica a ETH nativo — retiros de ERC20 strategies no pasan por receive()"
    - "Si receive() no tiene nonReentrant pero SÍ tiene logica compleja, hay riesgo de reentrancy real"
    - "La solucion no es simplemente quitar nonReentrant — hay que evaluar si receive() necesita proteccion"
    - "Algunos protocolos usan WETH wrapping que elimina este problema completamente"
  solodit_ids:
    - "h-03-eth-withdrawals-from-eigenlayer-always-fail-due-to-operatordelegators-nonreentrant-receive-code4rena-renzo-renzo-git"
  incidentes:
    - "Renzo (C4 H-03) — ETH withdrawals desde EigenLayer siempre fallan por receive() nonReentrant"
    - "Renzo (C4 H-01) — Withdrawals locked forever si recipient es contrato (related)"
```

---

## 10. Arbitraje en LRT por Discrepancia de Precio entre Chainlink Feeds

```yaml
- id: restake-010
  titulo: Arbitraje bidireccional en LRT por uso de feed de mercado (market rate) en vez de exchange rate
  causa_raiz: |
    Los protocolos de Liquid Restaking necesitan valorar los assets subyacentes (stETH,
    rETH, cbETH) para calcular el exchange rate del LRT. Si usan feeds de precio de
    mercado (stETH/ETH market rate en Curve/Uniswap) en vez del exchange rate canonico
    del protocolo LST, se abre una oportunidad de arbitraje. Cuando el market rate
    difiere del exchange rate (common durante volatilidad), un atacante puede:
    - Depositar cuando el LST esta por debajo del peg (market < exchange) → LRT barato.
    - Retirar cuando el LST esta por encima del peg (market > exchange) → LRT caro.
    Cada operacion extrae valor del protocolo y de los otros holders del LRT.

    En Kelp DAO, discrepancias entre feeds de Chainlink para distintos LSTs permitian
    arbitraje porque los heartbeats/deviations eran diferentes para cada feed.
  como_funciona: |
    1. Protocolo usa Chainlink stETH/ETH market rate (puede divergir 1-5% del exchange rate).
    2. stETH/ETH market rate cae a 0.97 por presion de venta en Curve.
    3. Atacante deposita stETH → protocolo lo valora a 0.97 ETH → mintea LRT a precio bajo.
    4. Market se recupera a 1.0 → atacante retira → recibe ETH valorado a 1.0.
    5. Profit: 3% por operacion, repetible con flash loans.
    6. Variante Kelp: feeds de diferentes LSTs tienen heartbeats distintos (24h vs 1h).
       Un feed actualiza y otro no → el protocolo cree que un LST es relativamente mas caro.
       Depositar en el LST "barato" y retirar del "caro" → arbitraje.
  invariante: |
    // El exchange rate del LRT no debe cambiar significativamente dentro de un bloque
    uint256 rateBefore = lrt.exchangeRate();
    // ... deposit or withdraw ...
    uint256 rateAfter = lrt.exchangeRate();
    uint256 diff = rateBefore > rateAfter ? rateBefore - rateAfter : rateAfter - rateBefore;
    assert(diff * 10000 / rateBefore < 10); // Max 0.1% change per operation
  que_mirar:
    - "Feeds Chainlink de mercado (stETH/ETH) usados para valorar depositos/retiros"
    - "Multiples feeds con heartbeats distintos usados en el mismo calculo de TVL"
    - "Ausencia de slippage protection o cooldown entre deposit y withdraw"
    - "Flash loan → deposit → withdraw en el mismo bloque sin restriccion"
    - "Oracle que compone price * rate de dos feeds distintas (heartbeat mismatch)"
  como_se_arregla: |
    Usar exchange rate canonico del LST (wstETH.stEthPerToken()) en vez de market rate.
    Si se usan feeds Chainlink, asegurar que todos tienen el mismo heartbeat.
    Implementar cooldown entre deposit y withdraw (min 1 bloque).
    Slippage check: require(mintedShares >= minShares).
    Usar TWAP en vez de spot price para depositos.
  trampas:
    - "El exchange rate canonico tambien puede ser manipulado (pero es mucho mas dificil)"
    - "Discrepancias pequenas (<0.1%) no son profitables despues de gas"
    - "En L2 las feeds Chainlink tienen heartbeats mas largos — el riesgo es mayor"
    - "No todo arbitraje es un bug — algunos protocolos lo aceptan como 'market making'"
  solodit_ids:
    - "h-01-possible-arbitrage-from-chainlink-price-discrepancy-code4rena-kelp-kelp-dao-rseth-git"
    - "m-14-stetheth-feed-being-used-opens-up-to-2-way-deposit-withdrawal-arbitrage-code4rena-renzo-renzo-git"
    - "m-12-incorrect-exchange-rate-provided-to-balancer-pools-code4rena-renzo-renzo-git"
  incidentes:
    - "Kelp DAO (C4 H-01) — Arbitraje posible por discrepancia de precios entre feeds Chainlink de diferentes LSTs"
    - "Renzo (C4 M-14) — Feed stETH/ETH market rate abre arbitraje bidireccional en deposit/withdraw"
    - "Renzo (C4 M-12) — Exchange rate incorrecto para Balancer pools"
```

---

## 11. DSS/AVS Slashing de Operadores No Registrados (Invariant Violation)

```yaml
- id: restake-011
  titulo: DSS puede ejecutar slashing contra operadores que no estan registrados, violando invariante fundamental
  causa_raiz: |
    En Karak, el invariante fundamental de seguridad es: un DSS solo puede slashear
    operadores que estan registrados con ese DSS. Si la verificacion de registro no es
    atomica con la ejecucion del slashing, o si hay paths alternativos que bypasean
    la verificacion, un DSS malicioso puede slashear a cualquier operador, incluso
    aquellos que nunca se registraron. Esto rompe la confianza del operador en el sistema:
    "solo los DSS que elijo pueden penalizarme".

    El bug en Karak era que el mapping de registro no se verificaba correctamente
    en el path de slashing, o que la deregistracion no cancelaba slashings pendientes.
  como_funciona: |
    1. Operador A esta registrado solo con DSS-1 (servicio legítimo).
    2. DSS-2 (malicioso) llama a requestSlashing(operatorA, vault, amount).
    3. El sistema no verifica (o verifica incorrectamente) que operador A esta registrado con DSS-2.
    4. La solicitud de slashing se crea exitosamente.
    5. Despues del SLASHING_VETO_WINDOW, DSS-2 finaliza el slashing.
    6. Se queman shares de operador A en el vault especificado.
    7. Resultado: operador A pierde fondos por un DSS con el que nunca se registro.
  invariante: |
    // Solo DSS registrado puede slashear a un operador
    function invariant_slashingOnlyRegistered() public {
        for (uint i = 0; i < operators.length; i++) {
            for (uint j = 0; j < dssContracts.length; j++) {
                if (!isRegistered[operators[i]][dssContracts[j]]) {
                    // Intentar slashear DEBE revertir
                    vm.expectRevert();
                    core.requestSlashing(operators[i], vaults[i], slashAmount);
                }
            }
        }
    }
  que_mirar:
    - "requestSlashing() sin verificacion de isRegistered[operator][dss]"
    - "Deregistration que no cancela slashings pendientes del DSS"
    - "Race condition: operador se deregistra pero slashing pendiente se ejecuta"
    - "Mapping de registro inconsistente entre Core y DSS contracts"
  como_se_arregla: |
    Verificar isRegistered[operator][msg.sender] atomicamente en requestSlashing().
    Cancelar automaticamente slashings pendientes cuando el operador se deregistra.
    Implementar SLASHING_VETO_WINDOW para que el operador pueda contestar.
    Usar pull-based slashing: el operador acepta la penalidad, no el DSS la ejecuta.
  trampas:
    - "El SLASHING_VETO_WINDOW de Karak permite al operador vetar — pero solo si lo ve a tiempo"
    - "No confundir con el caso legítimo donde un operador fue malicioso Y esta registrado"
    - "La deregistracion con slashings pendientes es un edge case critico — muchos protocolos lo ignoran"
    - "Karak M-03: el monto de slashing se calcula incorrecto si se solicita durante el periodo post-window"
  solodit_ids:
    - "h-04-violation-of-invariant-allowing-dsss-to-slash-unregistered-operators-code4rena-karak-karak-git"
    - "m-03-token-amount-to-be-slashed-calculated-higher-than-it-should-be-when-dss-requests-slashing-during-2-day-period-after-slashing_window-code4rena-karak-karak-git"
  incidentes:
    - "Karak (C4 H-04) — Violacion de invariante: DSS puede slashear operadores no registrados"
    - "Karak (C4 M-03) — Monto de slashing calculado mas alto durante periodo de 2 dias post-window"
    - "Karak (C4 M-04) — Slashing window retrasado y falta de transparencia para slashings pendientes"
```

---

## 12. MEV/Front-running en Retiros de LRT por Cambios de TVL

```yaml
- id: restake-012
  titulo: Withdrawals de LRT permiten MEV via front-running de cambios de TVL (zero-slippage swaps)
  causa_raiz: |
    Los protocolos de Liquid Restaking calculan el exchange rate deposit/withdrawal
    basandose en el TVL actual. Cuando ocurre un evento que cambia el TVL
    (rewards accrual, slashing, rebase de LSTs, oracle update), un atacante
    puede front-runnear la transaccion que actualiza el TVL:
    - Si TVL va a subir (rewards): depositar ANTES del update → recibir LRT barato → valor sube.
    - Si TVL va a bajar (slashing): retirar ANTES del update → recibir ETH a precio pre-slashing.
    Sin slippage protection ni cooldown, esto es un ataque de sandwich "zero-fee".
  como_funciona: |
    1. Oracle update o rewards harvest va a incrementar TVL de 100 ETH a 105 ETH.
    2. Atacante ve la tx del oracle update en el mempool.
    3. Atacante deposita 100 ETH → recibe 100 LRT (rate 1:1 pre-update).
    4. Oracle update ejecuta → TVL sube a 205 ETH → rate sube a 205/200 = 1.025.
    5. Atacante retira 100 LRT → recibe 102.5 ETH.
    6. Profit: 2.5 ETH sin riesgo. Amplificable con flash loans.

    Variante inversa (slashing):
    1. Slashing event va a reducir TVL de 100 ETH a 95 ETH.
    2. Atacante retira ANTES del slashing → recibe ETH a rate pre-slashing.
    3. Los holders restantes absorben toda la perdida del slashing.
  invariante: |
    // Deposit y withdrawal en el mismo bloque no debe ser profitable
    uint256 ethBefore = address(attacker).balance;
    lrt.deposit{value: depositAmount}(depositAmount);
    lrt.withdraw(lrt.balanceOf(attacker));
    uint256 ethAfter = address(attacker).balance;
    assert(ethAfter <= ethBefore); // No profit from round-trip
  que_mirar:
    - "Deposit y withdraw sin cooldown (ambos posibles en el mismo bloque)"
    - "TVL update (rewards, rebase, oracle) como transaccion separada (sandwicheable)"
    - "Ausencia de slippage check en deposit (minMint) y withdraw (minReceive)"
    - "Flash loan compatible: deposit y withdraw en misma tx"
    - "calculateMintAmount() usa TVL que puede cambiar en el mismo bloque"
  como_se_arregla: |
    Cooldown minimo entre deposit y withdraw (al menos 1 bloque, idealmente 1 epoch).
    Slippage protection: minAmountOut en deposit y withdraw.
    TWAP para TVL calculation (no spot).
    Atomicidad: rewards/rebase y deposit/withdraw en la misma tx.
    Deposit/withdrawal fees que hagan unprofitable el round-trip.
  trampas:
    - "En L2 (private mempool), sandwich es mas dificil pero no imposible (sequencer puede extraer)"
    - "Con fees de deposit/withdrawal >0.3%, el round-trip deja de ser profitable para la mayoria de eventos"
    - "No todo front-running de oracle es explotable — depende del tamano del update y la liquidez"
    - "Renzo H-04 vs M-10: H-04 es en L1 (mempool publico), M-10 es en L2 (xRenzoDeposit)"
  solodit_ids:
    - "h-04-withdrawals-logic-allows-mev-exploits-of-tvl-changes-and-zero-slippage-zero-fee-swaps-code4rena-renzo-renzo-git"
    - "m-10-potential-arbitrage-opportunity-in-the-xrenzodeposit-l2-contract-code4rena-renzo-renzo-git"
    - "m-07-lack-of-slippage-and-deadline-during-withdraw-and-deposit-code4rena-renzo-renzo-git"
  incidentes:
    - "Renzo (C4 H-04) — Logica de withdrawals permite MEV exploits de cambios de TVL y swaps zero-slippage"
    - "Renzo (C4 M-10) — Oportunidad de arbitraje en el contrato xRenzoDeposit L2"
    - "Renzo (C4 M-07) — Falta de slippage y deadline en withdraw y deposit"
```

---

## 13. Rebasing Tokens en Queued Withdrawals — Insolvencia

```yaml
- id: restake-013
  titulo: Withdrawals de rebasing tokens causan insolvencia porque el monto en cola cambia durante el delay
  causa_raiz: |
    Cuando un protocolo de restaking queue un withdrawal de un rebasing token (stETH),
    registra el monto actual. Durante el withdrawal delay (7+ dias en EigenLayer), el
    token rebasa (incrementa/decrementa el balance de todos los holders). El monto
    registrado ya no corresponde al balance real:
    - Si stETH rebasa positivamente: el protocolo debe mas de lo que registro.
    - Si stETH rebasa negativamente (slashing): el protocolo registro mas de lo que tiene.
    En ambos casos hay un mismatch. Si multiples withdrawals se completan despues de un
    rebase positivo, el protocolo puede no tener suficientes tokens para cubrir todos los
    claims → insolvencia.
  como_funciona: |
    1. Protocolo tiene 100 stETH. Usuario A queue withdrawal de 50 stETH.
    2. Se registra: pendingWithdrawal[A] = 50 stETH.
    3. Durante los 7 dias de delay, stETH rebasa +2% → balance del protocolo sube a 102 stETH.
    4. Pero el withdrawal registrado sigue siendo 50 stETH (no 51 stETH).
    5. Los 2 stETH de rebase quedan como "reserve fantasma" — nadie puede reclamarlos.
    6. Variante inversa (mas grave): rebase negativo. stETH baja a 98.
       Protocol debe 50 (withdrawal A) + tiene otros stakers por 50.
       Pero solo tiene 98 stETH total → insolvente por 2 stETH.
    7. Si se usa wstETH internamente pero stETH externamente: conversion rate mismatch.
  invariante: |
    // Total obligaciones (withdrawals + staker balances) <= total assets post-rebase
    uint256 totalObligations = sumPendingWithdrawals() + sumActiveStakerShares();
    uint256 totalAssets = rebasingToken.balanceOf(address(this));
    assert(totalObligations <= totalAssets + TOLERANCE);
    // Withdrawal amount debe ser en shares (no en tokens) para rebasing tokens
  que_mirar:
    - "Queued withdrawal que guarda amount en tokens (uint256) para rebasing tokens"
    - "stETH usado directamente en vez de wstETH (non-rebasing wrapper)"
    - "completeQueuedWithdrawal() que transfiere el amount registrado sin verificar balance"
    - "totalAssets() que no descuenta rebasing negativo de tokens en queued withdrawals"
    - "Conversion stETH → wstETH y viceversa sin rate actualizado"
  como_se_arregla: |
    Usar wstETH (non-rebasing) internamente. Solo convertir a stETH al momento de withdrawal.
    Si se debe usar stETH: registrar withdrawals en shares (getSharesByPooledEth), no tokens.
    Verificar que el balance es suficiente antes de completar el withdrawal.
    Reserve buffer para cubrir rebases negativos durante el delay.
  trampas:
    - "wstETH NO rebasa — si el protocolo solo usa wstETH, este patron no aplica"
    - "stETH puede tener rounding de 1-2 wei por transferencia — esto es benigno"
    - "El rebase de stETH es ~4% anual, ~0.011% diario — el impacto en 7 dias es ~0.08%"
    - "Para montos grandes ($10M+), 0.08% = $8K — significativo para insolvencia acumulada"
  solodit_ids:
    - "h-05-withdrawals-of-rebasing-tokens-can-lead-to-insolvency-and-unfair-distribution-of-protocol-reserves-code4rena-renzo-renzo-git"
  incidentes:
    - "Renzo (C4 H-05) — Withdrawals de rebasing tokens causan insolvencia y distribucion injusta de reservas"
    - "Multiple Sherlock/C4 findings — protocolos que guardan stETH amounts en vez de shares"
```

---

## 14. Withdrawal Delay Bypass via Delegation Tricks

```yaml
- id: restake-014
  titulo: Bypass del withdrawal delay via undelegation/redelegation o multiple queuing
  causa_raiz: |
    EigenLayer y protocolos similares imponen un withdrawal delay (MIN_WITHDRAWAL_DELAY_BLOCKS)
    para dar tiempo a los slashers de actuar antes de que los fondos salgan del sistema.
    Sin embargo, existen paths alternativos que pueden bypassear este delay:
    - Undelegacion forzada por el operador (no impone delay adicional).
    - Queuing multiples withdrawals antes de un evento de slashing.
    - Strategies con unbonding periods distintos al withdrawal delay del core.
    - Depositar/retirar via un contrato intermediario que no respeta el delay.

    En Karak, los operadores podian spammear requestUpdateVaultStakeInDSS() para
    bypassear el MIN_STAKE_UPDATE_DELAY.
  como_funciona: |
    1. Operador sabe que va a ser slasheado (recibio notificacion privada o vio pending slashing).
    2. Operador llama undelegate() que queue withdrawals para todos los stakers.
    3. El withdrawal delay comienza pero los fondos ya no estan "staked" con el operador.
    4. Cuando el slasher ejecuta, los shares ya no pertenecen al operador → slashing no aplica.
    5. Variante: operador usa requestUpdateVaultStakeInDSS() multiples veces para actualizar
       el stake sin respetar MIN_STAKE_UPDATE_DELAY → reduce stake antes del slashing.
    6. Otra variante: staker delega a operador B, que immediatamente queue withdrawals.
  invariante: |
    // Fondos deben permanecer slashable durante todo el withdrawal delay
    uint256 slashableStake = delegation.getSlashableStake(operator, strategy);
    // Despues de queueWithdrawals:
    uint256 slashableAfterQueue = delegation.getSlashableStake(operator, strategy);
    assert(slashableAfterQueue == slashableStake); // Queue no reduce slashable stake
    // El delay real debe ser >= SLASHING_WINDOW
    assert(withdrawalDelayBlocks >= SLASHING_WINDOW);
  que_mirar:
    - "undelegate() que mueve fondos fuera del scope de slashing inmediatamente"
    - "queueWithdrawals() que reduce operatorShares antes de que el slashing pueda ejecutar"
    - "MIN_STAKE_UPDATE_DELAY bypasseable via repeticion (spam)"
    - "Strategies con unbonding periods < withdrawal delay del core"
    - "Flash-delegation: delegar y desdelegar en el mismo bloque"
  como_se_arregla: |
    Fondos en queued withdrawals DEBEN seguir siendo slashable durante el delay.
    EigenLayer M2: operatorShares no se reducen al queue, solo al complete.
    Enforcar MIN_STAKE_UPDATE_DELAY con timestamp check por operador+DSS.
    Slashing window >= withdrawal delay (window debe cubrir todo el periodo).
  trampas:
    - "EigenLayer M2 ya mitigo esto: queued shares siguen siendo slashable"
    - "El withdrawal delay por si solo no es suficiente si el operador puede undelegarse"
    - "Strategies con delay propio (e.g., Lido 1-5 dias) pueden ser menores que el core delay"
    - "No confundir withdrawal delay del core con lock periods de individual strategies"
  solodit_ids:
    - "m-01-a-staker-with-verified-over-commitment-can-potentially-bypass-slashing-completely-code4rena-eigenlayer-eigenlayer-contest-git"
    - "m-04-delayed-slashing-window-and-lack-of-transparency-for-pending-slashes-could-lead-to-loss-of-funds-code4rena-karak-karak-git"
  incidentes:
    - "EigenLayer (C4 M-01) — Over-committed staker bypasses slashing via timing"
    - "Karak (C4 M-04) — Delayed slashing window + falta de transparencia → perdida de fondos"
    - "Karak (GitHub #89) — Operador bypassea MIN_STAKE_UPDATE_DELAY via spam de requestUpdateVaultStakeInDSS"
```

---

## 15. EigenPod Accounting — Partial vs Full Withdrawals

```yaml
- id: restake-015
  titulo: Accounting incorrecto de partial vs full withdrawals en EigenPod causa perdida o bloqueo de fondos
  causa_raiz: |
    EigenPods manejan dos tipos de retiros de la beacon chain:
    - Partial withdrawals: rewards acumulados (>32 ETH se retiran automaticamente).
    - Full withdrawals: exit completo del validator (toda la stake).

    El protocolo debe distinguir entre ambos para actualizar correctamente los balances.
    Si un partial withdrawal se trata como full (o viceversa), el accounting se rompe:
    - Partial tratado como full: el pod cree que el validator salio, libera toda la stake,
      pero el validator sigue activo → shares fantasma.
    - Full tratado como partial: el pod no libera la stake completa, ETH queda atrapado.

    La distincion se basa en el withdrawalAmount vs un threshold, pero el threshold
    puede ser incorrecto o la condicion puede evaluarse de forma diferente al spec.
  como_funciona: |
    1. Validator con 32.5 ETH recibe partial withdrawal de 0.5 ETH (excess sobre 32).
    2. Pod procesa verifyAndProcessWithdrawals() con 0.5 ETH.
    3. Bug: la condicion para "full withdrawal" es withdrawalAmount >= FULL_WITHDRAWAL_THRESHOLD.
    4. Si FULL_WITHDRAWAL_THRESHOLD esta mal configurado (e.g., 0), TODOS los partial se tratan como full.
    5. Pod marca validator como exited → libera 32.5 ETH de shares.
    6. Pero el validator sigue activo con 32 ETH → discrepancia permanente.
    7. Variante: validator con balance < 32 ETH (slashed) hace full exit.
       Pod usa withdrawalAmount para determinar tipo, pero un exit con 31.5 ETH
       puede caer bajo el threshold y ser tratado como partial.
  invariante: |
    // Post-withdrawal processing:
    if (isFullWithdrawal) {
        // Validator debe estar marcado como WITHDRAWN
        assert(pod.validatorStatus(validatorIndex) == WITHDRAWN);
        // Shares liberados == balance del validator pre-exit
        assert(sharesReleased == validatorBalance);
    } else {
        // Validator sigue activo
        assert(pod.validatorStatus(validatorIndex) == ACTIVE);
        // Solo rewards liberados, no stake principal
        assert(sharesReleased == withdrawalAmount); // Solo el excess
    }
  que_mirar:
    - "Condicion para distinguir partial vs full withdrawal (threshold check)"
    - "FULL_WITHDRAWAL_THRESHOLD constante — valor correcto segun spec de beacon chain"
    - "verifyAndProcessWithdrawals() manejo de ambos cases"
    - "Validator status transition: ACTIVE → WITHDRAWN solo en full withdrawal"
    - "withdrawableRestakedExecutionLayerGwei actualizacion correcta"
    - "L-05 de EigenLayer C4: condicion en codigo diferente a documentacion"
  como_se_arregla: |
    Usar el withdrawal epoch de la beacon chain (no el amount) para distinguir partial vs full.
    FULL_WITHDRAWAL_THRESHOLD = 32 ether (standard para Ethereum mainnet).
    Validar contra el validator exit epoch en la beacon state.
    Double-check: si validator sigue activo post-withdrawal, es partial por definicion.
  trampas:
    - "En la beacon chain, partial withdrawals ocurren automaticamente y son exactamente el excess sobre 32 ETH"
    - "Un validator slashed a 16 ETH que hace full exit puede parecer un partial withdrawal por el amount"
    - "EigenLayer usa una heuristica basada en amount — no es perfecta para validators muy slashed"
    - "El threshold cambio entre versiones de EigenLayer — verificar contra la version actual"
    - "L-07: usuario puede stakear dos veces con las mismas withdrawal credentials, perdiendo fondos"
  solodit_ids:
    - "l-05-the-condition-for-full-withdrawals-in-the-code-is-different-from-that-in-the-documentation-code4rena-eigenlayer-eigenlayer-contest-git"
    - "l-07-user-can-stake-twice-on-beacon-chain-from-same-eipod-thus-losing-funds-due-to-same-withdrawal-credentials-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 L-05) — Condicion para full withdrawals difiere entre codigo y documentacion"
    - "EigenLayer (C4 L-07) — Usuario puede stakear dos veces desde el mismo EigenPod, perdiendo fondos"
    - "EigenLayer (Trail of Bits) — Multiples findings sobre EigenPod accounting edge cases"
```

---

## 16. Points/Airdrop Gaming — Deposit Before Snapshot, Withdraw After

```yaml
- id: restake-016
  titulo: Gaming de puntos/airdrops en protocolos de restaking via depositos temporales alrededor de snapshots
  causa_raiz: |
    Muchos protocolos de restaking (EigenLayer, LRTs) tienen sistemas de puntos
    off-chain o on-chain que otorgan rewards basados en el balance en un momento
    especifico (snapshot). Si no hay lock period o cooldown, un atacante puede:
    depositar justo antes del snapshot (usando flash loans si es posible),
    acumular puntos/rewards, y retirar inmediatamente despues. Esto diluye las
    rewards de los stakers legítimos que mantienen su posicion long-term.

    Variante on-chain: rebase tokens que distribuyen rewards al momento del
    rebase. Flash-stake justo antes del rebase, capturar rewards, retirar.
  como_funciona: |
    1. Protocolo anuncia snapshot para puntos/airdrop en bloque N.
    2. Atacante obtiene flash loan de 10,000 ETH en bloque N-1.
    3. Deposita 10,000 ETH en protocolo → recibe LRT.
    4. En bloque N: snapshot captura el balance del atacante (10,000 LRT).
    5. En bloque N+1: atacante retira 10,000 ETH, repaga flash loan.
    6. Costo: solo gas + flash loan fee (~0.09%). Reward: puntos equivalentes
       a 10,000 ETH de staking legítimo.
    7. Variante temporal: depositar dias antes con capital propio, retirar despues.
       Sin flash loans pero misma dinamica si no hay lock period.
  invariante: |
    // Puntos acumulados deben ser proporcionales al tiempo stakeado, no al balance puntual
    uint256 pointsPerBlock = userBalance * (currentBlock - stakeBlock);
    assert(pointsAccrued[user] == pointsPerBlock);
    // Flash deposits (deposit y withdraw en mismo bloque) no generan puntos
    if (stakeBlock == withdrawBlock) {
        assert(pointsAccrued[user] == 0);
    }
  que_mirar:
    - "Snapshot basado en balanceOf() en un bloque especifico (manipulable)"
    - "Ausencia de lock period o cooldown entre deposit y withdraw"
    - "Puntos que se acumulan por balance instantaneo, no por balance*tiempo"
    - "Flash loan compatible: depositar y retirar en misma tx/bloque"
    - "Airdrop/token distribution basado en snapshot unico (no time-weighted)"
  como_se_arregla: |
    Time-weighted points: balance * duracion, no balance puntual.
    Lock period minimo para acumular puntos (7-30 dias).
    Anti-flash-loan: require(block.number > depositBlock + MIN_BLOCKS).
    Vesting del airdrop proporcional al tiempo stakeado.
    Multiple snapshots con ponderacion temporal.
  trampas:
    - "Si el protocolo tiene withdrawal delay (EigenLayer 7 dias), flash-stake no funciona para 1 bloque"
    - "Pero depositar-retirar en 7 dias sigue siendo viable si los puntos se acumulan por balance"
    - "Los puntos off-chain (backend) no son verificables on-chain — dificil probar gaming"
    - "Algunos protocolos QUIEREN este comportamiento para incrementar TVL temporalmente"
    - "Muchos airdrops usan Merkle proofs post-hoc — el snapshot ya paso y no se puede explotar"
  solodit_ids: []
  incidentes:
    - "EigenLayer Season 1-2 points — Multiples estrategias de gaming documentadas en Twitter/blogs"
    - "Blast (pre-launch) — Depositos masivos pre-airdrop con capital temporal, retiros post-snapshot"
    - "Multiple LRTs — Points farming via LP tokens en DEXs sin staking real"
  confianza: media
```

---

## 17. Operator Set Manipulation — Add/Remove During Active Tasks

```yaml
- id: restake-017
  titulo: Manipulacion del operator set durante tareas de validacion activas causa inconsistencia de quorum
  causa_raiz: |
    En AVS (EigenLayer) y DSS (Karak), los operadores se registran en "operator sets"
    para realizar tareas de validacion. Si un operador puede registrarse o deregistrarse
    mientras hay tareas activas que requieren un quorum especifico, el quorum puede
    romperse o inflarse artificialmente:
    - Deregistracion durante tarea: el quorum cae bajo el threshold → tarea no puede completarse.
    - Registro durante tarea: operador se agrega y vota, inflando quorum artificialmente.
    - Operador malicioso: se registra, vota maliciosamente, se deregistra antes del slashing.

    EigenLayer M2 introduce allocationDelay para mitigar parte de esto.
  como_funciona: |
    1. AVS tiene tarea T con quorum threshold de 67% (2/3 de operadores).
    2. 3 operadores registrados: A, B, C. Quorum requiere 2 firmas.
    3. Operador C se deregistra mientras la tarea T esta activa.
    4. Solo A y B quedan → pero la tarea fue creada con quorum basado en 3 operadores.
    5. Si el quorum check usa operadores ACTUALES: 2/2 = 100% → tarea completa (incorrecto).
    6. Si usa operadores AL MOMENTO DE CREACION: 2/3 = 67% → tarea completa (correcto).
    7. Variante: C se deregistra y re-registra como nuevo operador D (misma entidad).
       D vota de forma opuesta a C → misma entidad tiene dos votos.
  invariante: |
    // El quorum para una tarea debe evaluarse contra el operator set al momento de creacion
    uint256 quorumAtCreation = task.registeredOperators;
    uint256 currentSignatures = task.signatures.length;
    assert(currentSignatures * 100 / quorumAtCreation >= QUORUM_THRESHOLD);
    // Operadores no pueden votar en tareas creadas antes de su registro
    assert(operator.registrationBlock <= task.creationBlock);
  que_mirar:
    - "registerOperatorToAVS() y deregisterOperatorFromAVS() sin lock durante tareas activas"
    - "Quorum check que usa operadores actuales en vez de operadores al momento de la tarea"
    - "Operador que se deregistra y re-registra (nueva identidad, misma entidad)"
    - "allocationDelay y deallocationDelay en EigenLayer M2"
    - "Webhook/callback de deregistracion que puede revertir y bloquear la deregistracion"
  como_se_arregla: |
    Snapshot del operator set al crear cada tarea — evaluar quorum contra snapshot.
    Lock period: operador no puede deregistrarse con tareas activas pendientes.
    allocationDelay para nuevos registros (operador no puede votar inmediatamente).
    Cooldown entre deregistracion y nuevo registro (prevent identity cycling).
  trampas:
    - "EigenLayer M2 introduce allocationDelay pero los AVS deben implementar el snapshot"
    - "Muchos AVS simplemente checkean operadores actuales (vulnerable)"
    - "Karak M-05: slashings fallan en algunos casos por inconsistencia de operator set"
    - "No todos los AVS tienen tareas discretas — algunos son servicios continuos"
  solodit_ids:
    - "m-05-slashings-will-always-fail-in-some-cases-code4rena-karak-karak-git"
  incidentes:
    - "Karak (C4 M-05) — Slashings fallan en algunos casos por inconsistencia de operator state"
    - "Karak (GitHub #21) — Operador puede DoS funcion unregistrationHook del DSS"
    - "Karak (GitHub #94) — Operadores pueden stakear un vault mas de una vez al mismo DSS"
    - "EigenLayer AVS examples — Multiples findings en middleware sobre quorum inconsistencies"
```

---

## 18. calculateTVL Gas Exhaustion con Muchos Operadores/Strategies

```yaml
- id: restake-018
  titulo: calculateTVL() se queda sin gas con numero modesto de operadores y strategies
  causa_raiz: |
    En protocolos de Liquid Restaking, la funcion calculateTVL() itera sobre todos
    los OperatorDelegators y, para cada uno, sobre todas las strategies depositadas.
    Esto es O(operadores * strategies). Si el numero de operadores crece (10+) y cada
    uno tiene multiples strategies (5+), la iteracion puede exceder el gas limit del
    bloque. Como calculateTVL() se llama en deposit() y withdraw() (para calcular
    el exchange rate del LRT), esto causa DoS completo del protocolo.
  como_funciona: |
    1. Protocolo tiene 15 OperatorDelegators, cada uno con 8 strategies.
    2. calculateTVL() itera: 15 * 8 = 120 llamadas externas (cada una ~3K gas + overhead).
    3. Total gas: ~500K-1M gas solo para TVL calculation + resto de la logica de deposit.
    4. Si block gas limit es 30M y hay overhead significativo → tx puede fallar.
    5. En la practica, con rates complejos y oracle calls, el gas puede exceder limites mas bajos.
    6. Resultado: deposit() y withdraw() revertan → protocolo inutilizable.
    7. Atacante puede amplificar: registrar muchos operadores con strategies dummy.
  invariante: |
    // calculateTVL() debe completarse dentro de un gas budget razonable
    uint256 gasBefore = gasleft();
    protocol.calculateTVL();
    uint256 gasUsed = gasBefore - gasleft();
    assert(gasUsed < 5_000_000); // Max 5M gas para TVL calculation
    // Alternativa: cap en numero de operadores/strategies
    assert(operatorDelegators.length <= MAX_OPERATORS);
  que_mirar:
    - "Loops anidados: for(operators) { for(strategies) { ... } }"
    - "calculateTVL() llamado en el hot path (deposit/withdraw/mint/redeem)"
    - "Numero de operadores/strategies sin cap o con cap muy alto"
    - "External calls dentro del loop (oracle.getAssetPrice(), strategy.sharesToUnderlying())"
    - "updateWithdrawalQueue() con loop unbounded (related, Bridge Mutual)"
  como_se_arregla: |
    Cachear TVL y actualizar incrementalmente (no recalcular todo cada vez).
    Cap en numero de operadores y strategies (e.g., max 20 total).
    Lazy evaluation: calcular TVL off-chain y verificar on-chain con proof.
    Paginated calculation con state machine.
  trampas:
    - "En L2 (block gas limit alto), este problema es menos critico"
    - "Con pocos operadores (<5) y pocas strategies (<3), gas no es issue"
    - "El gas de Oracle calls depende del tipo de oracle — Chainlink es barato, TWAP es caro"
    - "No confundir con DoS por logica de negocio (pausable, etc.) vs DoS por gas"
  solodit_ids:
    - "m-05-calculatetvls-may-run-out-of-gas-for-modest-number-of-operators-and-tokens-code4rena-renzo-renzo-git"
  incidentes:
    - "Renzo (C4 M-05) — calculateTVLs puede agotar gas con numero modesto de operadores y tokens"
    - "Renzo (C4 M-01) — Withdrawals fallan por deposits que revertan en completeQueuedWithdrawal"
```

---

## 19. Withdrawal Credential Manipulation en Native Restaking

```yaml
- id: restake-019
  titulo: Validator withdrawal credentials apuntan a contrato incorrecto o son reutilizables
  causa_raiz: |
    En native restaking, cada validator de la beacon chain tiene withdrawal credentials
    (campo de 32 bytes en el deposit data). Para EigenLayer, estas credentials deben
    apuntar al EigenPod del staker. Si un usuario configura withdrawal credentials
    incorrectas (apuntando a un contrato diferente o a una EOA), los ETH del validator
    se enviaran al destino equivocado cuando el validator haga exit.

    Peor aun: si un usuario stakea dos veces desde el mismo EigenPod con las mismas
    withdrawal credentials, el segundo deposito de 32 ETH se pierde porque el
    validator ya existe y la beacon chain no acredita depositos duplicados al mismo
    pubkey (solo incrementa el effective balance existente pero EigenLayer no lo
    trackea correctamente).
  como_funciona: |
    1. Usuario crea EigenPod con address 0xPOD.
    2. Usuario stakea 32 ETH en beacon chain con withdrawal_credentials = 0xPOD. OK.
    3. Usuario stakea OTROS 32 ETH con el MISMO validator pubkey (error o ataque).
    4. Beacon chain ve mismo pubkey → incrementa balance a 64 ETH, pero solo 32 son "effective".
    5. EigenPod solo trackea 1 validator × 32 ETH → 32 ETH "extra" no tienen owner.
    6. Cuando el validator sale: 64 ETH llegan al Pod pero solo 32 tienen shares asignadas.
    7. Los 32 ETH extra quedan en el Pod sin que nadie pueda reclamarlos.
    8. O peor: si el usuario cambio withdrawal_credentials a otro address, todo el ETH va alli.
  invariante: |
    // Cada validator pubkey solo debe tener un deposito registrado en EigenPod
    assert(pod.validatorPubkeyToDeposits(pubkey) == 1);
    // Withdrawal credentials deben apuntar al EigenPod del staker
    bytes32 expectedCredentials = bytes32(uint256(uint160(address(eigenPod)))) | WITHDRAWAL_CREDENTIAL_PREFIX;
    assert(validatorCredentials == expectedCredentials);
  que_mirar:
    - "stake() o activateRestaking() sin verificacion de que pubkey no fue usado antes"
    - "Withdrawal credentials hardcoded vs parametro del usuario"
    - "EigenPod que acepta ETH de validators con credentials incorrectas"
    - "hasRestaked flag que puede togglarse incorrectamente"
    - "verifyWithdrawalCredentials() que acepta proofs para validators ya verificados"
  como_se_arregla: |
    Validar que cada pubkey solo se usa una vez por EigenPod.
    Generar withdrawal credentials automaticamente (no user-supplied).
    Verificar en verifyWithdrawalCredentials() que el validator no fue registrado antes.
    Usar hasRestaked como flag irreversible (solo true → no puede volver a false).
  trampas:
    - "Este es un error de usuario en la mayoria de los casos, no un ataque externo"
    - "La beacon chain SÍ permite depositar multiples veces al mismo pubkey — es by design"
    - "La perdida es limitada al segundo deposito — el primero funciona correctamente"
    - "Post-Shapella, los withdrawal credentials se pueden cambiar una vez (0x00 → 0x01) — complicacion adicional"
    - "EigenPod.hasRestaked es un flag que debe verificarse antes de cualquier operacion"
  solodit_ids:
    - "l-07-user-can-stake-twice-on-beacon-chain-from-same-eipod-thus-losing-funds-due-to-same-withdrawal-credentials-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 L-07) — Usuario puede stakear dos veces desde el mismo EigenPod con mismas withdrawal credentials, perdiendo fondos"
    - "EigenLayer (Trail of Bits) — Multiples findings sobre edge cases de EigenPod credential management"
```

---

## 20. Strategy Maliciosa Causa DoS Permanente en Withdrawals Pendientes

```yaml
- id: restake-020
  titulo: Strategy maliciosa en queued withdrawal causa DoS permanente porque revert bloquea toda la operacion
  causa_raiz: |
    En EigenLayer, cuando un usuario queue un withdrawal que incluye multiples strategies,
    la funcion completeQueuedWithdrawals() itera sobre todas las strategies y llama
    a withdraw() en cada una. Si una de las strategies es maliciosa (revierte siempre),
    toda la operacion de withdrawal falla. Como el withdrawal esta queued y no puede
    ser cancelado, los fondos de TODAS las strategies en ese withdrawal quedan
    permanentemente bloqueados.

    Un operador malicioso puede agregar una strategy que revierte intencionalmente
    para bloquear retiros de todos los stakers delegados a ese operador.
  como_funciona: |
    1. Operador malicioso crea StrategyMaliciosa que revierte en withdraw().
    2. Operador deposita tokens en StrategyMaliciosa (se suma a sus strategies).
    3. Staker delega a este operador.
    4. Staker quiere retirar → llama queueWithdrawals() para todas sus strategies.
    5. El withdrawal incluye: [Strategy1_legítima, Strategy2_legítima, StrategyMaliciosa].
    6. Despues del delay, staker llama completeQueuedWithdrawals().
    7. La funcion itera: Strategy1 OK, Strategy2 OK, StrategyMaliciosa → REVERT.
    8. Toda la tx falla. Los fondos de Strategy1 y Strategy2 quedan bloqueados.
    9. No hay mecanismo para retirar parcialmente o excluir la strategy maliciosa.
  invariante: |
    // Queued withdrawals siempre deben ser completables (no DoS-able)
    // Cada strategy individual debe poder retirarse independientemente
    for (uint i = 0; i < withdrawal.strategies.length; i++) {
        (bool success,) = address(withdrawal.strategies[i]).call(
            abi.encodeWithSignature("withdraw(address,address,uint256)",
                recipient, token, withdrawal.shares[i])
        );
        assert(success); // Si falla, la strategy es maliciosa
    }
  que_mirar:
    - "completeQueuedWithdrawals() sin try/catch por strategy individual"
    - "Loop que procesa todas las strategies atomicamente (todo o nada)"
    - "Operadores que pueden agregar strategies arbitrarias al delegation"
    - "Ausencia de mecanismo para remover strategies de un queued withdrawal"
    - "strategies[i].withdraw() como external call sin error handling"
  como_se_arregla: |
    Usar try/catch para cada strategy individual (fail gracefully).
    Permitir partial completion de withdrawals (completar las strategies que no fallan).
    Whitelist de strategies aprobadas (solo strategies auditadas pueden usarse).
    Implementar emergency withdrawal que bypass individual strategies.
    EigenLayer: indicesToSkip parameter fue el intento de fix (pero tenia bugs — ver restake-002).
  trampas:
    - "EigenLayer ahora tiene whitelist de strategies en StrategyManager — solo strategies aprobadas"
    - "En versiones actuales, operadores no pueden agregar strategies arbitrarias al core"
    - "El indicesToSkip parameter existia para esto pero tenia su propio bug (H-02)"
    - "Si el operador solo puede delegar a strategies whitelisted, el ataque no es posible"
    - "Variante: strategy legítima que empieza a revertir por un bug (no maliciosa pero mismo efecto)"
  solodit_ids:
    - "m-02-a-malicious-strategy-can-permanently-dos-all-currently-pending-withdrawals-that-contain-it-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4 M-02) — Strategy maliciosa causa DoS permanente en todos los queued withdrawals que la contienen"
    - "EigenLayer (C4 H-02) — El fix (indicesToSkip) tenia su propio bug de incremento de loop"
    - "Renzo (C4 H-07) — DoS de completeQueuedWithdrawal cuando el buffer ERC20 esta lleno (variante)"
```

---

## 21. Signature Replay en depositIntoStrategyWithSignature

```yaml
- id: restake-021
  titulo: Replay de signature en deposit con firma permite depositos no autorizados
  causa_raiz: |
    EigenLayer ofrece depositIntoStrategyWithSignature() que permite a un tercero
    depositar en nombre de un staker usando una firma EIP-712. Si la implementacion
    no incluye nonce, chainId, o domain separator correctos, la firma puede ser
    replayed:
    - En otra chain (si chainId no esta en el domain separator).
    - Multiples veces (si no hay nonce incrementing).
    - En otro contrato (si el domain separator no incluye verifyingContract).

    Aunque EigenLayer v1 tenia un nonce, el finding de C4 identifico paths
    donde la proteccion era insuficiente.
  como_funciona: |
    1. Staker firma un mensaje EIP-712 autorizando deposito de 100 tokens en Strategy X.
    2. Relayer ejecuta depositIntoStrategyWithSignature() con la firma → deposito OK.
    3. Bug: el nonce no se incrementa, o la firma no incluye expiry timestamp.
    4. Relayer (o cualquiera que tenga la firma) llama de nuevo con la misma firma.
    5. Segundo deposito de 100 tokens ejecutado sin autorizacion del staker.
    6. El staker pierde el doble de tokens (si tenia allowance/balance suficiente).
    7. Variante cross-chain: firma usada en mainnet se replay en Arbitrum si chainId no esta en la firma.
  invariante: |
    // Nonce debe incrementar despues de cada uso
    uint256 nonceBefore = strategyManager.nonces(staker);
    strategyManager.depositIntoStrategyWithSignature(staker, strategy, token, amount, expiry, signature);
    uint256 nonceAfter = strategyManager.nonces(staker);
    assert(nonceAfter == nonceBefore + 1);
    // Misma firma no puede usarse dos veces
    vm.expectRevert(); // Debe revertir
    strategyManager.depositIntoStrategyWithSignature(staker, strategy, token, amount, expiry, signature);
  que_mirar:
    - "depositIntoStrategyWithSignature sin nonce management"
    - "EIP-712 domain separator sin chainId o verifyingContract"
    - "Firma sin expiry timestamp (nunca expira)"
    - "Nonce shared entre multiples funciones (colision de nonce)"
    - "ecrecover sin verificacion de address(0)"
  como_se_arregla: |
    Incrementar nonce despues de cada uso exitoso de firma.
    Incluir chainId y verifyingContract en EIP-712 domain separator.
    Expiry timestamp obligatorio: require(expiry >= block.timestamp).
    Verificar ecrecover != address(0) (firma invalida).
  trampas:
    - "EigenLayer actual YA tiene nonce management — este finding fue corregido"
    - "La firma requiere que el staker tenga allowance al StrategyManager — sin allowance, replay falla"
    - "En la practica, depositIntoStrategyWithSignature se usa poco (la mayoria usa deposit directo)"
    - "No confundir con signature malleability (s-value) que es un problema separado"
  solodit_ids:
    - "h-01-depositintostrategywithsignature-is-susceptible-to-signature-replay-attack-code4rena-eigenlayer-eigenlayer-contest-git"
  incidentes:
    - "EigenLayer (C4) — depositIntoStrategyWithSignature susceptible a signature replay"
  confianza: media
```

---

## 22. Cross-Strategy Withdrawal Ordering y Unbonding Period Mismatch

```yaml
- id: restake-022
  titulo: Retiro de multiples strategies con unbonding periods distintos causa bloqueo de fondos o inconsistencia
  causa_raiz: |
    Cuando un staker tiene fondos en multiples strategies con diferentes unbonding
    periods (e.g., Strategy A con 7 dias, Strategy B con 21 dias), y hace un withdrawal
    que incluye ambas, el withdrawal delay del core (MIN_WITHDRAWAL_DELAY_BLOCKS) debe
    ser >= al maximo de todos los unbonding periods individuales. Si no, puede completarse
    antes de que una strategy haya procesado su unbonding:
    - Si core delay < strategy B delay: completeQueuedWithdrawal se llama cuando A esta
      ready pero B no → revert.
    - Si se usa el core delay para todo: A esta overdelayed (fondos bloqueados extra).

    Adicionalmente, si un staker retira de strategies con diferentes rates de exchange,
    el rate al momento de queue puede diferir del rate al momento de complete.
  como_funciona: |
    1. Staker tiene: Strategy A (stETH, 7 dias unbonding), Strategy B (custom token, 21 dias unbonding).
    2. Staker llama queueWithdrawals() incluyendo ambas strategies.
    3. Core withdrawal delay = 7 dias (coincide con A pero no con B).
    4. Despues de 7 dias, staker llama completeQueuedWithdrawals().
    5. Strategy A procesa OK. Strategy B: "unbonding not complete" → REVERT.
    6. Todo el withdrawal falla — fondos de Strategy A bloqueados por Strategy B.
    7. Alternativa: si el delay es 21 dias (el max), staker de Strategy A espera 14 dias extra innecesariamente.
    8. Los exchange rates de A y B cambian durante el delay → shares valen distinto al completar.
  invariante: |
    // Withdrawal delay >= max(all strategy unbonding periods)
    for (uint i = 0; i < strategies.length; i++) {
        uint256 stratDelay = strategies[i].unbondingPeriod();
        assert(withdrawalDelayBlocks >= stratDelay);
    }
    // Individual withdrawals deben ser posibles (no solo batch)
    // Withdraw de Strategy A no debe depender de Strategy B
  que_mirar:
    - "queueWithdrawals() que combina strategies con delays distintos en un solo batch"
    - "MIN_WITHDRAWAL_DELAY_BLOCKS < unbonding period de alguna strategy"
    - "completeQueuedWithdrawals() atomico (todo o nada) con strategies heterogeneas"
    - "Exchange rate changes durante el delay que no se reconcilian"
  como_se_arregla: |
    Permitir withdrawals individuales por strategy (no forzar batch).
    Cada strategy tiene su propio completion time: max(coreDelay, strategyDelay).
    Completar parcialmente: las strategies ready se completan, las otras quedan en queue.
    Snapshot del exchange rate al momento de queue (no al momento de complete).
  trampas:
    - "EigenLayer tiene un withdrawal delay uniforme que es >= todos los strategy delays"
    - "En la practica, la mayoria de strategies tienen delay similar (7 dias)"
    - "El exchange rate snapshot es complejo: si el rate baja durante el delay, beneficia al withdrawer"
    - "Strategies con unbonding periods muy largos (>30 dias) son raras en EigenLayer mainnet"
  solodit_ids: []
  incidentes:
    - "Renzo (C4 M-13) — Pending withdrawals previenen remocion segura de collateral assets (related)"
    - "EigenLayer design discussions — Withdrawal delay unification fue decision deliberada de diseno"
  confianza: media
```
