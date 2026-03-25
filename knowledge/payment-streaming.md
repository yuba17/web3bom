# Payment Streaming — Bug Patterns

## Quick Reference

```
grep_targets:
  - createStream
  - createLockupLinear
  - createLockupDynamic
  - createFlow
  - ratePerSecond
  - streamedAmount
  - withdrawableAmount
  - _calculateStreamedAmount
  - snapshotDebt
  - depletionTime
  - cancelStream
  - renounceStream
  - withdrawMax
  - refundableAmountOf
  - ISablierLockup
  - ISablierFlow
  - onStreamCanceled
  - onStreamRenounced
  - FlowStream
  - LockupLinear
  - LockupDynamic
  - ConstantFlowAgreement
  - IDAv1
  - SuperToken
  - flowRate
  - netFlowRate
  - buffer
  - deposit
  - sentinel
  - liquidation
  - cliffTime
  - endTime
  - startTime
  - streamId
  - recipient
  - sender
  - isCancelable
  - wasCanceled
  - transferable
  - protocolFee
  - brokerFee
```

---

## 1. Truncamiento de Rate-Per-Second — Underpayment Acumulado

```yaml
- id: stream-001
  titulo: La division entera al calcular ratePerSecond causa underpayment acumulado sobre duraciones largas
  causa_raiz: |
    Los protocolos de streaming calculan la tasa por segundo como:
    ratePerSecond = totalAmount / duration. Con integer division, el truncamiento
    pierde fracciones. Sobre streams de meses/anios, la diferencia se acumula
    y el recipient recibe significativamente menos de lo pactado.
    Ejemplo: 1000 USDC (6 dec) / 30 dias = 1000e6 / 2592000 = 385 wei/s.
    Real: 385.8024... → se pierden 0.8024 wei/s → ~2.08 USDC perdidos en 30 dias.
    En Sablier Flow, el snapshotDebt acumula el rounding de cada withdraw.
  como_funciona: |
    1. Creador abre stream: 10,000 USDC durante 365 dias.
    2. ratePerSecond = 10000e6 / 31536000 = 317 wei/s (real: 317.097...).
    3. Despues de 365 dias, total streamed = 317 * 31536000 = 9,998,932,000 wei = 9998.93 USDC.
    4. El recipient pierde ~1.07 USDC — retenido permanentemente en el contrato.
    5. Con tokens de 6 decimales (USDC) el efecto es peor que con 18 decimales.
    6. Si el recipient hace withdrawals frecuentes, cada withdraw trunca de nuevo
       y el error se multiplica (N withdrawals * rounding error por withdraw).
  invariante: |
    function check_total_streamed_not_less_than_expected(uint256 streamId) internal view {
        if (stream[streamId].endTime <= block.timestamp) {
            uint256 totalStreamed = stream[streamId].withdrawn + withdrawableAmount(streamId);
            uint256 totalDeposited = stream[streamId].depositAmount;
            // Tolerancia: 1 wei por segundo de duracion
            uint256 tolerance = stream[streamId].endTime - stream[streamId].startTime;
            t(totalDeposited - totalStreamed <= tolerance,
              "STREAM-001: accumulated truncation exceeds tolerance");
        }
    }
  que_mirar:
    - "Calculo de ratePerSecond sin usar UD21x18 o fixed-point de alta precision"
    - "Tokens con pocos decimales (USDC=6, WBTC=8) amplificando el truncamiento"
    - "Logica de ultimo withdraw que NO usa 'liberar todo lo restante' sino que recalcula"
    - "snapshotDebt acumulando rounding en cada operacion de withdraw"
    - "Funcion withdrawMax() que no entrega el deposito completo al final del stream"
  como_se_arregla: |
    - Usar fixed-point de alta precision (UD21x18) para ratePerSecond internamente.
    - En el ultimo withdraw (tiempo >= endTime), entregar depositAmount - totalWithdrawn
      en vez de recalcular con ratePerSecond.
    - Scaling interno a 18 decimales independientemente del token subyacente.
    - En Sablier Flow: el snapshotDebt se actualiza con el ongoing debt escalado.
  trampas:
    - "El error parece insignificante (fracciones de wei) pero se acumula linealmente con el tiempo"
    - "Tokens de 6 decimales (USDC) tienen 1e12 veces mas error relativo que tokens de 18 decimales"
    - "Sablier V2 mitiga parcialmente con UD60x18, pero Sablier Flow usa UD21x18 con uint128"
    - "El 'dust' remanente queda bloqueado en el contrato permanentemente si no hay mecanismo de sweep"
  solodit_ids:
    - "rounding-of-snapshotdebt-will-cause-all-streams-to-be-slightly-underpaid-cantina-none-sablier-pdf"
    - "m-1-unnecessary-precision-loss-in-_recipientbalance-sherlock-nouns-nounsdao-git"
    - "depletiontimeof-can-return-incorrect-time-due-to-unchecked-overflow-cantina-none-sablier-pdf"
  incidentes:
    - "Sablier (Cantina) — rounding de snapshotDebt causa que todos los streams paguen ligeramente de menos"
    - "NounsDAO (Sherlock, M-1) — precision loss innecesaria en _recipientBalance() del streaming de pagos"
    - "Sablier Flow (CodeHawks, H-4) — precision y rounding error en Flow.stream() token streaming calculations"
```

---

## 2. Overflow en Cliff + Linear Streaming con Tiempos Futuros

```yaml
- id: stream-002
  titulo: Overflow aritmetico en _calculateStreamedAmount cuando startTime esta en el futuro o cliff es cero
  causa_raiz: |
    En Sablier V2 Lockup Linear, el calculo del streamed amount usa un bloque unchecked
    para optimizar gas. Si el startTime esta en el futuro, la resta
    (block.timestamp - startTime) produce underflow en unchecked, resultando en un
    valor enorme. Cuando cliffTime es cero (sin cliff), el guard que normalmente
    previene esto no se activa.
  como_funciona: |
    1. Stream creado con startTime = block.timestamp + 1 dia (futuro), cliff = 0.
    2. Alguien llama withdrawableAmount() antes del startTime.
    3. En unchecked { elapsedTime = block.timestamp - startTime } → underflow → uint256.max.
    4. El calculo de streamedAmount produce un valor enorme o reverts inesperados.
    5. Si no reverts, el recipient podria retirar mas de lo depositado.
    Variante: cliff + end time overflow con uint40 — streams creados para 2034+
    causan overflow del timestamp storage.
  invariante: |
    function check_no_withdraw_before_start(uint256 streamId) internal view {
        LockupLinear.Stream memory s = lockup.getStream(streamId);
        if (block.timestamp < s.startTime) {
            uint128 withdrawable = lockup.withdrawableAmountOf(streamId);
            t(withdrawable == 0,
              "STREAM-002: withdrawable > 0 before stream startTime");
        }
    }
  que_mirar:
    - "Bloques unchecked que restan timestamps (block.timestamp - startTime)"
    - "Streams con cliff = 0 donde el guard del cliff no protege contra underflow"
    - "Storage de timestamps en uint40 (overflow en 2034) — Sablier Flow usa uint40"
    - "Funcion _calculateStreamedAmount sin check de startTime <= block.timestamp"
  como_se_arregla: |
    - Retornar 0 si block.timestamp < startTime ANTES del bloque unchecked.
    - Validar en createStream que endTime > cliffTime > startTime (orden estricto).
    - Considerar uint64 para timestamps si el protocolo debe funcionar post-2034.
    - Sablier lo arreglo retornando 0 en _calculateStreamedAmount si startTime > block.timestamp.
  trampas:
    - "El bug solo se manifiesta con streams programados para el futuro Y cliff = 0"
    - "Con cliff > 0, el check 'if timestamp < cliffTime return 0' lo oculta"
    - "uint40 overflow (2034) es un finding Low pero valido — no es un edge case absurdo"
  solodit_ids:
    - "the-overflow-in-the-_calculatestreamedamount-function-can-lead-to-unexpected-results-codehawks-sablier-git"
    - "integer-overflow-allows-the-creation-of-linear-streams-with-an-invalid-cliff-and-end-time-cantina-none-sablier-pdf"
    - "unchecked-calculation-of-a-variable-used-in-an-invariant-check-cantina-none-sablier-pdf"
  incidentes:
    - "Sablier V2.2 (CodeHawks, Medium) — overflow en _calculateStreamedAmount con startTime futuro y cliff=0"
    - "Sablier V2 (Cantina, Low) — integer overflow permite crear linear streams con cliff y endTime invalidos"
```

---

## 3. Cancelacion de Stream Front-Running — Recipient Retira Antes del Cancel

```yaml
- id: stream-003
  titulo: Recipient front-runea la cancelacion del sender para maximizar extraccion
  causa_raiz: |
    En streams cancelables, el sender puede cancelar y recuperar los fondos no
    streamed. El recipient puede monitorear la mempool y ejecutar withdrawMax()
    justo antes del cancel, extrayendo el maximo posible. Tambien el sender
    puede front-runear un squeeze/claim del recipient cancelando primero.
    Ambas direcciones del front-run son problematicas.
  como_funciona: |
    Escenario A (recipient front-runs cancel):
    1. Stream de 100,000 USDC durante 12 meses, 50% transcurrido.
    2. Sender envia tx cancel() a la mempool.
    3. Recipient ve la tx pendiente, envia withdrawMax() con mas gas.
    4. Recipient retira 50,000 USDC. Cancel ejecuta, sender recupera 50,000.
    5. Sin el front-run, recipient habria retirado menos (e.g., 40,000 no retirados previamente).
    → El front-run NO causa perdida directa (el recipient tiene derecho a lo streamed),
    pero si rompe la expectativa del sender de recuperar mas al cancelar.

    Escenario B (sender front-runs squeeze — Drips Protocol):
    1. En Drips, el receiver llama squeeze() para reclamar fondos drippeados.
    2. El sender ve la tx, front-runea con setDrips() cambiando la config.
    3. El squeeze del receiver falla porque la config hash ya no coincide.
    4. El sender puede repetir indefinidamente, bloqueando los claims del receiver.
  invariante: |
    function check_cancel_refund_consistent(uint256 streamId) internal view {
        // Lo que el sender recupera + lo que el recipient recibio = deposito total
        uint128 deposited = stream[streamId].depositAmount;
        uint128 withdrawn = stream[streamId].withdrawn;
        uint128 refunded = stream[streamId].refundedAmount;
        if (stream[streamId].wasCanceled) {
            t(withdrawn + refunded == deposited,
              "STREAM-003: cancel accounting mismatch");
        }
    }
  que_mirar:
    - "Tx de cancel en mempool publica sin proteccion (Flashbots/private tx)"
    - "En Drips: squeeze() depende de un hash que el sender puede cambiar atomicamente"
    - "Protocolos que integran Sablier streams y reaccionan al onStreamCanceled hook"
    - "Falta de commit-reveal o timelock en operaciones de cancel"
  como_se_arregla: |
    - Usar Flashbots/private mempool para tx de cancel (mitigation off-chain).
    - En Drips: no invalidar squeezes pendientes cuando se cambia config.
    - Timelock para cancel: announce cancel → esperar N bloques → execute cancel.
    - En Sablier: el front-run del recipient es "by design" — el recipient tiene derecho a lo streamed.
  trampas:
    - "El front-run del recipient en Sablier NO es un bug per se — solo retira lo que le corresponde"
    - "El front-run del sender en Drips SI es un bug: bloquea fondos que el receiver ya gano"
    - "En chains con mempool privada (Arbitrum), el front-running es menos viable"
    - "Stream creation puede ser front-run por governance subiendo la protocol fee"
  solodit_ids:
    - "m-01-squeezing-drips-from-a-sender-can-be-front-run-and-prevented-by-the-sender-code4rena-drips-protocol-drips-protocol-contest-git"
    - "stream-creation-can-be-front-run-by-governance-increasing-the-protocol-fee-cantina-none-sablier-pdf"
    - "recipient-can-block-the-sender-s-cancel-by-sending-the-nft-to-an-address-known-to-revert-the-transfer-of-the-underlying-erc20-cantina-none-sablier-pdf"
  incidentes:
    - "Drips Protocol (C4, M-01) — sender front-runea squeeze del receiver cambiando drips config"
    - "Sablier V2 (Cantina, Low) — governance front-runea stream creation subiendo protocol fee"
    - "Sablier V2 (Cantina, High) — recipient bloquea cancel enviando NFT a address que revierte ERC20 transfer"
```

---

## 4. NFT-Wrapped Stream — Honeypot en Mercados Secundarios

```yaml
- id: stream-004
  titulo: Stream NFT vendido en marketplace secundario con cancel/withdraw justo antes de la venta
  causa_raiz: |
    Los protocolos como Sablier representan streams como NFTs ERC-721 transferibles.
    El valor del NFT depende de los fondos pendientes de stream. Un atacante puede
    listar el NFT con un valor aparente alto, y justo antes de que se ejecute la
    compra, withdrawMax() o cancel() para vaciar el stream. El comprador recibe
    un NFT sin valor.
  como_funciona: |
    Escenario A — Recipient honeypot:
    1. Recipient tiene un stream de 100,000 USDC con 60,000 pendientes.
    2. Lista el NFT en OpenSea por 55,000 USDC (descuento del ~8%).
    3. Comprador acepta la oferta (tx entra en mempool).
    4. Recipient front-runea con withdrawMax(), retira los 60,000 USDC.
    5. La venta del NFT se ejecuta: comprador paga 55,000 por un stream vacio.

    Escenario B — Sender honeypot:
    1. Sender crea un stream generoso de 500,000 USDC a su propia wallet.
    2. Transfiere el NFT y lo lista en marketplace.
    3. Comprador ve stream con alto valor restante.
    4. Sender front-runea la compra con cancel(), recuperando los fondos no streamed.
    5. Comprador recibe NFT de un stream cancelado con valor minimo.
  invariante: |
    function check_stream_value_matches_nft(uint256 streamId) internal view {
        address nftOwner = lockup.ownerOf(streamId);
        uint128 withdrawable = lockup.withdrawableAmountOf(streamId);
        // No hay invariante on-chain perfecto — la proteccion debe ser en el marketplace
        // Pero el contrato puede exponer: getStreamValue(streamId) para que marketplaces lo usen
    }
  que_mirar:
    - "Streams marcados como 'transferable' Y 'cancelable' — combinacion peligrosa"
    - "Falta de hook o callback que notifique al marketplace del cambio de valor"
    - "ERC-721 metadata que muestra valor del stream sin actualizarse en tiempo real"
    - "Falta de mecanismo de freeze antes de transfer (como un escrow)"
  como_se_arregla: |
    - Marketplaces deben verificar on-chain el valor actual del stream en el mismo tx.
    - Sablier recomienda usar streams non-cancelable para trading en secundarios.
    - Implementar un mecanismo de 'freeze' que bloquea withdraw/cancel durante N bloques post-listing.
    - Los marketplaces podrian implementar checks especificos para Sablier NFTs.
  trampas:
    - "Este es un problema de UX/marketplace mas que del protocolo Sablier en si"
    - "Streams non-cancelable + non-transferable eliminan el riesgo pero reducen utilidad"
    - "El comprador sofisticado puede verificar on-chain antes de comprar, pero bots no lo hacen"
    - "No confundir con el bug de Cantina donde el recipient bloquea cancel — eso es un bug real"
  solodit_ids:
    - "malicious-user-can-honeypot-other-users-to-buy-their-stream-on-an-nft-marketplace-and-cancel-it-right-before-the-purchase-happens-codehawks-sablier-git"
    - "removal-of-trycatch-could-allow-the-recipient-to-make-cancelable-streams-uncancelable-cantina-none-sablier-pdf"
  incidentes:
    - "Sablier V2.2 (CodeHawks, Low) — honeypot en NFT marketplace: cancel/withdraw antes de venta"
    - "Sablier V2 (Cantina, Low) — removal de try/catch permite recipient hacer streams incancelables"
```

---

## 5. Hedgey Finance — Flash Loan + Approval Residual en Token Locking

```yaml
- id: stream-005
  titulo: createLockedCampaign no valida claimLockup — flash loan + approval residual drena $44M
  causa_raiz: |
    En Hedgey Finance, la funcion createLockedCampaign() daba approval al parametro
    claimLockup (tokenLocker) sin validar que fuera un contrato legitimo. Ademas,
    cancelCampaign() retiraba tokens al tokenLocker pero NO revocaba el approval.
    Un atacante podia: (1) flash loan tokens, (2) crear campaña con su propio contrato
    como tokenLocker, (3) cancelar la campaña, (4) usar el approval residual para
    drenar tokens adicionales del contrato.
  como_funciona: |
    1. Atacante toma flash loan de 1.3M USDC de Balancer.
    2. Llama createLockedCampaign() con claimLockup = contrato del atacante.
    3. El contrato de Hedgey da approval de USDC al contrato del atacante.
    4. Atacante llama cancelCampaign() — tokens van al tokenLocker (atacante).
    5. El approval sigue vigente porque cancelCampaign() no lo revoca.
    6. Atacante usa transferFrom() con el approval para drenar USDC adicionales del contrato.
    7. Repaga flash loan. Beneficio neto: $44.7M entre Ethereum ($2.1M) y Arbitrum ($42.6M).
    Tokens drenados: USDC, NOBL, MASA, BONUS.
  invariante: |
    function check_no_residual_approval_after_cancel(address campaign) internal view {
        // Despues de cancelar, el contrato NO debe tener approvals activos a terceros
        uint256 allowance = token.allowance(address(hedgey), campaign.tokenLocker);
        t(allowance == 0,
          "STREAM-005: residual approval after campaign cancel");
    }
  que_mirar:
    - "Funciones que dan approval a parametros controlados por el usuario"
    - "Falta de revoke en flujos de cancel/refund/emergency"
    - "Parametros de tipo address que no se validan contra un whitelist o registry"
    - "Combinacion de flash loan + create + cancel en la misma tx"
    - "Multiples tokens en el mismo contrato amplificando el dano"
  como_se_arregla: |
    - Validar que claimLockup sea un contrato conocido (whitelist/registry).
    - Revocar TODOS los approvals en cancelCampaign() (approve(tokenLocker, 0)).
    - Usar approve exacto (solo la cantidad necesaria) en vez de max approval.
    - Implementar reentrancy guard en create + cancel para evitar atomic exploitation.
  trampas:
    - "El protocolo tenia 3 audits previos (incluyendo Consensys Diligence) — el bug paso desapercibido"
    - "El bug requiere entender la interaccion entre create Y cancel — no es visible analizando funciones aisladas"
    - "Flash loans no son el bug, son el amplificador — el bug real es el approval residual"
    - "Similar a infinite approval bugs en routers DEX, pero en contexto de token locking"
  solodit_ids: []
  incidentes:
    - "Hedgey Finance (Abril 2024, $44.7M) — flash loan + createLockedCampaign sin validar claimLockup + approval no revocado en cancel"
    - "Analisis: Halborn, CertiK, rekt.news. Tokens drenados en Ethereum + Arbitrum en dos transacciones"
```

---

## 6. Superfluid — Buffer Insuficiente y Liquidacion de Flows Criticos

```yaml
- id: stream-006
  titulo: Buffer deposit insuficiente permite streams insolventes que generan tokens de la nada
  causa_raiz: |
    En Superfluid, los streams continuos (CFA — Constant Flow Agreement) requieren un
    buffer deposit para cubrir el periodo entre que un stream se vuelve critico y un
    sentinel lo cierra. Si el buffer es demasiado pequeno, o si el calculo del buffer
    no contempla el netFlowRate correcto, el stream puede volverse insolvente — pagando
    tokens que no existen. El protocolo absorbe el deficit con el stake del PIC
    (Patrician In Charge), pero si el deficit es mayor que el stake, se crean tokens
    sin respaldo.
  como_funciona: |
    1. Usuario abre stream de 1000 DAI/mes con buffer calculado para 4 horas.
    2. El balance del usuario se agota, pero nadie cierra el stream durante 8 horas.
    3. Durante las ultimas 4 horas, el stream paga DAI que el sender no tiene.
    4. El protocolo entra en periodo insolvente: el deficit se resta del PIC stake.
    5. Si el PIC stake es insuficiente, el SuperToken queda sub-colateralizado.
    Variante: Fontaine (Superfluid locker) nunca detiene flows al tax y recipient,
    causando que el buffer se pierda permanentemente.
  invariante: |
    function check_stream_solvency(address account) internal view {
        int96 netFlow = cfa.getNetFlow(superToken, account);
        uint256 balance = superToken.balanceOf(account);
        uint256 buffer = cfa.getDeposit(superToken, account);
        if (netFlow < 0) {
            // Tiempo hasta insolvencia = (balance - buffer) / |netFlow|
            uint256 timeToInsolvency = (balance) / uint96(-netFlow);
            t(timeToInsolvency > 4 hours,
              "STREAM-006: account critically close to insolvency");
        }
    }
  que_mirar:
    - "Calculo de buffer en createFlow — usa el flowRate actual pero no contempla flows futuros"
    - "Sentinels con latencia alta (>4h) en chains con bloques lentos"
    - "Funcion de liquidacion que no se ejecuta si el reward es menor que el gas cost"
    - "Dust streams que el sentinel ignora (buffer < gas cost de liquidacion)"
    - "Fontaine/locker contracts que nunca llaman deleteFlow()"
  como_se_arregla: |
    - Buffer minimo basado en el peor caso de latencia del sentinel.
    - Incentivos de liquidacion que cubran el gas cost (reward = buffer amount).
    - Patron TOGA: Patrician In Charge (PIC) stakea colateral para cubrir insolvencias.
    - Asegurar que contratos derivados (Fontaine, lockers) llamen deleteFlow() en cleanup.
  trampas:
    - "El sistema de PIC/sentinel es off-chain — si ningun sentinel esta activo, la insolvencia crece"
    - "En L2 baratas (Polygon), el gas cost es bajo pero la latencia del sentinel tambien — equilibrio"
    - "El buffer NO se pierde si el stream se cierra a tiempo — solo se pierde en insolvencia"
    - "isPatricianPeriod puede revertir en ciertos edge cases (Goerli issue #149)"
  solodit_ids:
    - "h-3-fontaine-never-stops-the-flows-to-the-tax-and-recipient-so-the-buffer-component-of-the-flows-will-be-lost-sherlock-superfluid-locking-contract-git"
    - "m-5-program-start-failure-due-to-incorrect-buffer-calculation-sherlock-superfluid-locker-system-git"
    - "m-3-incorrect-initial-deposit-calculation-may-cause-cancelprogram-to-revert-sherlock-superfluid-locker-system-git"
  incidentes:
    - "Superfluid Locking Contract (Sherlock, H-3) — Fontaine nunca para flows, buffer component se pierde permanentemente"
    - "Superfluid Locker System (Sherlock, M-5) — buffer calculation incorrecto causa revert al iniciar programa"
    - "Superfluid Locker System (Sherlock, M-3) — initial deposit calculation incorrecto causa revert en cancelProgram"
```

---

## 7. Drips Protocol — Squeeze de Drips Temporales Permite Drenar Fondos

```yaml
- id: stream-007
  titulo: Drip con endTime retroactivo permite squeeze sin depositar fondos — drain del contrato
  causa_raiz: |
    En Drips Protocol, un sender puede crear un drip con timestamps retroactivos
    (startTime en el pasado, endTime antes del momento de creacion pero despues del
    ciclo actual). El drip "termina" antes de ser creado, asi que el sender no necesita
    depositar fondos. Sin embargo, el receiver puede hacer squeeze() del drip y reclamar
    fondos como si el drip hubiera pagado normalmente. Si el receiver es controlado por
    el sender, esto drena fondos del contrato.
  como_funciona: |
    1. Cycle length = 10 segundos. Timestamp actual = segundo 5 del ciclo.
    2. Atacante crea drip: startTime = segundo 0, duration = 2 segundos (endTime = segundo 2).
    3. El drip "existio" del segundo 0 al 2, pero se creo en el segundo 5. Dripped = 0 para el sender.
    4. En el segundo 6, atacante remueve el drip. Balance del sender no cambia (dripped = 0).
    5. Atacante (como receiver) llama squeeze(). El sistema calcula que hubo 2 segundos de drip.
    6. squeeze() entrega fondos del contrato al receiver — fondos de OTROS senders.
    7. Repetir: cada ciclo el atacante drena fondos del pool.
  invariante: |
    function check_drips_conservation(address token) internal view {
        uint256 contractBalance = IERC20(token).balanceOf(address(drips));
        uint256 totalDeposited = drips.totalDeposited(token);
        uint256 totalWithdrawn = drips.totalWithdrawn(token);
        uint256 totalSqueezed = drips.totalSqueezed(token);
        t(contractBalance >= totalDeposited - totalWithdrawn - totalSqueezed,
          "STREAM-007: drips contract undercollateralized");
    }
  que_mirar:
    - "Creacion de drips con timestamps retroactivos (startTime < block.timestamp)"
    - "Diferencia entre 'dripped amount' contabilizado al sender vs 'squeezable amount' del receiver"
    - "Ciclos (cycles) que permiten overlaps temporales entre creacion y fin del drip"
    - "squeeze() que no valida que el drip existiera durante el periodo reclamado"
  como_se_arregla: |
    - Validar que startTime >= block.timestamp al crear un drip.
    - O que el dripped amount para el sender sea >= squeeze amount para el receiver.
    - Trackear la creacion real del drip y solo permitir squeeze despues de ese punto.
    - Solucion de Drips: validar coherencia temporal en setDrips().
  trampas:
    - "El bug requiere entender el concepto de 'cycles' en Drips — no es una timeline lineal"
    - "El squeeze puede ser llamado por cualquiera, no solo el receiver designado"
    - "Similar a un reentrancy temporal: la 'existencia' del drip es retroactiva"
  solodit_ids:
    - "h-01-drips-that-end-after-the-current-cycle-but-before-its-creation-can-allow-users-to-profit-from-squeezing-code4rena-drips-protocol-drips-protocol-contest-git"
    - "m-01-squeezing-drips-from-a-sender-can-be-front-run-and-prevented-by-the-sender-code4rena-drips-protocol-drips-protocol-contest-git"
  incidentes:
    - "Drips Protocol (C4, H-01) — drip retroactivo permite squeeze sin fondos, drenando el contrato"
    - "Drips Protocol (C4, M-01) — sender front-runea squeeze cambiando config de drips"
```

---

## 8. Gas Griefing en Hooks de Stream — Skip de Callbacks

```yaml
- id: stream-008
  titulo: Caller puede omitir hooks (onStreamCanceled) proveyendo gas insuficiente para el callback
  causa_raiz: |
    Sablier V2 permite que contratos recipientes implementen hooks (onStreamCanceled,
    onStreamRenounced) para reaccionar a eventos del stream. Sin embargo, si el caller
    de cancel/withdraw/renounce provee solo el gas justo para la funcion principal pero
    no para el hook, la ejecucion del hook se omite silenciosamente (63/64 rule).
    Esto es critico para integraciones que dependen del hook para actualizar estado.
  como_funciona: |
    1. Protocolo X integra Sablier: usa onStreamCanceled para actualizar rewards.
    2. Fjord Staking: si un stream se cancela, el hook debe reducir el stake amount.
    3. Atacante llama cancel() con gas calculado: suficiente para cancel, insuficiente para hook.
    4. El stream se cancela exitosamente, pero onStreamCanceled NO se ejecuta.
    5. En Fjord: el staker mantiene rewards calculados sobre el monto original (no cancelado).
    6. Resultado: claim de rewards sobre fondos fantasma.
    Regla 63/64: en una CALL, el caller retiene 1/64 del gas. Si el gas restante es
    insuficiente para el hook, falla silenciosamente con try/catch.
  invariante: |
    function check_hook_executed_on_cancel(uint256 streamId) internal {
        // Si el stream fue cancelado Y el recipient es un contrato con hook
        if (stream[streamId].wasCanceled && stream[streamId].recipient.code.length > 0) {
            // El hook debe haberse ejecutado — verificar estado post-hook
            bool hookFired = IStreamRecipient(stream[streamId].recipient).lastHookStreamId() == streamId;
            t(hookFired, "STREAM-008: onStreamCanceled hook was skipped");
        }
    }
  que_mirar:
    - "Uso de try/catch en llamadas a hooks — falla silenciosa si gas insuficiente"
    - "Integraciones que dependen de onStreamCanceled para actualizar staking/rewards"
    - "Regla 63/64: el caller controla cuanto gas se pasa al hook"
    - "Funciones que no requieren que el hook se ejecute exitosamente"
  como_se_arregla: |
    - Sablier V2.2 fix: allowlist de contratos integrados + si hook falla, la tx completa falla.
    - Eliminar try/catch: si el hook revierte, el cancel revierte — el hook es obligatorio.
    - Validar gas minimo antes de llamar al hook: require(gasleft() > MIN_HOOK_GAS).
    - Patron alternativo: separar cancel en dos fases (announce → execute con hook).
  trampas:
    - "La regla 63/64 NO es un bug de Sablier — es un comportamiento de EVM"
    - "Sin try/catch, un hook malicioso puede bloquear TODAS las cancelaciones (DoS inverso)"
    - "El fix de Sablier (allowlist) introduce centralizacion: admin decide quien puede usar hooks"
    - "Fjord tuvo el bug real: rewards full amount despues de cancel parcial"
  solodit_ids:
    - "owner-of-a-cancelled-sablier-stream-will-be-elegible-for-a-full-amount-reward-claim-due-to-a-revert-in-fjordstakingonstreamcanceled-codehawks-fjord-git"
    - "calls-to-untrusted-contracts-on-blast-are-incentivized-to-steal-gas-from-users-cantina-none-sablier-pdf"
  incidentes:
    - "Fjord Staking (CodeHawks, Medium) — onStreamCanceled revierte, staker reclama rewards sobre monto completo de stream cancelado"
    - "Sablier V2 (Cantina, Medium) — en Blast, llamadas a contratos untrusted incentivadas a robar gas de usuarios"
    - "Sablier V2.2 (CodeHawks, Medium) — caller puede skip hook calls con gas insuficiente"
```

---

## 9. Protocol Fee Bypass via Micro-Withdrawals

```yaml
- id: stream-009
  titulo: Withdrawals frecuentes y pequenos hacen que el protocol fee redondee a 0 — fee bypass completo
  causa_raiz: |
    Si el protocol fee se calcula como porcentaje del withdraw amount y se trunca
    (rounding down), un usuario puede hacer muchos withdrawals de montos pequenos
    donde fee = amount * feePercent / PRECISION trunca a 0. El usuario paga 0 fees
    mientras retira gradualmente todo el stream.
  como_funciona: |
    1. Protocol fee = 0.1% (10 bps). Stream de 100,000 USDC.
    2. Fee esperado en un solo withdraw: 100,000 * 10 / 10000 = 100 USDC.
    3. Atacante hace 10,000 withdrawals de 10 USDC cada uno.
    4. Fee por withdraw: 10e6 * 10 / 10000 = 10,000 wei = 0.01 USDC... parece que funciona.
    5. Pero con montos aun mas pequenos: 0.001 USDC = 1000 wei. Fee = 1000 * 10 / 10000 = 1 wei.
    6. Con 0.0001 USDC = 100 wei. Fee = 100 * 10 / 10000 = 0 (truncado).
    7. El atacante retira en chunks de 100 wei, pagando 0 fee por cada uno.
    En Sablier Flow: "protocol fee can be skirted because of default 0 value" — fee
    configuration defaulting to 0 permite bypass completo sin siquiera micro-withdrawals.
  invariante: |
    function check_cumulative_fee_paid(uint256 streamId) internal view {
        uint256 totalWithdrawn = stream[streamId].totalWithdrawn;
        uint256 totalFeePaid = stream[streamId].totalFeePaid;
        uint256 expectedMinFee = totalWithdrawn * protocolFeePercent / FEE_PRECISION;
        // Tolerancia: 1 wei por withdrawal
        uint256 tolerance = stream[streamId].withdrawalCount;
        t(totalFeePaid + tolerance >= expectedMinFee,
          "STREAM-009: cumulative fee significantly below expected");
    }
  que_mirar:
    - "Fee calculation con truncamiento: amount * fee / PRECISION donde el resultado puede ser 0"
    - "Falta de fee minimo por transaccion (e.g., min 1 wei fee)"
    - "Fee config que defaultea a 0 si no se setea explicitamente"
    - "Funciones de withdraw que no acumulan fees sino que los calculan atomicamente"
  como_se_arregla: |
    - Imponer fee minimo por withdraw: if (fee == 0 && amount > 0) fee = 1.
    - Acumular fees off-chain y cobrar en el claim final.
    - Usar rounding UP para fees (roundUp = (amount * fee + PRECISION - 1) / PRECISION).
    - Cobrar fee sobre el total streamed al momento del withdraw, no sobre el delta.
  trampas:
    - "En la practica, el gas cost de micro-withdrawals puede superar el fee ahorrado en L1"
    - "En L2 baratas (Arbitrum, Base), el attack es viable porque el gas es <$0.01"
    - "Sablier Flow tuvo el bug con fee default 0 — ni siquiera necesitaba micro-withdrawals"
    - "No confundir con broker fee (pagado al crear el stream) vs protocol fee (pagado al withdraw)"
  solodit_ids:
    - "it-is-possible-to-avoid-paying-the-protocolfee-codehawks-sablier-flow-git"
    - "protocol-fees-can-be-skirted-because-of-default-0-value-cantina-none-sablier-pdf"
    - "protocol-and-broker-are-overpaid-in-the-event-of-a-canceled-stream-cantina-none-sablier-pdf"
  incidentes:
    - "Sablier Flow (CodeHawks, Low) — posible evitar pagar protocolFee con withdrawals continuos"
    - "Sablier V2 (Cantina, Medium) — protocol fees skirted por default 0 value"
    - "Sablier V2 (Cantina, Medium) — protocol y broker overpaid cuando stream se cancela"
```

---

## 10. Rebasing Tokens en Streams — Balance Subyacente Cambia Sin Notificacion

```yaml
- id: stream-010
  titulo: Tokens rebasing (stETH, aTokens) rompen la contabilidad interna del stream
  causa_raiz: |
    Los protocolos de streaming almacenan depositAmount como un valor fijo al momento
    de crear el stream. Si el token subyacente es rebasing (como stETH que incrementa
    balance con staking rewards, o aTokens de Aave), el balance real del contrato
    cambia sin que el contrato lo registre. El stream puede tener mas (positive rebase)
    o menos (negative rebase/slashing) tokens de lo esperado.
  como_funciona: |
    Escenario A — Positive rebase (fondos bloqueados):
    1. Sender crea stream de 1000 stETH durante 1 anio.
    2. Despues de 1 anio, stETH ha rebaseado +5% → contrato tiene 1050 stETH.
    3. Stream entrega 1000 stETH al recipient. 50 stETH quedan bloqueados en el contrato.
    4. Sin mecanismo de sweep, esos 50 stETH se pierden permanentemente.

    Escenario B — Negative rebase (stream insolvente):
    1. Sender crea stream de 1000 stETH durante 1 anio.
    2. Slashing event: stETH rebases -3% → contrato tiene 970 stETH.
    3. Stream intenta entregar 1000 stETH pero solo hay 970 → ultimos withdrawals fallan.
    4. Recipient pierde 30 stETH o el stream queda en estado stuck.

    Escenario C — Fee-on-transfer (similar):
    1. Sender deposita 1000 tokens FOT (fee 1%) en stream.
    2. Solo 990 tokens llegan al contrato. Stream calcula basado en 1000.
    3. Los ultimos recipients no pueden retirar — contrato insolvente.
  invariante: |
    function check_stream_solvency_rebasing(address token) internal view {
        uint256 contractBalance = IERC20(token).balanceOf(address(streaming));
        uint256 totalCommitted = getTotalCommittedForToken(token);
        t(contractBalance >= totalCommitted,
          "STREAM-010: contract balance < total committed (rebasing or FOT)");
    }
  que_mirar:
    - "depositAmount almacenado como valor fijo sin considerar rebases posteriores"
    - "Tokens aceptados sin whitelist — stETH, aTokens, tokens elasticos"
    - "Falta de wrapper (wstETH en vez de stETH) para eliminar rebasing"
    - "Fee-on-transfer tokens: balance post-transfer != amount especificado"
    - "Falta de mecanismo de sweep/recover para excedentes de rebase positivo"
  como_se_arregla: |
    - Usar wstETH en vez de stETH (wrapper no-rebasing). Mismo patron para aTokens.
    - Verificar balance before/after transfer al depositar: realAmount = balAfter - balBefore.
    - Prohibir tokens rebasing explicitamente en la documentacion y con checks on-chain.
    - Para protocolos que quieran soportar rebasing: trackear shares internamente, no amounts.
  trampas:
    - "stETH es el ejemplo mas comun pero hay muchos tokens rebasing: OHM (positive), AMPL, aTokens"
    - "Sablier V2 NO soporta rebasing tokens oficialmente — es known issue"
    - "El rebase puede ser en ambas direcciones: positive (beneficio bloqueado) y negative (insolvencia)"
    - "Fee-on-transfer causa el mismo tipo de bug pero es detectable al depositar"
  solodit_ids:
    - "fee-on-transfer-and-rebasing-tokens-break-accounting-cyfrin-none-wannabet-markdown"
    - "arithmetic-underflow-in-withdrawerc20-when-there-is-a-negative-rebasing-of-asset-tokens-cyfrin-none-stbl-markdown"
    - "flow-stream-cannot-be-created-for-tokens-that-do-not-implement-the-decimals-function-codehawks-sablier-flow-git"
  incidentes:
    - "LlamaPay V2 (Electisec) — fee-on-transfer tokens causan accounting incorrecto: depositos registran mas de lo real"
    - "WannaBet (Cyfrin) — fee-on-transfer y rebasing tokens rompen contabilidad"
    - "STBL (Cyfrin, Medium) — underflow aritmetico al retirar ERC20 con negative rebasing"
    - "Kelp (C4) — stETH rebasing causa deposits bloqueados y calculo incorrecto de rsETH"
```

---

## 11. Batch Stream Creation — DoS via Dust Streams

```yaml
- id: stream-011
  titulo: Creacion masiva de streams de dust causa DoS en funciones de claim/iterate
  causa_raiz: |
    Si no hay un deposito minimo para crear streams, un atacante puede crear miles
    de streams de 1 wei cada uno hacia un recipient. Cualquier funcion que itere
    sobre los streams activos de ese recipient (claim all, compound, batch withdraw)
    se queda sin gas. Esto es especialmente problematico en protocolos que usan
    streams como mecanismo de governance o staking.
  como_funciona: |
    1. Protocolo usa streams para pagar rewards: un stream por staker.
    2. Funcion claimAll() itera sobre todos los streams del usuario y llama withdraw().
    3. Atacante crea 10,000 streams de 1 wei cada uno al mismo recipient.
    4. claimAll() intenta procesar 10,000 streams → out of gas.
    5. El recipient no puede reclamar sus rewards legitimos porque la funcion siempre revierte.
    Variante: en Drips Protocol, el cycle-based dripping puede acumular entradas que
    hacen la iteracion prohibitivamente cara.
  invariante: |
    function check_claim_gas_bounded(address recipient) internal {
        uint256 gasBefore = gasleft();
        // Simular un claim
        try streaming.claimAll(recipient) {} catch {}
        uint256 gasUsed = gasBefore - gasleft();
        t(gasUsed < 5_000_000,
          "STREAM-011: claimAll gas exceeds safe limit");
    }
  que_mirar:
    - "Funciones que iteran sobre TODOS los streams de un usuario sin limite"
    - "Falta de deposito minimo al crear streams"
    - "Funciones batch (claimAll, withdrawAll, compoundAll) sin paginacion"
    - "Mapping user → streamId[] sin limite de longitud"
    - "Costo de crear un stream vs costo de iterar sobre el"
  como_se_arregla: |
    - Deposito minimo por stream (e.g., 1 USD equivalente).
    - Paginacion en funciones de iteracion: claimAll(uint256 offset, uint256 limit).
    - Permitir que el recipient ignore/rechaze streams de dust.
    - Rate limit en creacion de streams por sender (max N streams por bloque).
  trampas:
    - "En L2 baratas, crear 10,000 streams cuesta <$10 pero el DoS bloquea miles de dolares"
    - "El deposito minimo debe ser lo suficiente para que el gas de iteracion sea cubierto"
    - "Sablier usa streamId incremental (no array por usuario) — mitiga parcialmente este vector"
    - "El bug de Telcoin CouncilMember muestra como un stream que falla causa DoS en todo el contrato"
  solodit_ids:
    - "l-01-unbounded-batch-claim-loop-may-cause-out-of-gas-reverts-in-claimweekly-and-claimjackpot-shieldify-none-onchainheroes-mazeofgains-markdown"
    - "m-1-the-councilmember-contract-dos-due-to-the-_retrieve-function-revert-sherlock-telcoin-platform-audit-git"
    - "m-2-sablier-stream-update-in-councilmembersol-can-cause-loss-of-funds-if-the-streamed-balance-is-not-withdrawn-sherlock-telcoin-platform-audit-git"
  incidentes:
    - "Telcoin (Sherlock, M-1) — CouncilMember DoS porque _retrieve() de un stream revierte y bloquea todo el contrato"
    - "Telcoin (Sherlock, M-2) — update de Sablier stream en CouncilMember causa perdida de fondos si balance no retirado"
    - "OnchainHeroes (Shieldify, L-01) — unbounded batch claim loop causa out-of-gas en claimWeekly"
```

---

## 12. Integracion de Streams con DeFi — Composability Risks

```yaml
- id: stream-012
  titulo: Streams usados como colateral o integrados con staking crean superficies de ataque compuestas
  causa_raiz: |
    Cuando los stream NFTs se usan como colateral para prestamos, o cuando protocolos
    integran Sablier/Superfluid para distribuir rewards de staking, la composicion
    crea nuevos vectores: el valor del stream como colateral cambia en tiempo real,
    la cancelacion del stream puede liquidar posiciones, y los hooks de stream pueden
    interactuar con logica de staking de formas no previstas.
  como_funciona: |
    Escenario A — Stream NFT como colateral:
    1. Protocolo acepta Sablier NFTs como colateral para prestamos.
    2. Stream de 100,000 USDC con 80,000 pendientes → valorado como colateral a 80,000.
    3. Usuario pide prestamo de 60,000 USDC contra el stream NFT.
    4. El sender del stream llama cancel() → el stream ahora vale ~0.
    5. El protocolo de lending tiene una posicion insolvente: 60,000 prestados contra 0 de colateral.

    Escenario B — Staking rewards via stream:
    1. Protocolo distribuye rewards de staking via Sablier streams.
    2. El stream se basa en el monto stakeado al momento de crear el stream.
    3. Usuario unstakea pero el stream sigue pagando rewards al rate original.
    4. Rewards pagados exceden lo que el usuario deberia recibir.

    Escenario C — Flash loan tokens en stream:
    1. Sablier acepta cualquier ERC-20 con high-volume flash minting.
    2. Atacante flash-minta tokens, crea stream, usa el stream NFT como colateral.
    3. Repaga flash mint. El stream tiene tokens sin valor real como respaldo.
  invariante: |
    function check_stream_collateral_value(uint256 streamId) internal view {
        uint128 withdrawable = lockup.withdrawableAmountOf(streamId);
        bool isCancelable = lockup.isCancelable(streamId);
        // Si es cancelable, el valor como colateral debe descontar el riesgo de cancel
        if (isCancelable) {
            // Solo contar lo ya streamed (withdrawable), no el futuro
            t(collateralValue[streamId] <= withdrawable,
              "STREAM-012: collateral value includes uncancelable future");
        }
    }
  que_mirar:
    - "Protocolos que aceptan stream NFTs como colateral sin verificar isCancelable"
    - "Valoracion de stream NFT que incluye fondos futuros (no solo withdrawable)"
    - "Integraciones de staking donde el stream no se actualiza al unstake"
    - "onStreamCanceled hooks que interactuan con logica de lending/liquidation"
    - "Tokens con flash minting usados para crear streams de apariencia valiosa"
  como_se_arregla: |
    - Solo aceptar stream NFTs non-cancelable como colateral.
    - Valorar colateral = withdrawableAmountOf() (ya streamed), no el total futuro.
    - Implementar hook que actualice colateral cuando el stream se cancela.
    - Para staking: actualizar o cancelar stream cuando el usuario cambia su posicion.
    - Whitelist de tokens aceptados para streams en integraciones criticas.
  trampas:
    - "Un stream non-cancelable Y non-transferable no puede usarse como colateral (no se puede transferir al liquidador)"
    - "El valor de un stream non-cancelable es mas predecible pero sigue dependiendo del token subyacente"
    - "Sablier V2 (Cantina, High) — cualquier token con flash minting de alto volumen puede ser robado"
    - "La composability es el vector mas prometedor para findings High en protocolos que integran streaming"
  solodit_ids:
    - "any-token-with-large-volume-flash-minting-capability-can-be-stolen-cantina-none-sablier-pdf"
    - "h-2-wrong-parameter-when-retrieving-causes-a-complete-dos-of-the-protocol-sherlock-telcoin-platform-audit-git"
    - "h-02-tokens-can-be-stolen-when-deposittoken-rewardtoken-code4rena-streaming-protocol-streaming-protocol-contest-git"
  incidentes:
    - "Sablier V2 (Cantina, High) — token con flash minting de alto volumen permite robo de fondos"
    - "Telcoin (Sherlock, H-2) — parametro incorrecto al recuperar stream causa DoS completo"
    - "Streaming Protocol (C4, H-02) — tokens robados cuando depositToken == rewardToken"
    - "Fjord Staking (CodeHawks) — staking rewards basados en stream cancelado"
```

---

## 13. Superfluid — Unlock y Penalty Bypass en Fluid Lockers

```yaml
- id: stream-013
  titulo: Errores matematicos en unlocking percentage permiten bypass de penalidades o fondos stuck
  causa_raiz: |
    Los contratos de FluidLocker de Superfluid calculan un porcentaje de unlock
    basado en el tiempo transcurrido desde el lock. Errores en la formula (division
    antes de multiplicacion, unidades incorrectas, constantes mal escaladas) causan
    que el penalty sea incorrecto: 0% penalty (unlock gratis) o >100% (fondos stuck
    permanentemente por underflow).
  como_funciona: |
    Escenario A — Constante sin unidades (Sherlock H-2):
    1. _getUnlockingPercentage() usa 540 como constante en vez de 540 days.
    2. Con 540 (en segundos) vs 540 days (46656000 segundos), el calculo diverge enormemente.
    3. unlockingPercentage > 100% → operacion de unlock causa underflow → fondos stuck.

    Escenario B — Division antes de multiplicacion (Sherlock M-2):
    1. Formula: result = (a / s) * b en vez de (a * b) / s.
    2. La division primero trunca precision → resultado significativamente menor.
    3. Penalty es mas alto de lo esperado → usuarios pierden tokens injustamente.

    Escenario C — Bypass cuando nadie stakea (Sherlock M-3):
    1. Tax pool tiene 0 stakers → getTotalUnits() == 0.
    2. La division por 0 deberia revertir, pero hay bypass path.
    3. Unlock sin penalty cuando no hay stakers.
  invariante: |
    function check_unlock_percentage_bounded(address locker) internal view {
        uint256 pct = FluidLocker(locker)._getUnlockingPercentage();
        t(pct <= 100e18, "STREAM-013: unlock percentage > 100%");
        t(pct >= 0, "STREAM-013: unlock percentage negative");
    }
  que_mirar:
    - "Constantes temporales sin sufijo 'days/hours' (540 vs 540 days)"
    - "Division antes de multiplicacion en formulas de penalty/unlock"
    - "Edge case: getTotalUnits() == 0 (sin stakers en el pool)"
    - "Formulas con multiples divisiones encadenadas perdiendo precision"
  como_se_arregla: |
    - Usar constantes con unidades explicitas: 540 days, no 540.
    - Multiplicar antes de dividir: (a * b) / c, no (a / c) * b.
    - Handle edge case de pool vacio: if totalUnits == 0, aplicar penalty maximo.
    - Tests con fuzzing sobre la formula de unlock para todo el rango temporal.
  trampas:
    - "540 vs 540 days es un typo que parece trivial pero causa fondos permanentemente stuck"
    - "La formula puede 'funcionar' en tests unitarios con valores convenientes pero fallar en produccion"
    - "El bypass de penalty con 0 stakers es un MEV opportunity: unstake todos → unlock sin penalty → re-stake"
  solodit_ids:
    - "h-2-fluidlocker_getunlockingpercentage-uses-540-instead-of-540-days-leading-to-stuck-funds-as-the-unlocking-percentage-will-be-bigger-than-100-and-underflow-sherlock-superfluid-locking-contract-git"
    - "h-1-fluidlocker_getunlockingpercentage-incorrectly-divides-one-of-the-components-of-the-formula-by-s-leading-to-always-having-80-penalty-sherlock-superfluid-locking-contract-git"
    - "m-2-fluidlocker_getunlockingpercentage-divides-before-multiplying-suffering-a-significant-precision-error-sherlock-superfluid-locking-contract-git"
    - "m-3-a-malicious-user-may-unlock-instantly-all-the-funds-from-the-fluidlocker-when-no-one-is-staking-in-the-tax-pool-sherlock-superfluid-locking-contract-git"
  incidentes:
    - "Superfluid Locking Contract (Sherlock, H-2) — usa 540 en vez de 540 days → unlock% > 100% → underflow → fondos stuck"
    - "Superfluid Locking Contract (Sherlock, H-1) — divide por 's' incorrectamente → siempre 80% penalty"
    - "Superfluid Locking Contract (Sherlock, M-2) — divides before multiplying → precision error significativo"
    - "Superfluid Locking Contract (Sherlock, M-3) — unlock sin penalty cuando 0 stakers en tax pool"
```

---

## 14. Cancelacion de Stream — Accounting de Refund y Overpayment

```yaml
- id: stream-014
  titulo: Cancelacion de stream causa overpayment de protocol/broker fees o accounting inconsistente
  causa_raiz: |
    Cuando un stream se cancela, el sender recupera los fondos no-streamed (refund).
    Si los fees de protocolo/broker se calcularon sobre el deposito total al crear
    el stream, pero parte del deposito se devuelve al cancelar, el fee cobrado
    es proporcionalmente mayor al servicio prestado. Ademas, refundableAmountOf()
    puede retornar un valor incluso cuando isCancelable es false — inconsistencia.
  como_funciona: |
    1. Stream de 100,000 USDC, protocol fee = 1%, broker fee = 0.5%.
    2. Al crear: protocol fee = 1,000 USDC, broker fee = 500 USDC. Deposited = 98,500.
    3. Despues de 10% del tiempo, sender cancela. Solo se streamed 9,850 USDC.
    4. Sender recupera 88,650 USDC (refund).
    5. Protocol fee pagado: 1,000 USDC por solo 9,850 streamed → ~10% fee efectivo.
    6. Si el fee se hubiera calculado solo sobre lo streamed: 98.5 USDC.
    7. Protocol/broker ganaron 1,500 - 148 = 1,352 USDC de mas.
  invariante: |
    function check_fee_proportional_to_streamed(uint256 streamId) internal view {
        if (stream[streamId].wasCanceled) {
            uint128 streamed = stream[streamId].withdrawn;
            uint128 deposited = stream[streamId].depositAmount;
            uint256 feeRate = stream[streamId].protocolFeeRate;
            uint256 expectedMaxFee = streamed * feeRate / FEE_PRECISION;
            uint256 actualFee = stream[streamId].protocolFeePaid;
            t(actualFee <= expectedMaxFee * 2,
              "STREAM-014: fee grossly disproportionate to amount streamed");
        }
    }
  que_mirar:
    - "Fees calculados sobre depositAmount total al crear, sin refund proporcional al cancelar"
    - "refundableAmountOf() retornando valor cuando isCancelable == false"
    - "Falta de fee refund mecanismo en la funcion cancel()"
    - "Broker fee que no se devuelve parcialmente al cancelar"
  como_se_arregla: |
    - Calcular fees proporcionalmente al tiempo transcurrido al momento del cancel.
    - Refund parcial de protocol/broker fees basado en (totalTime - elapsedTime) / totalTime.
    - refundableAmountOf() debe retornar 0 si isCancelable == false.
    - Patron alternativo: cobrar fees al withdraw (no al create).
  trampas:
    - "Sablier V2 cobra fees al crear — es un design choice, no un bug per se"
    - "El overpayment de fees es 'by design' en algunos protocolos (el fee cubre el servicio de crear el stream)"
    - "Para finding Medium+, demostrar que el fee es desproporcionado Y que hay un path explotable"
  solodit_ids:
    - "protocol-and-broker-are-overpaid-in-the-event-of-a-canceled-stream-cantina-none-sablier-pdf"
    - "refundableamountof-will-return-a-value-when-iscancelable-is-false-cantina-none-sablier-pdf"
    - "consider-returning-withdrawn-and-refunded-amounts-for-improved-integrations-cantina-none-sablier-pdf"
  incidentes:
    - "Sablier V2 (Cantina, Medium) — protocol y broker reciben fees excesivos cuando stream se cancela temprano"
    - "Sablier V2 (Cantina, Medium) — refundableAmountOf retorna valor cuando isCancelable es false"
```
