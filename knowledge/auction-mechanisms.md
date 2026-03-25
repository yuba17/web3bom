# Auction Mechanisms — Bug Patterns

## Quick Reference

```
grep_targets:
  - auction
  - bid
  - placeBid
  - cancelBid
  - settleAuction
  - finalizeAuction
  - claimProceeds
  - refundBid
  - dutchAuction
  - englishAuction
  - sealedBid
  - batchAuction
  - clearingPrice
  - reservePrice
  - buyoutPrice
  - minimumBid
  - auctionEndTime
  - timeBuffer
  - auctionDuration
  - startingPrice
  - decayRate
  - priceDecay
  - commit
  - reveal
  - isValidSignature
  - GPv2Settlement
  - onAuctionEnd
  - _settle
  - _payout
  - winningBid
  - highestBid
  - highestBidder
  - lotSize
  - auctionId
  - bidAmount
  - auctionHouse
  - liquidate
```

---

## 1. Dutch Auction Price Curve Manipulation

```yaml
- id: auction-001
  titulo: Manipulación de la curva de precio en subastas holandesas — bid timing exploit
  causa_raiz: |
    En una subasta holandesa, el precio decrece linealmente (o exponencialmente) desde un
    precio alto hasta un precio mínimo. Si el cálculo del precio depende de block.timestamp
    y el minero/validador puede manipular el timestamp dentro del rango permitido (~15s en
    Ethereum), puede forzar que un bid se ejecute a un precio más bajo del esperado. Además,
    si la curva de decaimiento no tiene granularidad suficiente (saltos discretos grandes),
    un bidder puede esperar al borde de un salto para comprar significativamente más barato.
    En protocolos como Chainlink PA v2, la subasta holandesa convierte fees → LINK: si el
    precio decae demasiado rápido, el protocolo vende assets a descuento.
  como_funciona: |
    1. Subasta holandesa inicia a precio P_max con duración D bloques.
    2. Precio actual = P_max - (P_max - P_min) * (block.timestamp - startTime) / D.
    3. Atacante espera hasta que el precio está justo por encima de un "salto" discreto.
    4. Validador manipula timestamp +12s → precio cae al siguiente step.
    5. Atacante compra a precio significativamente menor que el fair value.
    Variante (Cally): si la duración de la subasta es demasiado corta, el precio colapsa
    rápidamente y los assets se venden a una fracción de su valor.
  invariante: |
    // El precio actual de la subasta nunca debe estar por debajo del precio mínimo aceptable
    function check_dutchAuctionPriceFloor() internal view {
        uint256 currentPrice = auction.getCurrentPrice(auctionId);
        uint256 minPrice = auction.getReservePrice(auctionId);
        t(currentPrice >= minPrice, "AUCTION-001: price below reserve");
    }
    // La diferencia de precio entre bloques consecutivos no excede un threshold razonable
    function check_priceGranularity() internal view {
        uint256 priceNow = auction.getCurrentPrice(auctionId);
        // vm.warp(block.timestamp + 12); // simular 1 bloque
        uint256 priceNext = auction.getCurrentPrice(auctionId);
        uint256 diff = priceNow > priceNext ? priceNow - priceNext : 0;
        uint256 maxStepBps = 100; // max 1% por bloque
        t(diff * 10000 / priceNow <= maxStepBps, "AUCTION-001: price step too large");
    }
  que_mirar:
    - Función de cálculo de precio: ¿usa block.timestamp directamente?
    - ¿Hay un precio mínimo (reserve price) que actúa como floor?
    - ¿La curva tiene saltos discretos grandes entre bloques?
    - ¿La duración es configurable? ¿Puede ser demasiado corta?
    - ¿El protocolo vende assets propios (fee conversion)? Si sí, el descuento lo paga el protocolo.
  como_se_arregla: |
    Usar TWAP o precio promedio entre múltiples bloques para suavizar la curva.
    Establecer un reserve price mínimo (floor) que nunca se cruza.
    Granularidad de precio: steps de máximo 0.5-1% entre bloques.
    Duración mínima de la subasta que impida colapso rápido del precio.
  trampas:
    - En L2s (Arbitrum, Optimism) el block.timestamp lo controla el secuenciador — la manipulación de timestamp es MÁS fácil, no menos.
    - Si la subasta tiene suficientes participantes compitiendo, la manipulación de timing tiene poco impacto práctico (competencia natural corrige).
    - No confundir "precio bajo" con "exploit" — en subastas legítimas el precio DEBE bajar. El bug es cuando baja MÁS de lo diseñado.
  solodit_ids:
    - "dutch-auctions-should-be-sold-using-currentprice-cantina-none-kim-exchange-pdf"
    - "h-02-inefficiency-in-the-dutch-auction-due-to-lower-duration-code4rena-cally-cally-contest"
    - "m-26-dutch-auction-can-be-manipulated-code4rena-malt-finance-malt-finance-contest-git"
    - "lack-of-monotonicity-enforcement-in-dutch-auction-rate-bumps-quantstamp-1inch-fusion-markd"
  incidentes:
    - "Cally (C4, H-02) — Dutch auction con duración demasiado corta permite comprar opciones/NFTs muy por debajo de su valor"
    - "Malt Finance (C4, M-26) — Dutch auction manipulable por timing de bids"
    - "1inch Fusion (Quantstamp) — Falta de monotonía en rate bumps de subasta holandesa"
    - "Chainlink PA v2 (C4, 2026) — Dutch auction permissionless para conversión fee→LINK, riesgo de venta a descuento"
```

---

## 2. English Auction Shill Bidding y Last-Block Sniping

```yaml
- id: auction-002
  titulo: Shill bidding y sniping en subastas inglesas — griefing por block stuffing
  causa_raiz: |
    En subastas inglesas, el highest bidder gana al finalizar el período. Un atacante puede:
    (a) Hacer shill bids (bids propios para inflar el precio artificialmente) y cancelar/no pagar.
    (b) Hacer bid sniping en el último bloque usando gas alto para bloquear a competidores.
    (c) En Nouns-style auctions, forzar pause del contrato para congelar fondos.
    Si no hay timeBuffer (extensión automática ante bids tardíos), el sniping es trivial.
    Si el refund mechanism usa push pattern (envía ETH al bidder anterior), un contrato
    malicioso puede revertir la recepción y bloquear la subasta permanentemente.
  como_funciona: |
    Shill bidding:
    1. Seller crea subasta y hace bid desde otra cuenta a precio alto.
    2. Si alguien supera el bid, bien — el precio subió. Si no, el seller "gana" su propia subasta.
    3. Net: el precio se infló artificialmente.

    Last-block sniping:
    1. Atacante monitorea la subasta y espera al último bloque antes de auctionEndTime.
    2. Envía bid con gas price extremo para asegurar inclusión.
    3. Si no hay timeBuffer, la subasta termina inmediatamente con su bid.
    4. Otros bidders no tienen tiempo de responder.

    DoS por refund:
    1. Atacante despliega contrato que revierte en receive()/fallback().
    2. Hace un bid desde ese contrato.
    3. Cuando otro bidder supera el bid, el refund al atacante falla → tx revierte → subasta bloqueada.
  invariante: |
    // La subasta debe extenderse si hay un bid dentro del timeBuffer
    function check_timeBufferExtension(uint256 auctionId) internal view {
        IAuction.AuctionData memory data = auction.getAuction(auctionId);
        if (data.lastBidTime > 0 && data.endTime - data.lastBidTime < data.timeBuffer) {
            t(data.endTime >= data.lastBidTime + data.timeBuffer,
              "AUCTION-002: no time extension after late bid");
        }
    }
    // El refund no puede bloquear nuevos bids (pull pattern check)
    function check_refundDoesNotBlock() internal {
        // Desplegar contrato que revierte en receive()
        // Hacer bid desde ese contrato
        // Hacer bid superior desde otra cuenta
        // Verificar que la tx NO revierte (pull pattern = refund se encola, no se envía inline)
    }
  que_mirar:
    - ¿Existe timeBuffer que extiende la subasta ante bids tardíos?
    - ¿El refund del bidder anterior es push (inline transfer) o pull (withdraw pattern)?
    - ¿Hay límite en número de extensiones? ¿Un atacante puede extender indefinidamente?
    - ¿Hay mecanismo anti-shill (deposit requerido, penalización por no pagar)?
    - ¿El self-bidding está permitido? (seller bideando su propia subasta)
  como_se_arregla: |
    timeBuffer de 5-15 minutos: si hay bid en los últimos N minutos, extender la subasta.
    Pull pattern para refunds: el bidder anterior retira sus fondos, no se le envían automáticamente.
    Anti-shill: el creador de la subasta no puede bidear (o se verifica on-chain).
    Gas limit en refund calls para evitar DoS por contratos maliciosos.
  trampas:
    - El timeBuffer legítimo puede causar subastas que duran indefinidamente si se abusa — necesita cap máximo de extensiones.
    - En Nouns DAO, el timeBuffer es feature principal del diseño. No es un bug, es intencional.
    - Self-bidding on Flooring Protocol fue flaggeado como Medium — pero muchos protocolos lo permiten intencionalmente.
    - Push refunds no siempre son un bug: si el token es ERC20 (no ETH nativo), el transfer raramente revierte.
  solodit_ids:
    - "self-bidding-on-auctions-ottersec-none-flooring-protocol-pdf"
    - "m-02-highest-bid-in-first-auction-can-get-irretrievably-stuck-in-the-protocol-code4rena-nouns-builde"
    - "m-1-attacker-can-force-pause-the-auction-contract-sherlock-nouns-builder-git"
    - "setting-nounsauctionhouses-timebuffer-too-big-is-possible-which-will-freeze-bidders-funds-spearbit-n"
  incidentes:
    - "Nouns Builder (Sherlock, M-1) — atacante puede forzar pause del contrato de subastas"
    - "Nouns Builder (C4, M-02) — highest bid de la primera subasta puede quedarse stuck"
    - "Flooring Protocol (OtterSec) — self-bidding en subastas permite inflación artificial"
    - "Nouns DAO (Spearbit) — timeBuffer excesivo congela fondos de bidders"
```

---

## 3. Sealed-Bid Auction Front-Running — Bypass de Commit-Reveal

```yaml
- id: auction-003
  titulo: Front-running de subastas sealed-bid — bypass del esquema commit-reveal
  causa_raiz: |
    Las subastas sealed-bid usan un esquema commit-reveal: los bidders envían un hash de su
    bid (commit) y luego revelan el bid real (reveal). Si el commit no incluye la dirección
    del bidder o un salt único, un front-runner puede:
    (a) Copiar el hash y submitear como propio.
    (b) Observar la reveal tx en el mempool y front-runearla.
    En Axis Finance (Sherlock), el uso de BN254 para encriptar bids fue inefectivo por
    seguridad insuficiente de la curva elíptica. Si el seller puede desencriptar los bids
    antes del reveal, puede ajustar su reserve price — rompiendo la fairness de la subasta.
  como_funciona: |
    Commit sin address binding:
    1. Bidder A envía commit = keccak256(bidAmount, salt).
    2. Atacante ve el commit en la cadena y copia el mismo hash.
    3. En la fase reveal, atacante front-runea la tx de Bidder A observando el mempool.
    4. Atacante revela primero con el mismo (bidAmount, salt) → se adjudica la subasta.

    Seller desencripta bids (Axis Finance):
    1. Subasta encriptada usa ECIES con BN254.
    2. BN254 tiene <80 bits de seguridad — un atacante con GPU puede romperlo.
    3. Seller desencripta todos los bids antes del reveal.
    4. Seller ajusta reserve price o cancela si los bids son bajos.
  invariante: |
    // El commit debe incluir msg.sender para prevenir replay
    function check_commitIncludesAddress() internal {
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, bidAmount, salt));
        // Verificar que el contrato valida msg.sender en el commit
        t(auction.getCommitment(auctionId, msg.sender) != bytes32(0),
          "AUCTION-003: commitment not bound to sender address");
    }
    // Bidders no pueden ver bids de otros antes del reveal
    // (Verificar que bidAmount no es readable on-chain antes de reveal phase)
  que_mirar:
    - ¿El commitment hash incluye msg.sender?
    - ¿El esquema de encriptación tiene seguridad suficiente (>128 bits)?
    - ¿El seller tiene acceso a la clave de desencriptación antes del reveal?
    - ¿Hay penalty por no revelar (slashing del deposit)?
    - ¿La fase de reveal tiene protección contra front-running (commit-reveal en 2 pasos)?
    - ¿Pueden los bidders enviar bids en claro además de encriptados?
  como_se_arregla: |
    Incluir msg.sender y un nonce único en el commitment hash.
    Usar curvas con >=128 bits de seguridad (BLS12-381, secp256k1) para ECIES.
    Submarine sends o commit-reveal de 3 pasos para ocular totalmente los bids.
    Penalizar no-reveal con slashing del deposit de commitment.
  trampas:
    - En cadenas con mempool público (Ethereum L1), el front-running del reveal es casi inevitable sin protección adicional (Flashbots, private mempool).
    - En L2s con secuenciador centralizado, el front-running NO es posible por MEV público, pero sí por el secuenciador mismo.
    - Muchos protocolos usan commit-reveal "correctamente" pero con salt predecible — eso es igualmente vulnerable.
    - El finding de Axis Finance sobre BN254 fue downgraded a Medium — la seguridad "insuficiente" era debatible.
  solodit_ids:
    - "m-05-sellers-ability-to-decrypt-bids-before-reveal-could-result-in-a-much-higher-cleari"
    - "m-4-users-can-be-grieved-by-not-submitting-the-private-key-sherlock-axis-finance-git"
    - "cancelling-an-auction-refunds-the-wrong-amount-for-unrevealed-offers-sigmaprime-none-term-"
  incidentes:
    - "Axis Finance (Sherlock) — BN254 curve con seguridad insuficiente para ECIES en subasta sealed-bid"
    - "Axis Finance (Sherlock, M-4) — no submitir private key deja a los bidders sin poder reclamar"
    - "Term Finance (Sigmaprime) — cancelar subasta refund monto incorrecto para ofertas no reveladas"
```

---

## 4. Batch Auction — Manipulación del Clearing Price

```yaml
- id: auction-004
  titulo: Manipulación del clearing price en batch/frequent auctions
  causa_raiz: |
    En subastas batch (Gnosis Auction, Axis Finance EMPAM), todos los bids se resuelven a
    un precio uniforme (clearing price). El clearing price se determina por la intersección
    de oferta y demanda. Un atacante puede manipular este precio mediante:
    (a) Submitir muchos bids pequeños para inflar la demanda aparente.
    (b) Submitir un bid enorme que determina el clearing price y luego cancelar.
    (c) Explotar la lógica de settlement cuando hay demasiados bids (gas limit DoS).
    Si el settlement excede el gas limit, la subasta no puede liquidarse y los fondos
    quedan stuck.
  como_funciona: |
    Gas DoS en settlement:
    1. Atacante envía miles de bids pequeños a una batch auction.
    2. Cuando llega el momento de settle, el loop que procesa los bids excede el block gas limit.
    3. La subasta no puede liquidarse → fondos de TODOS los bidders quedan locked.

    Clearing price manipulation:
    1. Atacante observa los bids existentes (si son públicos o desencriptables).
    2. Envía un bid masivo justo por encima del clearing price actual.
    3. El clearing price sube → otros bidders pagan más de lo esperado.
    4. Atacante cancela su bid antes del settlement (si es posible).
  invariante: |
    // Settlement debe completarse dentro del gas limit
    function check_settlementGasLimit(uint256 auctionId) internal {
        uint256 gasBefore = gasleft();
        auction.settle(auctionId);
        uint256 gasUsed = gasBefore - gasleft();
        t(gasUsed < 25_000_000, "AUCTION-004: settlement exceeds reasonable gas");
    }
    // Clearing price no puede divergir excesivamente del price feed externo
    function check_clearingPriceSanity(uint256 auctionId) internal view {
        uint256 clearingPrice = auction.getClearingPrice(auctionId);
        uint256 oraclePrice = oracle.getPrice(baseToken, quoteToken);
        uint256 divergenceBps = clearingPrice > oraclePrice
            ? ((clearingPrice - oraclePrice) * 10000) / oraclePrice
            : ((oraclePrice - clearingPrice) * 10000) / oraclePrice;
        t(divergenceBps <= 1000, "AUCTION-004: clearing price >10% from oracle");
    }
  que_mirar:
    - ¿El settlement loop tiene un número máximo de bids que puede procesar?
    - ¿Existe paginación (settle en batches) para evitar gas limit?
    - ¿Los bids cancelados afectan el clearing price? ¿Se puede cancelar post-deadline?
    - ¿La subasta verifica que el clearing price es "razonable" vs un oracle externo?
    - ¿Hay un costo mínimo por bid para prevenir spam?
  como_se_arregla: |
    Paginación en settlement: procesar máximo N bids por tx, continuar en siguiente tx.
    Costo mínimo por bid (gas deposit) para disuadir spam.
    Snapshot del bid set al cierre — no permitir cancelaciones después del deadline.
    Sanity check del clearing price contra oracle externo con threshold.
  trampas:
    - La paginación introduce complejidad adicional: ¿qué pasa si alguien settle solo parcialmente y abandona?
    - En Gnosis Auction el front-running resistance es BY DESIGN — cuidado con reportar como bug algo que es intencional.
    - Gas DoS en settlement es más viable en L1 Ethereum que en L2s con gas limits más altos.
    - El bid spamming tiene costo (gas por cada tx) — calcular si el ataque es económicamente viable.
  solodit_ids:
    - "m-8-settlement-of-batch-auction-can-exceed-the-gas-limit-sherlock-axis-finance-git"
    - "h-01-bidders-might-fail-to-withdraw-their-unused-funds-after-the-auction-was-finalized-bec"
    - "user-could-cancel-the-rest-of-bids-of-an-auction-by-doing-200-different-bids-halborn-irrigation-prot"
  incidentes:
    - "Axis Finance (Sherlock, M-8) — settlement de batch auction excede gas limit con muchos bids"
    - "Axis Finance (Sherlock, H-1) — Malicious user overtakes prefunded auction, roba fondos depositados"
    - "Irrigation Protocol (Halborn) — 200 bids cancelan el resto de la subasta por gas"
```

---

## 5. EIP-1271 Order Validation TOCTOU — CowSwap/GPv2

```yaml
- id: auction-005
  titulo: EIP-1271 isValidSignature TOCTOU — validación pasa pero estado cambia antes del settlement
  causa_raiz: |
    En protocolos que usan EIP-1271 (isValidSignature) para validar órdenes de smart contract
    wallets (CowSwap/GPv2, 1inch Fusion), hay una ventana TOCTOU (Time-of-Check vs Time-of-Use):
    la firma se valida en un momento pero la orden se ejecuta después, cuando las condiciones
    pueden haber cambiado. Si isValidSignature no incluye la dirección del signer en el hash,
    las firmas son replayables entre wallets del mismo owner. Además, si appData no se verifica,
    un atacante puede modificar el routing para extraer surplus.
  como_funciona: |
    Replay entre wallets:
    1. Usuario posee WalletA y WalletB (ambas con el mismo owner/signer).
    2. Usuario firma orden en WalletA via EIP-1271.
    3. CowSwap no incluye la wallet address en el order struct.
    4. Atacante toma la firma y la submitea como orden de WalletB.
    5. WalletB.isValidSignature() retorna true (mismo owner firma).
    6. Fondos de WalletB se usan para llenar la orden — no autorizado por el usuario.

    AppData tampering:
    1. Orden firmada con isValidSignature que ignora el campo appData.
    2. Atacante modifica appData para cambiar el routing (e.g., agregar su address como surplus recipient).
    3. isValidSignature sigue retornando true — no verifica appData.
    4. El surplus de la orden va al atacante en vez del usuario.
  invariante: |
    // Verificar que isValidSignature incluye msg.sender/address en el hash
    function check_signatureBindsToWallet() internal {
        bytes32 orderHash = GPv2Order.hash(order, domainSeparator);
        // La orden debe incluir la dirección del owner/wallet
        // Si order.receiver == address(0), se usa msg.sender — verificar este comportamiento
        t(order.receiver != address(0) || order.owner == msg.sender,
          "AUCTION-005: order not bound to specific wallet");
    }
    // Verificar que no se pueden replay firmas entre wallets
    function check_noSignatureReplay() internal {
        // Crear dos wallets con el mismo owner
        // Firmar orden desde walletA
        // Intentar submitear desde walletB
        // Debe revertir
    }
  que_mirar:
    - ¿El order struct incluye la dirección del sender/wallet?
    - ¿isValidSignature verifica TODOS los campos del order (incluyendo appData)?
    - ¿Hay protección contra replay entre múltiples wallets del mismo owner?
    - ¿El protocolo usa EIP-712 domain separator que incluye verifyingContract?
    - ¿La orden tiene nonce o timestamp que previene replay temporal?
  como_se_arregla: |
    Incluir la dirección del wallet en el order hash (no solo el signer).
    Verificar TODOS los campos de la orden en isValidSignature, incluyendo appData.
    Usar nonces incrementales por wallet para prevenir replay.
    Campo "signer" en metadata de la API para validar qué wallet autorizó.
  trampas:
    - Safe wallets NO son vulnerables a replay — sus firmas son inherentemente bound al contrato Safe.
    - El impacto real es "stale prices" y "MEV losses", no theft directo de fondos — muchos jueces lo clasifican como Medium, no High.
    - En CowSwap, la API tiene protección adicional off-chain (campo signer en metadata) — el bug on-chain puede no ser explotable en la práctica si la API lo bloquea.
    - EIP-1271 replay afecta 15+ equipos (Alchemy reportó en Oct 2023) — verificar si el protocolo ya aplicó el fix.
  solodit_ids:
    - "trst-l-1-cow-swap-orders-are-seen-as-filled-although-they-are-cancelled-trust-security-non"
    - "transfer-assets-out-of-wallet-using-erc1271-signature-verification-quantstamp-cyan-markdow"
    - "m-02-static-signatures-bound-to-caller-revert-under-erc-4337-causing-dos-code4rena-sequenc"
  incidentes:
    - "CowSwap/GPv2 (Alchemy, Oct 2023) — ERC-1271 signature replay entre wallets del mismo owner, ~15 equipos afectados"
    - "Cyan (Quantstamp) — transferencia de assets via verificación de firma ERC1271"
    - "Sequence (C4, M-02) — firmas estáticas bound a caller revert bajo ERC-4337"
```

---

## 6. Auction Settlement Race Conditions — Dual Settlement Paths

```yaml
- id: auction-006
  titulo: Race condition entre rutas de settlement — bid directo vs DEX vs CowSwap compitiendo por los mismos tokens
  causa_raiz: |
    Cuando una subasta tiene múltiples rutas de settlement (e.g., bid directo on-chain +
    settlement via CowSwap/DEX solver), los tokens aprobados para la subasta pueden ser
    consumidos por una ruta antes de que la otra se ejecute. En Chainlink PA, el approval
    al contrato de CowSwap se hace al inicio de la subasta, pero si alguien bidea directamente,
    los tokens se transfieren inmediatamente — dejando el approval de CowSwap sin fondos detrás.
    El resultado: tokens "fantasma" aprobados pero no disponibles, o doble-spending si ambas
    rutas se ejecutan simultáneamente.
  como_funciona: |
    1. Subasta inicia: contrato aprueba tokenAmount al CowSwap GPv2Settlement.
    2. Solver de CowSwap encuentra una ruta y prepara settlement tx.
    3. Antes de que el solver submitee, un bidder directo llama bid() y transfiere los tokens.
    4. Solver de CowSwap intenta ejecutar settlement → falla porque los tokens ya se transfirieron.
    5. O peor: si hay tokens adicionales depositados entre medias, CowSwap consume tokens
       que NO pertenecían a esta subasta.

    Variante (balance-based accounting):
    1. Contrato usa balanceOf para determinar cuántos tokens tiene para subastar.
    2. Alguien deposita tokens directamente al contrato (donation).
    3. La subasta "ve" más tokens de los que debería → approval mismatch → tokens extra
       se quedan stuck o se subastan gratuitamente.
  invariante: |
    // Pre/post balance check en settlement
    function check_settlementBalanceConsistency() internal {
        uint256 balanceBefore = token.balanceOf(address(auction));
        auction.settle(auctionId);
        uint256 balanceAfter = token.balanceOf(address(auction));
        // El balance debe decrementar exactamente por el monto subastado
        uint256 auctionedAmount = auction.getAuctionedAmount(auctionId);
        t(balanceBefore - balanceAfter == auctionedAmount,
          "AUCTION-006: settlement moved wrong amount");
    }
    // No debe haber approval residual después del settlement
    function check_noResidualApproval() internal {
        auction.settle(auctionId);
        uint256 remaining = token.allowance(address(auction), cowSwapSettlement);
        t(remaining == 0, "AUCTION-006: residual approval after settlement");
    }
  que_mirar:
    - ¿Cuántas rutas de settlement existen? ¿Pueden competir entre sí?
    - ¿El contrato usa balance-based accounting o internal accounting?
    - ¿Los approvals se revocan después del settlement?
    - ¿Qué pasa si se depositan tokens entre el inicio y el fin de la subasta?
    - ¿Hay mutex/lock que previene settlement paralelo?
  como_se_arregla: |
    Internal accounting: trackear auctionedAmount explícitamente, no confiar en balanceOf.
    Mutex entre rutas de settlement: solo una puede ejecutarse, la primera que llegue.
    Revocar approvals inmediatamente después del settlement (approve(0)).
    Snapshot del balance al inicio de la subasta, ignorar deposits posteriores.
  trampas:
    - En Chainlink PA v1, el balance-based approach es documentado como known issue — no es reportable si está en el scope de known issues.
    - CowSwap solvers operan off-chain — la race condition solo se materializa si un solver y un bidder directo actúan en el mismo bloque.
    - Si el protocolo SOLO tiene una ruta de settlement, esta categoría no aplica.
    - Approval residual post-settlement es a menudo Low/QA, no High, a menos que haya un exploit concreto.
  solodit_ids:
    - "m-08-settleauction-may-be-impossible-if-locked-at-a-wrong-time-code4rena-kuiper-kuiper-con"
    - "h-01-bonding-mechanism-allows-malicious-user-to-dos-auctions-code4rena-kuiper-kuiper-conte"
  incidentes:
    - "Chainlink PA v1 (C4, 2024) — balance-based accounting permite que deposits directos interfieran con la subasta"
    - "Kuiper (C4, H-01) — bonding mechanism permite DoS de subastas; settlement bloqueado"
    - "Kuiper (C4, M-08) — settleAuction imposible si locked en momento incorrecto"
```

---

## 7. Reserve Price / Minimum Bid Bypass

```yaml
- id: auction-007
  titulo: Bypass del reserve price o minimum bid — edge cases en validación de monto mínimo
  causa_raiz: |
    Las subastas tienen un precio mínimo (reserve price) para proteger al vendedor. Si la
    validación es incorrecta (off-by-one, truncamiento por decimales, token con deflation),
    un bidder puede ganar la subasta pagando menos del mínimo. En subastas con buyout price,
    si no se valida que el bid sea <= buyoutPrice, un atacante puede hacer un bid mayor al
    buyout y explotar la lógica de payout para drenar fondos. ThirdWeb Marketplace V3 tuvo
    exactamente este bug: bid > buyoutPrice permitía drain de todo el marketplace.
  como_funciona: |
    Buyout price exploit (ThirdWeb):
    1. Marketplace tiene subastas con buyoutPrice = 100 ETH.
    2. Atacante bidea 200 ETH (> buyoutPrice). Contrato no valida.
    3. La subasta se cierra inmediatamente. El payout usa _winningBid.bidAmount (200 ETH).
    4. Pero el atacante solo deposita 200 ETH. Al reclamar, el payout repite N veces.
    5. Atacante drena TODOS los fondos de esa currency del marketplace.

    Reserve price truncation:
    1. Reserve price = 1000 (en tokens con 6 decimales = 0.001 USDC).
    2. Bid amount = 999. La comparación bid >= reserve falla... en teoría.
    3. Si hay un cálculo intermedio con rounding down, 999 * X / Y puede redondear a >= 1000.
    4. El bid pasa la validación a pesar de ser inferior al reserve.
  invariante: |
    // Verificar que NO se puede bidear por encima del buyout price
    function check_bidNotAboveBuyout(uint256 auctionId) internal {
        uint256 buyoutPrice = auction.getBuyoutPrice(auctionId);
        if (buyoutPrice > 0) {
            // Intentar bid con buyoutPrice + 1
            try auction.bid{value: buyoutPrice + 1}(auctionId) {
                t(false, "AUCTION-007: bid above buyout price accepted");
            } catch {}
        }
    }
    // Verificar que bids por debajo del reserve se rechazan
    function check_reservePriceEnforced(uint256 auctionId) internal {
        uint256 reservePrice = auction.getReservePrice(auctionId);
        try auction.bid{value: reservePrice - 1}(auctionId) {
            t(false, "AUCTION-007: bid below reserve price accepted");
        } catch {}
    }
  que_mirar:
    - ¿Se valida bid <= buyoutPrice antes de aceptar?
    - ¿El reserve price se valida con >= o solo >?
    - ¿Hay cálculos intermedios que puedan redondear el bid amount?
    - ¿El reserve price se aplica al primer bid Y a bids subsiguientes?
    - ¿Tokens con distintos decimales causan problemas en la comparación?
    - ¿Se puede modificar el reserve durante una subasta activa?
  como_se_arregla: |
    Revertir si bidAmount > buyoutPrice (ThirdWeb fix).
    Usar >= estricto para reserve price en todas las comparaciones.
    No permitir cambio de reserve price durante subasta activa.
    Sanitizar bid amounts normalizando a la misma precisión decimal.
  trampas:
    - No reportar "reserve price not fully taken care of" como High — en Nouns DAO esto fue Low porque el impacto era marginal (off-by-one en un edge case).
    - El bug de ThirdWeb fue CRITICAL porque permitía drain de todo el marketplace, no solo de una subasta.
    - Verificar si el buyoutPrice == 0 significa "no buyout" o "buyout at zero" — semántica ambigua.
  solodit_ids:
    - "01-reserve-price-not-fully-taken-care-of-code4rena-nouns-dao-nouns-dao-git"
    - "dutch-auctions-can-be-used-to-drain-honest-buyers-escrowed-funds-from-the-market-cantina-n"
    - "m-20-user-can-cancel-or-modify-dutch-auctions-compromising-market-integrity-and-user-trust"
  incidentes:
    - "ThirdWeb Marketplace V3 (Sep 2023) — bid > buyoutPrice permite drain de todos los fondos del marketplace. 6 marketplaces comprometidos, 0 explotados en mainnet."
    - "Nouns DAO (C4, Low) — reserve price no validado correctamente en edge case"
    - "Kim Exchange (Cantina) — dutch auction drena fondos de compradores honestos"
```

---

## 8. Auction Duration Manipulation — Terminación Prematura o Extensión Infinita

```yaml
- id: auction-008
  titulo: Manipulación de la duración de la subasta — terminación prematura o extensión indefinida
  causa_raiz: |
    La duración de una subasta puede ser manipulada si: (a) un admin/owner puede cambiar
    auctionDuration durante una subasta activa, afectando retroactivamente subastas en curso;
    (b) la lógica de extensión (timeBuffer) no tiene cap, permitiendo extensión indefinida;
    (c) el balance/colateral puede ser drenado forzando una terminación prematura.
    En el caso de AkuDreams, la condición de terminación dependía de que el número de bids
    igualara el número de NFTs, pero como se podían comprar múltiples NFTs en un solo bid,
    la condición nunca se cumplía → $34M de ETH locked para siempre.
  como_funciona: |
    Cambio retroactivo de duración (BendDAO):
    1. Admin cambia auctionDuration de 48h a 12h.
    2. Subastas en curso que tenían 48h ahora tienen 12h.
    3. Bidders que esperaban tener más tiempo pierden la oportunidad de bidear.
    4. Subasta se cierra prematuramente a precio subóptimo.

    Extensión infinita:
    1. Atacante hace bids repetidos justo antes del deadline.
    2. Cada bid extiende la subasta por timeBuffer minutos.
    3. Sin cap en extensiones, la subasta nunca termina.
    4. Fondos de todos los bidders quedan locked indefinidamente.

    AkuDreams lock:
    1. Subasta dutch con 5,495 NFTs.
    2. processRefunds() requiere que totalBids == totalNFTs.
    3. Algunos bidders mintean múltiples NFTs por bid → totalBids < totalNFTs.
    4. Condición nunca se cumple → withdrawAll() bloqueado → $34M stuck.
  invariante: |
    // Cambios de duration no afectan subastas activas
    function check_durationChangeNotRetroactive(uint256 auctionId) internal {
        uint256 endTimeBefore = auction.getEndTime(auctionId);
        // Simular admin cambiando duration
        auction.setDuration(newDuration);
        uint256 endTimeAfter = auction.getEndTime(auctionId);
        t(endTimeBefore == endTimeAfter,
          "AUCTION-008: duration change affected active auction");
    }
    // Extensiones tienen un cap máximo
    function check_extensionCap(uint256 auctionId) internal view {
        uint256 originalEnd = auction.getOriginalEndTime(auctionId);
        uint256 currentEnd = auction.getEndTime(auctionId);
        uint256 maxExtension = 24 hours; // cap razonable
        t(currentEnd <= originalEnd + maxExtension,
          "AUCTION-008: auction extended beyond max cap");
    }
  que_mirar:
    - ¿Los parámetros de duración pueden cambiarse durante subastas activas?
    - ¿Las extensiones por timeBuffer tienen un cap máximo?
    - ¿La condición de terminación depende de estado externo manipulable?
    - ¿Qué pasa si la condición de terminación nunca se cumple?
    - ¿El withdraw/refund depende de que la subasta termine correctamente?
  como_se_arregla: |
    Snapshot de parámetros al crear la subasta — no usar parámetros globales para subastas activas.
    Cap máximo de extensiones (e.g., 24-48h adicionales máximo).
    Fallback para terminación forzada si pasa X tiempo del deadline original.
    Separar condición de terminación de condición de withdraw.
  trampas:
    - AkuDreams no fue un "hack" en el sentido tradicional — fue un bug de lógica que nadie explotó maliciosamente. Pero el resultado ($34M locked forever) fue peor que muchos hacks.
    - El timeBuffer de Nouns (5 min) es intencional y funciona bien — no reportar como bug.
    - Verificar si el admin puede realmente cambiar parámetros durante subastas activas antes de reportar — muchos protocolos ya previenen esto con un check.
  solodit_ids:
    - "m-17-changing-auction-duration-will-have-effect-on-ongoing-auctions-code4rena-benddao-bend"
    - "m-5-extension-logic-incorrectly-extends-the-auction-by-an-additional-amount-of-existing-du"
    - "disallow-bidding-after-auction-duration-ends-ottersec-none-mythos-studios-pdf"
    - "if-auction-time-is-reduced-withdrawproxy-can-lock-funds-from-final-auctions-spearbit-astaria-pdf"
  incidentes:
    - "AkuDreams (Abril 2022) — $34M de ETH locked para siempre por bug en condición de terminación de dutch auction"
    - "BendDAO (C4, M-17) — cambio de auction duration afecta subastas en curso"
    - "Astaria (Spearbit) — reducción de auction time bloquea fondos en withdrawProxy"
    - "Mythos Studios (OtterSec) — bidding permitido después de que la subasta termina"
```

---

## 9. Flash Loan Auction Participation

```yaml
- id: auction-009
  titulo: Flash loans para manipular subastas — capital prestado distorsiona resultados
  causa_raiz: |
    Un atacante puede usar flash loans para participar en subastas con capital que no posee,
    manipulando el resultado y devolviendo el préstamo en la misma transacción. Esto es
    especialmente peligroso en subastas de liquidación (MakerDAO Black Thursday) donde el
    atacante puede ser el único bidder por condiciones de red (gas wars), y en subastas que
    determinan parámetros del protocolo (governance, interest rates) donde un bid temporal
    masivo puede cambiar el resultado.
  como_funciona: |
    Flash loan + liquidation auction:
    1. Posición underwater necesita liquidarse. Subasta de colateral inicia.
    2. Atacante toma flash loan de DAI.
    3. Bidea en la subasta con todo el DAI — gana por ser el único/más grande.
    4. Recibe colateral (ETH) a precio de descuento.
    5. Vende parte del ETH en DEX para repagar flash loan + fee.
    6. Net: adquirió ETH a descuento significativo sin capital propio.

    MakerDAO Black Thursday:
    1. Gas prices se disparan 10x. Keeper bots con gas fijo se quedan en mempool.
    2. Un bot envía bids de 0 DAI (zero-bid) con gas price alto.
    3. Sin competencia (otros bots no pueden operar), gana 1,000+ subastas a precio 0.
    4. Resultado: $8.32M en ETH adquirido por 0 DAI.
  invariante: |
    // El bid amount debe ser significativo respecto al valor del colateral
    function check_bidMinimumRelativeToValue(uint256 auctionId) internal view {
        uint256 bidAmount = auction.getHighestBid(auctionId);
        uint256 collateralValue = oracle.getPrice(collateralToken) * auction.getLotSize(auctionId) / 1e18;
        // El bid debe ser al menos 50% del valor del colateral
        uint256 minBidPct = 5000; // 50%
        t(bidAmount * 10000 / collateralValue >= minBidPct,
          "AUCTION-009: bid too low relative to collateral value");
    }
    // Verificar que el bidder tiene balance ANTES de la transacción (anti-flash-loan)
    // Nota: esto es difícil de verificar on-chain; alternativa es requerir pre-deposit
    function check_bidderHasBalance() internal view {
        // El bidder debe tener los fondos depositados ANTES del bloque de la subasta
        // Implementar con snapshot de balance en bloque anterior
    }
  que_mirar:
    - ¿La subasta requiere que los fondos estén pre-depositados (no permita bidding en la misma tx)?
    - ¿Hay un minimum bid relativo al valor del colateral?
    - ¿El mecanismo de liquidación tiene un "floor price" por debajo del cual no se acepta bid?
    - ¿La subasta puede funcionar con un solo bidder?
    - ¿Hay keeper incentives suficientes para asegurar competencia?
  como_se_arregla: |
    Minimum bid de 50-70% del valor oráculo del colateral.
    Requerir pre-deposit: fondos deben estar en el contrato al menos 1 bloque antes del bid.
    Liquidation incentives: keeper reward + discount suficiente para atraer competencia.
    Circuit breaker: si gas > threshold, pausar liquidaciones o extender duración.
  trampas:
    - Flash loans para liquidación son LEGÍTIMOS en la mayoría de protocolos modernos (Aave, Compound) — el flash loan es la herramienta, no el bug. El bug es la falta de minimum bid.
    - MakerDAO Black Thursday fue un evento de red extremo, no un bug de smart contract per se — pero la falta de minimum bid SÍ fue un fallo de diseño.
    - Pre-deposit requirement hace la subasta menos eficiente — hay trade-off legítimo.
    - Verificar si el protocolo ya tiene protección post-Black-Thursday (MakerDAO v2 tiene circuit breakers).
  solodit_ids:
    - "h-2-attacker-can-deposit-after-the-keeper-reports-a-loss-but-before-the-collateral-auction-to-steal-from-other-depositors-sherlock-yearn-ybold-git"
    - "m-8-malicious-users-can-donateleave-dust-amounts-of-collateral-in-contract-during-auctions-to-buy-ot"
  incidentes:
    - "MakerDAO Black Thursday (Marzo 2020) — $8.32M en ETH adquirido por 0 DAI en 1,000+ zero-bid auctions"
    - "Yearn yBOLD (Sherlock, H-2) — atacante deposita después de loss report pero antes de collateral auction para robar a otros depositantes"
    - "Euler Finance (2023) — flash loan de $30M usado para manipulación de préstamos ($197M perdidos, no subasta directa pero mecánica similar)"
```

---

## 10. Fee-on-Transfer Tokens en Subastas

```yaml
- id: auction-010
  titulo: Tokens con fee-on-transfer rompen accounting de subastas
  causa_raiz: |
    Algunos tokens ERC20 cobran una comisión en cada transfer (e.g., USDT puede activar fee,
    STA, PAXG). Si un contrato de subasta asume que transferAmount == receivedAmount, la
    contabilidad interna se descuadra. El contrato registra más tokens de los que realmente
    tiene, lo que puede causar:
    (a) El último bidder/claimer no puede retirar porque no hay fondos suficientes.
    (b) El seller recibe menos de lo esperado.
    (c) El clearing price se calcula sobre montos incorrectos.
  como_funciona: |
    1. Subasta acepta TokenX que cobra 2% fee on transfer.
    2. Bidder envía 100 TokenX como bid. Contrato registra bid = 100.
    3. Contrato realmente recibe 98 TokenX (100 - 2% fee).
    4. Bidder gana la subasta. Seller intenta clamar 100 TokenX.
    5. Contrato solo tiene 98 → tx revierte o seller recibe menos.

    Variante con múltiples bids:
    1. 10 bidders cada uno envía 100 TokenX (1000 total registrado).
    2. Contrato recibe 980 TokenX (20 perdidos en fees).
    3. Al settlear, el contrato intenta distribuir 1000 → underflow/revert.
    4. Refunds parciales fallan: los últimos en reclamar no reciben nada.
  invariante: |
    // Balance real del contrato debe ser >= la suma de bids registrados
    function check_balanceMatchesAccounting() internal view {
        uint256 contractBalance = bidToken.balanceOf(address(auction));
        uint256 totalBidsRecorded = auction.getTotalBidsValue();
        t(contractBalance >= totalBidsRecorded,
          "AUCTION-010: contract balance less than recorded bids");
    }
    // Pre/post balance check en cada bid
    function check_bidRecordsActualReceived() internal {
        uint256 balBefore = bidToken.balanceOf(address(auction));
        auction.bid(auctionId, bidAmount);
        uint256 balAfter = bidToken.balanceOf(address(auction));
        uint256 actualReceived = balAfter - balBefore;
        uint256 recordedBid = auction.getLatestBidAmount(auctionId);
        t(recordedBid == actualReceived,
          "AUCTION-010: recorded bid != actual tokens received");
    }
  que_mirar:
    - ¿El contrato mide el balance pre/post transfer para determinar el monto real recibido?
    - ¿Hay una whitelist de tokens aceptados que excluye fee-on-transfer?
    - ¿Los refunds devuelven el monto registrado o el monto real?
    - ¿El settlement calcula payouts basado en registros internos o balance real?
  como_se_arregla: |
    Medir balance antes y después del transfer: actualReceived = balAfter - balBefore.
    Registrar actualReceived, no el amount del argumento.
    O mantener una whitelist de tokens que NO cobran fee.
    Revertir si actualReceived < amount * (1 - maxToleranceBps).
  trampas:
    - USDT actualmente NO cobra fee on transfer, pero tiene la capacidad de activarlo — esto es un riesgo teórico, no un bug actual. Muchos jueces lo clasifican como Low/QA.
    - La mayoría de tokens mainstream (USDC, DAI, WETH) no tienen fee on transfer — el impacto real es limitado a tokens exóticos.
    - Si el protocolo documenta explícitamente que no soporta fee-on-transfer tokens, NO es reportable.
    - Verificar si el scope del bounty incluye "all ERC20s" o solo tokens específicos.
  solodit_ids:
    - "lps-3-fee-on-transfer-tokens-guardian-audits-none-key-finance-markdown"
    - "fee-on-transfer-tokens-are-not-supported-cyfrin-none-cyfrin-swapexchange-markdown"
    - "m-03-this-protocol-doesnt-support-all-fee-on-transfer-tokens-code4rena-streaming-protocol-"
  incidentes:
    - "Balancer (STA token, 2020) — fee-on-transfer token drenó pool porque accounting asumía 1:1 transfer"
    - "Multiple protocols (genérico) — fee-on-transfer es finding recurrente en audits, usualmente Medium o Low"
```

---

## 11. Oracle Staleness en Auction Pricing

```yaml
- id: auction-011
  titulo: Oracle stale en pricing de subastas automatizadas — mispricing por datos desactualizados
  causa_raiz: |
    Las subastas automatizadas (liquidation auctions, fee conversion auctions) usan price feeds
    (Chainlink, TWAP) para establecer precios de referencia, reserve prices, o para convertir
    entre tokens. Si el oracle es stale (no se actualiza por gas alto, downtime del secuenciador
    en L2, o heartbeat excesivo), la subasta opera con precios desactualizados. Esto permite:
    (a) Comprar colateral a precio demasiado bajo (si el precio real subió).
    (b) Evitar liquidación cuando debería ocurrir (si el precio real bajó).
    (c) Arbitraje entre el precio stale de la subasta y el precio real del mercado.
  como_funciona: |
    1. Chainlink feed para ETH/USD tiene heartbeat de 1h y threshold de 0.5%.
    2. ETH sube 15% en 30 minutos (crash recovery). Feed no se actualiza aún.
    3. Liquidation auction usa el precio stale (15% debajo del real).
    4. Liquidador compra colateral ETH a precio de descuento + 15% adicional de staleness.
    5. El protocolo realiza la liquidación a un precio injusto, creando bad debt.

    Secuenciador L2:
    1. Secuenciador de Arbitrum/Optimism se cae por 2 horas.
    2. Chainlink feeds no se actualizan durante ese tiempo.
    3. Al reiniciar, subastas pendientes se liquidan con precios de 2h atrás.
    4. Si ETH se movió significativamente en esas 2h → mispricing masivo.
  invariante: |
    // Oracle feed no debe ser stale al momento del bid/settlement
    function check_oracleNotStale() internal view {
        (, , , uint256 updatedAt, ) = priceFeed.latestRoundData();
        uint256 staleness = block.timestamp - updatedAt;
        uint256 maxStaleness = 3600; // 1 hora
        t(staleness <= maxStaleness, "AUCTION-011: oracle stale for auction pricing");
    }
    // En L2, verificar que el secuenciador está activo
    function check_sequencerUp() internal view {
        (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
        t(answer == 0, "AUCTION-011: L2 sequencer is down");
        t(block.timestamp - startedAt > GRACE_PERIOD, "AUCTION-011: sequencer grace period");
    }
  que_mirar:
    - ¿El contrato valida updatedAt del price feed?
    - ¿Hay un maxStaleness configurable?
    - ¿En L2, se verifica el sequencer uptime feed?
    - ¿Las subastas se pausan automáticamente si el oracle es stale?
    - ¿El heartbeat del feed es apropiado para la frecuencia de las subastas?
  como_se_arregla: |
    Validar latestRoundData: require(block.timestamp - updatedAt < MAX_STALENESS).
    En L2: verificar sequencer uptime feed con grace period de 1h post-restart.
    Pausar subastas automáticamente si oracle staleness > threshold.
    Usar múltiples fuentes de precio (Chainlink + TWAP on-chain) con circuit breaker.
  trampas:
    - Oracle staleness es el finding MÁS sobrereportado en audits — verificar que realmente causa pérdida de fondos, no solo "precio ligeramente desactualizado".
    - En L1 Ethereum, Chainlink feeds se actualizan cada 1h O si el precio cambia >0.5% — la staleness real es usualmente <1h.
    - Muchos protocolos YA tienen staleness checks — verificar antes de reportar.
    - En L2s con secuenciador centralizado, el riesgo de staleness es MUCHO mayor — buscar aquí.
  solodit_ids:
    - "m-05-uninitialized-or-incorrectly-set-auctioninterval-may-lead-to-liquidation-engine-livel"
    - "if-a-collaterals-liquidation-auction-on-seaport-ends-without-a-winning-bid-the-call-to-liq"
  incidentes:
    - "MakerDAO Black Thursday (2020) — oracle lag por gas alto causó liquidaciones tardías + zero bids"
    - "Venus Protocol (2021) — oracle stale para XVS permitió manipulación de préstamos ($200M+ en riesgo)"
    - "Mango Markets (2022) — oracle manipulation (no staleness, pero ilustra riesgo de pricing en subastas)"
```

---

## 12. Approval Persistence After Auction End

```yaml
- id: auction-012
  titulo: Approvals persistentes después de finalizar la subasta — tokens vulnerables a extracción posterior
  causa_raiz: |
    Cuando una subasta termina (por settlement, cancelación, o expiración), el contrato puede
    dejar approvals activos a contratos de settlement (GPv2Settlement, Uniswap Router, etc.).
    Estos approvals permiten que esos contratos muevan tokens del contrato de subasta en el
    futuro, incluso después de que la subasta haya terminado. Si el contrato de settlement es
    explotable o si nuevos tokens se depositan en el contrato de subasta, los approvals
    residuales permiten drenarlos.
  como_funciona: |
    1. Subasta inicia: contrato aprueba 1000 USDC al GPv2Settlement.
    2. Subasta se completa: solo se usan 800 USDC.
    3. Approval residual: 200 USDC siguen aprobados al GPv2Settlement.
    4. Nuevo depósito: alguien envía 500 USDC al contrato para una nueva subasta.
    5. Solver malicioso de CowSwap usa el approval residual para extraer 200 USDC.

    Variante (infinite approval):
    1. Contrato aprueba type(uint256).max al settlement contract "por eficiencia".
    2. Subasta termina. Approval sigue activo para TODOS los tokens.
    3. Cualquier exploit futuro del settlement contract tiene acceso ilimitado a los fondos.
  invariante: |
    // Post-settlement, no debe haber approvals residuales
    function check_approvalCleanupAfterSettle(uint256 auctionId) internal {
        auction.settle(auctionId);
        address[] memory settlementContracts = auction.getSettlementContracts();
        for (uint i = 0; i < settlementContracts.length; i++) {
            uint256 allowance = auctionToken.allowance(address(auction), settlementContracts[i]);
            t(allowance == 0, "AUCTION-012: residual approval after settlement");
        }
    }
    // Post-cancel, misma verificación
    function check_approvalCleanupAfterCancel(uint256 auctionId) internal {
        auction.cancel(auctionId);
        address[] memory settlementContracts = auction.getSettlementContracts();
        for (uint i = 0; i < settlementContracts.length; i++) {
            uint256 allowance = auctionToken.allowance(address(auction), settlementContracts[i]);
            t(allowance == 0, "AUCTION-012: residual approval after cancel");
        }
    }
  que_mirar:
    - ¿El contrato revoca approvals (approve(0)) después de settlement/cancel?
    - ¿Se usan infinite approvals (type(uint256).max)?
    - ¿Hay múltiples settlement contracts que reciben approvals?
    - ¿El contrato puede recibir depósitos después de una subasta terminada?
    - ¿Los settlement contracts (CowSwap, Uniswap) son upgradeable?
  como_se_arregla: |
    Revocar approvals explícitamente al finalizar: token.approve(spender, 0).
    Usar approve exacto por monto (no infinite approval).
    Si se usa forceApprove (para tokens como USDT que requieren approve(0) primero),
    asegurar que se ejecuta al final.
    Considerar usar transferFrom directamente en vez de approve + pull.
  trampas:
    - Residual approvals de monto pequeño (dust) son usualmente QA/Low, no High.
    - Si el settlement contract es inmutable y trusted (e.g., CowSwap GPv2Settlement), el riesgo de exploit es bajo.
    - Infinite approvals son COMUNES y a menudo intencionales para ahorrar gas — verificar si el protocolo lo documenta como decisión de diseño.
    - El costo de gas de revocar approvals puede ser significativo en L1 — hay trade-off legítimo.
  solodit_ids:
    - "h-1-escrow-approvals-are-not-cleared-when-club-is-transferred-allowing-for-abuse-after-tra"
    - "residual-permissions-after-benefactor-removal-cyfrin-none-boundary-markdown"
  incidentes:
    - "Chainlink PA (2024) — approval al CowSwap settlement contract persiste tras auction end; tokens adicionales depositados son accesibles via approval residual (known issue documentado)"
    - "Generic (múltiples audits) — infinite approvals a routers/settlement contracts son finding recurrente, usualmente Low-Medium"
```

---

## 13. Cross-Auction Accounting — Estado Compartido Entre Subastas Concurrentes

```yaml
- id: auction-013
  titulo: Contabilidad cruzada entre subastas — balance global compartido entre subastas simultáneas
  causa_raiz: |
    Cuando un contrato maneja múltiples subastas simultáneamente y usa balanceOf() del contrato
    (en vez de contabilidad interna por subasta), las acciones de una subasta afectan a otras.
    En particular, si _onAuctionEnd() sweep del balance completo de un token, puede barrer
    fondos que pertenecen a subastas aún activas. Esto es el patrón BA-SWEEP-01: el settlement
    de una subasta consume tokens de otra subasta no relacionada.
  como_funciona: |
    1. Contrato de subasta tiene 2 subastas activas: A (1000 USDC) y B (500 USDC).
    2. Balance total del contrato: 1500 USDC.
    3. Subasta A termina. _onAuctionEnd() hace transfer(winner, token.balanceOf(this)).
    4. Winner de A recibe 1500 USDC en vez de 1000 — los 500 de subasta B se fueron.
    5. Subasta B termina. Intenta transferir 500 USDC → balance = 0 → revierte.

    Variante sutil:
    1. Subasta A y B usan el mismo token (USDC) pero distintos lotes.
    2. Settlement usa contabilidad interna para A, pero el approval al settlement contract
       es por el balance total del contrato.
    3. Settlement contract (CowSwap solver) puede consumir hasta el approval total,
       tomando fondos de ambas subastas.
  invariante: |
    // Cada subasta debe tener contabilidad independiente
    function check_perAuctionAccounting() internal {
        uint256 totalAuctioned = 0;
        uint256[] memory activeAuctions = auction.getActiveAuctionIds();
        for (uint i = 0; i < activeAuctions.length; i++) {
            totalAuctioned += auction.getAuctionedAmount(activeAuctions[i]);
        }
        uint256 contractBalance = auctionToken.balanceOf(address(auction));
        t(contractBalance >= totalAuctioned,
          "AUCTION-013: contract balance < sum of active auctions");
    }
    // Settlement de una subasta no puede mover más tokens de los asignados a ella
    function check_settlementBounded(uint256 auctionId) internal {
        uint256 auctionAmount = auction.getAuctionedAmount(auctionId);
        uint256 balBefore = auctionToken.balanceOf(address(auction));
        auction.settle(auctionId);
        uint256 balAfter = auctionToken.balanceOf(address(auction));
        uint256 moved = balBefore - balAfter;
        t(moved <= auctionAmount, "AUCTION-013: settlement moved more than auction amount");
    }
  que_mirar:
    - ¿El contrato usa balanceOf(this) o contabilidad interna por subasta?
    - ¿_onAuctionEnd() transfiere el monto de la subasta o el balance completo?
    - ¿Los approvals son por subasta o globales para el contrato?
    - ¿Pueden existir múltiples subastas del mismo token simultáneamente?
    - ¿Hay un mapping(auctionId => amount) o se usa un uint256 global?
  como_se_arregla: |
    Contabilidad interna per-auction: mapping(auctionId => uint256 allocatedAmount).
    Settlement transfiere solo allocatedAmount, no balanceOf(this).
    Approvals por subasta: approve(spender, auctionAmount) al inicio, revoke al final.
    Si se usa balance-based: require que solo exista 1 subasta activa por token.
  trampas:
    - Si el contrato SOLO permite 1 subasta activa a la vez (por token), este patrón NO aplica.
    - En Chainlink PA v1, este fue documentado como known issue — no reportable en ese contexto.
    - La mayoría de protocolos simples (NFT auctions) no tienen este problema porque cada subasta es un NFT único.
    - Buscar este patrón en: fee conversion contracts, liquidation engines, batch auction houses.
  solodit_ids:
    - "m-14-placebid-possible-participation-in-auctions-that-have-been-modified-code4rena-venus-protocol-ve"
    - "h-4-auction-creators-have-the-ability-to-lock-bidders-funds-sherlock-axis-finance-git"
    - "insufficient-permissions-granted-to-new-auctions-sigmaprime-none-term-finance-pdf"
  incidentes:
    - "Chainlink PA v1 (C4, 2024) — balance-based accounting; tokens depositados durante subasta activa no se incluyen en approval al CowSwap, pero sí en subastas futuras (known issue)"
    - "Term Finance (Sigmaprime) — permisos insuficientes para nuevas subastas creadas"
    - "Venus Protocol (C4, M-14) — participación en subastas que han sido modificadas"
```

---

## 14. Auction Callback Reentrancy — Flash-Swap Style

```yaml
- id: auction-014
  titulo: Reentrancy via callbacks durante ejecución de bids — flash-swap style attacks
  causa_raiz: |
    Algunas subastas permiten callbacks al bidder durante la ejecución del bid (similar a
    Uniswap flash swaps), donde el bidder recibe los tokens subastados y debe devolver el
    pago en el mismo callback. Si el contrato no sigue el patrón CEI (Checks-Effects-Interactions)
    o no tiene reentrancy guard, el bidder puede re-entrar en el contrato de subasta durante
    el callback para:
    (a) Hacer bids adicionales con fondos que aún no ha pagado.
    (b) Cancelar su bid original mientras recibe los tokens.
    (c) Manipular el estado de la subasta a su favor.
    También aplica cuando el contrato de subasta interactúa con ERC-777 tokens (tokensReceived
    callback) o ERC-721 (onERC721Received).
  como_funciona: |
    ERC-777 reentrancy:
    1. Subasta acepta TokenX (ERC-777 compatible) como bid token.
    2. Bidder A es superado por Bidder B. Contrato refunds TokenX a Bidder A.
    3. TokenX.send() trigger tokensReceived() callback en contrato de Bidder A.
    4. En el callback, Bidder A hace un nuevo bid, manipulando estado interno.
    5. El refund no se ha completado (estado inconsistente) → accounting corrupto.

    Flash-swap style:
    1. Contrato de subasta ofrece "bid with callback": te da el asset, tú pagas en el callback.
    2. En el callback, el atacante re-entra en la subasta y cancela el bid.
    3. Recibe el asset + le refundean el pago → doble-spending.
  invariante: |
    // ReentrancyGuard debe estar activo en todas las funciones de bid/settle/cancel
    function check_reentrancyProtection() internal {
        // Desplegar contrato atacante que re-entra en bid() desde un callback
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(auction));
        // Intentar reentrancy
        try attacker.attack(auctionId) {
            t(false, "AUCTION-014: reentrancy possible in auction");
        } catch {
            // Esperado: revert por ReentrancyGuard
        }
    }
    // State updates antes de external calls
    function check_CEIPattern() internal {
        // Verificar que bids/balances se actualizan ANTES de transferir tokens
        // Esto es mejor verificado por análisis estático que por fuzzing
    }
  que_mirar:
    - ¿El contrato usa ReentrancyGuard (OpenZeppelin) en funciones de bid/settle/refund?
    - ¿Hay callbacks al bidder durante la ejecución (flash-swap style)?
    - ¿El contrato interactúa con tokens ERC-777 o NFTs ERC-721 (onReceived callbacks)?
    - ¿El refund se hace ANTES de actualizar el estado interno?
    - ¿Hay transferencias de ETH nativo (que permiten reentrancy via receive())?
  como_se_arregla: |
    Aplicar ReentrancyGuard a todas las funciones que mutan estado + hacen external calls.
    Seguir patrón CEI estricto: actualizar estado → transferir tokens (no al revés).
    No soportar ERC-777 tokens, o si se soportan, aplicar reentrancy guard.
    Para flash-swap style: completar todas las actualizaciones de estado antes del callback.
  trampas:
    - OpenZeppelin ReentrancyGuard es la solución estándar — verificar que está aplicado a TODAS las funciones relevantes, no solo a las obvias.
    - ERC-777 está en declive — pocos tokens nuevos lo usan. Pero USDT/USDC NO son ERC-777, así que no aplica a los tokens más comunes.
    - Read-only reentrancy (view functions que leen estado inconsistente) es un vector separado — buscar funciones view que se llaman durante callbacks.
    - En subastas de NFTs, onERC721Received es un vector MÁS probable que ERC-777.
  solodit_ids:
    - "h-01-bonding-mechanism-allows-malicious-user-to-dos-auctions-code4rena-kuiper-kuiper-conte"
    - "funds-can-be-drained-from-the-protocol-by-liquidating-an-account-during-an-asset-transfer-"
    - "incorrect-implementation-of-self-liquidation-ottersec-none-blend-capital-pdf"
  incidentes:
    - "Blend Capital (OtterSec) — implementación incorrecta de self-liquidation permite reentrancy durante asset transfer"
    - "Kuiper (C4, H-01) — bonding mechanism explotable via reentrancy durante auction settlement"
    - "Múltiples protocolos NFT — onERC721Received callback permite re-bid durante mint/transfer"
```

---

## 15. Bidder Fund Locking — Fondos de Bidders Bloqueados por Diseño o Bug

```yaml
- id: auction-015
  titulo: Fondos de bidders bloqueados — no pueden reclamar después del settlement o por DoS
  causa_raiz: |
    Después de una subasta, los bidders perdedores deben poder reclamar sus fondos (refund).
    Si la lógica de refund depende de que el auction creator haga un claim primero, o si hay
    un blacklist que bloquea transfers, o si el loop de refund excede gas limits, los fondos
    de los bidders quedan stuck. En Axis Finance, si el auction creator reclama proceeds antes
    de que los bidders reclamen sus bids, los bidders no pueden reclamar. También: si un
    prefunded bidder (pfBidder) es blacklisted en el token, el settlement completo se rompe.
  como_funciona: |
    Axis Finance (bidders locked):
    1. Batch auction termina. Creator llama claimProceeds().
    2. claimProceeds() modifica estado que es prerequisito para claimBids().
    3. Bidders intentan claimBids() → revierte porque el prerequisito cambió.
    4. Fondos de bidders quedan locked en el contrato.

    pfBidder blacklisted:
    1. Auction tiene un prefunded bidder (pfBidder) que debe recibir tokens primero.
    2. pfBidder es blacklisted en el token (USDC blacklist, por ejemplo).
    3. Settlement intenta transferir a pfBidder → revierte.
    4. TODO el settlement se bloquea → TODOS los bidders pierden fondos.

    Gas DoS en refunds (Axis Finance):
    1. EMPAM module refundBid() itera sobre todos los bids.
    2. Si hay miles de bids antes del bid a refundear, gas se acaba.
    3. Bidder no puede obtener refund → fondos locked.
  invariante: |
    // Bidders deben poder reclamar independientemente del auction creator
    function check_bidderCanClaimIndependently(uint256 auctionId) internal {
        // Settle auction
        auction.settle(auctionId);
        // Creator NO reclama proceeds
        // Bidder intenta reclamar
        vm.prank(bidder);
        auction.claimBid(auctionId, bidId);
        // Debe funcionar sin que el creator haya reclamado
        t(bidToken.balanceOf(bidder) > 0, "AUCTION-015: bidder cannot claim independently");
    }
    // El blacklisting de un bidder no debe bloquear a los demás
    function check_singleBidderBlacklistNoDoS(uint256 auctionId) internal {
        // Simular blacklist de pfBidder
        // Otros bidders deben poder reclamar
    }
  que_mirar:
    - ¿claimBids() depende de que claimProceeds() se haya ejecutado?
    - ¿El settlement es atómico (todo o nada) o permite settlement parcial?
    - ¿Qué pasa si un participante está blacklisted en el token?
    - ¿El loop de refund escala con el número de bids? ¿Tiene gas limit?
    - ¿Hay un mecanismo de "rescue" si el settlement normal falla?
  como_se_arregla: |
    Independencia: claimBids() no debe depender de claimProceeds().
    Blacklist resilience: usar try/catch en transfers individuales, saltar los que fallan.
    Paginación en refunds: procesar máximo N refunds por tx.
    Emergency withdraw: función admin que permite rescue de fondos bloqueados.
  trampas:
    - USDC blacklist es administrada por Circle — un bidder blacklisted es un escenario raro pero posible.
    - "Fondos locked" puede ser temporal si hay un mecanismo de rescue — verificar que realmente es permanente.
    - El gas DoS en refunds requiere miles de bids — calcular si el costo de generar esos bids es viable económicamente.
    - En Axis Finance, estos fueron findings High — el impact es real (pérdida directa de fondos de bidders).
  solodit_ids:
    - "h-5-bidders-can-not-claim-their-bids-if-the-auction-creator-claims-the-proceeds-sherlock-a"
    - "h-4-auction-creators-have-the-ability-to-lock-bidders-funds-sherlock-axis-finance-git"
    - "m-2-if-pfbidder-gets-blacklisted-the-settlement-process-would-be-broken-and-every-other-bi"
    - "h-1-malicious-user-can-overtake-a-prefunded-auction-and-steal-the-deposited-funds-sherlock-axis-fina"
  incidentes:
    - "Axis Finance (Sherlock, H-5) — bidders no pueden reclamar si el auction creator reclama proceeds primero"
    - "Axis Finance (Sherlock, H-4) — auction creators pueden lockear fondos de bidders"
    - "Axis Finance (Sherlock, M-2) — pfBidder blacklisted rompe settlement para todos"
    - "Axis Finance (Sherlock, H-1) — usuario malicioso overtake prefunded auction, roba fondos"
```

---

## 16. Liquidation Auction Zero-Bid / Insufficient Competition

```yaml
- id: auction-016
  titulo: Zero-bid en subastas de liquidación — ausencia de competencia permite adquisición gratis
  causa_raiz: |
    Las subastas de liquidación asumen que habrá múltiples keepers compitiendo por el colateral.
    Cuando la competencia desaparece (gas extremo, bug en keeper bots, congestión de red), un
    solo keeper puede ganar subastas a precios cercanos a cero. Si no hay minimum bid
    relativo al valor del colateral, el keeper adquiere assets gratuitamente o casi gratis.
    MakerDAO Black Thursday es el incidente canónico: $8.32M en ETH adquirido por 0 DAI.
  como_funciona: |
    1. Crash de mercado: ETH cae 43% en horas. Gas se dispara 10x.
    2. Keeper bots tienen gas price fijo → txs stuck en mempool.
    3. Cientos de vaults se liquidan simultáneamente.
    4. Un solo bot con gas price alto envía bids de 0 DAI.
    5. Sin competencia, gana 1,000+ subastas con bid = 0.
    6. Adquiere $8.32M en ETH sin pagar nada.
    7. Protocolo (MakerDAO) absorbe la pérdida como bad debt: 6.65M DAI.
  invariante: |
    // El bid en una liquidation auction debe ser >= X% del valor oráculo del colateral
    function check_liquidationBidMinimum(uint256 auctionId) internal view {
        uint256 bidAmount = auction.getHighestBid(auctionId);
        uint256 collateralValue = auction.getCollateralValue(auctionId); // oracle-based
        uint256 minBidPct = 3000; // 30% mínimo
        if (bidAmount > 0) {
            t(bidAmount * 10000 / collateralValue >= minBidPct,
              "AUCTION-016: liquidation bid < 30% of collateral value");
        }
    }
    // La subasta no puede finalizar con 0 bids reales
    function check_noBidAuctionHandling(uint256 auctionId) internal view {
        if (auction.isFinished(auctionId) && auction.getHighestBid(auctionId) == 0) {
            // Debe haber un fallback: extender duración, ir a backstop, etc.
            t(auction.hasBackstop(auctionId), "AUCTION-016: no fallback for zero-bid auction");
        }
    }
  que_mirar:
    - ¿Hay un minimum bid como % del valor oráculo?
    - ¿Qué pasa si nadie bidea? ¿Hay fallback o backstop liquidator?
    - ¿La subasta tiene keeper incentives suficientes para atraer competencia?
    - ¿El gas price se adapta automáticamente o es fijo?
    - ¿Hay circuit breakers que pausan liquidaciones si gas > threshold?
  como_se_arregla: |
    Minimum bid = max(30% oracle value, dust threshold).
    Backstop pool (insurance fund) que bidea si nadie más lo hace.
    Circuit breaker: pausar liquidaciones si gas > X gwei o si hay > N liquidaciones pendientes.
    Keeper incentives dinámicos que escalan con el descuento del colateral.
    Post-Black Thursday fixes: MakerDAO aumentó lot size y duración de subastas.
  trampas:
    - MakerDAO ya implementó fixes post-Black Thursday (circuit breakers, lot size changes, backstop module) — verificar versión actual antes de reportar.
    - La competencia entre keepers es un mecanismo ECONÓMICO, no técnico — si el descuento no es suficiente, los keepers no van a participar.
    - En L2s con gas predecible y bajo, el escenario de "gas wars impiden keepers" es mucho menos probable.
    - Aave/Compound usan fixed-spread liquidation (no auction) — este patrón solo aplica a protocolos con subastas de liquidación.
  solodit_ids:
    - "h-2-attacker-can-deposit-after-the-keeper-reports-a-loss-but-before-the-collateral-auction-to-steal-from-other-depositors-sherlock-yearn-ybold-git"
    - "backstop-liquidation-safeguards-ottersec-none-blend-capital-pdf"
    - "if-a-collaterals-liquidation-auction-on-seaport-ends-without-a-winning-bid-the-call-to-liq"
  incidentes:
    - "MakerDAO Black Thursday (Marzo 2020) — $8.32M en ETH adquirido por 0 DAI. 1,461 zero-bid auctions. 320 vaults afectados. Lawsuit de $28M."
    - "Blend Capital (OtterSec) — backstop liquidation safeguards insuficientes"
    - "Seaport liquidation (Sigmaprime) — si la subasta de liquidación en Seaport termina sin winning bid, la llamada a liquidation falla → colateral stuck"
```
