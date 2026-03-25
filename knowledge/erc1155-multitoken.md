# ERC-1155 & Multi-Token Systems — Bug Patterns

> Superficie de ataque: callbacks onERC1155Received/onERC1155BatchReceived, batch operations,
> setApprovalForAll sin granularidad, totalSupply desync, token ID space collisions,
> semi-fungible state transitions, multi-token vault accounting, soulbound bypass.
> Especialmente relevante para: gaming NFTs (Axie, AI Arena), DeFi con receipt tokens 1155
> (Notional, Panoptic), marketplaces (Seaport, Blur, LooksRare), rental protocols (reNFT),
> fractionalization (Fractional, Hypercerts).
> Sources: Code4rena, Sherlock, OpenZeppelin advisories, ChainSecurity, Pashov, Ackee.

---

## Quick Reference

```
grep_targets:
  - ERC1155
  - IERC1155
  - IERC1155Receiver
  - onERC1155Received
  - onERC1155BatchReceived
  - safeTransferFrom
  - safeBatchTransferFrom
  - setApprovalForAll
  - isApprovedForAll
  - balanceOf(address,uint256)
  - balanceOfBatch
  - _mint
  - _mintBatch
  - _burn
  - _burnBatch
  - totalSupply(uint256)
  - ERC1155Supply
  - ERC1155Holder
  - ERC1155Receiver
  - supportsInterface
  - ERC2981
  - royaltyInfo
  - ERC5192
  - locked(uint256)
  - ERC3525
  - SemiFungible
  - _splitValue
  - _mergeValue
  - tokenOfOwnerByIndex
  - _beforeTokenTransfer
  - _afterTokenTransfer
  - uri(uint256)
  - TransferSingle
  - TransferBatch
```

---

## 1. Reentrancia vía onERC1155Received en transferencias individuales

```yaml
- id: mt-001
  titulo: safeTransferFrom/mint dispara callback onERC1155Received — reentrancia por CEI violado
  causa_raiz: |
    ERC1155.safeTransferFrom() y _mint() llaman onERC1155Received() en el receptor ANTES
    de que la función que inició la transferencia actualice su estado interno. Si el contrato
    actualiza balances, deudas, o colateral DESPUÉS de la transferencia, el callback del
    receptor puede reentrar y explotar estado stale. Es el mismo patrón que ERC721 pero
    peor porque ERC1155 tiene DOS callbacks (individual y batch) que frecuentemente se
    olvida proteger.
  como_funciona: |
    1. Protocolo llama safeTransferFrom(protocol, attacker, tokenId, amount, data).
    2. ERC1155 ejecuta onERC1155Received() en el contrato atacante — aún dentro de la función.
    3. Atacante reenter a la función original (o a otra que lea el mismo estado).
    4. Estado aún no actualizado → operación se ejecuta con datos stale.
    5. Ejemplo reNFT: rental no registrado antes del swap de tokens → atacante hijackea
       cualquier ERC1155 rentado llamando transferencia desde onERC1155Received.
  invariante: |
    // Todo estado debe actualizarse ANTES de safeTransferFrom
    // Check: ninguna escritura a storage después de safeTransferFrom en la misma función
    function invariant_no_state_after_transfer() internal {
        // Si balances[user] cambia después de _safeTransferFrom → violación CEI
        // Verificar con nonReentrant en toda función que haga transfer
    }
  que_mirar:
    - "safeTransferFrom() o _mint() llamado ANTES de actualizar estado interno"
    - "Funciones que hacen transfer + write sin nonReentrant modifier"
    - "grep: safeTransferFrom seguido de asignaciones a storage en la misma función"
    - "onERC1155Received implementado como fallback handler (Gnosis Safe pattern)"
  como_se_arregla: |
    Seguir CEI estrictamente: actualizar TODO el estado antes de safeTransferFrom.
    Añadir nonReentrant a toda función que haga transferencias ERC1155.
    Si el receptor es conocido/trusted, considerar usar transferencia sin callback.
  trampas:
    - "El callback va al RECEPTOR, no al sender — el atacante ES el receptor"
    - "En reNFT, el callback iba a un Gnosis Safe con fallback handler malicioso"
    - "Los jueces pueden rechazar si nonReentrant ya está presente — verificar TODAS las funciones"
  solodit_ids:
    - "h-01-an-attacker-can-hijack-any-erc1155-token-he-rents-due-to-a-design-issue-code4rena-renft-renft-git"
    - "erc1155-has-reentrancy-possibilities-code4rena-notional-notional-git"
  incidentes:
    - "reNFT (C4 2024) — atacante hijackea cualquier ERC1155 rentado via reentrancia en onERC1155Received del Gnosis Safe (High)"
    - "Notional (C4 2021) — ERC1155Action.sol permite reentrancia via callback en transferencias (Medium, disputado)"
```

---

## 2. Reentrancia vía onERC1155BatchReceived en batch mint/transfer

```yaml
- id: mt-002
  titulo: _mintBatch/_safeBatchTransferFrom dispara onERC1155BatchReceived — estado no actualizado
  causa_raiz: |
    Las operaciones batch de ERC1155 (_mintBatch, safeBatchTransferFrom) llaman
    onERC1155BatchReceived() en el receptor. El problema es idéntico a mt-001 pero
    amplificado: durante el callback, el receptor puede ver balances parcialmente
    actualizados (los tokens ya están en su balance pero el estado del protocolo
    aún no refleja la operación). Esto es especialmente peligroso en funciones que
    splitean o fraccionalizan tokens.
  como_funciona: |
    1. Protocolo llama _mintBatch() para crear fracciones de un token (Hypercerts).
    2. _mintBatch() transfiere tokens y llama onERC1155BatchReceived() en el receptor.
    3. Atacante reenter a splitValue() — el valueLeft aún no se decrementó en storage.
    4. Atacante crea fracciones infinitas del mismo token: cada reentrancia usa el
       valueLeft original (no decrementado).
    5. Resultado: atacante tiene N*amount de fracciones, valor real = amount.
  invariante: |
    // valueLeft DEBE escribirse en storage ANTES de _mintBatch
    // Invariante: sum(fractions[tokenId]) == originalValue[tokenId]
    function invariant_fraction_conservation(uint256 tokenId) internal {
        uint256 totalFractions = 0;
        for (uint i = 0; i < fractionIds[tokenId].length; i++) {
            totalFractions += balanceOf(address(this), fractionIds[tokenId][i]);
        }
        assert(totalFractions == originalValue[tokenId]);
    }
  que_mirar:
    - "Funciones split/merge/fractionalize que llaman _mintBatch"
    - "Storage writes que ocurren DESPUÉS de _mintBatch o safeBatchTransferFrom"
    - "grep: _mintBatch.*onERC1155BatchReceived — ¿hay storage writes pendientes?"
    - "¿El contrato tiene nonReentrant en la función que llama _mintBatch?"
  como_se_arregla: |
    Escribir valueLeft/state a storage ANTES de llamar _mintBatch().
    Añadir nonReentrant modifier.
    Verificar que sum(fractions) == original en un invariante post-operación.
  trampas:
    - "OZ _mintBatch llama al callback DESPUÉS de actualizar balances internos del ERC1155, pero ANTES de que el protocolo actualice SU propio estado"
    - "El atacante puede llamar funciones DISTINTAS en la reentrancia, no solo la misma"
    - "Batch operations procesan todos los IDs y luego hacen UN solo callback — no un callback por ID"
  solodit_ids:
    - "reentrancy-attack-in-splitvalue-pashov-none-hypercerts-markdown"
  incidentes:
    - "Hypercerts (Pashov) — splitValue() llama _mintBatch antes de escribir valueLeft → reentrancia crea fracciones infinitas (High)"
    - "OpenSea ERC1155 (GitHub #9) — reentrancy en mint() permite mint excesivo via callback"
```

---

## 3. totalSupply desincronizado durante callback (OZ ERC1155Supply)

```yaml
- id: mt-003
  titulo: ERC1155Supply no incrementa totalSupply hasta después del callback — supply manipulation
  causa_raiz: |
    En versiones de OpenZeppelin < 4.3.3, ERC1155Supply._beforeTokenTransfer() no se
    llamaba en el orden correcto respecto al callback. Durante onERC1155Received, el
    totalSupply(id) reportado era MENOR que la cantidad real de tokens en circulación.
    Protocolos que usan totalSupply para cálculos de share/proportion durante el callback
    dan al atacante una proporción inflada.
  como_funciona: |
    1. Atacante llama mint(attackerContract, tokenId, 1000).
    2. ERC1155 llama onERC1155Received() — atacante tiene 1000 tokens.
    3. Pero totalSupply(tokenId) aún no se incrementó (sigue en valor anterior).
    4. Atacante llama función que calcula share = balanceOf(attacker) / totalSupply.
    5. share > 100% (balanceOf = 1000, totalSupply = 0 o valor pre-mint).
    6. Atacante extrae más rewards/votos de los que le corresponden.
  invariante: |
    // totalSupply(id) >= balanceOf(anyUser, id) en TODO momento, incluido durante callbacks
    function invariant_supply_gte_balance(uint256 id, address user) internal {
        assert(totalSupply(id) >= balanceOf(user, id));
    }
  que_mirar:
    - "¿Versión de OZ contracts? < 4.3.3 es vulnerable"
    - "¿El protocolo usa totalSupply(id) en lógica de governance/rewards/shares?"
    - "¿Hay contratos que leen totalSupply durante un callback?"
    - "grep: totalSupply.*balanceOf en la misma función — ¿ratio calculado?"
  como_se_arregla: |
    Actualizar a OZ >= 4.3.3 donde el fix está incluido.
    No hacer mint a receptores untrusted si el supply tracking es crítico.
    Usar _beforeTokenTransfer para actualizar totalSupply ANTES del callback.
  trampas:
    - "Versiones modernas de OZ (>= 4.3.3) ya tienen este fix — verificar la versión exacta"
    - "El bug solo es explotable si algún contrato LEE totalSupply durante el callback"
    - "Si no hay governance/reward/share logic, el impacto puede ser Info"
  solodit_ids:
    - "erc1155supply-vulnerability-in-openzeppelin-contracts-openzeppelin-ghsa-wmpv-c2jp-j2xg"
  incidentes:
    - "OpenZeppelin (GHSA-wmpv-c2jp-j2xg) — totalSupply inconsistency en ERC1155Supply < 4.3.3, permite share inflation durante callback (Critical advisory)"
    - "ChainSecurity — publicó análisis detallado del bug: totalSupply reportaba valor incorrecto durante onERC1155Received"
```

---

## 4. setApprovalForAll — over-permission sin granularidad de token ID

```yaml
- id: mt-004
  titulo: setApprovalForAll da acceso a TODOS los token IDs — no hay approval granular en ERC1155
  causa_raiz: |
    A diferencia de ERC20 (approve por cantidad) o ERC721 (approve por tokenId),
    ERC1155 solo tiene setApprovalForAll(operator, true) que da al operador control
    total sobre TODOS los token IDs del usuario. No hay forma nativa de aprobar solo
    un ID o limitar la cantidad. Esto crea un blast radius enorme: cualquier contrato
    aprobado puede transferir cualquier token 1155 del usuario.
  como_funciona: |
    1. Usuario llama setApprovalForAll(protocol, true) para depositar gameItem #42.
    2. Protocol tiene bug o es malicioso → también transfiere gameItem #1, #2, #99.
    3. O: usuario olvida revocar → protocolo upgradeable añade función que drainea.
    4. Boost AA Wallet (Sherlock): allocate() acepta parámetro `from` arbitrario.
       Cualquier usuario que haya aprobado el Budget puede tener sus tokens transferidos
       por CUALQUIERA que llame allocate() con el from del usuario aprobado.
  invariante: |
    // Si el protocolo recibe approval, solo debe transferir los IDs explícitamente
    // autorizados por la operación en curso
    function invariant_no_excess_transfer(address user, uint256[] memory authorizedIds) internal {
        // Verificar que solo authorizedIds fueron transferidos, no otros IDs del user
        for (uint i = 0; i < allIds.length; i++) {
            if (!isAuthorized(allIds[i], authorizedIds)) {
                assert(balanceOf(user, allIds[i]) == balanceBefore[user][allIds[i]]);
            }
        }
    }
  que_mirar:
    - "Contratos que aceptan setApprovalForAll como prerequisito para operaciones"
    - "Funciones con parámetro `from` que no validan msg.sender == from"
    - "grep: isApprovedForAll — ¿se usa como único check sin validar msg.sender?"
    - "¿El protocolo permite revocar approval después de la operación?"
  como_se_arregla: |
    Validar que msg.sender == from en toda función que use safeTransferFrom(from, ...).
    Implementar approval wrapper con granularidad por ID/amount (ERC1155Permit style).
    Revocar approval después de la operación si es one-time.
    Considerar pull pattern (user deposita, no push from protocol).
  trampas:
    - "Este es un design limitation de ERC1155, no un bug del protocolo — solo reportar si el protocolo AMPLIFICA el riesgo"
    - "Muchos jueces marcan esto como informational si no hay concrete exploit path"
    - "El equivalente ERC721 (setApprovalForAll) tiene el mismo problema"
  solodit_ids:
    - "setapprovalforall-can-be-abused-to-transfer-more-tokens-to-budget-than-intended-sherlock-boost-aa-wallet-git"
    - "malicious-users-can-exploit-residual-allowance-to-steal-assets-code4rena-fractional-fractional-git"
  incidentes:
    - "Boost AA Wallet (Sherlock 2024) — setApprovalForAll + allocate(from=victim) permite transferir todos los 1155 del victim sin su consentimiento (Medium)"
    - "Fractional v2 (C4 2022) — residual allowance después de deposit permite a cualquiera robar ERC20/721/1155 del usuario via batchDepositERC1155 con from=victim (High)"
```

---

## 5. safeBatchTransferFrom no overrideado — bypass de restricciones de transferencia

```yaml
- id: mt-005
  titulo: Protocolo restringe safeTransferFrom pero olvida overridear safeBatchTransferFrom
  causa_raiz: |
    Protocolos que implementan restricciones de transferencia (non-transferable items,
    soulbound tokens, cooldowns, whitelists) frecuentemente override safeTransferFrom()
    con los checks necesarios, pero OLVIDAN overridear safeBatchTransferFrom(). La
    función batch hereda de ERC1155 sin restricciones → los tokens "non-transferable"
    se transfieren libremente via la función batch.
  como_funciona: |
    1. AI Arena marca GameItem #5 como non-transferable: transferable[5] = false.
    2. Override en safeTransferFrom: require(transferable[id], "not transferable").
    3. safeBatchTransferFrom NO está overrideado — usa ERC1155 base sin checks.
    4. Atacante llama safeBatchTransferFrom(from, to, [5], [1], "") → transfer exitoso.
    5. Item non-transferable ahora está en otra wallet — restricción completamente bypasseada.
  invariante: |
    // Si safeTransferFrom tiene restricciones, safeBatchTransferFrom DEBE tenerlas también
    // Test: intentar batch transfer de item no-transferable debe revertir
    function invariant_batch_respects_transfer_restrictions(uint256 id) external {
        if (!transferable[id]) {
            // safeBatchTransferFrom con este id DEBE revertir
            try this.safeBatchTransferFrom(owner, other, _toArray(id), _toArray(1), "") {
                assert(false); // NO debería llegar aquí
            } catch {
                // Correcto: reverted
            }
        }
    }
  que_mirar:
    - "Override de safeTransferFrom sin override correspondiente de safeBatchTransferFrom"
    - "grep: override.*safeTransferFrom — ¿hay override de safeBatchTransferFrom también?"
    - "¿La restricción está en _beforeTokenTransfer (cubre ambos) o en la función pública?"
    - "Soulbound tokens, locked items, cooldown items — ¿cuál es el mecanismo de restricción?"
  como_se_arregla: |
    Poner las restricciones en _beforeTokenTransfer() que cubre AMBAS funciones.
    O overridear AMBAS funciones (safeTransferFrom Y safeBatchTransferFrom).
    Verificar en tests que la restricción aplica por ambos paths.
  trampas:
    - "En OZ, _beforeTokenTransfer se llama en AMBAS funciones — si la restricción está ahí, ambas están cubiertas"
    - "El bug solo existe si la restricción está en la función pública, no en el hook interno"
    - "ERC721 tiene el mismo patrón: override transferFrom pero olvidar safeTransferFrom"
  solodit_ids:
    - "h-02-non-transferable-gameitems-can-be-transferred-with-safebatchtransferfrom-code4rena-ai-arena-ai-arena-git"
  incidentes:
    - "AI Arena (C4 2024) — GameItems non-transferable se transfieren via safeBatchTransferFrom no overrideado (High, H-02)"
```

---

## 6. Missing onERC1155Received — tokens enviados a contrato que no los puede manejar

```yaml
- id: mt-006
  titulo: Tokens 1155 enviados a contrato sin implementar IERC1155Receiver — fondos perdidos
  causa_raiz: |
    ERC1155 requiere que el receptor de safeTransferFrom implemente IERC1155Receiver
    y retorne el magic value. Si un protocolo usa transferencias internas que NO
    llaman safeTransferFrom (e.g., _transfer interno, o manipulación directa de
    balances), los tokens pueden llegar a un contrato que no sabe manejarlos →
    tokens permanentemente bloqueados.
    También: si onERC1155Received revierte en el receptor durante una operación
    crítica (liquidación, settlement), la operación entera se bloquea.
  como_funciona: |
    Escenario 1 — Lock permanente:
    1. Protocolo usa función interna para mover tokens 1155 a otro contrato.
    2. Contrato receptor no implementa onERC1155Received (ni ERC1155Holder).
    3. Tokens quedan en el contrato receptor sin forma de extraerlos.

    Escenario 2 — DoS via revert:
    1. reNFT intenta devolver ERC1155 al lender en stopRent().
    2. Lender tiene onERC1155Received() que revierte intencionalmente.
    3. stopRent() revierte → rental no se puede terminar → tokens del borrower congelados.
  invariante: |
    // Todo receptor de tokens 1155 debe implementar IERC1155Receiver
    // O: usar try/catch en transferencias a direcciones arbitrarias
    function invariant_receiver_supports_1155(address to) internal {
        if (to.code.length > 0) {
            assert(IERC165(to).supportsInterface(type(IERC1155Receiver).interfaceId));
        }
    }
  que_mirar:
    - "Transferencias internas que no usan safeTransferFrom (bypass del receiver check)"
    - "Liquidaciones/settlements que envían 1155 a dirección del usuario sin try/catch"
    - "grep: _transfer, _safeTransfer vs safeTransferFrom — ¿cuál se usa?"
    - "¿El protocolo asume que el receptor siempre acepta? ¿Hay fallback?"
  como_se_arregla: |
    Siempre usar safeTransferFrom (con callback check) para enviar a direcciones externas.
    Implementar try/catch alrededor de transfers en operaciones críticas.
    Considerar escrow pattern si el receptor puede bloquear la operación.
  trampas:
    - "safeTransferFrom SÍ verifica el receptor — el bug es cuando se usa _transfer interno"
    - "El DoS via revert en callback es el inverso: SÍ se verifica, pero el receptor lo usa como arma"
    - "Bunker Finance (C4): revert en safeTransferFrom rompe composability del estándar"
  solodit_ids:
    - "cnftsol-revert-inside-safetransferfrom-will-break-composability-standard-behaviour-code4rena-bunker-finance-git"
    - "h-03-malicious-lender-can-freeze-borrowers-erc1155-tokens-indefinitely-code4rena-renft-renft-git"
  incidentes:
    - "Bunker Finance (C4 2022) — revert en safeTransferFrom rompe composability de cNFT (Medium)"
    - "reNFT (C4 2024) — lender malicioso congela tokens del borrower indefinidamente via revert en onERC1155Received (High)"
```

---

## 7. Batch array length mismatch — ids[] y amounts[] de diferente longitud

```yaml
- id: mt-007
  titulo: ids[] y amounts[] de diferente longitud en batch operations — comportamiento indefinido
  causa_raiz: |
    Las funciones batch de ERC1155 (safeBatchTransferFrom, _mintBatch, _burnBatch)
    reciben dos arrays: ids[] y amounts[]. Si no se valida que tengan la misma
    longitud, el comportamiento es indefinido: puede revertir con index-out-of-bounds,
    o peor, procesar parcialmente (algunos IDs sin amount correspondiente) dejando
    estado inconsistente.
  como_funciona: |
    1. Atacante llama mintBatch(to, [1, 2, 3], [100, 200]) — 3 IDs, 2 amounts.
    2. Sin validación de longitud: id[2] = 3 busca amounts[2] que no existe.
    3. En Solidity < 0.8: lee basura de memoria → amount arbitrario.
    4. En Solidity >= 0.8: revierte con panic, pero si la función tiene side effects
       antes del loop, el estado ya se modificó parcialmente.
    5. Implementaciones custom que no usan OZ pueden no validar esto.
  invariante: |
    // ids.length == amounts.length en TODA operación batch
    function invariant_batch_arrays_equal_length(
        uint256[] memory ids, uint256[] memory amounts
    ) internal pure {
        assert(ids.length == amounts.length);
    }
  que_mirar:
    - "Implementaciones custom de ERC1155 que no heredan de OZ"
    - "grep: ids.length.*amounts.length — ¿se valida antes del loop?"
    - "Funciones wrapper que construyen arrays y los pasan a batch — ¿longitudes consistentes?"
    - "¿Hay require(ids.length == amounts.length) explícito?"
  como_se_arregla: |
    Usar OZ ERC1155 que valida automáticamente.
    Si es custom: require(ids.length == amounts.length, "length mismatch") al inicio.
    En funciones que construyen arrays: assert consistency antes de pasar a batch.
  trampas:
    - "OZ ERC1155 ya valida esto — solo es bug en implementaciones custom"
    - "En Solidity >= 0.8 el pánico por OOB impide explotación, pero es un DoS vector"
    - "El estándar EIP-1155 especifica que los arrays DEBEN tener la misma longitud"
  solodit_ids: []
  incidentes:
    - "Múltiples implementaciones custom pre-OZ — array length mismatch en batch operations (típicamente Medium/Low)"
```

---

## 8. Token ID collision/confusion — fungible vs non-fungible IDs en el mismo contrato

```yaml
- id: mt-008
  titulo: Confusión entre IDs fungibles y non-fungibles — el mismo ID tratado como ambos
  causa_raiz: |
    ERC1155 permite que un mismo contrato tenga IDs fungibles (supply > 1) y non-fungibles
    (supply = 1). Si el protocolo no distingue claramente cuál es cuál, puede tratar un
    token fungible como NFT (asumiendo unicidad) o un NFT como fungible (permitiendo
    "más de uno"). Esto es especialmente problemático cuando el encoding del ID incluye
    metadata (e.g., bits altos = tipo, bits bajos = serial) y el protocolo usa uint128
    o uint64 internamente, truncando el ID.
  como_funciona: |
    Escenario 1 — NFT tratado como fungible:
    1. Token ID #42 es un NFT único (supply = 1).
    2. Protocolo permite "deposit" de amount=5 del ID #42.
    3. No hay validación de supply → protocolo registra 5 unidades de algo que solo existe 1.
    4. Atacante retira 5, recibe 1 real + 4 créditos fantasma.

    Escenario 2 — ID truncation:
    1. Protocolo almacena token IDs en uint128 (para ahorrar storage slots).
    2. ID real es uint256 con bits altos significativos.
    3. Truncation: dos IDs distintos colapsan al mismo uint128 → collision.
    4. Usuario A deposita ID X, usuario B deposita ID Y → ambos mapean al mismo slot.
  invariante: |
    // Si el token es NFT (supply == 1), no permitir amount > 1
    function invariant_nft_amount_is_one(uint256 id, uint256 amount) internal {
        if (totalSupply(id) == 1 || isNFT[id]) {
            assert(amount <= 1);
        }
    }
    // Si se trunca ID, verificar que no hay collision
    function invariant_no_id_collision(uint256 fullId) internal {
        uint128 truncated = uint128(fullId);
        assert(idMapping[truncated] == 0 || idMapping[truncated] == fullId);
    }
  que_mirar:
    - "¿El protocolo distingue IDs fungibles de NFTs? ¿Cómo?"
    - "¿Se almacenan IDs en tipos más pequeños que uint256?"
    - "grep: uint128.*tokenId, uint64.*tokenId — posible truncation"
    - "¿El protocolo valida amount <= totalSupply(id) en deposits?"
    - "Encoding de IDs: ¿bits altos para tipo, bits bajos para serial?"
  como_se_arregla: |
    Mantener registry explícito: mapping(uint256 => TokenType) donde TokenType = {FUNGIBLE, NFT}.
    Validar amount contra totalSupply/maxSupply.
    Nunca truncar token IDs — usar uint256 completo.
    Si se usa encoding: validar que el encoding es inyectivo (sin colisiones).
  trampas:
    - "Algunos protocolos usan ID ranges (0-999 = fungible, 1000+ = NFT) — verificar que se respeta"
    - "ERC1155 NO tiene una forma nativa de saber si un ID es fungible o NFT"
    - "supply(id) == 0 puede ser un token aún no minteado, no necesariamente inexistente"
  solodit_ids: []
  incidentes:
    - "OpenSea ERC1155 (GitHub #11) — mint puede overflowear totalSupply dando falsa impresión de escasez en tokens NFT"
    - "Diversos protocolos gaming — confusión fungible/NFT en items con mismo contrato ERC1155"
```

---

## 9. Marketplace: amount incorrecto en policy de matching ERC1155

```yaml
- id: mt-009
  titulo: Marketplace ERC1155 policy retorna amount=1 en vez de order.amount — buyer pierde fondos
  causa_raiz: |
    Marketplaces que soportan tanto ERC721 como ERC1155 frecuentemente tienen policies
    de matching separadas. La policy ERC1155 debe considerar el amount del order (un
    seller puede vender 10 copias de un item). Si la policy hardcodea amount=1 o no
    propaga el amount correcto, el buyer paga el precio de 10 pero recibe 1.
  como_funciona: |
    1. Seller crea order: vender 10 unidades de tokenId #5 por 1 ETH total.
    2. Buyer matchea la order, paga 1 ETH.
    3. StandardPolicyERC1155.canMatchMakerAsk() retorna amount=1 (hardcoded).
    4. _executeTokenTransfer() transfiere solo 1 unidad al buyer.
    5. Buyer pagó 1 ETH, recibió 1/10 de lo esperado. Seller conserva 9 unidades + 1 ETH.
  invariante: |
    // Amount transferido == amount del order matcheado
    function invariant_correct_amount_transferred(
        Order memory order, uint256 actualTransferred
    ) internal {
        assert(actualTransferred == order.amount);
    }
  que_mirar:
    - "Policies de matching para ERC1155 — ¿retornan el amount del order o hardcodean 1?"
    - "grep: StandardPolicyERC1155, canMatchMakerAsk, canMatchMakerBid"
    - "¿_executeTokenTransfer usa el amount de la policy o del order original?"
    - "¿Tests cubren orders con amount > 1?"
  como_se_arregla: |
    La policy debe retornar order.amount, no un valor hardcodeado.
    Verificar que el flow completo propaga amount desde order → policy → execute → transfer.
    Tests con amount = 1, 10, 100, type(uint256).max.
  trampas:
    - "En Blur, la policy ERC1155 era placeholder no deployado — verificar si está en producción"
    - "El seller también puede ser víctima: envía 1 token pero esperaba enviar 10 y cobrar más"
    - "Algunos marketplaces cobran fee por unidad — verificar que fees se calculan sobre amount correcto"
  solodit_ids:
    - "standardpolicyerc1155sol-returns-amount-1-instead-of-amount-orderamount-code4rena-blur-blur-git"
  incidentes:
    - "Blur (C4 2022) — StandardPolicyERC1155 retorna amount=1 hardcoded en vez de order.amount → buyer pierde ETH (Medium)"
```

---

## 10. ERC2981 royalty bypass — transferencias fuera del marketplace

```yaml
- id: mt-010
  titulo: Royalties ERC2981 no enforceadas on-chain — bypass via transfer directa o wrapper
  causa_raiz: |
    ERC2981 es un estándar INFORMATIVO: define royaltyInfo() que retorna (receiver, amount)
    pero NO enforcea el pago. El pago depende del marketplace que ejecuta la venta.
    Si la transferencia ocurre fuera del marketplace (safeTransferFrom directo, wrapper
    contract, o marketplace non-compliant), el royalty no se paga. Para ERC1155 esto
    es peor porque el batch transfer puede mover muchos tokens en una sola tx sin
    triggerar ningún royalty.
  como_funciona: |
    1. NFT tiene royalty del 5% configurada via ERC2981.
    2. Comprador y vendedor acuerdan off-marketplace.
    3. Vendedor llama safeTransferFrom(seller, buyer, tokenId, amount, "") directamente.
    4. ERC2981.royaltyInfo() nunca se consulta — no hay marketplace que enforece.
    5. 0% royalty pagado. Con batch transfer, N tokens se mueven sin un solo centavo de royalty.

    Bypass via wrapper:
    1. Atacante crea WrapperContract que deposita el NFT y emite un ERC20 wrapper.
    2. Se tradea el ERC20 (sin royalty) y luego se redeemea el NFT.
  invariante: |
    // En un marketplace: royalty DEBE pagarse antes de completar la transferencia
    function invariant_royalty_paid(
        uint256 tokenId, uint256 salePrice, uint256 royaltyPaid
    ) internal {
        (address receiver, uint256 royaltyAmount) = IERC2981(nft).royaltyInfo(tokenId, salePrice);
        assert(royaltyPaid >= royaltyAmount);
    }
  que_mirar:
    - "¿El marketplace consulta royaltyInfo() y paga antes de transferir?"
    - "¿Hay forma de transferir tokens sin pasar por la función de venta del marketplace?"
    - "grep: royaltyInfo, ERC2981, royaltyReceiver"
    - "¿El protocolo tiene operator filter (OperatorFilterRegistry de OpenSea)?"
  como_se_arregla: |
    Marketplace: consultar y pagar royalty en execute() antes de transfer.
    Considerar operator filter registry para bloquear marketplaces non-compliant.
    Aceptar que on-chain enforcement es imposible al 100% — ERC2981 es advisory by design.
  trampas:
    - "ERC2981 by design NO enforcea — reportar solo si el marketplace AFIRMA pagar royalties pero no lo hace"
    - "OperatorFilterRegistry de OpenSea fue deprecado — no asumir que está activo"
    - "Royalty bypass via direct transfer es 'by design' de ERC2981, no un bug del marketplace"
    - "Solo es finding si hay un claim explícito de royalty enforcement que se viola"
  solodit_ids:
    - "royalty-fee-limit-of-nft-marketplace-bypass-via-eip-2981-haechi-audit-blog"
  incidentes:
    - "Haechi Audit — marketplace con límite de royalty fee bypassed via EIP-2981 return value manipulation (Medium)"
    - "Mintra (CoinFabrik) — royalty distribution inconsistente entre tokens con/sin ERC2981 support"
```

---

## 11. Semi-fungible token (SFT) — partial transfer de posiciones compuestas

```yaml
- id: mt-011
  titulo: Partial transfer de posiciones semi-fungibles corrompe accounting de premiums/rewards
  causa_raiz: |
    Protocolos que usan ERC1155 como semi-fungible tokens (SFTs) donde cada ID representa
    una posición con valor intrínseco (Panoptic options, Hypercerts fractions) permiten
    transferencias parciales. Si el accounting de premiums/rewards/debt está ligado al
    balance completo del ID y no se prorratea correctamente en transferencias parciales,
    el receptor hereda premiums/debt incorrectos.
  como_funciona: |
    1. Panoptic: usuario minta short put (deposita tokens) → tiene ERC1155 con right slot.
    2. Usuario minta long put en el mismo rango → right slot ahora es mínimo.
    3. Usuario transfiere solo la fracción small (right slot) a la víctima.
    4. Víctima ahora tiene posición que parece haber removido mucha liquidez.
    5. Si víctima minta posiciones en el mismo rango → premiums owed son extremamente
       inflados (se calculan sobre la liquidez aparente, no la real).
    6. Víctima paga premiums excesivos al atacante.
  invariante: |
    // En partial transfer de SFT:
    // premiums_owed(recipient) debe ser proporcional al amount recibido, no heredar todo
    function invariant_premium_proportional(
        uint256 id, address recipient, uint256 amountTransferred, uint256 totalAmount
    ) internal {
        uint256 expectedPremium = totalPremium[id] * amountTransferred / totalAmount;
        assert(owedPremium[recipient][id] <= expectedPremium + DUST_TOLERANCE);
    }
  que_mirar:
    - "¿El protocolo permite partial transfers de ERC1155 posiciones?"
    - "¿Premiums/rewards/debt se recalculan en _beforeTokenTransfer o _afterTokenTransfer?"
    - "grep: right slot, left slot, SemiFungiblePositionManager"
    - "¿Hay validación de que partial transfer no crea posiciones 'envenenadas'?"
    - "¿El protocolo bloquea transfers de SFTs que tienen debt/premium asociado?"
  como_se_arregla: |
    Recalcular premiums/rewards proporcionalmente en cada transfer.
    O bloquear partial transfers de posiciones con debt/premium no settled.
    Verificar que net liquidity del recipient es correcto post-transfer.
    Tests con: transfer 1% de posición grande → verificar premiums del receptor.
  trampas:
    - "El bug requiere que atacante y víctima operen en el mismo rango de precios"
    - "Solo aplica a protocolos que usan 1155 como position tokens (Panoptic, Solv Protocol)"
    - "La mayoría de ERC1155 son simples items sin debt/premium — no aplica"
  solodit_ids:
    - "h-01-partial-transfers-are-still-possible-leading-to-incorrect-storage-updates-code4rena-panoptic-panoptic-git"
  incidentes:
    - "Panoptic (C4 2023) — partial transfer de SFT permite inflar premiums owed de la víctima; atacante puede envenenar posiciones (High)"
```

---

## 12. Multi-token vault con estado compartido — cross-ID accounting desync

```yaml
- id: mt-012
  titulo: Vault que almacena múltiples ERC1155 IDs con contabilidad compartida — desync entre IDs
  causa_raiz: |
    Vaults o contratos que aceptan depósitos de múltiples token IDs (e.g., gaming items,
    fracciones de NFTs, receipt tokens) a veces comparten estado global (totalDeposited,
    rewardPool, feeAccumulator) sin segregar por ID. Operaciones sobre un ID afectan
    cálculos de todos los demás IDs. Especialmente peligroso con ERC4626-style vaults
    que usan ERC1155 para tracking de shares por asset.
  como_funciona: |
    1. MultiVault acepta depósitos de tokenId #1 (stETH receipt) y #2 (USDC receipt).
    2. totalDeposited = sum(deposits[#1] + deposits[#2]) — no segregado.
    3. Rewards se calculan como: reward[user] = userDeposit / totalDeposited * rewardPool.
    4. Atacante deposita gran cantidad de #2 (valor bajo) → infla totalDeposited.
    5. Reward pool se diluye para depositantes de #1 (valor alto).
    6. Atacante retira #2 + claim de rewards desproporcionados.
  invariante: |
    // Cada token ID debe tener su propio accounting
    function invariant_per_id_accounting(uint256 id) internal {
        assert(totalDeposited[id] == sum_of_individual_deposits[id]);
        assert(rewardPool[id] == accumulated_rewards_for_id[id]);
        // No mezclar IDs en cálculos globales
    }
  que_mirar:
    - "¿El vault/contrato tiene estado global compartido entre token IDs?"
    - "¿totalDeposited, totalShares, rewardPool son por-ID o globales?"
    - "grep: totalSupply sin parámetro de ID vs totalSupply(id)"
    - "¿Depósitos de diferentes IDs se mezclan en el mismo pool de rewards?"
    - "¿Los precios/valores de diferentes IDs se tratan como equivalentes?"
  como_se_arregla: |
    Segregar TODO el accounting por token ID: mapping(uint256 => AccountingState).
    Si hay reward pool compartido, ponderar por valor real del token depositado (oracle).
    Nunca sumar cantidades de diferentes IDs sin normalizar por precio.
  trampas:
    - "MultiVault (z0r0z) es un patrón emergente — pocos audits reales existen"
    - "Si todos los IDs representan el mismo asset (e.g., fracciones del mismo NFT), la contabilidad compartida puede ser correcta"
    - "El riesgo principal es cuando IDs tienen valores distintos pero se tratan igual"
  solodit_ids: []
  incidentes:
    - "Patrón genérico — múltiples protocolos gaming y DeFi con ERC1155 receipt tokens han tenido accounting desync entre IDs"
```

---

## 13. Residual approval después de operación — cualquiera puede drenar tokens

```yaml
- id: mt-013
  titulo: Aprovación residual post-operación permite a terceros drenar tokens ERC1155 del usuario
  causa_raiz: |
    Debido a que ERC1155 solo tiene setApprovalForAll (sin granularidad), cuando un usuario
    aprueba un contrato para realizar una operación (deposit, stake, fractionalize), la
    aprobación persiste después. Si el contrato tiene funciones que aceptan un parámetro
    `from` sin validar que from == msg.sender, cualquier persona puede llamar esa función
    con from=victim y transferir todos los tokens 1155 del victim que aún están aprobados.
  como_funciona: |
    1. Alice llama setApprovalForAll(vault, true) para depositar su NFT en el vault.
    2. Alice deposita. Pero NO revoca la aprobación (comportamiento típico — gas).
    3. Vault tiene batchDepositERC1155(from, to, ids, amounts) sin check from == msg.sender.
    4. Bob llama batchDepositERC1155(alice, bob, [todos_los_ids], [amounts]) → legítimo
       según el contrato (isApprovedForAll(alice, vault) == true).
    5. Todos los ERC1155 de Alice que aprobó van a la vault de Bob.
  invariante: |
    // Toda función que usa from != msg.sender debe verificar ownership O autorización directa
    function invariant_no_arbitrary_from(address from, address caller) internal {
        assert(from == caller || isApprovedForAll(from, caller));
        // NOTA: isApprovedForAll(from, address(this)) NO es suficiente
        // El check debe ser que el CALLER tenga permiso, no solo que el contrato tenga permiso
    }
  que_mirar:
    - "Funciones con parámetro `from` o `_from` que no validan msg.sender"
    - "grep: function.*deposit.*from.*address, function.*transfer.*from.*address"
    - "¿El contrato usa safeTransferFrom(from, ...) donde from viene del calldata?"
    - "¿Se verifica isApprovedForAll(from, msg.sender) o isApprovedForAll(from, address(this))?"
  como_se_arregla: |
    Forzar from == msg.sender en funciones de depósito.
    O verificar que msg.sender tiene approval del from (no que el contrato tiene approval).
    Documentar que usuarios DEBEN revocar approval después de operaciones.
    Implementar aprobaciones con expiración (ERC1155Permit patterns).
  trampas:
    - "Este bug es DISTINTO de mt-004 — aquí el contrato YA tiene approval y una función permite a cualquiera usar esa approval"
    - "Muchos usuarios NUNCA revocan approvals — el blast radius es permanente"
    - "El fix correcto es from == msg.sender, no agregar otro approval check"
  solodit_ids:
    - "steal-erc20s-erc721s-and-erc1155s-from-users-code4rena-fractional-fractional-git"
  incidentes:
    - "Fractional v2 (C4 2022) — batchDepositERC1155(from=victim) permite robar todos los tokens 1155 aprobados (High)"
```

---

## 14. ERC1155 en DeFi como colateral — callback durante liquidación

```yaml
- id: mt-014
  titulo: ERC1155 usado como colateral en lending — onERC1155Received permite reentrancia en liquidación
  causa_raiz: |
    Protocolos DeFi que aceptan ERC1155 como colateral (gaming items, LP positions,
    receipt tokens) deben transferir el colateral durante liquidaciones. La transferencia
    vía safeTransferFrom dispara onERC1155Received en el liquidador, que puede ser un
    contrato malicioso. Si la liquidación no actualiza estado (deuda, colateral) ANTES
    de la transferencia, el liquidador puede reentrar y manipular la posición.
  como_funciona: |
    1. Protocolo de lending acepta ERC1155 #42 como colateral.
    2. Posición cae underwater → liquidation triggered.
    3. Liquidación llama safeTransferFrom(vault, liquidator, 42, amount, "").
    4. Liquidator.onERC1155Received() reenter al protocolo:
       - Puede llamar borrow() (colateral aún no removido del registro).
       - Puede liquidar otra posición que depende del mismo colateral.
    5. Estado inconsistente: colateral transferido pero no removido del ledger.
  invariante: |
    // En liquidación: estado de colateral DEBE actualizarse ANTES de transferir el token
    function invariant_collateral_before_transfer(
        address borrower, uint256 tokenId
    ) internal {
        // Post-liquidation: collateral[borrower][tokenId] debe ser 0
        // ANTES de llamar safeTransferFrom
        assert(collateral[borrower][tokenId] == 0);
    }
  que_mirar:
    - "¿El protocolo acepta ERC1155 como colateral?"
    - "¿Liquidación usa safeTransferFrom o transferFrom sin callback?"
    - "¿Estado de colateral se actualiza antes o después de la transferencia?"
    - "grep: liquidat.*safeTransfer, seize.*safeTransfer"
    - "¿Hay nonReentrant en la función de liquidación?"
  como_se_arregla: |
    Actualizar registro de colateral ANTES de transferir el token (CEI pattern).
    Añadir nonReentrant a toda la cadena de liquidación.
    Considerar usar transferFrom sin callback cuando el liquidator es un contrato conocido.
    Pull pattern: liquidator llama claim() después de la liquidación en tx separada.
  trampas:
    - "ERC721 safeTransferFrom tiene el mismo problema — pero ERC1155 lo tiene DOBLE (single + batch)"
    - "El liquidador puede ser un contrato propio del atacante con onERC1155Received malicioso"
    - "Si el protocolo usa nonReentrant correctamente, este ataque no funciona"
  solodit_ids:
    - "erc1155-has-reentrancy-possibilities-code4rena-notional-notional-git"
  incidentes:
    - "Notional (C4 2021) — ERC1155Action.sol acepta colateral 1155 con reentrancy no mitigada (Medium)"
    - "Patrón genérico en lending protocols que aceptan NFTs/1155 como colateral"
```

---

## 15. ENS-style wrapper: transferFrom sin retorno silently fails → mint/burn desync

```yaml
- id: mt-015
  titulo: ERC1155 wrapper con transferFrom que falla silenciosamente — mint sin respaldo real
  causa_raiz: |
    Contratos que wrappean tokens ERC20/ERC721 dentro de un ERC1155 (ENS ERC20MultiDelegate,
    fractionalization contracts) llaman transferFrom() del token subyacente y luego
    mint() del ERC1155. Si transferFrom() no revierte en fallo sino que retorna false
    (o no retorna nada, como USDT), y el wrapper no verifica el retorno, se mintean
    tokens 1155 sin que el token subyacente realmente se haya transferido.
  como_funciona: |
    1. Wrapper llama token.transferFrom(user, wrapper, amount) — retorna false.
    2. Wrapper no usa SafeERC20, no verifica retorno.
    3. Wrapper llama _mint(user, wrappedId, amount, "") — ERC1155 tokens minteados.
    4. Wrapper tiene ERC1155 sin respaldo del token subyacente.
    5. Usuario (o atacante) puede redeem el 1155 → extrae tokens que nunca depositó.
    6. En ENS: transferFrom silently failing permite mint infinito de ERC1155 delegation tokens.
  invariante: |
    // Post-wrap: balanceOf(wrapper, underlyingToken) >= totalSupply(wrappedId)
    function invariant_wrapper_fully_backed(uint256 wrappedId) internal {
        uint256 backing = underlyingToken.balanceOf(address(wrapper));
        uint256 wrapped = totalSupply(wrappedId);
        assert(backing >= wrapped);
    }
  que_mirar:
    - "¿El wrapper usa SafeERC20 para las transferencias del token subyacente?"
    - "grep: transferFrom sin require() o SafeERC20 en contratos que mintean ERC1155"
    - "¿Tokens como USDT/BNB (sin return value) están en scope?"
    - "¿El wrapper verifica balance before/after en vez de confiar en return value?"
  como_se_arregla: |
    Usar SafeERC20.safeTransferFrom() para el token subyacente.
    O verificar balance antes/después: received = balanceAfter - balanceBefore.
    Solo mintear ERC1155 por la cantidad realmente recibida.
  trampas:
    - "Este bug combina dos patrones: token-004 (unchecked return) + 1155 minting — verificar ambos"
    - "En ENS, el ERC1155 representa voting power — inflation de 1155 = inflation de votos"
    - "Si el wrapper solo acepta tokens con return value, no es finding"
  solodit_ids:
    - "missing-check-for-return-values-of-transferfrom-can-cause-token-holders-to-lose-tokens-code4rena-ens-ens-git"
  incidentes:
    - "ENS ERC20MultiDelegate (C4 2023) — transferFrom sin check de retorno permite mint de ERC1155 delegation tokens sin respaldo (Medium)"
    - "RabbitHole (C4 2023) — cualquiera puede mint receipt NFTs de quest IDs existentes via modifier onlyMinter que no revierte (High)"
```

---

## 16. Soulbound / non-transferable tokens — bypass via burn+remint o approval

```yaml
- id: mt-016
  titulo: Tokens soulbound/locked bypassed via mecanismos alternativos de transferencia
  causa_raiz: |
    Implementaciones de soulbound tokens (ERC5192, custom locked flags) que bloquean
    transfer/safeTransferFrom pueden ser bypassed si:
    1. El usuario puede burn y otro puede remint (transfer efectivo).
    2. El approval mechanism no está bloqueado (approve → operator transfiere).
    3. Solo _transfer está bloqueado pero _mint/_burn no (bypass via intermediario).
    4. La restricción está en la función pública pero no en _beforeTokenTransfer.
  como_funciona: |
    Bypass 1 — Burn+Remint:
    1. Token soulbound: transferFrom bloqueado.
    2. Pero burn() es público (o accesible al owner).
    3. Atacante burn su soulbound → protocolo permite remint a otra dirección.
    4. Resultado: token "transferred" via burn+remint.

    Bypass 2 — Approval path:
    1. Token soulbound: safeTransferFrom(from, to, id, amt, data) bloqueado.
    2. Pero setApprovalForAll() no está bloqueado.
    3. Otro contrato con approval puede usar un path que no pasa por el check.
  invariante: |
    // Si un token está locked, NINGÚN mecanismo debe permitir moverlo
    function invariant_locked_means_locked(uint256 id) internal {
        if (locked(id)) {
            // No debe poder: transfer, burn, approve, safeBatchTransferFrom
            assert(ownerOf(id) == originalOwner[id]);
        }
    }
  que_mirar:
    - "¿La restricción está en _beforeTokenTransfer (cubre todo) o en funciones individuales?"
    - "¿burn() está bloqueado para tokens soulbound?"
    - "¿setApprovalForAll() está bloqueado para tokens soulbound?"
    - "grep: locked, soulbound, nonTransferable — ¿dónde se enforcea?"
    - "¿safeBatchTransferFrom está overrideado? (ver mt-005)"
  como_se_arregla: |
    Bloquear en _beforeTokenTransfer para cubrir TODOS los paths (transfer, batch, mint, burn).
    También bloquear approve/setApprovalForAll para tokens locked.
    Si burn es necesario (e.g., para revoke credential): que solo lo pueda hacer el issuer.
  trampas:
    - "ERC5192 es minimal — solo define locked() view function, no enforcea nada"
    - "El enforcement real depende de la implementación del protocolo, no del estándar"
    - "Algunos protocolos permiten burn de soulbound intencionalmente (e.g., revocar credencial)"
  solodit_ids: []
  incidentes:
    - "Múltiples implementaciones custom de soulbound tokens con bypass via safeBatchTransferFrom o burn+remint"
    - "AI Arena (C4 2024) — tokens non-transferable bypassed via batch transfer (High, relacionado con mt-005)"
```
