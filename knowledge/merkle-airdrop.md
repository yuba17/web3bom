# Merkle Proofs & Airdrop Mechanisms — Bug Patterns

## Quick Reference

```
grep_targets:
  - merkleRoot
  - merkleProof
  - MerkleProof
  - MerkleProofUpgradeable
  - MerkleDistributor
  - verify
  - verifyProof
  - verifyCalldata
  - claim
  - claimed
  - isClaimed
  - hasClaimed
  - claimedBitMap
  - setClaimed
  - claimAirdrop
  - claimTokens
  - canClaim
  - setMerkleRoot
  - updateMerkleRoot
  - proof
  - leaf
  - node
  - keccak256
  - abi.encodePacked
  - abi.encode
  - bytes32
  - getLeaf
  - computeLeaf
  - initializeDistributionRecord
  - sweepUnclaimed
  - claimPeriod
  - claimDeadline
  - vestedAmount
  - claimableAmount
  - cumulativeClaimed
  - bitmap
  - BitMaps
  - snapshot
  - snapshotId
  - balanceOfAt
  - totalSupplyAt
  - EIP712
  - DOMAIN_SEPARATOR
  - claimWithSignature
```

---

## 1. Double-Claim via Missing Claim Tracking

```yaml
- id: merkle-001
  titulo: Reclamaciones múltiples del airdrop por falta de tracking de claims
  causa_raiz: |
    El contrato de airdrop verifica el merkle proof correctamente pero no registra
    que el usuario ya reclamó sus tokens. Sin un mapping `hasClaimed[address]` o un
    bitmap de claims, el mismo usuario puede llamar `claim()` repetidamente con el
    mismo proof válido, drenando todo el balance del contrato de airdrop.
    Este es el bug más elemental y más común en implementaciones de merkle airdrops.
  como_funciona: |
    1. Contrato despliega con merkle root y balance de tokens para distribuir.
    2. Usuario legítimo llama `claim(proof, amount)` — proof verifica correctamente.
    3. Contrato transfiere `amount` tokens al usuario.
    4. No hay `claimed[msg.sender] = true` ni bitmap que marque el claim como usado.
    5. Usuario llama `claim(proof, amount)` de nuevo — el proof sigue siendo válido.
    6. Repite hasta drenar completamente el contrato.
    Variante: el tracking usa un mapping `address => bool` pero la clave es un
    parámetro controlable por el usuario (no `msg.sender`), permitiendo bypass.
  invariante: |
    // Después de un claim exitoso, el mismo usuario NO puede reclamar de nuevo
    // Pre: user no ha reclamado
    bool couldClaimBefore = !hasClaimed[user];
    claim(proof, user, amount);
    // Post: claim registrado
    assert(hasClaimed[user] == true);
    // Intentar reclamar de nuevo debe revertir
    // try claim(proof, user, amount) { assert(false); } catch {}
  que_mirar:
    - Función claim() sin require(!claimed[msg.sender]) o equivalente
    - Bitmap sin setBit después del claim exitoso
    - Tracking basado en un index que el usuario puede manipular
    - Contratos que solo verifican el proof sin estado persistente
    - Función initializeDistributionRecord() llamable múltiples veces
  como_se_arregla: |
    Usar bitmap (gas-eficiente para grandes distribuciones) o mapping address=>bool.
    Marcar ANTES de transferir tokens (check-effects-interactions).
    El patrón de Uniswap MerkleDistributor usa bitmap con index:
    `_setClaimed(index)` después de verificar `!isClaimed(index)`.
  trampas:
    - Asegurar que el index del bitmap corresponde 1:1 con cada leaf del árbol.
    - Si se usa un mapping, la clave debe ser msg.sender, NO un parámetro del calldata.
    - El tracking con signatures (ver merkle-013) necesita invalidar la signature usada.
    - Contratos upgradeable: verificar que el storage slot del bitmap no colisiona.
  solodit_ids:
    - "initializeDistributionrecord-can-be-called-multiple-times-sherlock-tokensoft-tokensoft-git"
    - "m-03-users-can-call-initializeDistributionRecord-to-mint-votingTokens-multiple-times-sherlock-tokensoft-git"
  incidentes:
    - "Tokensoft (Sherlock 2023) — initializeDistributionRecord() llamable múltiples veces, mintea voting tokens sin límite"
    - "Múltiples NFT minting contracts (2021-2022) — allowlist merkle sin tracking de claims, mint ilimitado"
    - "Wayfinder PROMPT airdrop (2025) — claim sin validación de destinatario permitió front-running masivo"
```

---

## 2. Merkle Tree Leaf Collision — Second Preimage Attack

```yaml
- id: merkle-002
  titulo: Colisión entre hojas y nodos internos del merkle tree (second preimage)
  causa_raiz: |
    En un merkle tree, los nodos internos son el hash de dos hijos concatenados
    (64 bytes). Si las hojas del árbol también son 64 bytes antes del hash, un
    atacante puede presentar un nodo interno como si fuera una hoja válida.
    Esto ocurre cuando leaf = keccak256(abi.encodePacked(a, b)) donde a y b son
    uint256 (32+32 = 64 bytes), sin double-hashing ni prefijo de dominio.
    OpenZeppelin documenta explícitamente este riesgo en MerkleProof.sol.
  como_funciona: |
    1. Árbol construido con hojas de 64 bytes: hash(uint256 clubId, uint256 tier).
    2. Nodo interno N = hash(hijo_izq || hijo_der) también es hash de 64 bytes.
    3. Atacante toma un nodo interno N y construye un proof válido donde N es la "hoja".
    4. El proof verifica correctamente porque hash(N_left || N_right) = N_parent.
    5. Atacante reclama tokens/NFTs para parámetros que nunca estuvieron en el árbol original.
    Ejemplo: si leaf = hash(address, amount), y address||amount tiene 64 bytes,
    el atacante puede forjar un claim con address y amount derivados de un nodo interno.
  invariante: |
    // Las hojas del merkle tree deben tener longitud != 64 bytes antes del hash,
    // o usar double-hashing: leaf = keccak256(abi.encodePacked(keccak256(abi.encode(data))))
    // Verificar que: abi.encode(address, uint256) = 64 bytes → VULNERABLE
    // Fix: bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
  que_mirar:
    - Hojas que son hash de exactamente 64 bytes (dos uint256, o address + uint256 packed)
    - Uso de abi.encodePacked para construir hojas con tipos de longitud variable
    - Ausencia de double-hashing (keccak256(keccak256(...)))
    - Código que ignora el warning de OpenZeppelin en MerkleProof.sol
    - abi.encodePacked(string, string) o (bytes, bytes) — colisiones por falta de delimitador
  como_se_arregla: |
    1. Double-hash las hojas: leaf = keccak256(bytes.concat(keccak256(abi.encode(data)))).
    2. O asegurar que las hojas nunca sean exactamente 64 bytes antes del hash.
    3. Usar abi.encode() en vez de abi.encodePacked() cuando hay tipos variables.
    4. OpenZeppelin >= 4.7 incluye verificación opcional con safeVerify().
    5. Agregar un prefijo de dominio: leaf = hash(0x00 || data), nodo = hash(0x01 || left || right).
  trampas:
    - address (20 bytes) + uint256 (32 bytes) = 52 bytes con encodePacked → NO vulnerable a second preimage.
    - Pero address + uint256 con abi.encode = 64 bytes (address padded a 32) → SÍ vulnerable.
    - uint256 + uint256 = 64 bytes → SIEMPRE vulnerable sin double-hash.
    - La explotabilidad depende de poder controlar los valores internos del nodo.
  solodit_ids:
    - "merkle-leaf-values-for-clubdivsmerkleroot-are-64-bytes-before-hashing-which-can-lead-to-merkle-tree-collisions-sherlock-footium-footium-git"
    - "merkle-leaves-are-the-same-length-as-the-parents-that-are-hashed-code4rena-factorydao-factorydao-contest-git"
  incidentes:
    - "Footium (Sherlock 2023) — clubId + divisionTier como uint256+uint256 = 64 bytes, colisión con nodos internos"
    - "FactoryDAO (C4 2022) — hojas de merkle del mismo tamaño que los nodos padres → colisión"
    - "OpenSea Seaport (C4 2022) — nodo intermedio del merkle tree aceptable como tokenId en offers"
    - "Paladin (Hats Finance) — leaf/node values de claim() son 64 bytes → colisión con nodos internos"
    - "CVE-2023-34459 — OpenZeppelin MerkleProof multiproofs: nodo con valor 0 en depth 1 permite probar hojas arbitrarias"
```

---

## 3. Front-Running de Claims de Airdrop (MEV)

```yaml
- id: merkle-003
  titulo: Front-running de claims — MEV bot roba airdrop redirigiendo destinatario
  causa_raiz: |
    Si la función claim() no vincula el proof al msg.sender (es decir, el campo
    "beneficiario" es un parámetro del calldata y no se valida contra msg.sender),
    un MEV bot puede observar la transacción de claim en el mempool, extraer el
    proof y los parámetros, y enviar una transacción idéntica pero con su propia
    dirección como beneficiario. El proof sigue siendo válido porque no incluye
    al msg.sender, solo al beneficiario original que ahora el bot puede cambiar.
  como_funciona: |
    1. Usuario legítimo envía tx: claim(proof, amount) al mempool.
    2. MEV bot "Yoink" detecta la tx, extrae el proof y amount.
    3. Bot envía claim(proof, amount) con gas más alto, pero cambiando el beneficiario.
    4. Si claim() envía tokens a un parámetro `recipient` sin validar msg.sender:
       - Bot recibe los tokens
       - Tx del usuario falla (si hay claim tracking) o también reclama (double-drain)
    5. Variante: el proof incluye la dirección, pero claim() acepta un `recipient`
       separado del `account` del proof → bot llama claim(proof, victimAddress, botAddress).
  invariante: |
    // El destinatario de los tokens DEBE ser el address codificado en el leaf del merkle proof
    // Y debe validarse contra msg.sender o incluir una signature del beneficiario
    function claim(bytes32[] proof, address account, uint256 amount) external {
        require(account == msg.sender, "can only claim for yourself");
        bytes32 leaf = keccak256(abi.encode(account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
        // ...
    }
  que_mirar:
    - claim() con parámetro `recipient` separado del address en el leaf
    - Ausencia de require(msg.sender == account) en la función claim
    - Proofs que no codifican ningún address — cualquiera puede usar el proof
    - Funciones claim() sin protección contra front-running (no usan Flashbots/private mempool)
    - Contratos que permiten "claim on behalf of" sin signature del beneficiario
  como_se_arregla: |
    1. Vincular el proof a msg.sender: leaf = hash(msg.sender, amount).
    2. O requerir firma del beneficiario: claimWithSignature(proof, signature).
    3. Usar commit-reveal scheme para el claim (dos txs pero resistente a MEV).
    4. Desplegar en L2 con sequencer (menor riesgo de MEV público).
    5. Si se permite "claim on behalf", el destinatario debe ser el address del leaf.
  trampas:
    - Incluso con msg.sender check, si el proof se genera off-chain y se publica
      en un frontend, el bot puede front-runear el RPC call al backend.
    - Protección real requiere private mempool (Flashbots Protect) o commit-reveal.
    - En chains con sequencer centralizado (Optimism, Base), el riesgo de MEV público es menor.
    - "Claim on behalf" es un feature legítimo para meta-transacciones, pero debe enviar
      tokens al address del leaf, no a msg.sender.
  solodit_ids: []
  incidentes:
    - "Wayfinder PROMPT (2025) — MEV bot 'Yoink' robó ~$200K frontruneando claims del airdrop de Kaito yappers. El contrato TokenTable no vinculaba el proof a msg.sender."
    - "Múltiples NFT mints (2021-2022) — bots monitorizaban mempool y mintaban con proofs extraídos de txs pendientes"
```

---

## 4. Actualización de Merkle Root sin Invalidar Claims Anteriores

```yaml
- id: merkle-004
  titulo: Nuevo merkle root permite que proofs del root anterior sigan siendo válidos
  causa_raiz: |
    Cuando el admin actualiza el merkle root (para agregar/remover beneficiarios
    o cambiar amounts), el contrato no invalida los claims anteriores ni resetea
    el bitmap de claims. Esto abre dos vectores:
    1. Si el bitmap NO se resetea: usuarios del árbol anterior que ya reclamaron
       pueden reclamar de nuevo si su leaf aparece en el nuevo árbol con el mismo index.
    2. Si el bitmap SÍ se resetea: todos los usuarios que reclamaron con el root
       anterior pueden reclamar de nuevo si sus datos se mantienen en el nuevo árbol.
    En airdrops "cumulativos" (merkle root actualizable con totales acumulados),
    la confusión entre "total asignado" y "reclamable pendiente" es frecuente.
  como_funciona: |
    Escenario 1 — bitmap no reseteado:
    1. Root v1: Alice (index 0, 100 tokens). Alice reclama → bit 0 marcado.
    2. Admin sube Root v2 (nuevo árbol). Alice sigue en index 0 con 100 tokens.
    3. Bit 0 sigue marcado → Alice NO puede reclamar → pierde tokens legítimos.
    Escenario 2 — bitmap reseteado:
    1. Root v1: Alice reclama 100 tokens.
    2. Admin sube Root v2 + resetea bitmap.
    3. Alice reclama 100 tokens de nuevo → doble pago.
    Escenario 3 — cumulative distributor sin delta:
    1. Root v1: Alice total = 100. Alice reclama 100.
    2. Root v2: Alice total = 150 (50 nuevos). Contrato envía 150 - cumulativeClaimed.
    3. Si cumulativeClaimed no se actualiza correctamente → Alice recibe 150 en vez de 50.
  invariante: |
    // En distribuidor cumulative:
    // claimable = merkleTotal - cumulativeClaimed[user]
    // Después de claim: cumulativeClaimed[user] += claimable
    // Total reclamado por user NUNCA debe exceder merkleTotal del root actual
    assert(cumulativeClaimed[user] <= merkleTotal);
  que_mirar:
    - Función setMerkleRoot() o updateMerkleRoot() — qué pasa con claims existentes
    - Si el bitmap se resetea o no cuando cambia el root
    - Distribuidores "cumulative" — cómo calculan el delta pendiente
    - Tracking de versión del root (epoch/round) sin tracking por usuario por epoch
    - Funciones claim() que no verifican contra qué root se generó el proof
  como_se_arregla: |
    Para airdrops con root actualizable, usar el patrón cumulative:
    - Leaf = hash(address, totalAllocated). El total solo crece.
    - claimable = totalAllocated - cumulativeClaimed[address].
    - cumulativeClaimed se incrementa, nunca se resetea.
    Para airdrops de un solo round: no permitir actualización de root después del deployment.
    Si se necesitan múltiples rounds: un contrato por round, o epoch tracking explícito.
  trampas:
    - El patrón cumulative de 1inch (merkle-distribution) es el estándar seguro.
    - Si se reduce la asignación de un usuario en un nuevo root (merkleTotal < cumulativeClaimed),
      el underflow puede revertir o wrapar — manejar explícitamente.
    - Off-chain: el frontend/backend debe re-generar proofs para todos los usuarios
      cuando cambia el root, no solo para los nuevos.
  solodit_ids:
    - "merkle-tree-related-contracts-vulnerable-to-cross-chain-replay-attacks-code4rena-factorydao-factorydao-contest-git"
  incidentes:
    - "Lido VettedGate (C4 2025) — root update mid-season invalida todos los proofs previos, usuarios deben obtener proofs nuevos"
    - "Múltiples distribuidores cumulative — confusión entre total asignado y pendiente por reclamar"
```

---

## 5. Replay Cross-Chain de Proofs de Airdrop

```yaml
- id: merkle-005
  titulo: Mismo merkle proof válido en múltiples chains — replay cross-chain
  causa_raiz: |
    El leaf del merkle tree no incluye el chainId ni la dirección del contrato
    de distribución. Si el mismo contrato (o un fork) se despliega en múltiples
    chains con el mismo merkle root, un atacante puede usar el mismo proof para
    reclamar en todas las chains. Incluso si son contratos diferentes, si comparten
    el mismo root (ej: airdrop multi-chain), el proof es reutilizable.
  como_funciona: |
    1. Protocolo despliega MerkleDistributor en Ethereum y Arbitrum con el mismo root.
    2. Leaf = hash(address, amount) — sin chainId ni contract address.
    3. Alice reclama en Ethereum con proof P.
    4. Alice (o atacante) usa el mismo proof P en Arbitrum → reclama de nuevo.
    5. Si el contrato tiene balance en ambas chains, doble cobro.
    Variante: después de un hard fork, el contrato existe en ambas chains.
    Cualquier claim en una chain se puede replicar en la otra.
  invariante: |
    // El leaf DEBE incluir chainId y dirección del contrato distribuidor
    bytes32 leaf = keccak256(abi.encode(
        block.chainid,
        address(this),
        account,
        amount
    ));
    // Esto garantiza que el proof solo es válido en esta chain y este contrato
  que_mirar:
    - Leaf que solo contiene (address, amount) sin chain-specific data
    - Protocolos multi-chain que comparten el mismo merkle root
    - Contratos desplegados con CREATE2 en la misma dirección en múltiples chains
    - Ausencia de block.chainid o address(this) en la construcción del leaf
    - Airdrops que se lanzan post-fork sin considerar la chain paralela
  como_se_arregla: |
    Incluir en el leaf: chainId + address(distributor) + account + amount.
    O usar un root diferente por chain (generado off-chain con parámetros por chain).
    Si es EIP-712 signed claim: el DOMAIN_SEPARATOR ya incluye chainId + contract address.
    Para forks: tener un mecanismo de pausa que se active si se detecta un fork.
  trampas:
    - block.chainid se puede cachear en el constructor → si hay fork, el chainId cacheado
      puede ser el mismo en ambas chains hasta que se actualice.
    - CREATE2 produce la misma dirección en chains con el mismo factory → address(this)
      no es suficiente como protección sin chainId.
    - En L2 rollups, el chainId suele ser diferente al L1, pero verificar explícitamente.
  solodit_ids:
    - "merkle-tree-related-contracts-vulnerable-to-cross-chain-replay-attacks-code4rena-factorydao-factorydao-contest-git"
  incidentes:
    - "FactoryDAO (C4 2022) — contratos de merkle vesting vulnerables a replay cross-chain porque leaf no incluye chainId"
    - "Múltiples airdrops post-merge (2022) — proofs reutilizados en ETHPoW fork"
```

---

## 6. abi.encodePacked Collision en Leaf Encoding

```yaml
- id: merkle-006
  titulo: Colisión de hash en hojas merkle por uso de abi.encodePacked con tipos variables
  causa_raiz: |
    abi.encodePacked no incluye padding ni información de tipo, lo que permite
    colisiones cuando se concatenan tipos de longitud variable. Ejemplo clásico:
    abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc") == 0x616263.
    En merkle trees, si la hoja usa encodePacked con strings, bytes, o arrays
    dinámicos, un atacante puede forjar una hoja que produce el mismo hash con
    parámetros diferentes. Esto es distinto de merkle-002 (second preimage).
  como_funciona: |
    1. Leaf = keccak256(abi.encodePacked(name, role)) donde name y role son strings.
    2. Árbol tiene leaf para ("Alice", "Admin").
    3. Atacante construye leaf para ("AliceA", "dmin") — misma codificación packed.
    4. Hash idéntico → proof de "Alice,Admin" funciona para "AliceA,dmin".
    5. Si el contrato usa los parámetros decodificados (no el leaf) para lógica:
       atacante reclama con parámetros manipulados que pasan la verificación.
    Caso realista en airdrops: leaf = hash(encodePacked(address, tokenAddress, amount))
    donde tokenAddress es bytes20 → colisión con otro address + otro token.
  invariante: |
    // NUNCA usar abi.encodePacked con tipos de longitud variable en merkle leaves
    // SIEMPRE usar abi.encode que incluye padding y length prefixes
    bytes32 leafSafe = keccak256(abi.encode(account, amount, token));
    // O si se necesita encodePacked, asegurar que TODOS los tipos son fixed-size:
    bytes32 leafOk = keccak256(abi.encodePacked(uint256(x), address(y), uint256(z)));
  que_mirar:
    - abi.encodePacked con string, bytes, o tipos dinámicos en construcción de leaf
    - Concatenación manual de bytes sin delimitadores
    - Funciones que mezclan tipos fixed (uint256, address) y variable (string) en encodePacked
    - Off-chain: script de generación del árbol que usa codificación diferente al contrato
  como_se_arregla: |
    Usar abi.encode() siempre que el leaf contenga tipos de longitud variable.
    Si todos los tipos son fixed-size (address, uint256, bool), abi.encodePacked es seguro
    PERO cuidado con la longitud total (ver merkle-002 para el riesgo de 64 bytes).
    Alternativa: incluir un separator/delimiter entre campos variables.
  trampas:
    - address es 20 bytes con encodePacked, 32 bytes con encode — la diferencia importa.
    - Solidity compiler genera warning para abi.encodePacked con tipos variables desde 0.8.x.
    - El riesgo real depende de si el atacante controla los parámetros de la hoja.
    - Si la hoja solo tiene (address, uint256), encodePacked es 52 bytes → no 64 → seguro vs second preimage.
  solodit_ids:
    - "hash-collisions-when-using-abi-encodepacked-with-multiple-variable-length-arguments-swc-registry"
    - "abi-encodepacked-allows-hash-collision-leading-to-miscalculation-of-funds-and-protocol-malfunction-sherlock-debita-debita-git"
  incidentes:
    - "Debita (Sherlock 2024) — abi.encodePacked() con argumentos variables permite colisión de hash → miscalculation de fondos"
    - "SWC-133 (SWC Registry) — patrón documentado como vulnerabilidad conocida de Solidity"
    - "Nethermind research (2024) — análisis detallado de colisiones con encodePacked en contratos de producción"
```

---

## 7. Snapshot Timing Manipulation para Elegibilidad de Airdrop

```yaml
- id: merkle-007
  titulo: Manipulación de balance justo antes del snapshot para calificar al airdrop
  causa_raiz: |
    Los airdrops retroactivos se basan en snapshots de balance en un bloque específico.
    Si el bloque del snapshot es conocido de antemano (anunciado públicamente o
    predecible), un atacante puede:
    1. Pedir un flash loan de tokens/NFTs justo antes del bloque.
    2. Holdear durante el snapshot.
    3. Devolver el loan inmediatamente después.
    El atacante aparece como holder legítimo en el snapshot y califica para el airdrop.
    Si el snapshot NO se basa en bloque sino en balanceOf() spot, es aún peor.
  como_funciona: |
    1. Protocolo anuncia: "snapshot en bloque N para holders con >= 10 tokens".
    2. Atacante monitorea y en bloque N-1: compra/presta 10 tokens.
    3. En bloque N: atacante tiene 10 tokens → incluido en merkle tree.
    4. En bloque N+1: atacante vende/devuelve los tokens.
    5. Atacante reclama airdrop con proof legítimo del snapshot.
    Variante con flash loan: si el snapshot usa un hook en la misma transacción
    (ej: callback que checkea balance), atacante usa flash loan intratransacción.
    Ejemplo real: APE airdrop — atacante usó flash loan de BAYC NFTs para reclamar ApeCoin.
  invariante: |
    // El snapshot DEBE usar mecanismo a prueba de manipulación intratransacción
    // Usar ERC20Snapshot de OpenZeppelin (snapshot por bloque, no por tx)
    // O verificar que el holder mantuvo el balance por N bloques mínimo
    // Anti-flashloan: balanceOfAt(account, snapshotBlock) requiere que el balance
    // haya sido establecido ANTES del bloque del snapshot
    require(balanceOfAt(user, snapshotBlock) >= minBalance, "not eligible");
    // Verificación adicional: balance promedio over N bloques
  que_mirar:
    - Snapshot basado en balanceOf() spot (no snapshotted) — manipulable intratx
    - Bloque de snapshot anunciado antes del evento — permite gaming
    - NFT-based airdrops que verifican ownership spot, no historical
    - Ausencia de time-weighted average balance (TWAB) para elegibilidad
    - Flash loan de NFTs (NFTX, BendDAO) para reclamar airdrops basados en ownership
  como_se_arregla: |
    1. Snapshot secreto: no anunciar el bloque hasta después de tomado.
    2. Usar balance promedio (TWAB) sobre ventana de N bloques/días.
    3. ERC20Snapshot con snapshotting periódico, no predecible.
    4. Para NFTs: verificar ownership durante M bloques consecutivos.
    5. Anti-flash-loan: blacklistear protocolos de lending de NFTs en la verificación.
    6. Usar Chainlink VRF para elegir bloque de snapshot aleatorio en un rango.
  trampas:
    - ERC20Snapshot de OZ ya está deprecated — usar ERC20Votes con checkpoints.
    - Flash loans de NFTs (NFTX vaults, BendDAO) hacen esto trivialmente explotable.
    - Incluso sin flash loans, "snapshot sniping" (comprar justo antes) es gaming legítimo
      pero puede considerarse unfair — no siempre es un bug de smart contract.
    - Airdrops basados en on-chain activity (txs, gas used) son más difíciles de gamear.
  solodit_ids: []
  incidentes:
    - "APE/ApeCoin airdrop (2022) — flash loan de BAYC NFTs vía NFTX para reclamar APE tokens, ~$1.1M extraídos"
    - "Blur airdrop Season 1 (2023) — sybil farming masivo con cuentas múltiples que tradeaban NFTs entre sí para acumular puntos"
    - "Optimism OP airdrop (2022) — criterios de elegibilidad basados en actividad on-chain, pero el snapshot block fue publicado → gaming masivo"
```

---

## 8. Vesting Cliff en Airdrop Claims — Reclamación Prematura

```yaml
- id: merkle-008
  titulo: Tokens de airdrop reclamables antes del cliff de vesting
  causa_raiz: |
    Muchos airdrops incluyen vesting schedules (ej: 25% disponible inmediatamente,
    75% con vesting lineal durante 12 meses). Si la lógica de vesting se implementa
    incorrectamente — o peor, si el merkle proof solo verifica la asignación total
    sin considerar el schedule — el usuario puede reclamar el 100% inmediatamente.
    Variante: el cliff no se enforce on-chain, solo off-chain en el frontend.
  como_funciona: |
    1. Airdrop con vesting: 1000 tokens asignados, cliff de 3 meses, vesting 12 meses.
    2. Leaf = hash(address, 1000) — sin datos de vesting en el proof.
    3. claim(proof, 1000) verifica contra el merkle root → válido.
    4. Contrato transfiere 1000 tokens inmediatamente — no hay lógica de vesting on-chain.
    5. El "vesting" solo existía en la documentación o frontend.
    Variante: contrato tiene vesting pero usa block.timestamp mal:
    - cliff = deployTime + 90 days, pero deployTime es 0 (no inicializado) → cliff ya pasó.
    - vestedAmount calcula mal el progreso: usa totalTime en vez de elapsed time.
  invariante: |
    // Antes del cliff, el usuario NO puede reclamar nada
    // Después del cliff, solo puede reclamar la porción vested
    uint256 elapsed = block.timestamp - startTime;
    uint256 claimable;
    if (elapsed < cliff) {
        claimable = 0;
    } else {
        claimable = totalAllocation * elapsed / vestingDuration;
    }
    uint256 pending = claimable - alreadyClaimed[user];
    assert(pending <= claimable);
    assert(alreadyClaimed[user] + pending <= totalAllocation);
  que_mirar:
    - Merkle leaf que solo incluye (address, totalAmount) sin parámetros de vesting
    - Lógica de vesting separada del claim — ¿qué pasa si se llama claim directamente?
    - startTime no inicializado (default 0) → vesting ya terminó al deployar
    - cliff implementado en el frontend pero no en el contrato
    - vestedAmount que retorna totalAmount si block.timestamp > algún threshold
  como_se_arregla: |
    Incluir parámetros de vesting en el leaf: hash(address, total, cliff, duration, start).
    O manejar el vesting a nivel de contrato con schedule uniforme para todos.
    Validar on-chain: require(block.timestamp >= startTime + cliff).
    Usar SafeMath / checks para evitar que elapsed > duration cause overflows.
  trampas:
    - Si el vesting está en el leaf, el proof se vuelve más pesado y costoso en gas.
    - Alternativa: parámetros de vesting global en storage, solo amount en el leaf.
    - Cuidado con block.timestamp manipulation por miners (±15 seg en Ethereum, irrelevante para vestings de meses).
    - Sushi MerkleTreeClawback — ejemplo de merkle + vesting combinados correctamente.
  solodit_ids:
    - "multiple-vestings-for-the-same-user-will-fail-code4rena-factorydao-factorydao-contest-git"
  incidentes:
    - "FactoryDAO (C4 2022) — múltiples vestings para el mismo usuario fallan, lógica de vesting acoplada al merkle de forma incorrecta"
    - "Truflation (Sherlock 2023) — cancelVesting no entrega fondos unvested a usuarios aunque giveUnclaimed=true"
    - "Sushi MerkleTreeClawback (2023) — ejemplo de implementación correcta de merkle + vesting con cliff"
```

---

## 9. Whitelist Bypass via Proof para Zero Amount

```yaml
- id: merkle-009
  titulo: Proof de merkle para amount=0 permite bypass de whitelist sin beneficio aparente
  causa_raiz: |
    Si el merkle tree incluye entradas con amount=0 (ej: usuarios removidos pero
    no eliminados del árbol, o entradas de testing), un atacante puede usar el proof
    de amount=0 para pasar la verificación de merkle. Esto le da "membership" en
    la whitelist aunque no reciba tokens directamente. Si la función claim()
    tiene efectos secundarios al pasar la verificación (registrar membership,
    mintear NFTs de governance, obtener roles), el atacante los obtiene gratis.
  como_funciona: |
    1. Merkle tree incluye leaf (address_test, amount=0) para testing.
    2. Atacante descubre el proof para esta leaf (off-chain, calculable si conoce el árbol).
    3. Atacante llama claim(proof, address_test, 0) — proof verifica contra el root.
    4. Contrato procesa el claim: no transfiere tokens (amount=0) pero:
       a. Registra al atacante como "claimed" → acceso a features post-airdrop
       b. Mintea un NFT de membership/governance
       c. Incrementa un contador que afecta recompensas futuras
    5. Atacante tiene acceso sin haber recibido ni pagado nada.
    Variante: amount no es 0 pero es dust (1 wei) → proof válido, membership obtenida
    con costo insignificante.
  invariante: |
    // Requerir que amount > 0 en el claim para evitar claims vacíos
    function claim(bytes32[] proof, uint256 amount) external {
        require(amount > 0, "zero claim");
        require(amount >= MIN_CLAIM_AMOUNT, "below minimum");
        // ... verificación merkle ...
    }
    // En la generación del árbol: excluir entradas con amount == 0
  que_mirar:
    - Función claim() que no valida amount > 0
    - Efectos secundarios del claim más allá de transferir tokens (minting, registros, roles)
    - Merkle trees generados con entradas de testing o vacías
    - Contratos que usan "merkle-verified" como gate para otras funcionalidades
    - NFT minting whitelists donde "estar en el merkle" da derechos de mint
  como_se_arregla: |
    1. require(amount > 0) o require(amount >= MIN_AMOUNT) en claim().
    2. Generar el árbol sin entradas de amount=0.
    3. Separar la verificación de membership de la distribución de tokens.
    4. Si el claim tiene side effects, evaluar si amount=0 debería activarlos.
  trampas:
    - En NFT whitelists, el "amount" suele ser la cantidad de NFTs que puede mintear.
      amount=0 puede no existir, pero amount=1 con mint price=0 es equivalente.
    - Algunos protocolos usan amount=0 intencionalmente para "invalidar" una entrada
      sin regenerar el árbol — esto es un design choice, no un bug.
    - La explotabilidad depende enteramente de los side effects del claim.
  solodit_ids: []
  incidentes:
    - "Múltiples NFT minting contracts (2021-2022) — whitelists con entradas residuales permitían mint no autorizado"
```

---

## 10. Gas DoS en Batch Claims con Arrays de Proofs

```yaml
- id: merkle-010
  titulo: DoS por gas en funciones de batch claim con múltiples proofs
  causa_raiz: |
    Funciones que permiten reclamar múltiples airdrops en una transacción
    (batchClaim, multiClaim) iteran sobre un array de proofs sin límite de longitud.
    Cada verificación de proof requiere O(log N) hashes donde N es el número de hojas.
    Con arrays grandes, la transacción excede el gas limit del bloque.
    Si la función es requerida para un proceso crítico (ej: governance vote que
    depende de haber reclamado), el DoS bloquea funcionalidad.
  como_funciona: |
    1. Protocolo implementa batchClaim(ClaimData[] calldata claims) para eficiencia.
    2. Cada ClaimData contiene: proof (bytes32[]), amount, index.
    3. Para un árbol con 1M hojas, cada proof tiene ~20 hashes.
    4. batchClaim con 1000 claims = 20,000 keccak256 + 1000 bitmap checks + 1000 transfers.
    5. Gas consumption excede el block gas limit → transacción revierte.
    6. Si no hay alternativa de claim individual, usuarios no pueden reclamar.
    Variante: una sola llamada claim() con un proof array enorme (proof falso con miles
    de hashes) que consume gas aunque el proof sea inválido → grief attack.
  invariante: |
    // Limitar la longitud del array de batch claims
    function batchClaim(ClaimData[] calldata claims) external {
        require(claims.length <= MAX_BATCH_SIZE, "batch too large");
        for (uint i; i < claims.length; ++i) {
            require(claims[i].proof.length <= MAX_PROOF_DEPTH, "proof too deep");
            _claim(claims[i]);
        }
    }
  que_mirar:
    - Funciones batchClaim/multiClaim sin require(array.length <= MAX)
    - Proof arrays sin límite de profundidad — un proof falso de 10,000 hashes consume gas
    - Loops sobre arrays de claims que hacen external calls (transfer + proof verify)
    - Admin-only functions que procesan todos los claims pendientes en una tx
  como_se_arregla: |
    1. Limitar batch size: MAX_BATCH_SIZE = 50-100 claims por tx.
    2. Limitar proof depth: MAX_PROOF_DEPTH = ceil(log2(totalLeaves)) + 1.
    3. Proveer siempre una función claim individual como fallback.
    4. Validar proof length antes de iterar: require(proof.length <= 32).
  trampas:
    - La verificación de proof consume ~600 gas por hash → un proof de 20 niveles
      cuesta ~12,000 gas → 100 claims en batch = ~1.5M gas → aceptable.
    - El riesgo real es cuando el batch incluye transfers (ERC20.transfer puede costar
      20K+ gas si es primera vez) → 100 transfers = 2M gas adicional.
    - En L2 con gas limit alto (Arbitrum ~32M, Base ~60M), el riesgo es menor.
  solodit_ids: []
  incidentes:
    - "Múltiples protocolos DeFi — funciones de batch processing sin límite de array causan DoS recurrentemente"
```

---

## 11. Confusión Cumulative vs Per-Claim en Merkle Distributors

```yaml
- id: merkle-011
  titulo: Confusión entre total acumulado y monto por claim en distribuidores merkle
  causa_raiz: |
    Existen dos modelos de merkle distributor:
    1. **Per-claim**: cada leaf = hash(address, amountThisRound). Cada root es independiente.
    2. **Cumulative**: cada leaf = hash(address, totalAllocatedEver). El contrato trackea
       cumulativeClaimed[address] y envía el delta.
    La confusión entre modelos causa pérdida de fondos: si el contrato asume per-claim
    pero el root es cumulative, envía el total en cada round. Si asume cumulative pero
    el root es per-claim, el delta es negativo/cero en rounds posteriores.
  como_funciona: |
    Escenario 1 — Contrato per-claim con root cumulative:
    1. Root round 1: Alice totalAllocated = 100. claim(100) → recibe 100. OK.
    2. Root round 2: Alice totalAllocated = 250. claim(250) → recibe 250 en vez de 150.
    3. Alice recibe 350 total, debería ser 250.
    Escenario 2 — Contrato cumulative con root per-claim:
    1. Root round 1: Alice amount = 100. claim → recibe 100. cumulativeClaimed = 100.
    2. Root round 2: Alice amount = 80. claim → claimable = 80 - 100 = underflow → revert.
    3. Alice no puede reclamar en round 2.
  invariante: |
    // Para modelo cumulative:
    // totalClaimed[user] NUNCA excede el allocation del último root
    assert(totalClaimed[user] <= currentMerkleAllocation[user]);
    // El delta enviado es: currentMerkleAllocation - totalClaimed (pre-claim)
    uint256 delta = allocation - totalClaimed[user];
    assert(delta >= 0); // allocation debe ser monotónicamente creciente
  que_mirar:
    - Cómo se genera el root off-chain (cumulative vs per-round amounts)
    - Si el contrato compara con cumulativeClaimed o no
    - Función setMerkleRoot que se llama en cada round — qué storage se resetea
    - Documentation vs implementation mismatch
    - Tests que solo prueban un round (no detectan el bug)
  como_se_arregla: |
    Elegir un modelo y ser consistente end-to-end (contract + off-chain script + tests):
    - Cumulative (recomendado para múltiples rounds): leaf = totalAllocated,
      contrato envía delta = totalAllocated - cumulativeClaimed.
    - Per-claim: un contrato/root por round, tracking independiente.
    Documentar explícitamente qué modelo se usa.
    Tests con múltiples rounds obligatorios.
  trampas:
    - 1inch merkle-distribution es el estándar de facto para cumulative — revisarlo.
    - En modelo cumulative, la asignación solo puede CRECER. Si un usuario pierde
      elegibilidad, no se puede reducir su totalAllocated sin causar issues.
    - El modelo per-claim es más simple pero requiere un contrato/deployment por round.
  solodit_ids: []
  incidentes:
    - "Múltiples proyectos DeFi — confusión entre modelos cumulative/per-claim en distribuidores con múltiples rounds"
    - "Penguin Finance / Jito distributor — implementaciones de referencia de modelo cumulative"
```

---

## 12. Admin Key Comprometida — sweepUnclaimed y Root Manipulation

```yaml
- id: merkle-012
  titulo: Admin key comprometida permite drenar tokens no reclamados o cambiar root
  causa_raiz: |
    Los contratos de airdrop suelen tener funciones admin para:
    1. sweepUnclaimed() — recuperar tokens no reclamados después del deadline
    2. setMerkleRoot() — actualizar el root para correcciones
    3. pause()/unpause() — control de emergencia
    Si el admin key se compromete, el atacante puede: cambiar el root a uno que
    le asigna todos los tokens, o llamar sweepUnclaimed() prematuramente,
    o pausar para bloquear claims legítimos mientras drena por otro path.
  como_funciona: |
    Caso ZKsync (real, abril 2025):
    1. Admin key de 3 contratos de Merkle distribution comprometida.
    2. Atacante llama sweepUnclaimed() — mintea 111M ZK tokens no reclamados ($5M).
    3. Tokens existían como "unclaimed" del airdrop de junio 2024.
    4. Atacante liquida en DEX antes de que se detecte.
    5. Protocolo negocia: atacante devuelve 90% a cambio de 10% de bounty.
    Variante: atacante llama setMerkleRoot(atackerRoot) donde atackerRoot asigna
    100% de los tokens a su address, luego claim() → drena el contrato.
  invariante: |
    // sweepUnclaimed solo permitido después del deadline Y por multisig/timelock
    function sweepUnclaimed(address to) external onlyOwner {
        require(block.timestamp > claimDeadline, "claims still active");
        require(to == treasury, "can only sweep to treasury"); // hardcoded
        // ...
    }
    // setMerkleRoot con timelock
    function setMerkleRoot(bytes32 newRoot) external onlyOwner {
        require(pendingRoot == newRoot, "must go through timelock");
        // ...
    }
  que_mirar:
    - sweepUnclaimed() sin deadline check — admin puede drenar en cualquier momento
    - setMerkleRoot() sin timelock ni multisig — cambio instantáneo de beneficiarios
    - Admin functions con EOA (externally owned account) en vez de multisig
    - onlyOwner en funciones críticas sin time-delayed execution
    - Funciones de emergencia que permiten transferir tokens arbitrariamente
  como_se_arregla: |
    1. sweepUnclaimed() solo ejecutable después de claim deadline + buffer.
    2. setMerkleRoot() con timelock de 48h mínimo para que usuarios puedan reaccionar.
    3. Admin debe ser multisig (Gnosis Safe) con 3/5 threshold mínimo.
    4. Considerar hacer el root inmutable después del deployment (más seguro pero inflexible).
    5. Implementar pausability con timelock para evitar pause-and-drain attacks.
  trampas:
    - "El admin es trusted" es la defensa típica, pero trust assumptions
      se rompen cuando las keys se comprometen — que es exactamente lo que pasó con ZKsync.
    - Bug bounties suelen excluir "admin compromise" — verificar scope antes de reportar.
    - El riesgo es proporcional al valor de tokens no reclamados en el contrato.
    - Timelock protege contra compromiso rápido pero no contra atacante persistente.
  solodit_ids: []
  incidentes:
    - "ZKsync (abril 2025) — admin key comprometida, 111M ZK tokens ($5M) drenados via sweepUnclaimed() de 3 contratos merkle"
    - "Optimism OP (2022) — $15M en OP robados vía compromiso de market maker key (no merkle directo, pero mismo vector de admin key)"
```

---

## 13. EIP-712 Signature Replay en Claims con Firma

```yaml
- id: merkle-013
  titulo: Replay de signatures en claims de airdrop que usan EIP-712
  causa_raiz: |
    Algunos airdrops permiten "claim via signature" donde un tercero (relayer/meta-tx)
    envía la transacción en nombre del beneficiario. El beneficiario firma un mensaje
    EIP-712 autorizando el claim. Si la implementación no incluye nonce, deadline,
    o no invalida la firma después del uso, la misma firma puede replayearse.
    Vectores: replay en la misma chain, replay cross-chain, replay después de
    revocación de permisos.
  como_funciona: |
    1. Alice firma mensaje EIP-712: "Claim 1000 tokens to Alice" (sin nonce ni deadline).
    2. Relayer Bob envía claimWithSignature(Alice, 1000, signature) → Alice recibe tokens.
    3. Si no hay tracking de signatures usadas:
       - Bob (o cualquiera) envía la misma tx de nuevo → Alice recibe 1000 más.
    4. Variante cross-chain: DOMAIN_SEPARATOR no incluye chainId.
       - Misma firma válida en Ethereum y Arbitrum → doble claim.
    5. Variante revocación: Alice fue removida del whitelist pero su firma vieja
       sigue siendo válida → reclama después de la revocación.
  invariante: |
    // Claim con signature DEBE incluir: nonce + deadline + chainId
    bytes32 structHash = keccak256(abi.encode(
        CLAIM_TYPEHASH,
        account,
        amount,
        nonces[account]++,  // nonce auto-incrementing
        deadline
    ));
    bytes32 digest = _hashTypedDataV4(structHash); // incluye DOMAIN_SEPARATOR con chainId
    address signer = ECDSA.recover(digest, signature);
    require(signer == account, "invalid signature");
    require(block.timestamp <= deadline, "expired");
  que_mirar:
    - claimWithSignature() sin nonce — misma firma reutilizable
    - DOMAIN_SEPARATOR sin chainId — replay cross-chain
    - Signatures sin deadline/expiry — válidas indefinidamente
    - ecrecover que retorna address(0) sin validar — cualquier firma inválida "verifica"
    - Nonce que no se incrementa después de uso exitoso
    - OpenZeppelin < 4.7.3 — vulnerable a signature malleability (s-value manipulation)
  como_se_arregla: |
    1. Incluir nonce per-usuario en el struct hash — incrementar ANTES de transferir.
    2. Incluir deadline en la firma — rechazar firmas expiradas.
    3. Usar EIP-712 DOMAIN_SEPARATOR con chainId y verifyingContract.
    4. Validar que ecrecover retorna address != 0.
    5. Usar OpenZeppelin ECDSA.recover() que hace esta validación.
    6. Considerar EIP-2612 como referencia de implementación correcta.
  trampas:
    - EIP-712 DOMAIN_SEPARATOR incluye chainId por defecto — pero si se cachea en
      el constructor y hay un fork, el chainId cacheado es incorrecto.
    - OpenZeppelin >= 4.9 recalcula DOMAIN_SEPARATOR si chainId cambia (EIP-2612 style).
    - La signature malleability (ECDSA s-value) permite crear una segunda firma válida
      a partir de la primera — si el tracking usa el hash de la firma, falla.
    - Meta-transactions (ERC-2771) tienen su propio set de problemas — no mezclar con merkle claims.
  solodit_ids:
    - "addkycaddressviasignature-does-not-protect-against-replay-attacks-code4rena-ondo-finance-ondo-finance-git"
  incidentes:
    - "Ondo Finance (C4) — addKYCAddressViaSignature sin nonce, replay permite re-grant KYC después de revocación"
    - "CodeHawks Snowman Airdrop (2025) — EIP-712 hash cambia cuando balance cambia → firma inválida si balance se modifica"
    - "Múltiples protocolos — ecrecover(address(0)) no validado, cualquier firma inválida pasa verificación"
```

---

## 14. Off-Chain Tree Construction Mismatch

```yaml
- id: merkle-014
  titulo: Discrepancia entre construcción off-chain del árbol y verificación on-chain
  causa_raiz: |
    El merkle tree se construye off-chain (JavaScript/Python) y se verifica on-chain
    (Solidity). Si la codificación de las hojas difiere entre ambos entornos, proofs
    válidos off-chain son rechazados on-chain (o viceversa: proofs inválidos off-chain
    son aceptados on-chain). Causas comunes:
    - abi.encodePacked off-chain vs abi.encode on-chain (o viceversa)
    - Endianness de uint256 entre JavaScript y Solidity
    - Sorting de pares de nodos: OpenZeppelin ordena lexicográficamente, otras libs no
    - Double-hash on-chain pero single-hash off-chain
  como_funciona: |
    1. Script JS genera árbol: leaf = ethers.solidityPackedKeccak256(["address","uint256"], [addr, amount]).
    2. Contrato Solidity verifica: leaf = keccak256(abi.encode(addr, amount)).
    3. abi.encode padea address a 32 bytes. solidityPackedKeccak256 usa 20 bytes.
    4. Hashes diferentes → proof generado off-chain SIEMPRE falla on-chain.
    5. Todos los usuarios legítimos no pueden reclamar → fondos bloqueados.
    Variante: el script off-chain ordena los nodos de forma diferente al contrato.
    Proof falla esporádicamente dependiendo de la posición en el árbol.
  invariante: |
    // Test obligatorio: generar proof off-chain y verificar on-chain en el mismo test
    // En Foundry:
    function test_proofConsistency() public {
        // Leaf generado exactamente como en el contrato
        bytes32 leaf = keccak256(abi.encodePacked(user, amount));
        // Proof generado por el script off-chain (hardcoded en test)
        bytes32[] memory proof = new bytes32[](3);
        proof[0] = ...; proof[1] = ...; proof[2] = ...;
        assertTrue(MerkleProof.verify(proof, root, leaf));
    }
  que_mirar:
    - Script de generación (JS/Python) vs contrato — misma codificación de leaf?
    - abi.encode vs abi.encodePacked — padding difference
    - Sort order de nodos: OpenZeppelin sortPairs vs custom implementation
    - Single hash vs double hash (keccak256(keccak256(...)))
    - Tipo de enteros: JS BigNumber vs Solidity uint256 edge cases
    - Tests que solo verifican on-chain con leaf hardcoded (no end-to-end)
  como_se_arregla: |
    1. Usar la misma librería para generar y verificar: OpenZeppelin merkle-tree (JS) + MerkleProof.sol.
    2. Tests end-to-end: generar proof en JS → pasar a Foundry test → verificar on-chain.
    3. Documentar explícitamente la codificación del leaf en el contrato Y en el script.
    4. Usar StandardMerkleTree de OpenZeppelin JS que garantiza compatibilidad con MerkleProof.sol.
  trampas:
    - ethers.js v5 vs v6 tienen APIs diferentes para solidityKeccak256 vs solidityPackedKeccak256.
    - merkletreejs (npm) NO es compatible out-of-the-box con OZ MerkleProof.sol — el sorting difiere.
    - OpenZeppelin StandardMerkleTree (JS) es la referencia correcta para compatibilidad con OZ contracts.
    - El error suele descubrirse DESPUÉS del deployment → fondos bloqueados, need redeploy.
  solodit_ids: []
  incidentes:
    - "Múltiples proyectos NFT (2021-2022) — whitelist merkle trees generados con merkletreejs incompatible con OZ MerkleProof, usuarios no podían mintear"
    - "Numerosos postmortem de airdrops fallidos por encoding mismatch off-chain/on-chain"
```

---

## 15. Proof Verification sin Validar Caller — Claim-on-Behalf Abuse

```yaml
- id: merkle-015
  titulo: Claim ejecutable por cualquiera en nombre de otro sin autorización
  causa_raiz: |
    El contrato permite que cualquier address llame claim() con un proof para
    otro usuario. Esto es un feature (meta-transactions, gasless claims) pero si
    el destinatario de los tokens no es el address del leaf sino msg.sender o un
    parámetro `to`, el caller puede redirigir los tokens.
    Incluso si los tokens van al address correcto, el timing del claim puede ser
    weaponizado: forzar un claim en un momento desfavorable (ej: high gas, bajo
    precio del token) o antes de que el usuario esté listo.
  como_funciona: |
    Patrón vulnerable:
    1. claim(proof, account, amount, address to) — `to` es donde van los tokens.
    2. Atacante llama: claim(proof_alice, alice, 1000, attacker_address).
    3. Proof verifica contra (alice, 1000) → válido.
    4. Tokens enviados a attacker_address → robo directo.
    Patrón "timing grief":
    1. claim(proof, account, amount) — tokens van a `account`, pero claim marca como "done".
    2. Atacante fuerza claim de Alice cuando el token vale $0.01.
    3. Alice quería esperar a que el token valiera $1 → pérdida de oportunidad.
    4. Si hay vesting, el claim prematuro activa el cliff → Alice pierde flexibilidad.
  invariante: |
    // Si claim-on-behalf está permitido, los tokens SIEMPRE van al address del leaf
    function claim(bytes32[] proof, address account, uint256 amount) external {
        bytes32 leaf = keccak256(abi.encode(account, amount));
        require(MerkleProof.verify(proof, root, leaf), "bad proof");
        // Tokens van a `account`, NO a msg.sender
        token.transfer(account, amount); // NUNCA: token.transfer(msg.sender, amount)
    }
  que_mirar:
    - Parámetro `to` o `recipient` separado del `account` en el leaf
    - msg.sender usado como destinatario en vez del account del proof
    - Claim-on-behalf sin signature del beneficiario
    - Side effects del claim (vesting start, voting power) que el caller controla
    - Funciones que no validan msg.sender == account NI requieren signature
  como_se_arregla: |
    Opción A: require(msg.sender == account) — solo el propio usuario puede reclamar.
    Opción B: claim-on-behalf permitido pero tokens SIEMPRE van al account del leaf.
    Opción C: claim-on-behalf con signature EIP-712 del beneficiario (ver merkle-013).
    Nunca: un parámetro `to` que override el destino de los tokens.
  trampas:
    - Claim-on-behalf es DESEADO en gasless/meta-tx scenarios — no siempre es un bug.
    - El bug está en poder REDIRIGIR tokens, no en poder ACTIVAR el claim.
    - Si el claim solo envía tokens al account del leaf, claim-on-behalf es seguro
      (aunque el caller paga gas sin beneficio propio).
    - Timing grief es Low/Info en la mayoría de plataformas — el usuario no pierde fondos.
  solodit_ids: []
  incidentes:
    - "Wayfinder PROMPT (2025) — MEV bot redirigió $200K en tokens porque claim no vinculaba proof a msg.sender"
    - "Múltiples NFT minting contracts — allowlist proofs usables por cualquier caller para mintear a dirección arbitraria"
```
