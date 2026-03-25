# Diamond Proxy & Advanced Proxy Patterns — Bug Patterns

> **Scope**: ERC-2535 Diamond multi-facet proxies, ERC-1167 minimal proxy clones,
> metamorphic contracts (CREATE2 + selfdestruct), beacon proxy edge cases,
> ERC-7201 namespaced storage, and cross-facet interaction bugs.
> **Complementa**: `proxy-upgrade.md` (UUPS, Transparent, Beacon, basic diamond).
> Este briefing cubre patrones AVANZADOS que no están en el briefing base.
> **Sources**: CertiK Diamond best practices, ChainScore Labs EIP-2535 vulns,
> Solodit/Code4rena/Sherlock findings, a16z metamorphic detector, Tornado Cash exploit,
> Beanstalk Diamond audits, Cyfrin/Pashov/Spearbit reports.
> **Last updated**: 2026-03-22

---

## Quick Reference

```
grep_targets:
  - diamondCut
  - IDiamondCut
  - IDiamondLoupe
  - DiamondCutFacet
  - DiamondLoupeFacet
  - selectorToFacet
  - facetAddress
  - facetAddresses
  - facetFunctionSelectors
  - FacetCutAction
  - DiamondStorage
  - AppStorage
  - LibDiamond
  - ds.selectorToFacetAndPosition
  - ds.facetFunctionSelectors
  - DIAMOND_STORAGE_POSITION
  - keccak256("diamond.standard.diamond.storage")
  - ERC7201
  - erc7201:
  - StorageSlot
  - _IMPLEMENTATION_SLOT
  - Clones.clone
  - Clones.cloneDeterministic
  - ClonesUpgradeable
  - minimal proxy
  - CREATE2
  - create2
  - selfdestruct
  - SELFDESTRUCT
  - UpgradeableBeacon
  - IBeacon
  - BeaconProxy
  - _setBeacon
  - implementation()
  - delegatecall
  - _fallback
  - _delegate
  - immutable
  - reinitializer
  - _disableInitializers
  - facets()
```

---

## 1. Storage Collision Between Facets (AppStorage vs Diamond Storage)

```yaml
- id: diamond-001
  titulo: Colisión de almacenamiento entre facets — mezcla de AppStorage y Diamond Storage
  causa_raiz: |
    ERC-2535 no prescribe CÓMO gestionar el storage. Existen dos patrones dominantes:
    (1) AppStorage — un struct único en slot 0 compartido por todos los facets.
    (2) Diamond Storage — cada librería hashea un string único para obtener un slot
        aleatorio (keccak256("diamond.standard.diamond.storage")).
    Si un facet usa AppStorage (slot 0) y otro usa Diamond Storage (slot hasheado),
    o si dos facets usan Diamond Storage con el MISMO string, las variables se solapan.
    En un Diamond, TODOS los facets comparten el mismo espacio de storage del proxy,
    así que la colisión corrompe estado silenciosamente.
  como_funciona: |
    1. FacetA define AppStorage como primer state variable (slot 0+).
    2. FacetB hereda de una librería que define su propio struct en slot 0 (e.g., ReentrancyGuard).
    3. FacetA escribe a slot 0 (AppStorage.field1), FacetB escribe a slot 0 (reentrancy status).
    4. El lock de reentrancy se sobrescribe con datos de negocio — protección deshabilitada.
    5. Alternativa: dos librerías usan Diamond Storage con strings idénticos — struct completo corrupto.
    Ejemplo real: CryptoLegacy — plugins del Diamond heredan ReentrancyGuard estándar (slot 0),
    colisionando con AppStorage del Diamond principal.
  invariante: |
    // Cada facet debe usar un namespace de storage único
    // Verificar con: forge inspect FacetA storage-layout
    // Comparar slots con forge inspect FacetB storage-layout
    // Ningún slot debe aparecer en dos facets distintos
    bytes32 constant FACET_A_STORAGE = keccak256("protocol.facetA.storage");
    bytes32 constant FACET_B_STORAGE = keccak256("protocol.facetB.storage");
    assert(FACET_A_STORAGE != FACET_B_STORAGE);
  que_mirar:
    - "¿El facet hereda contratos estándar OZ (ReentrancyGuard, Ownable) que usan slot 0?"
    - "¿Mezcla AppStorage (slot 0 struct) con Diamond Storage (slot hasheado) en el mismo Diamond?"
    - "forge inspect <Facet> storage-layout — ¿hay slots que colisionan con otros facets?"
    - "¿Dos librerías de Diamond Storage usan el mismo string de hash?"
    - "¿Un facet añadido después del deploy introduce variables en slots ya usados?"
  como_se_arregla: |
    Elegir UN solo patrón para todo el Diamond:
    - AppStorage: un struct único en slot 0, compartido por todos los facets, append-only.
    - Diamond Storage: cada módulo con su propio keccak256 hash único.
    - ERC-7201: namespace estandarizado (recomendado para nuevos proyectos).
    Nunca heredar contratos estándar OZ en facets — usar versiones Upgradeable o Diamond-aware.
  trampas:
    - "Si un Diamond tiene solo 2-3 facets y todos usan AppStorage, no hay colisión HOY — pero añadir un facet futuro puede introducirla"
    - "Diamond Storage con strings distintos es seguro — el riesgo es copypaste del mismo string"
    - "La herencia en Solidity puede meter variables en slots inesperados — flatten + inspect siempre"
  solodit_ids:
    - "standard-reentrancyguard-inheritance-risks-diamond-storage-collision-mixbytes-none-cryptolegacy-markdown"
    - "risk-of-storage-collision-in-proxy-contract-openzeppelin-none-anvil-protocol-audit-markdown"
  incidentes:
    - "CryptoLegacy (MixBytes) — Plugins del Diamond heredan ReentrancyGuard estándar que usa slot 0, colisionando con AppStorage del Diamond (Low)"
    - "Anvil Protocol (OpenZeppelin) — Riesgo de storage collision en proxy por layout no alineado entre implementaciones (Medium)"
    - "GainsNetwork GNSMultiCollatDiamond (Pashov) — Upgrade inserta variable nueva y desplaza accessControl mapping, perdiendo todos los roles (High)"
```

---

## 2. Selector Clashing Between Diamond Facets

```yaml
- id: diamond-002
  titulo: Dos funciones con el mismo selector de 4 bytes en facets distintos del Diamond
  causa_raiz: |
    En un Diamond, el fallback despacha cada llamada al facet registrado para ese selector.
    Si dos funciones en facets distintos producen el mismo selector de 4 bytes (colisión de hash),
    solo una puede registrarse. La otra se pierde silenciosamente o, peor, la diamondCut
    REEMPLAZA la función original sin que el developer lo note.
    Con 2^32 posibles selectores (~4.3 mil millones), las colisiones accidentales son raras
    pero NO imposibles — existen herramientas para generar colisiones a propósito.
  como_funciona: |
    1. FacetA tiene función `transfer(address,uint256)` → selector 0xa9059cbb.
    2. Se despliega FacetB con función `collate_propagate_storage(bytes16)` → mismo selector 0xa9059cbb.
    3. diamondCut(Add, FacetB, [0xa9059cbb]) — si no valida existencia, sobrescribe FacetA.
    4. Usuarios llaman transfer() → ejecuta collate_propagate_storage() de FacetB.
    5. Fondos no se transfieren, estado se corrompe con datos interpretados incorrectamente.
    Alternativa maliciosa: atacante genera función con selector colisionante a propósito
    para reemplazar función crítica del Diamond.
  invariante: |
    // Antes de diamondCut(Add), verificar que el selector NO existe ya
    // La implementación de referencia de Nick Mudge lo hace — verificar que la custom no lo omite
    require(
      ds.selectorToFacetAndPosition[selector].facetAddress == address(0),
      "diamondCut: selector already exists"
    );
  que_mirar:
    - "¿La implementación de diamondCut valida que Add no sobreescribe selectores existentes?"
    - "¿Hay funciones en facets distintos con nombres similares que podrían generar colisión?"
    - "cast sig <function_signature> — comparar selectores entre todos los facets"
    - "¿Se usa una implementación custom de Diamond o la referencia de Nick Mudge?"
    - "¿FacetCutAction.Replace se usa intencionalmente o podría ser un Add accidental?"
  como_se_arregla: |
    Usar la implementación de referencia diamond-3 que valida colisiones en Add.
    Pre-deploy: script que calcula TODOS los selectores de todos los facets y verifica unicidad.
    Post-deploy: llamar IDiamondLoupe.facets() y verificar que no hay duplicados.
    Herramienta: solidity-function-selector-collision-checker.
  trampas:
    - "La implementación de referencia de Nick Mudge SÍ previene esto — el riesgo es en implementaciones custom"
    - "FacetCutAction.Replace es LEGÍTIMO para upgrades — solo es bug si el developer creía que era Add"
    - "En un Diamond grande (50+ funciones), colisiones accidentales se vuelven más probables"
  solodit_ids:
    - "possible-function-selector-clashing-openzeppelin-none-venus-protocol-diamond-comptroller-audit-markdown"
    - "custom-selectors-could-facilitate-proxy-selector-clashing-attack-openzeppelin-none-security-review-ink-cargo-contract-markdown"
  incidentes:
    - "Venus Protocol Diamond Comptroller (OpenZeppelin) — Múltiples facets riesgo de colisión de selectores 4-byte entre facets; auditoría OZ señala riesgo sistemático (Low)"
    - "Ink Cargo Contract (OpenZeppelin) — Selectores custom facilitan ataques de clashing en proxy (Medium)"
```

---

## 3. Facet Initialization Missing After diamondCut

```yaml
- id: diamond-003
  titulo: Facet añadido via diamondCut sin ejecutar su inicializador
  causa_raiz: |
    diamondCut acepta un parámetro _init (address) y _calldata (bytes) que ejecuta un
    delegatecall de inicialización DESPUÉS de añadir/reemplazar/remover facets.
    Si _init es address(0) y _calldata es vacío, el facet se añade sin inicializar.
    Variables críticas del nuevo facet (owner, parámetros, whitelists) quedan en cero.
    Un atacante puede llamar una función pública del nuevo facet que asuma inicialización
    y explotar el estado en cero (e.g., address(0) como owner → cualquiera es owner).
  como_funciona: |
    1. Protocolo hace diamondCut(Add, LendingFacet, selectors, address(0), "").
    2. LendingFacet tiene variable interestRate, maxLTV, oracleAddress — todo queda en 0.
    3. interestRate = 0 → préstamos gratis, maxLTV = 0 → no se puede pedir prestado,
       o si la lógica hace maxLTV = type(uint256).max cuando es 0 → borrow infinito.
    4. oracleAddress = address(0) → llamadas al oracle fallan o retornan 0 como precio.
    5. Dependiendo de la lógica, atacante obtiene préstamos sin colateral o rompe el protocolo.
  invariante: |
    // Después de diamondCut, todas las variables críticas del nuevo facet deben estar inicializadas
    // En test: verificar post-diamondCut
    IDiamondLoupe(diamond).facetAddresses(); // facet existe
    assert(LendingFacet(diamond).oracleAddress() != address(0));
    assert(LendingFacet(diamond).maxLTV() > 0);
  que_mirar:
    - "¿El script de deploy/upgrade pasa _init y _calldata a diamondCut, o address(0) y ''?"
    - "¿El nuevo facet tiene una función initialize() que requiere ser llamada por separado?"
    - "¿Qué pasa si las variables del facet son 0? ¿Hay defaults peligrosos?"
    - "¿El _init contract tiene onlyDiamond o similar, o cualquiera puede llamarlo?"
    - "¿El initializer tiene un guard para no ser llamado dos veces?"
  como_se_arregla: |
    SIEMPRE pasar _init y _calldata en diamondCut para inicializar el nuevo facet atómicamente.
    El contrato _init debe ser un DiamondInit dedicado que setea todas las variables críticas.
    Añadir un modifier initialized al facet que revierte si las variables no fueron seteadas.
    Test: después de cada diamondCut, verificar que todas las variables del facet están configuradas.
  trampas:
    - "Si el facet no tiene estado propio (pure view functions), no necesita inicialización"
    - "Si el facet comparte AppStorage que ya fue inicializado por otro facet, puede no necesitar init propio"
    - "El riesgo principal es facets CON estado propio añadidos vía governance sin init"
  solodit_ids:
    - "initializefunctions-not-protected-auditone-none-newwit-markdown"
    - "implementation-contracts-can-be-initialized-cantina-none-olas-pdf"
  incidentes:
    - "Beanstalk (Cyfrin) — Múltiples upgrades vía diamondCut donde la inicialización de nuevos facets depende de script externo; si el script falla, facet queda sin inicializar (Medium)"
    - "Olas Protocol (Cantina) — Implementation contracts can be initialized por cualquiera; patrón similar aplica a facets de Diamond (Medium)"
```

---

## 4. delegatecall to Facet with selfdestruct Destroys Diamond

```yaml
- id: diamond-004
  titulo: Facet con selfdestruct destruye el Diamond entero via delegatecall
  causa_raiz: |
    Cuando el Diamond hace delegatecall a un facet, el código del facet se ejecuta
    en el contexto del Diamond (storage, balance, address). Si el facet contiene
    SELFDESTRUCT (directamente o via otro delegatecall), destruye el contrato del Diamond,
    no el facet. Todos los fondos y estado del Diamond se pierden permanentemente.
    Pre-EIP-6780 (Cancun upgrade), SELFDESTRUCT destruía el contrato y enviaba el balance.
    Post-EIP-6780, SELFDESTRUCT solo destruye si se llama en la misma tx de creación —
    pero aún envía el balance ETH, vaciando el Diamond.
  como_funciona: |
    1. Facet malicioso o comprometido contiene función con selfdestruct(attacker).
    2. Atacante obtiene acceso a diamondCut (o facet ya tiene la función expuesta).
    3. Facet se registra en el Diamond vía diamondCut(Add, ...).
    4. Atacante llama la función con selfdestruct a través del Diamond.
    5. delegatecall ejecuta selfdestruct en contexto del Diamond.
    6. Pre-EIP-6780: Diamond destruido, balance enviado a atacante, protocolo muerto.
    7. Post-EIP-6780: Diamond no se destruye pero todo el balance ETH se envía al atacante.
  invariante: |
    // Ningún facet del Diamond debe contener SELFDESTRUCT
    // Verificación estática obligatoria pre-diamondCut
    // En bytecode: opcode 0xFF = SELFDESTRUCT
    // Script: cast code <facet_address> | grep -c "ff" (simplificado)
    // Mejor: análisis estático con Slither o Foundry
  que_mirar:
    - "rg 'selfdestruct' --type sol — en TODOS los facets y sus dependencias"
    - "¿Hay delegatecall chains? FacetA → delegatecall → LibraryB → selfdestruct"
    - "¿El facet importa librerías externas que podrían contener selfdestruct?"
    - "¿Hay una función execute(address target, bytes data) en algún facet que permita delegatecall arbitrario?"
    - "Post-EIP-6780: ¿hay balance ETH nativo en el Diamond que se perdería?"
  como_se_arregla: |
    Prohibir SELFDESTRUCT en todos los facets — validar estáticamente antes de diamondCut.
    No incluir funciones de delegatecall arbitrario en facets.
    Usar Slither detector: slither . --detect suicidal.
    Añadir check en diamondCut custom: analizar bytecode del facet antes de registrar.
  trampas:
    - "Post-EIP-6780 (Cancun, marzo 2024), selfdestruct ya no destruye el contrato excepto en la misma tx de creación"
    - "PERO sigue enviando el balance ETH — el Diamond pierde fondos aunque no se destruya"
    - "Si el Diamond no tiene ETH nativo (solo ERC20), el impacto post-6780 es menor"
    - "En cadenas L2 que no implementaron EIP-6780 todavía, selfdestruct sigue siendo destructivo"
  solodit_ids:
    - "h-06-storage-collision-between-proxy-and-implementation-lack-eip-1967-code4rena-joyn-joyn-contest-git"
  incidentes:
    - "Parity Multisig (Nov 2017) — Atacante llamó selfdestruct en la librería de implementación, destruyendo 513K ETH en wallets dependientes ($150M+, Critical)"
    - "Revest Finance (2022) — delegatecall vulnerability en proxy manipula storage pointers, drena fondos ($2M)"
    - "CertiK advisory — Señala explícitamente que facets con selfdestruct destruyen el Diamond entero via delegatecall (Best Practice)"
```

---

## 5. Cross-Facet Reentrancy via Diamond Dispatch

```yaml
- id: diamond-005
  titulo: Reentrancy entre facets — FacetA llama external que re-entra por FacetB
  causa_raiz: |
    En un Diamond, todos los facets comparten el mismo storage y el mismo address.
    Si FacetA hace una llamada externa (e.g., token.transfer) y el receptor re-entra
    al Diamond llamando una función de FacetB, la protección de reentrancy SOLO funciona
    si ambos facets comparten el MISMO lock de reentrancy en el mismo slot de storage.
    Si cada facet tiene su propio ReentrancyGuard independiente (o si alguno no tiene),
    el lock de FacetA no protege contra reentrada en FacetB.
  como_funciona: |
    1. FacetA.withdraw() tiene ReentrancyGuard con lock en slot X.
    2. FacetA hace token.transfer(attacker, amount) — callback al atacante.
    3. Atacante re-entra al Diamond llamando FacetB.borrow().
    4. FacetB tiene su propio ReentrancyGuard en slot Y (o ninguno).
    5. El lock de slot X no bloquea FacetB — FacetB.borrow() se ejecuta.
    6. FacetB lee balance/state que FacetA aún no ha actualizado (checks-effects violado cross-facet).
    7. Atacante obtiene borrow basado en balance inflado, drena fondos.
  invariante: |
    // TODOS los facets del Diamond deben compartir UN SOLO lock de reentrancy
    // Usar Diamond Storage para el lock, no herencia de OZ ReentrancyGuard
    bytes32 constant REENTRANCY_STORAGE = keccak256("diamond.reentrancy.guard");
    struct ReentrancyStorage { uint256 status; }
    function _reentrancyLock() internal {
        ReentrancyStorage storage rs = reentrancyStorage();
        require(rs.status != 2, "reentrant");
        rs.status = 2;
    }
  que_mirar:
    - "¿Cada facet hereda su propio ReentrancyGuard, o hay un lock compartido en Diamond Storage?"
    - "¿FacetA hace external calls (transfers, callbacks) que podrían re-entrar por otro facet?"
    - "¿Hay funciones en FacetB accesibles externamente que leen estado que FacetA modifica?"
    - "¿Se usa nonReentrant solo en algunos facets y no en otros?"
    - "¿Los tokens que maneja el Diamond son ERC-777 o ERC-1155 (callbacks de transferencia)?"
  como_se_arregla: |
    Implementar un ReentrancyGuard global en Diamond Storage compartido por TODOS los facets.
    O mejor: seguir CEI (Checks-Effects-Interactions) estrictamente en cada facet.
    Si se usan tokens con callbacks (ERC-777, ERC-1155), el guard global es obligatorio.
    Auditar TODAS las combinaciones de facets — el guard individual por facet NO es suficiente.
  trampas:
    - "Si el Diamond solo tiene funciones view/pure en algunos facets, esos no necesitan guard"
    - "El patrón más peligroso: FacetA actualiza estado DESPUÉS de external call, FacetB lee ESE estado"
    - "Read-only reentrancy cross-facet es especialmente difícil de detectar"
    - "Auditorías individuales por facet NO detectan este bug — se necesita análisis cross-facet"
  solodit_ids:
    - "standard-reentrancyguard-inheritance-risks-diamond-storage-collision-mixbytes-none-cryptolegacy-markdown"
  incidentes:
    - "ChainScore Labs advisory — Documenta que auditoría individual de facets es insuficiente; composabilidad de facets crea behavior emergente no revisado, similar a reentrancy en early DeFi (Systemic Risk)"
    - "Beanstalk Wells (Cyfrin) — Read-only reentrancy en removeLiquidity; reserves se setean DESPUÉS de enviar tokens, violando CEI en contexto de Diamond (High)"
```

---

## 6. Facet Removal Leaves Dangling Storage

```yaml
- id: diamond-006
  titulo: Remover facet via diamondCut no limpia su storage — estado fantasma
  causa_raiz: |
    diamondCut con FacetCutAction.Remove solo elimina la REFERENCIA del selector al facet
    en el mapping del Diamond. El storage que el facet escribió permanece intacto en los
    slots del proxy. Si un facet nuevo se añade y reutiliza esos slots (mismo namespace o
    posición en AppStorage), lee datos residuales del facet anterior como si fueran propios.
  como_funciona: |
    1. FacetV1 escribe totalSupply = 1000 en Diamond Storage namespace "lending".
    2. diamondCut(Remove, FacetV1, selectors) — FacetV1 ya no es accesible vía el Diamond.
    3. totalSupply = 1000 permanece en storage del proxy en el namespace "lending".
    4. FacetV2 se añade con el mismo namespace "lending" pero diferente struct layout.
    5. FacetV2 lee slot que contenía totalSupply como su variable interestRate.
    6. interestRate = 1000 (valor absurdo) — préstamos con tasa 1000x, accounting roto.
  invariante: |
    // Después de Remove + Add, las variables del nuevo facet deben ser 0 o inicializadas explícitamente
    // En test: diamondCut(Remove, ...) → diamondCut(Add, newFacet) → assert(newFacet.var == expected)
    // NUNCA asumir que el storage está limpio después de un Remove
  que_mirar:
    - "¿Se hace Remove de un facet y luego Add de otro que usa el MISMO namespace/slots?"
    - "¿El nuevo facet tiene un initializer que sobrescribe explícitamente todos sus campos?"
    - "¿El namespace string del facet removido se reutiliza en el nuevo facet?"
    - "¿Hay un migration script que limpia los slots del facet removido antes de añadir el nuevo?"
  como_se_arregla: |
    Al hacer Remove + Add con mismo namespace, SIEMPRE ejecutar un initializer que sobrescribe
    todos los campos del struct (no solo los nuevos).
    Alternativa: usar un namespace DIFERENTE para el nuevo facet.
    En migraciones complejas, incluir un DiamondInit que lee datos viejos, los borra, y escribe datos nuevos.
  trampas:
    - "Si el nuevo facet usa un namespace completamente diferente, no hay riesgo de datos fantasma"
    - "AppStorage es más susceptible porque TODO está en el mismo slot range (slot 0+)"
    - "En production, la mayoría de facets se Replace en vez de Remove+Add — Replace hereda storage intencionalmente"
    - "Solo es bug si el layout del nuevo facet es DIFERENTE al del viejo en el mismo namespace"
  solodit_ids: []
  incidentes:
    - "Patrón documentado por CertiK y RareSkills — Diamond Storage con Remove no limpia slots; nuevo facet hereda datos residuales (Best Practice)"
    - "Beanstalk múltiples BIPs — Migración entre facets requiere DiamondInit scripts para resetear estado; sin ellos, datos fantasma corrompen la nueva lógica"
```

---

## 7. Minimal Proxy (ERC-1167) Clone Manipulation

```yaml
- id: diamond-007
  titulo: Clone ERC-1167 apunta a implementación manipulable o destruible
  causa_raiz: |
    ERC-1167 minimal proxy clones son 45 bytes de bytecode que hacen delegatecall a una
    dirección de implementación INMUTABLE embebida en el bytecode del clone.
    Si la implementación es upgradeable, tiene selfdestruct, o puede ser destruida,
    TODOS los clones derivados de ella se rompen simultáneamente.
    Adicionalmente, si la factory que crea clones no valida la dirección de implementación,
    un atacante puede crear clones apuntando a un contrato malicioso.
  como_funciona: |
    Escenario 1 — Implementación destruida:
    1. Factory despliega Implementation y luego crea 100 clones con Clones.clone(impl).
    2. Implementation no tiene _disableInitializers — atacante la inicializa directamente.
    3. Atacante llama selfdestruct en Implementation (pre-EIP-6780).
    4. 100 clones ahora hacen delegatecall a address sin código → todas las llamadas retornan (true, "").
    5. Usuarios creen que sus operaciones funcionan, pero no ejecutan nada.

    Escenario 2 — Clone con implementación maliciosa:
    1. Factory tiene createClone(address impl) sin validar que impl es la implementación esperada.
    2. Atacante llama createClone(maliciousContract).
    3. Clone creado delega todo a maliciousContract — roba fondos de quien interactúe con el clone.
  invariante: |
    // La implementación de un clone ERC-1167 debe ser inmutable, no-destructible, e inicializada
    // assert(impl.code.length > 0) — implementación tiene código
    // assert(impl == expectedImplementation) — factory valida dirección
    address cloneImpl = getImplementationFromBytecode(clone);
    assert(cloneImpl == trustedImplementation);
    assert(cloneImpl.code.length > 0);
  que_mirar:
    - "¿La Factory valida que la dirección de implementación es la esperada antes de crear el clone?"
    - "¿La implementación tiene _disableInitializers() en el constructor?"
    - "¿La implementación contiene selfdestruct o delegatecall arbitrario?"
    - "¿Hay funciones que permitan cambiar la implementación después del deploy? (No debería — es inmutable)"
    - "rg 'Clones.clone|Clones.cloneDeterministic' --type sol — revisar qué dirección se pasa"
  como_se_arregla: |
    Implementación con _disableInitializers() en constructor.
    Factory debe hardcodear la dirección de implementación, no aceptarla como parámetro.
    Post-EIP-6780: riesgo de destrucción reducido pero no eliminado en L2s pre-Cancun.
    Si la implementación es upgradeable (UUPS), proteger _authorizeUpgrade rigurosamente.
  trampas:
    - "ERC-1167 clones NO pueden actualizarse — si la implementación tiene un bug, todos los clones lo heredan PARA SIEMPRE"
    - "Clones.cloneDeterministic usa CREATE2 — la dirección es predecible, puede facilitar phishing"
    - "Post-EIP-6780 la destrucción de implementación es muy difícil — pero en L2s puede variar"
    - "Si la implementación es un proxy UUPS, el admin del proxy controla TODOS los clones indirectamente"
  solodit_ids:
    - "l-01-add-constructor-initializer-in-implementation-contracts-code4rena-jpyc-jpyc-contest-git"
  incidentes:
    - "Thirdweb (Dic 2023) — Vulnerabilidad crítica en implementaciones ERC-20, ERC-721, ERC-1155 usadas por miles de clones; millones de contratos afectados simultáneamente. Thirdweb desplegó tool de mitigación (Critical)"
    - "JPYC (Code4rena) — Implementation contracts sin _disableInitializers; cualquiera puede inicializar directamente (Low)"
```

---

## 8. Metamorphic Contract Redeployment (CREATE2 + selfdestruct)

```yaml
- id: diamond-008
  titulo: Contrato metamórfico — CREATE2 + selfdestruct permite reemplazar código en la misma dirección
  causa_raiz: |
    CREATE2 calcula la dirección del contrato como hash(0xFF, deployer, salt, initCodeHash).
    Si el contrato desplegado tiene selfdestruct, puede ser destruido y redesplegado en la
    misma dirección con código DIFERENTE (usando un deployer intermediario que cambia el
    código real vía CREATE). El address no cambia pero el comportamiento del contrato sí.
    Esto permite governance attacks: propuesta se verifica con código benigno, se destruye,
    se redespliega con código malicioso, y se ejecuta la propuesta ya aprobada.
  como_funciona: |
    1. Atacante despliega DeployerFactory con CREATE2 → dirección predecible.
    2. DeployerFactory despliega ProposalContract via CREATE (nonce-based).
    3. ProposalContract contiene código benigno → pasa verificación de la DAO.
    4. DAO aprueba la propuesta (voto toma días/semanas).
    5. Atacante llama selfdestruct en ProposalContract (nonce se resetea).
    6. Atacante llama selfdestruct en DeployerFactory (nonce se resetea).
    7. Atacante redespliega DeployerFactory con CREATE2 (misma address — mismo salt).
    8. DeployerFactory despliega NUEVO ProposalContract via CREATE (mismo nonce = misma address).
    9. Nuevo ProposalContract tiene código MALICIOSO.
    10. DAO ejecuta la propuesta aprobada → ejecuta el código malicioso.
  invariante: |
    // Propuestas de governance NO deben ser contratos deployados con CREATE2
    // y NO deben contener selfdestruct
    // assert(proposal.code does not contain SELFDESTRUCT opcode)
    // assert(proposal was not deployed via CREATE2)
    // Herramienta: a16z/metamorphic-contract-detector
  que_mirar:
    - "¿Las propuestas de governance son contratos? ¿Se pueden destruir y redeployar?"
    - "¿El sistema de governance verifica el code hash en el momento de EJECUCIÓN, no solo de propuesta?"
    - "¿Hay contratos desplegados con CREATE2 que también contienen selfdestruct?"
    - "rg 'CREATE2|create2' --type sol — buscar factories que podrían crear metamorphics"
    - "rg 'selfdestruct|SELFDESTRUCT' --type sol — en contratos de propuestas o factories"
  como_se_arregla: |
    Prohibir propuestas que contengan SELFDESTRUCT opcode.
    Prohibir propuestas desplegadas via CREATE2.
    Verificar el code hash del proposal contract en el momento de EJECUCIÓN, no solo propuesta.
    Post-EIP-6780 (Cancun): SELFDESTRUCT solo funciona en la misma tx de creación — riesgo DRASTICAMENTE reducido.
  trampas:
    - "Post-EIP-6780 (Marzo 2024, mainnet), este ataque es MUCHO más difícil — selfdestruct no elimina código entre txs"
    - "En L2s sin EIP-6780, el ataque sigue siendo viable"
    - "La detección requiere análisis de bytecode, no solo código fuente (el contrato puede ser unverified)"
    - "a16z publicó metamorphic-contract-detector — úsalo en assessments"
  solodit_ids: []
  incidentes:
    - "Tornado Cash Governance Takeover (Mayo 2023) — Atacante usó propuesta metamórfica CREATE2+selfdestruct para tomar control total del DAO, retirar fondos de governance vaults, drenar TORN ($900K+, Critical)"
    - "FiatDAO (Code4rena) — Operador puede usar CREATE2 + SELFDESTRUCT para evitar blocklist; create new contract at same address con diferente código (Medium)"
    - "Coinbase advisory — Documenta el patrón metamórfico como vector de governance attack con herramienta de detección (Research)"
```

---

## 9. Beacon Proxy Upgrade Race — Shared Failure Domain

```yaml
- id: diamond-009
  titulo: Upgrade del Beacon afecta TODOS los proxies simultáneamente — dominio de fallo compartido
  causa_raiz: |
    En el patrón Beacon, múltiples BeaconProxy comparten un UpgradeableBeacon que retorna
    la dirección de implementación. Cuando el Beacon se upgradea, TODOS los proxies apuntan
    a la nueva implementación instantáneamente, sin rollout gradual. Si la nueva implementación
    tiene un bug, TODOS los proxies se rompen al mismo tiempo. No hay rollback.
  como_funciona: |
    1. Beacon apunta a ImplementationV1. 100 BeaconProxy funcionan correctamente.
    2. Admin llama beacon.upgradeTo(ImplementationV2).
    3. ImplementationV2 tiene un bug en withdraw() que revierte siempre.
    4. 100 proxies ahora delegan withdraw() a V2 → TODOS los retiros bloqueados.
    5. Fondos locked en 100 contratos simultáneamente.
    6. Si el admin key se pierde o está comprometido, no hay forma de revertir.

    Escenario de ataque:
    1. Atacante compromete el admin del Beacon (single point of failure).
    2. beacon.upgradeTo(maliciousImplementation).
    3. maliciousImplementation tiene backdoor que drena fondos de cada proxy.
    4. Atacante itera sobre los 100 proxies y drena cada uno.
  invariante: |
    // Post-upgrade, TODAS las funciones críticas de TODOS los proxies deben seguir funcionando
    // En test de fork: upgrade beacon → llamar cada función crítica en cada proxy
    for (uint i = 0; i < proxies.length; i++) {
        IProtocol(proxies[i]).deposit(1e18); // no debe revert
        IProtocol(proxies[i]).withdraw(1e18); // no debe revert
        assert(IProtocol(proxies[i]).balanceOf(user) == expected);
    }
  que_mirar:
    - "¿Cuántos BeaconProxy comparten un mismo Beacon? (más = más riesgo)"
    - "¿El admin del Beacon es un multisig con timelock, o un EOA?"
    - "¿Hay mecanismo de rollback si la nueva implementación falla?"
    - "¿Los tests de upgrade verifican TODOS los proxies, o solo uno?"
    - "¿Hay un mecanismo de upgrade gradual (canary proxy que se upgradea primero)?"
  como_se_arregla: |
    Implementar timelock en el Beacon admin (mínimo 48h para que la comunidad revise).
    Usar multisig (3/5 o más) para el admin del Beacon.
    Implementar canary proxy: un proxy especial que se upgradea primero y se testea.
    Storage layout check automático pre-upgrade (forge inspect diff).
    Circuit breaker: función de pausa global que se activa si se detecta anomalía post-upgrade.
  trampas:
    - "El riesgo es proporcional al número de proxies + TVL total — 3 proxies con $100 no es lo mismo que 100 proxies con $100M"
    - "Si el protocolo tiene mecanismo de pausa, la ventana de daño se reduce"
    - "Beacon con timelock mitiga el riesgo — verificar que el timelock no es bypasseable"
    - "Algunos protocolos usan Beacon INTENCIONALMENTE para atomic upgrades — es feature, no bug, si está bien protegido"
  solodit_ids: []
  incidentes:
    - "DeFiHackLabs advisory — Beacon proxy shared failure domain: un bad upgrade rompe todos los proxies; admin = root access sobre el sistema completo (Systemic Risk)"
    - "Cyfrin CodeHawks (Hawk High) — Proxy won't be upgraded with new implementation contract; missing call to upgradeTo in graduateAndUpgrade breaks upgrade path for all beacon proxies (High)"
```

---

## 10. Immutable Variables in Proxy/Facet Context

```yaml
- id: diamond-010
  titulo: Variables immutable en implementación no disponibles cuando se accede via proxy/delegatecall
  causa_raiz: |
    En Solidity, las variables `immutable` se embeben directamente en el BYTECODE del contrato
    durante el deploy del constructor. No se almacenan en storage. Cuando un proxy hace
    delegatecall a la implementación, usa el storage del proxy pero el BYTECODE de la
    implementación. Si la implementación tiene immutables seteados durante SU deploy,
    esos valores son los del deploy de la IMPLEMENTACIÓN, no los que el proxy esperaría.
    En un Diamond, cada facet desplegado independientemente tiene SUS propios immutables,
    que pueden ser diferentes del contexto esperado del Diamond.
  como_funciona: |
    1. Implementation desplegada con: immutable address WETH = 0xWETH_MAINNET.
    2. Proxy desplegado en otra chain (o el admin quería otro WETH address para el proxy).
    3. Proxy hace delegatecall a Implementation.deposit(). Dentro, lee WETH del bytecode de Implementation.
    4. WETH = 0xWETH_MAINNET — incorrecto para el proxy que está en L2.
    5. Transfer a dirección incorrecta, fondos perdidos o tx revierte.

    En Diamond:
    1. FacetA desplegado con immutable ORACLE = 0xOracle_Staging.
    2. Diamond en production usa Oracle_Production.
    3. FacetA siempre lee ORACLE = 0xOracle_Staging via su bytecode.
    4. Precios incorrectos → liquidaciones incorrectas → pérdida de fondos.
  invariante: |
    // Implementaciones detrás de proxies NO deben usar immutable para valores configurables
    // Verificar: grep 'immutable' en contratos que se usan como implementation/facet
    // Excepciones: valores verdaderamente universales (e.g., type(uint256).max)
  que_mirar:
    - "rg 'immutable' --type sol — en contratos que son implementaciones de proxy o facets de Diamond"
    - "¿Las immutables se setean en el constructor de la implementación? ¿Son correctas para el contexto del proxy?"
    - "¿El proxy y la implementación están en la misma chain? (multi-chain deployment con misma impl)"
    - "¿Hay immutables que deberían ser diferentes entre proxies pero son idénticas por estar en bytecode?"
    - "¿Immutables de addresses de contratos externos (oracles, tokens, routers)?"
  como_se_arregla: |
    En implementaciones de proxy: usar storage variables en vez de immutables para valores configurables.
    Setear en initialize() en lugar del constructor.
    Immutables solo para constantes UNIVERSALES (e.g., PRECISION = 1e18, MAX_BPS = 10000).
    En Diamond: usar AppStorage o Diamond Storage para direcciones, nunca immutables en facets.
  trampas:
    - "Immutables que son verdaderamente constantes (PRECISION, MAX) son SEGUROS en proxy — solo addresses/configs son peligrosos"
    - "Si hay un solo proxy por implementación y se despliegan juntos, los immutables son correctos — el riesgo es multi-proxy"
    - "OpenZeppelin v5 usa immutables internos en algunos contratos — verificar que no afectan al proxy"
    - "Clones ERC-1167 comparten bytecode de la implementación — mismos immutables para todos los clones"
  solodit_ids:
    - "m-04-pool-designed-to-be-upgradeable-but-does-not-set-owner-making-it-un-upgradeable-code4rena-blur-exchange-blur-exchange-contest-git"
  incidentes:
    - "Blur Exchange (Code4rena) — Pool diseñado para ser upgradeable pero usa immutable owner seteado en constructor de la implementación; proxy no puede cambiar owner post-deploy (Medium)"
    - "Coinmonks advisory — Variables immutable en proxy context son leídas del bytecode de la implementación, no del storage del proxy; documented pitfall para proxy developers"
```

---

## 11. ERC-7201 Namespaced Storage Violations

```yaml
- id: diamond-011
  titulo: Violación de ERC-7201 — namespace mal calculado, colisión, o incompleto
  causa_raiz: |
    ERC-7201 define una fórmula para calcular slots de storage aislados por namespace:
    erc7201(id) = keccak256(keccak256(id) - 1) & ~0xff
    Si un protocolo implementa ERC-7201 pero: (1) omite el `& ~0xff`, (2) usa un ID de
    namespace que ya existe en otro módulo, (3) el NatSpec tag no coincide con el ID usado
    en el código, o (4) dos módulos usan el mismo string → colisión de storage.
  como_funciona: |
    Escenario 1 — & ~0xff omitido:
    1. Módulo calcula slot = keccak256(keccak256("protocol.module") - 1) sin el mask final.
    2. Último byte del slot NO es 0x00 como exige ERC-7201.
    3. Futuro upgrade a Verkle Trees puede causar colisiones de caché de slots.
    4. Herramientas de verificación de ERC-7201 reportan non-compliance.

    Escenario 2 — IDs duplicados:
    1. MóduloA usa namespace "protocol.lending.storage".
    2. MóduloB (por copypaste) también usa "protocol.lending.storage".
    3. Ambos módulos escriben al mismo slot range — struct layouts incompatibles.
    4. Datos corrompidos silenciosamente.
  invariante: |
    // Verificar que cada namespace ERC-7201 cumple la fórmula completa
    bytes32 constant SLOT = keccak256(abi.encode(uint256(keccak256("protocol.module")) - 1)) & ~bytes32(uint256(0xff));
    // NatSpec tag @custom:storage-location erc7201:protocol.module debe coincidir con el ID
  que_mirar:
    - "rg 'erc7201:|ERC7201|@custom:storage-location' --type sol — verificar compliance"
    - "¿El cálculo del slot incluye el & ~bytes32(uint256(0xff)) final?"
    - "¿Dos módulos usan el mismo string de namespace?"
    - "¿El NatSpec @custom:storage-location coincide con el ID usado en el keccak256?"
    - "¿Hay módulos que mezclan ERC-7201 con Diamond Storage o AppStorage?"
  como_se_arregla: |
    Seguir la fórmula EXACTA de ERC-7201: keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff)).
    Un solo archivo de constantes con TODOS los namespace IDs — verificar unicidad.
    NatSpec tag DEBE coincidir con el ID del código.
    Test: verificar que el cálculo produce un slot que termina en 0x00.
  trampas:
    - "Si el protocolo no dice usar ERC-7201, la omisión del & ~0xff no es un bug — es su propio patrón"
    - "ERC-7201 es relativamente nuevo (2023) — muchos protocolos usan Diamond Storage sin ERC-7201 y es válido"
    - "La colisión de IDs entre módulos PROPIOS es rara pero real por copypaste"
    - "El mask & ~0xff es para forward-compatibility con Verkle Trees — no causa bugs HOY pero sí en el futuro"
  solodit_ids:
    - "several-libraries-are-not-erc7201-compliant-cyfrin-codehawks-zaros-part-2"
  incidentes:
    - "Zaros Part 2 (Cyfrin CodeHawks) — Varias librerías no son ERC-7201 compliant: falta el & ~0xff en el cálculo del slot, slots no terminan en 0x00 (Low)"
    - "Zaros Part 2 (Cyfrin CodeHawks) — Inconsistent implementation of ERC-7201 namespaced storage locations: NatSpec tag usa ID diferente al del cálculo (Low)"
```

---

## 12. diamondCut Callback Arbitrary Execution

```yaml
- id: diamond-012
  titulo: El parámetro _init de diamondCut permite ejecución arbitraria con storage del Diamond
  causa_raiz: |
    diamondCut acepta (_init, _calldata) que ejecuta delegatecall(_init, _calldata) después
    de modificar los facets. Si el control de acceso a diamondCut es débil, o si _init puede
    apuntar a CUALQUIER contrato, el atacante puede ejecutar código arbitrario con el storage
    y balance del Diamond. Esto es más poderoso que simplemente añadir un facet malicioso:
    permite acceso inmediato sin necesidad de que usuarios llamen funciones del facet.
  como_funciona: |
    1. Atacante obtiene acceso a diamondCut (access control débil, key comprometida, governance attack).
    2. Llama diamondCut([], address(maliciousInit), abi.encodeWithSignature("steal()")).
    3. El array de FacetCut está vacío — no se añade/remueve ningún facet.
    4. Pero _init = maliciousInit se ejecuta via delegatecall en contexto del Diamond.
    5. maliciousInit.steal() hace: token.transfer(attacker, token.balanceOf(address(this))).
    6. Ejecutado con el address y storage del Diamond — drena todos los fondos.
  invariante: |
    // El _init de diamondCut debe ser:
    // (1) address(0) (no callback), o
    // (2) un contrato verificado en una whitelist, o
    // (3) el propio Diamond
    // assert(_init == address(0) || isApprovedInit[_init])
  que_mirar:
    - "¿diamondCut valida que _init es un contrato conocido/whitelisted?"
    - "¿O acepta CUALQUIER address como _init?"
    - "¿El access control de diamondCut es robusto (multisig + timelock)?"
    - "¿Se puede llamar diamondCut con FacetCut[] vacío pero _init no-vacío? (ejecución sin cambio de facets)"
    - "¿Los logs de DiamondCut events muestran _init calls inesperados?"
  como_se_arregla: |
    Restringir _init a una whitelist de contratos de inicialización aprobados.
    O mejor: _init debe ser el propio Diamond o address(0).
    Añadir timelock a diamondCut para que la comunidad pueda revisar el _init propuesto.
    Validar que _init no contiene selfdestruct, transferFrom, o delegatecall.
  trampas:
    - "La implementación de referencia de Nick Mudge NO restringe _init — es responsabilidad del protocolo"
    - "Un _init legítimo (DiamondInit que configura variables) es indistinguible de uno malicioso a nivel de diamondCut"
    - "Este vector es especialmente peligroso en governance diamonds donde una propuesta puede incluir _init arbitrario"
  solodit_ids:
    - "possible-function-selector-clashing-openzeppelin-none-venus-protocol-diamond-comptroller-audit-markdown"
  incidentes:
    - "Beanstalk Governance Attack (Abril 2022) — Atacante usó propuesta de governance para ejecutar BIP-18 via Diamond; flash loan de $1B para obtener 2/3 de Stalk y ejecutar propuesta que drenó $182M del Diamond ($182M, Critical)"
    - "Burve Protocol (Pashov) — diamondCut sin access control: atacante puede ejecutar _init arbitrario con delegatecall en contexto del Diamond (Critical)"
```

---

## 13. Diamond Loupe Inconsistency — Facet Registry Desync

```yaml
- id: diamond-013
  titulo: IDiamondLoupe retorna datos inconsistentes con el estado real del Diamond
  causa_raiz: |
    ERC-2535 requiere que el Diamond implemente IDiamondLoupe con funciones:
    facets(), facetFunctionSelectors(), facetAddresses(), facetAddress(selector).
    Si la implementación custom de diamondCut no actualiza correctamente las estructuras
    de datos del loupe (arrays y mappings), el loupe puede retornar información stale:
    facets que ya no existen, selectores incorrectos, o facets faltantes.
    Herramientas de monitoreo y auditoría que dependen del loupe obtienen vista incorrecta.
  como_funciona: |
    1. diamondCut(Remove, OldFacet, [selectorA]) se ejecuta.
    2. Bug en la implementación custom: el selector se remueve del mapping pero NO del array.
    3. IDiamondLoupe.facets() retorna OldFacet en la lista — pero llamar selectorA revierte (no existe).
    4. Inspector tools (inspector-facet, Etherscan Diamond tab) muestran facets incorrectos.
    5. Auditor asume que OldFacet todavía existe y no revisa el nuevo facet que lo reemplazó.
    6. Peor caso: selectorA se mapea a address(0) pero el array todavía lo lista — llamar selectorA
       hace delegatecall a address(0) → retorna success con data vacía.
  invariante: |
    // Después de cada diamondCut, verificar consistencia del loupe
    address[] memory facetAddrs = IDiamondLoupe(diamond).facetAddresses();
    for (uint i = 0; i < facetAddrs.length; i++) {
        bytes4[] memory selectors = IDiamondLoupe(diamond).facetFunctionSelectors(facetAddrs[i]);
        for (uint j = 0; j < selectors.length; j++) {
            assert(IDiamondLoupe(diamond).facetAddress(selectors[j]) == facetAddrs[i]);
        }
    }
  que_mirar:
    - "¿La implementación de diamondCut es custom o usa diamond-3 de referencia?"
    - "¿Remove actualiza tanto el mapping como el array del loupe?"
    - "¿Replace actualiza tanto el mapping como el array del loupe?"
    - "Llamar IDiamondLoupe.facets() y verificar que cada selector mapea al facet correcto"
    - "¿Hay un test que verifica consistencia del loupe después de cada diamondCut?"
  como_se_arregla: |
    Usar la implementación de referencia diamond-3 que mantiene arrays y mappings sincronizados.
    Si es custom: test exhaustivo post-diamondCut que verifica la bidireccionalidad:
    selector → facet y facet → selectors deben ser consistentes.
    Herramienta: inspector-facet de moonstream (github.com/moonstream-to/inspector-facet).
  trampas:
    - "Si se usa diamond-3 de referencia, este bug es extremadamente improbable"
    - "En implementaciones custom (frecuente en protocolos grandes como Beanstalk), el riesgo es real"
    - "El loupe inconsistente no causa pérdida de fondos directamente — pero oculta el estado real del Diamond"
    - "Etherscan Diamond Proxy tab depende del loupe — datos incorrectos misleading para la comunidad"
  solodit_ids: []
  incidentes:
    - "Veritas Protocol — Diamond Proxy Scanner verifica compliance de ERC-2535 incluyendo consistencia del loupe; múltiples protocolos con inconsistencias detectadas (Tool)"
    - "OpenZeppelin zkSync audit — Auditoría del Diamond de zkSync L1 identificó complejidad en la gestión del registry de facets como vector de riesgo (Audit)"
```

---

## 14. Upgradeable Facet Dependencies — Facet A Depends on Facet B Interface

```yaml
- id: diamond-014
  titulo: Facet A depende de interfaz de Facet B — upgrade de B rompe A silenciosamente
  causa_raiz: |
    En un Diamond, los facets pueden llamarse entre sí a través del Diamond dispatch
    (address(this).call(abi.encodeWithSelector(...))). Si FacetA hardcodea una dependencia
    en la interfaz de FacetB (función signature, return types), un upgrade de FacetB que
    cambie la interfaz rompe FacetA sin tocar su código. El Diamond no tiene un mecanismo
    nativo para verificar dependencias entre facets.
  como_funciona: |
    1. FacetA.calculateLTV() llama: (bool s, bytes memory d) = address(this).call(
         abi.encodeWithSignature("getPrice(address)", token));
    2. FacetB tiene function getPrice(address) returns (uint256 price).
    3. Upgrade: FacetB_v2 cambia a getPrice(address,uint8) returns (uint256,uint8).
    4. FacetA llama getPrice(address) → selector 0x41976e09 → ya no existe en FacetB_v2.
    5. Diamond dispatch no encuentra el selector → revierte (o peor, otro facet lo tiene).
    6. FacetA.calculateLTV() falla para todos los usuarios → liquidaciones bloqueadas.
  invariante: |
    // Después de cualquier upgrade de facet, TODAS las funciones de TODOS los facets deben
    // seguir funcionando. Test de integración obligatorio:
    for (uint i = 0; i < allFunctions.length; i++) {
        (bool success,) = diamond.call(allFunctions[i]);
        assert(success); // ninguna función debe revert por dependencia rota
    }
  que_mirar:
    - "¿Algún facet llama a funciones de otros facets via address(this).call(...)?"
    - "¿Hay interfaces hardcodeadas entre facets que podrían cambiar en un upgrade?"
    - "¿El upgrade de un facet incluye test de integración con TODOS los demás facets?"
    - "¿Se usan internal libraries compartidas en vez de cross-facet calls? (más seguro)"
    - "rg 'address(this).call|address(this).staticcall' --type sol — buscar cross-facet dependencies"
  como_se_arregla: |
    Minimizar cross-facet calls — usar shared internal libraries en vez de dispatch externo.
    Si es necesario: definir interfaces estables (versionadas) para cross-facet communication.
    Test de integración obligatorio: después de cada upgrade, test suite ejecuta TODAS las funciones.
    Documentar explícitamente las dependencias entre facets en un dependency graph.
  trampas:
    - "Internal libraries compartidas no tienen este problema — solo cross-facet via dispatch"
    - "Si FacetA usa IFacetB interface para las llamadas, el compiler no detecta la rotura post-upgrade"
    - "Algunos protocolos usan un FacetRegistry interno para resolver dependencias — verificar que se actualiza"
    - "Este bug no causa pérdida de fondos directamente pero puede bloquear liquidaciones, retiros, etc."
  solodit_ids: []
  incidentes:
    - "ChainScore Labs advisory — Documenta que inter-facet dependencies crean attack surfaces complejas; upgrade de FacetB puede violar security assumptions de FacetA (Systemic Risk)"
    - "Aavegotchi Diamond (Certik/Quantstamp) — Múltiples auditorías del Diamond de Aavegotchi donde la complejidad de inter-facet calls fue señalada como riesgo de mantenimiento (Low)"
```

---

## 15. CREATE2 Deterministic Address Front-Running

```yaml
- id: diamond-015
  titulo: Dirección predecible con CREATE2 permite front-running del deploy
  causa_raiz: |
    CREATE2 calcula la dirección de deployment como hash(0xFF, deployer, salt, initCodeHash).
    Si el salt es predecible o público, un atacante puede pre-calcular la dirección y:
    (1) enviar tokens a esa dirección antes del deploy (para manipular estado inicial),
    (2) front-runear el deploy con un salt/bytecode diferente para claimear la dirección,
    (3) interactuar con contratos que ya confían en esa dirección futura.
    En contexto de clones (Clones.cloneDeterministic), la dirección predecible del clone
    puede ser usada para phishing o para pre-cargar tokens.
  como_funciona: |
    Escenario 1 — Pre-fund manipulation:
    1. Factory va a deployar VaultClone en address predecible via CREATE2.
    2. Atacante calcula la address y envía 1 wei de ETH.
    3. VaultClone se despliega con address(this).balance = 1 wei inesperado.
    4. Si el constructor/initializer usa address(this).balance para accounting → estado corrupto.

    Escenario 2 — Address squatting:
    1. Protocolo anuncia que va a deployar GovernanceToken en address X (calculada con CREATE2).
    2. Atacante front-runea y deploya un contrato diferente en address X (usando el mismo salt + factory).
    3. Si el atacante no puede usar la factory, puede deployar un selfdestruct contract en X,
       destruirlo, y ahora X está "libre" pero puede haber aprobaciones previas.
  invariante: |
    // Clones.cloneDeterministic con salt predecible — verificar que no se puede front-runear
    // assert(salt includes msg.sender o es secreto hasta el momento del deploy)
    bytes32 salt = keccak256(abi.encodePacked(msg.sender, userSalt));
    address clone = Clones.cloneDeterministic(implementation, salt);
  que_mirar:
    - "rg 'cloneDeterministic|create2' --type sol — ¿el salt incluye msg.sender?"
    - "¿La address del deploy se anuncia públicamente antes del deploy?"
    - "¿El contrato usa address(this).balance en constructor/initializer?"
    - "¿Hay aprobaciones (approve) para la address futura antes del deploy?"
    - "¿El salt es simplemente un counter o un valor predecible (block.number, block.timestamp)?"
  como_se_arregla: |
    Incluir msg.sender en el salt para que solo el deployer pueda claimar la address.
    Usar salt secreto hasta el momento del deploy (commit-reveal si es necesario).
    No confiar en address(this).balance en initializers — usar internal tracking.
    Deploy + initialize atómicamente para eliminar ventana de front-running.
  trampas:
    - "Pre-funding con ETH es raro en practice porque la mayoría de contratos no usan balance en init"
    - "En L2s con sequencer ordering, front-running de deploy es más difícil pero no imposible"
    - "Si el factory verifica que msg.sender es el expected deployer, el squatting no es posible"
    - "Este es más un vector de griefing/DoS que de fund theft en la mayoría de casos"
  solodit_ids: []
  incidentes:
    - "Wintermute ($160M, Sep 2022) — Vanity address de deployer generada con Profanity (vulnerable) permitió al atacante derivar la private key y acceder a fondos. No es CREATE2 directamente pero demuestra riesgo de addresses predecibles (Critical)"
    - "Patrón documentado por RareSkills — CREATE2 address prediction como vector de front-running en factory patterns"
```

---

## Cross-Reference con proxy-upgrade.md

```
Este briefing COMPLEMENTA proxy-upgrade.md:

proxy-upgrade.md ya cubre:
  - proxy-001: Storage collision between proxy and implementation (basic)
  - proxy-002: Uninitialized implementation
  - proxy-003: UUPS missing authorization
  - proxy-004: Initializer front-running
  - proxy-007: Selector clashing proxy vs implementation
  - proxy-019: Diamond slot 0 collision (ReentrancyGuard specific)
  - proxy-021: Unrestricted diamondCut (basic access control)
  - proxy-022: Storage slot shift loses roles
  - proxy-024: delegatecall to zero-code address

Este briefing añade:
  - diamond-001: AppStorage vs Diamond Storage pattern mixing (deeper than proxy-019)
  - diamond-002: Selector clashing BETWEEN facets (not proxy vs impl)
  - diamond-003: Facet initialization missing after diamondCut
  - diamond-004: selfdestruct in facet destroys Diamond
  - diamond-005: Cross-facet reentrancy via Diamond dispatch
  - diamond-006: Facet removal dangling storage
  - diamond-007: ERC-1167 minimal proxy clone manipulation
  - diamond-008: Metamorphic contract redeployment (CREATE2 + selfdestruct)
  - diamond-009: Beacon proxy shared failure domain
  - diamond-010: Immutable variables in proxy context
  - diamond-011: ERC-7201 namespaced storage violations
  - diamond-012: diamondCut _init callback arbitrary execution
  - diamond-013: Diamond Loupe registry desync
  - diamond-014: Inter-facet dependency breakage on upgrade
  - diamond-015: CREATE2 deterministic address front-running
```

---

## Hunting Checklist — Diamond & Advanced Proxy

```
Cuando encuentres un protocolo que usa Diamond (ERC-2535):
[ ] ¿Qué patrón de storage usa? AppStorage / Diamond Storage / ERC-7201 / Mix?
[ ] ¿Hay facets que hereden OZ estándar (ReentrancyGuard, Ownable, ERC20)?
[ ] ¿diamondCut tiene access control robusto (multisig + timelock)?
[ ] ¿diamondCut valida _init address? ¿O acepta cualquiera?
[ ] ¿Hay selectores duplicados entre facets? (cast sig en cada función)
[ ] ¿Hay cross-facet calls (address(this).call)? ¿Reentrancy guard es compartido?
[ ] ¿El loupe (facets(), facetAddress()) es consistente post-upgrade?
[ ] ¿Los facets contienen selfdestruct o delegatecall arbitrario?

Cuando encuentres ERC-1167 clones:
[ ] ¿La implementación tiene _disableInitializers?
[ ] ¿La implementación contiene selfdestruct?
[ ] ¿La factory valida la dirección de implementación?
[ ] ¿Hay immutables en la implementación que son incorrectos para el contexto del clone?

Cuando encuentres CREATE2 / metamorphic patterns:
[ ] ¿Hay contratos con CREATE2 + selfdestruct? (post-EIP-6780: verificar cadena)
[ ] ¿Las propuestas de governance son contratos que podrían ser metamórficos?
[ ] ¿Los salts de CREATE2 son predecibles? ¿Incluyen msg.sender?

Cuando encuentres Beacon proxies:
[ ] ¿Cuántos proxies comparten el beacon? ¿TVL total?
[ ] ¿El admin del beacon tiene timelock + multisig?
[ ] ¿Hay mecanismo de rollback o pausa?
```
