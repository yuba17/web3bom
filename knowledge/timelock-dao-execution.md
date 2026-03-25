# Timelock & DAO Execution — Bug Patterns

> Superficie de ataque: ejecucion de propuestas, delays de timelock, roles de guardian,
> acciones de emergencia, reentrancia en ejecucion, colisiones de hash, desync cross-chain.
> Complemento a governance.md (que cubre voting power, flash loan votes, proposal lifecycle).
> Este briefing se centra en los MECANISMOS DE EJECUCION: timelocks, execute/cancel, guardian bypass.
> Fuentes: OZ TimelockController CVE, Compound GovernorBravo OZ audit, Beanstalk $182M,
> Tornado Cash governance takeover, Solodit verified findings.

## Quick Reference

```
grep_targets:
  - TimelockController
  - Timelock
  - timelockDelay
  - minDelay
  - setDelay
  - updateDelay
  - schedule
  - scheduleBatch
  - execute
  - executeBatch
  - cancel
  - isOperationReady
  - isOperationPending
  - isOperationDone
  - getTimestamp
  - queueTransaction
  - executeTransaction
  - cancelTransaction
  - eta
  - GRACE_PERIOD
  - MINIMUM_DELAY
  - MAXIMUM_DELAY
  - queue
  - executeProposal
  - _afterCall
  - _beforeCall
  - guardian
  - emergencyAction
  - breakGlass
  - fastTrack
  - pauseGuardian
  - EXECUTOR_ROLE
  - PROPOSER_ROLE
  - CANCELLER_ROLE
  - TIMELOCK_ADMIN_ROLE
  - operationId
  - hashOperation
  - hashOperationBatch
  - predecessor
  - salt
```

---

## 1. Timelock Reentrancy — Executor Escalates to Admin

```yaml
- id: tl-001
  titulo: Reentrancia en TimelockController permite al executor tomar control total del timelock
  causa_raiz: |
    En versiones de OZ TimelockController anteriores a 4.3.1 (CVE-2021-39168), la verificacion
    isOperationReady se hacia solo en _afterCall, no en _beforeCall. Un executor podia reentrar
    durante la ejecucion de una operacion para ejecutar otras operaciones que aun no estaban
    ready, incluyendo llamadas al propio timelock para: (1) setDelay(0), (2) revocar proposers
    existentes, (3) asignarse como proposer, y (4) ejecutar llamadas arbitrarias sin delay.
    El resultado: el executor toma control completo del timelock y todos los fondos custodiados.
  como_funciona: |
    1. Operacion A esta queued y ready (delay expirado).
    2. Executor llama execute(A). A contiene una llamada a un contrato malicioso.
    3. Contrato malicioso reentra al timelock via execute(B) — B no esta ready pero el check
       solo se hace en _afterCall (que aun no se ejecuto para A).
    4. B llama timelock.updateDelay(0) + timelock.grantRole(PROPOSER, attacker).
    5. Attacker ahora puede schedule + execute cualquier cosa con delay=0.
    6. Drena todos los fondos del timelock.
  invariante: |
    // isOperationReady DEBE verificarse ANTES y DESPUES de la ejecucion
    function execute(bytes32 id, ...) external {
        require(isOperationReady(id), "NotReady"); // _beforeCall
        (bool ok,) = target.call(data);
        require(isOperationReady(id), "ReentrancyDetected"); // _afterCall (ya cambiado a Done)
    }
  que_mirar:
    - "Version de OZ < 4.3.1 — vulnerable. Verificar import en package.json"
    - "EXECUTOR_ROLE asignado a address(0) = cualquiera puede ejecutar = riesgo critico"
    - "grep: _afterCall, _beforeCall, isOperationReady, EXECUTOR_ROLE"
    - "grep: updateDelay, grantRole, revokeRole dentro del scope de execute()"
  como_se_arregla: |
    Upgrade a OZ >= 4.3.1. El fix agrega isOperationReady check en _beforeCall ademas de
    _afterCall. Revocar EXECUTOR_ROLE de address(0) si no es estrictamente necesario.
    Implementar ReentrancyGuard adicional en execute/executeBatch como defensa en profundidad.
  trampas:
    - "El bug solo es explotable si el executor puede triggear una llamada a un contrato externo — si todas las operaciones son internas, no hay vector de reentrancia"
    - "address(0) como executor significa que CUALQUIERA puede explotar esto — verificar primero"
    - "La vulnerabilidad afecta tanto execute() como executeBatch()"
  solodit_ids:
    - "l-09-timelock-prevents-multiple-replays-but-is-subject-to-cross-operation-reentrancy-recon-audits-none-kleidi-report-markdown"
    - "timelockcontrolleremergency-could-be-used-to-allow-anyone-to-execute-proposals-trailofbits-none-mass-pdf"
  incidentes:
    - "OpenZeppelin TimelockController CVE-2021-39168 — reentrancia permite al executor tomar admin del timelock. $25K bounty pagado. Afecto a un proyecto anonimo en Immunefi."
    - "Kleidi (ReconAudits) — timelock previene replay pero es susceptible a reentrancia cross-operation"
```

---

## 2. Timelock Bypass via Llamada Directa

```yaml
- id: tl-002
  titulo: Funcion critica callable directamente sin pasar por el timelock
  causa_raiz: |
    El timelock protege las funciones que se ejecutan VIA el timelock (schedule + execute).
    Pero si una funcion critica tiene un modificador onlyOwner separado y el owner es un EOA
    o multisig (no el timelock), esa funcion se puede llamar inmediatamente sin esperar el
    delay. Patron comun: el deployer asigna ownership al multisig pero olvida transferir
    ownership al timelock, o crea setters con paths alternativos que bypasean el timelock.
  como_funciona: |
    1. Protocolo tiene TimelockController con 7 dias de delay para governance.
    2. VaultFactory.setOwner() tiene modificador onlyOwner — owner es un multisig EOA.
    3. Multisig llama setOwner(attacker) directamente — ejecucion inmediata.
    4. Attacker ahora es owner del VaultFactory — puede cambiar implementacion, drenar fondos.
    5. Los usuarios confiaban en el timelock de 7 dias para reaccionar, pero el path directo
       nunca paso por el timelock.
  invariante: |
    // TODAS las funciones que modifican parametros criticos deben tener
    // msg.sender == address(timelock) como unica ruta de ejecucion
    modifier onlyTimelock() {
        require(msg.sender == address(timelockController), "NotTimelock");
        _;
    }
  que_mirar:
    - "Funciones con onlyOwner que DEBERIAN pasar por timelock pero no lo hacen"
    - "Owner del contrato = EOA o multisig en vez de TimelockController"
    - "grep: onlyOwner, setOwner, transferOwnership, acceptOwnership"
    - "Comparar: que funciones pasan por timelock vs cuales son directas"
  como_se_arregla: |
    Transferir ownership de todos los contratos criticos al TimelockController.
    Eliminar paths directos de setter. Si se necesita emergency action, usar un guardian
    con scope limitado (solo pause, no upgrade ni transfer de fondos).
  trampas:
    - "El protocolo puede documentar el timelock prominentemente pero tener setters directos ocultos"
    - "VaultFactory ownership bypass fue M-9 en Y2K (Sherlock) — la ownership se cambiaba inmediatamente"
    - "Verificar que el ADMIN_ROLE del timelock no esta asignado a un EOA"
  solodit_ids:
    - "m-9-vault-factory-ownership-can-be-changed-immediately-and-bypass-timelock-delay-sherlock-none-y2k-git"
    - "h-01-timelock-can-be-bypassed-code4rena-malt-finance-malt-finance-contest-git"
    - "quantammbaseadministrationonlyexecutor-modifier-does-not-enforce-a-time-lock-on-actions-cyfrin-none-quantamm-markdown"
  incidentes:
    - "Y2K (Sherlock M-9) — VaultFactory ownership cambiable inmediatamente, bypass del timelock delay"
    - "Malt Finance (C4 H-01) — timelock bypasseado completamente via path alternativo"
    - "QuantAMM (Cyfrin) — modifier onlyExecutor no enforcea el time lock sobre las acciones"
```

---

## 3. Governance Flash Loan Attack — Beanstalk Pattern

```yaml
- id: tl-003
  titulo: Flash loan de tokens de governance para votar y ejecutar propuesta en una transaccion
  causa_raiz: |
    Si el protocolo permite votar Y ejecutar la propuesta en la misma transaccion (sin delay
    entre votacion y ejecucion), un atacante puede pedir un flash loan de tokens de governance,
    votar a favor de una propuesta maliciosa, ejecutarla, y devolver los tokens — todo en un
    bloque. La condicion necesaria es: (1) sin snapshot previo al bloque de votacion, o
    (2) emergencyExecute que bypasea el timelock, o (3) proposal + vote + execute sin delay.
    Beanstalk perdio $182M exactamente por este patron.
  como_funciona: |
    1. Atacante crea BIP-18 (propuesta maliciosa): transferir todo el colateral al atacante.
    2. Crea BIP-19 (donation a Ucrania) para distraer atencion.
    3. En la tx de ejecucion: flash loan $1B de Aave → deposita en Beanstalk →
       obtiene governance tokens (Stalk) → vota BIP-18 → pasa quorum →
       BIP-18 se ejecuta inmediatamente (sin timelock) → fondos transferidos →
       devuelve flash loan.
    4. Profit neto: ~$80M. Total drenado: $182M.
  invariante: |
    // Voting power DEBE snapshot en bloque previo a la propuesta
    // Y la ejecucion DEBE tener delay (timelock)
    function castVote(uint proposalId, uint8 support) external {
        uint256 snapshotBlock = proposals[proposalId].startBlock;
        require(snapshotBlock < block.number, "SnapshotNotReady");
        uint256 weight = getPastVotes(msg.sender, snapshotBlock);
        // NO usar balanceOf(msg.sender) — vulnerable a flash loans
    }
  que_mirar:
    - "Voting power calculado con balanceOf en vez de getPastVotes/snapshot"
    - "Propuesta ejecutable en el mismo bloque que se vota"
    - "Sin timelock entre aprobacion y ejecucion"
    - "grep: balanceOf, getPastVotes, getPriorVotes, proposalSnapshot"
    - "grep: emergencyExecute, immediateExecute, forceExecute"
  como_se_arregla: |
    Usar ERC20Votes con checkpoints: voting power = getPastVotes(voter, snapshotBlock).
    Snapshot al crear la propuesta (snapshotBlock = block.number - 1).
    Timelock obligatorio entre aprobacion y ejecucion (minimo 24-48h).
    Voting delay > 0 entre creacion de propuesta e inicio de votacion.
  trampas:
    - "Solo funciona si hay suficiente liquidez para flash loan — pero en DeFi hay miles de millones disponibles"
    - "Algunos protocolos usan 'emergencyExecute' que bypasea el timelock — vector alternativo"
    - "La donacion a Ucrania (BIP-19) era distraccion social, no tecnica — el ataque era puramente on-chain"
  solodit_ids:
    - "h-05-flash-loans-can-affect-governance-voting-in-daosol-code4rena-vader-protocol-vader-protocol-contest-git"
    - "malicious-user-could-flash-loan-the-vealcx-to-inflate-the-voting-balance-of-their-account-immunefi-alchemix-git"
  incidentes:
    - "Beanstalk ($182M, abril 2022) — flash loan $1B, voto + ejecucion en una tx, sin timelock ni snapshot"
    - "Vader Protocol (C4 H-05) — flash loans afectan votacion de governance en DAO.sol"
    - "Alchemix (Immunefi) — flash loan de veALCX infla voting balance del atacante"
```

---

## 4. Timelock Delay Cero o Insuficiente

```yaml
- id: tl-004
  titulo: Delay del timelock configurado a cero o demasiado corto para que usuarios reaccionen
  causa_raiz: |
    El timelock es un contrato de seguridad para que los usuarios tengan tiempo de reaccionar
    ante cambios peligrosos (sacar fondos, migrar a otra plataforma). Si el delay se configura
    a 0 en el constructor, o si no hay un MINIMUM_DELAY hardcodeado, el admin puede setear el
    delay a 0 y ejecutar cualquier cosa inmediatamente. Tambien: un delay de 1 hora en un
    protocolo con $100M TVL es insuficiente — los usuarios necesitan dias, no minutos.
  como_funciona: |
    1. Constructor: TimelockController(minDelay=0, proposers, executors, admin).
    2. Admin puede schedule + execute en el mismo bloque porque delay es 0.
    3. O: admin llama updateDelay(0) — sin check de MINIMUM_DELAY.
    4. Admin drena treasury, cambia oracle, o upgradea implementacion a contrato malicioso.
    5. Usuarios no tuvieron tiempo de reaccionar porque el delay era insuficiente o cero.
  invariante: |
    // El delay DEBE tener un minimo hardcodeado, no configurable
    uint256 public constant MINIMUM_DELAY = 2 days;
    function updateDelay(uint256 newDelay) external onlyRole(TIMELOCK_ADMIN_ROLE) {
        require(newDelay >= MINIMUM_DELAY, "DelayTooShort");
        _minDelay = newDelay;
    }
  que_mirar:
    - "Constructor del timelock: minDelay = 0?"
    - "updateDelay() sin check de MINIMUM_DELAY"
    - "grep: MINIMUM_DELAY, minDelay, updateDelay, setDelay, constructor.*delay"
    - "Deployment script o init: que valor se pasa como delay?"
  como_se_arregla: |
    Hardcodear MINIMUM_DELAY >= 24h (idealmente 48h para protocolos con > $10M TVL).
    No permitir que updateDelay baje por debajo del minimo.
    Verificar en el constructor: require(minDelay >= MINIMUM_DELAY).
  trampas:
    - "Un delay de 0 puede ser intencional para testnet pero letal en mainnet — verificar deployment config"
    - "Moonwell tuvo delay=0 en el constructor (Halborn M) — el guardian podia actuar sin espera"
    - "El delay se puede reducir gradualmente en multiples pasos si no hay check de minimo"
  solodit_ids:
    - "timelock-delay-is-set-to-zero-in-the-constructor-halborn-moonwell-governance-timelock-updates-markdown"
    - "timelock-duration-check-missing-allows-near-zero-delay-mixbytes-none-cryptolegacy-markdown"
    - "lack-of-min_delay-in-root-could-invalidate-timelock-cantina-none-centrifuge-pdf"
    - "lack-of-configurable-delay-setting-in-timelock-ottersec-none-lombard-finance-pdf"
  incidentes:
    - "Moonwell (Halborn M) — delay del timelock seteado a 0 en el constructor"
    - "CryptoLegacy (MixBytes) — sin check de duracion minima, permite delay near-zero"
    - "Centrifuge (Cantina) — falta de MIN_DELAY en root podria invalidar todo el timelock"
    - "Lombard Finance (OtterSec) — delay no configurable, rigidez que impide adaptar a necesidades"
```

---

## 5. Guardian / Emergency Action Overprivilegiado

```yaml
- id: tl-005
  titulo: Guardian o rol de emergencia con poderes excesivos que bypasean todas las protecciones
  causa_raiz: |
    Muchos protocolos tienen un "guardian" o "break glass" role para emergencias (pausar el
    protocolo, cancelar propuestas maliciosas). Pero si el guardian puede hacer MAS que pausar
    — por ejemplo, cambiar la implementacion, transferir fondos, o ejecutar propuestas sin
    delay — entonces el guardian ES el admin sin timelock. Un guardian comprometido (multisig
    hackeado, key leak) puede drenar todo el protocolo inmediatamente.
  como_funciona: |
    1. Guardian tiene BREAK_GLASS_ROLE con capacidad de: pause + setOracle + setFeeRecipient.
    2. Multisig del guardian comprometido (2-of-3, y 2 keys leakeadas).
    3. Guardian llama setOracle(maliciousOracle) + setFeeRecipient(attacker) sin timelock.
    4. Oracle malicioso reporta precios inflados → usuarios liquidados injustamente.
    5. Fee recipient redirige todos los fees al atacante.
    6. No hubo delay porque el guardian bypasea el timelock "por emergencia".
  invariante: |
    // Guardian SOLO debe poder PAUSAR y CANCELAR propuestas maliciosas
    // Nunca: upgrade, transfer fondos, cambiar oracle, cambiar fees
    modifier onlyGuardian() {
        require(hasRole(GUARDIAN_ROLE, msg.sender), "NotGuardian");
        _;
    }
    // Funciones del guardian: SOLO defensivas
    function pause() external onlyGuardian { _pause(); }
    function cancelProposal(uint id) external onlyGuardian { _cancel(id); }
    // NUNCA: function setOracle(...) external onlyGuardian { ... }
  que_mirar:
    - "Que funciones puede llamar el guardian? Solo pause/cancel, o tambien upgrade/transfer?"
    - "El guardian bypasea el timelock para TODAS las acciones o solo para pause?"
    - "grep: guardian, GUARDIAN_ROLE, BREAK_GLASS, breakGlass, emergencyAction, fastTrack"
    - "grep: onlyGuardian.*set, onlyGuardian.*upgrade, onlyGuardian.*transfer"
  como_se_arregla: |
    Principio de minimo privilegio: guardian SOLO puede pausar y cancelar.
    Cambios de parametros SIEMPRE via timelock, incluso en emergencia.
    Si se necesita emergency upgrade: guardian pausa + propuesta de governance con delay reducido
    (24h en vez de 7 dias), no delay=0.
  trampas:
    - "Moonwell (C4) — guardian puede fast-track TODA propuesta, no solo emergencias"
    - "fastTrackProposalExecution no chequea intendedRecipient (M-07) — guardian ejecuta propuesta equivocada"
    - "El guardian 'solo puede pausar' pero pause() bloquea withdrawals = DoS de usuarios"
  solodit_ids:
    - "overprivileged-role-on-the-break-glass-guardian-halborn-moonwell-governance-timelock-updates-markdown"
    - "emergency-timelock-bypass-no-enforced-1-day-delay-for-emergency-actions-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "l-01-guardian-can-fast-track-every-proposal-code4rena-moonwell-moonwell-git"
    - "m-07-fasttrackproposalexecution-doesnt-check-intendedrecipient-code4rena-moonwell-moonwell-git"
  incidentes:
    - "Moonwell (Halborn M) — break glass guardian con rol overprivilegiado"
    - "Moonwell (C4 L-01) — guardian puede fast-track TODA propuesta, no solo emergencias"
    - "Moonwell (C4 M-07) — fastTrackProposalExecution no chequea intendedRecipient"
    - "RAAC (CodeHawks) — emergency timelock bypass sin delay de 1 dia enforceado"
```

---

## 6. Proposal Front-Running via Salt Predecible

```yaml
- id: tl-006
  titulo: Front-running de propuesta por salt predecible en scheduleBatch del TimelockController
  causa_raiz: |
    En TimelockController, el operationId se calcula como keccak256(abi.encode(targets, values,
    payloads, predecessor, salt)). Si el salt es predecible (e.g., bytes32(0) o basado en
    block.number), un atacante puede calcular el mismo operationId, hacer schedule de la
    misma operacion ANTES que el proposer legitimo, y controlar la ejecucion. El atacante
    puede: (1) ejecutar antes del momento esperado, o (2) cancelar la operacion del proposer
    legitimo.
  como_funciona: |
    1. Proposer prepara una operacion con salt conocido (e.g., 0x0).
    2. Atacante observa la tx en el mempool.
    3. Atacante front-runea con schedule() usando el mismo salt → mismo operationId.
    4. La tx original del proposer revierte (operacion ya existe con ese id).
    5. Atacante ahora controla la operacion: puede cancelar o ejecutar cuando quiera.
    6. Si el atacante tiene EXECUTOR_ROLE, puede ejecutar inmediatamente cuando el delay expire.
  invariante: |
    // El salt DEBE ser unico y no predecible
    // Usar un nonce incremental o un hash que incluya msg.sender
    bytes32 salt = keccak256(abi.encode(msg.sender, nonce++));
    // O verificar que la operacion no puede ser overrideada por otro proposer
    require(_timestamps[id] == 0, "AlreadyScheduled");
  que_mirar:
    - "Salt hardcodeado a 0x0 o valor fijo en schedule/scheduleBatch"
    - "Salt derivado de valores publicos (block.number, block.timestamp)"
    - "Multiples proposers — un proposer puede front-runear al otro?"
    - "grep: salt, scheduleBatch, hashOperation, hashOperationBatch"
  como_se_arregla: |
    Usar salt que incluya msg.sender como componente. O usar nonce incremental gestionado
    por el contrato. El operationId ya incluye el salt, pero si el salt es predecible, el
    operationId tambien lo es. Alternativa: solo un proposer por timelock.
  trampas:
    - "El salt de OZ TimelockController es arbitrario — es responsabilidad del caller elegir uno seguro"
    - "Si solo hay un proposer (multisig), el front-running entre proposers no aplica"
    - "El riesgo real es cuando PROPOSER_ROLE esta asignado a multiples direcciones"
  solodit_ids:
    - "proposal-front-running-via-predictable-salt-in-timelockcontrollerschedulebatch-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "RAAC (CodeHawks M) — front-running de propuesta via salt predecible en TimelockController.scheduleBatch"
```

---

## 7. Propuestas Derrotadas se Vuelven Ejecutables al Bajar Quorum

```yaml
- id: tl-007
  titulo: Propuestas derrotadas se vuelven ejecutables retroactivamente al reducir el quorum
  causa_raiz: |
    Si el quorum se evalua DINAMICAMENTE (en base a total supply actual o parametro configurable)
    en lugar de snapshot en el momento de la propuesta, bajar el quorum retroactivamente puede
    hacer que propuestas que NO pasaron el quorum original ahora SI lo pasen. Un atacante puede:
    (1) crear propuestas que fallen por poco margen, (2) esperar a que se baje el quorum via
    otra propuesta, y (3) ejecutar las propuestas "derrotadas" que ahora pasan el nuevo quorum.
  como_funciona: |
    1. Quorum actual: 10% del total supply = 1M tokens necesarios.
    2. Propuesta A: 900K votos a favor, 100K en contra → no pasa quorum (faltan 100K).
    3. Propuesta B (legitima): "Reducir quorum a 8%".
    4. Propuesta B pasa y se ejecuta. Nuevo quorum: 8% = 800K tokens.
    5. Propuesta A ahora se evalua con quorum de 800K → 900K > 800K → PASA.
    6. Propuesta A se ejecuta — podria ser maliciosa y fue "derrotada" originalmente.
  invariante: |
    // Quorum DEBE almacenarse como snapshot al crear la propuesta
    function propose(...) external returns (uint256 proposalId) {
        proposals[proposalId].quorumSnapshot = quorum(); // fijado al crear
        // ...
    }
    function _quorumReached(uint256 proposalId) internal view returns (bool) {
        return forVotes[proposalId] >= proposals[proposalId].quorumSnapshot;
    }
  que_mirar:
    - "Quorum evaluado con valor actual o con snapshot al crear la propuesta?"
    - "Cambiar quorum afecta propuestas pasadas que no alcanzaron quorum?"
    - "grep: quorum, quorumNumerator, setQuorum, updateQuorum, _quorumReached"
    - "grep: proposalSnapshot, quorumVotes, GovernorVotesQuorumFraction"
  como_se_arregla: |
    Snapshot del quorum al crear la propuesta: proposals[id].quorum = quorum().
    Usar OZ GovernorVotesQuorumFraction con quorumDenominator() y snapshot.
    Nunca evaluar quorum con parametros actuales sobre propuestas pasadas.
  trampas:
    - "Alchemix tuvo exactamente este bug — propuestas derrotadas se volvian ejecutables al bajar quorum"
    - "Es un bug sutil: parece 'por diseno' que quorum sea dinamico, pero el efecto retroactivo es peligroso"
    - "GovernorCompatibilityBravo de OZ SI usa snapshot de quorum, pero implementaciones custom no"
  solodit_ids:
    - "past-defeated-proposals-may-become-executable-if-the-quorum-requirement-is-lowered-immunefi-alchemix-git"
    - "past-defeated-proposals-can-be-executed-in-the-future-immunefi-alchemix-git"
    - "alchemixgovernor-updates-to-quorum-can-affect-past-defeated-proposals-immunefi-alchemix-git"
    - "m-22-governance-deadlock-potential-in-blackgovernorsol-due-to-quorum-mismatch-code4rena-audit-507-audit-507-git"
  incidentes:
    - "Alchemix (Immunefi) — propuestas derrotadas se vuelven ejecutables al bajar quorum"
    - "Alchemix (Immunefi) — updates al quorum afectan propuestas pasadas retroactivamente"
    - "Audit 507 (C4 M-22) — quorum mismatch causa deadlock en governance"
```

---

## 8. Colision de Operaciones en Timelock — Mismo Hash para Dos Propuestas

```yaml
- id: tl-008
  titulo: Dos operaciones con mismo hash en el timelock — una sobreescribe o bloquea a la otra
  causa_raiz: |
    El operationId en TimelockController es keccak256(targets, values, payloads, predecessor,
    salt). Si dos propuestas legitimamente distintas usan los mismos parametros (mismo target,
    mismo calldata, mismo salt — e.g., "llamar setFee(100) dos veces"), generan el mismo hash.
    La segunda propuesta no puede ser scheduled porque el id ya existe. O peor: si la primera
    se ejecuta y se marca como Done, la segunda se considera tambien Done y nunca se ejecuta.
    En Compound GovernorBravo: funciones con mismos parametros y mismo eta colisionan.
  como_funciona: |
    1. Propuesta A: call setFee(100) con eta=1700000000.
    2. Propuesta B: call setFee(100) con eta=1700000000 (mismos params, mismo momento).
    3. queueTransaction(target, value, sig, data, eta) para A → almacena hash.
    4. queueTransaction para B → mismo hash → depende de implementacion:
       - Revierte (AlreadyQueued) → propuesta B bloqueada.
       - Sobreescribe → propuesta A desaparece.
    5. Solo una de las dos propuestas puede ejecutarse.
  invariante: |
    // Cada propuesta debe tener un id unico, incluyendo un nonce o proposalId
    bytes32 operationId = keccak256(abi.encode(
        targets, values, payloads, predecessor,
        keccak256(abi.encode(proposalId)) // <- hace el hash unico
    ));
    require(_timestamps[operationId] == 0, "AlreadyQueued");
  que_mirar:
    - "Dos propuestas con mismos parametros pueden colisionar en el timelock?"
    - "El salt incluye proposalId o nonce unico?"
    - "Compound GovernorBravo: misma funcion + misma eta = colision"
    - "grep: hashOperation, queueTransaction, keccak256.*target.*value.*data.*eta"
  como_se_arregla: |
    Incluir proposalId o nonce en el calculo del hash.
    Usar salt unico por propuesta en scheduleBatch.
    OZ TimelockController ya permite salt arbitrario — usarlo correctamente.
    Compound fix: GovernorBravo documenta que misma accion + misma eta colisiona.
  trampas:
    - "El bug es por diseno en Compound's Timelock — documentado pero sigue siendo un riesgo si no se sabe"
    - "Propuestas con multiples acciones identicas (e.g., batch grant) son especialmente vulnerables"
    - "OZ TimelockController con salt=0 por defecto colisiona si mismas acciones"
  solodit_ids:
    - "l-08-optimistic-and-standard-proposals-collide-in-shared-id-space-pashov-audit-group-none-reserve_2026-02-27-markdown"
    - "proposals-could-allow-timelockadmin-takeover-trailofbits-origin-dollar-pdf"
  incidentes:
    - "Reserve (Pashov L-08) — propuestas optimistas y standard colisionan en el mismo ID space"
    - "Origin Dollar (Trail of Bits H) — propuestas podrian permitir takeover del Timelock.admin"
    - "Compound GovernorBravo (OZ audit) — acciones con mismos parametros + misma eta colisionan"
```

---

## 9. Tornado Cash Pattern — Propuesta con Codigo Malicioso Oculto via CREATE2 + SELFDESTRUCT

```yaml
- id: tl-009
  titulo: Propuesta incluye contrato que se autodestruye y se redeployea con codigo malicioso
  causa_raiz: |
    Una propuesta de governance apunta a ejecutar un contrato en una direccion especifica.
    Los votantes verifican el codigo del contrato ANTES de votar. Pero si el contrato usa
    CREATE2, el atacante puede: (1) deployear codigo benigno que pasa la verificacion,
    (2) hacer selfdestruct, (3) redeployear en la MISMA direccion con codigo malicioso
    (usando el mismo salt en CREATE2). Cuando la propuesta se ejecuta post-timelock,
    el codigo en esa direccion ya no es el que los votantes verificaron.
  como_funciona: |
    1. Atacante crea propuesta: "Ejecutar logicContract.doUpgrade()".
    2. logicContract (deployeado via CREATE2) contiene codigo benigno — votantes lo verifican.
    3. Propuesta pasa la votacion y entra en timelock (7 dias).
    4. Durante el timelock delay: atacante llama logicContract.emergencyDestroy() → selfdestruct.
    5. Atacante redeployea via CREATE2 con mismo salt en la MISMA direccion → codigo malicioso:
       - Mint 1.2M tokens de governance al atacante
       - O drenar treasury directamente
    6. Timelock expira, propuesta se ejecuta → llama el codigo MALICIOSO, no el benigno.
    7. Tornado Cash: atacante obtuvo 1.2M TORN (> 700K legitimos) → control total del DAO.
  invariante: |
    // La propuesta debe verificar que el codigo del target no cambio entre vote y execute
    // Almacenar el codehash del target al momento de crear la propuesta
    function propose(address[] targets, ...) external {
        for (uint i; i < targets.length; i++) {
            proposals[id].targetCodeHash[i] = targets[i].codehash;
        }
    }
    function execute(uint id) external {
        for (uint i; i < targets.length; i++) {
            require(targets[i].codehash == proposals[id].targetCodeHash[i], "CodeChanged");
        }
    }
  que_mirar:
    - "La propuesta apunta a un contrato deployeado via CREATE2?"
    - "El contrato target tiene funcion de selfdestruct?"
    - "Se verifica codehash del target al momento de ejecutar?"
    - "grep: selfdestruct, CREATE2, create2, codehash, extcodehash"
    - "grep: delegatecall en el contrato target — podria ejecutar selfdestruct via proxy"
  como_se_arregla: |
    Verificar codehash del target en execute(): require(target.codehash == storedCodeHash).
    No permitir propuestas que apunten a contratos con selfdestruct.
    Almacenar el calldata completo on-chain (no solo el hash del target).
    Prohibir CREATE2 para contratos de governance.
  trampas:
    - "El atacante de Tornado Cash uso este EXACTO patron — $2.1M robados via 1.2M TORN tokens"
    - "selfdestruct esta deprecado en EIP-6780 (Cancun) — pero SOLO si se llama en la misma tx que el create. Contratos legacy aun pueden hacer selfdestruct cross-tx"
    - "delegatecall a un contrato con selfdestruct tambien destruye el proxy — vector indirecto"
  solodit_ids: []
  incidentes:
    - "Tornado Cash (mayo 2023) — propuesta con contrato benigno, selfdestruct + CREATE2 redeploy con codigo malicioso. 1.2M TORN mintados, control total del DAO, ~$2.1M robados."
```

---

## 10. Cross-Chain Governance Desync — Ejecucion Desfasada entre L1 y L2

```yaml
- id: tl-010
  titulo: Accion de governance en L1 se ejecuta con delay variable en L2 — estado inconsistente
  causa_raiz: |
    Protocolos multi-chain tienen governance en L1 y ejecucion en L2 via bridge (LayerZero,
    CCIP, canonical bridge). El mensaje cross-chain tiene latencia variable (minutos a dias
    dependiendo del bridge y congestion). Si el protocolo asume que la accion se ejecuta
    "inmediatamente" en todas las chains, pueden haber ventanas donde L1 tiene el nuevo
    parametro pero L2 tiene el viejo — o viceversa. Un atacante puede explotar esta ventana.
  como_funciona: |
    1. Governance en L1: "Reducir colateral ratio de 150% a 120%".
    2. Propuesta se ejecuta en L1: parametro actualizado inmediatamente.
    3. Mensaje cross-chain enviado a L2 via bridge con 2h de delay.
    4. Durante 2h: L1 tiene ratio=120%, L2 tiene ratio=150%.
    5. Atacante en L2: puede hacer operaciones con ratio 150% (mas estricto) que serian
       invalidas con 120% — o puede mover colateral entre chains explotando la diferencia.
    6. O viceversa: ratio mas permisivo en L2 durante el gap permite sub-colaterizacion.
  invariante: |
    // Los cambios de parametros cross-chain deben ser atomicos o tener grace period
    // Si no son atomicos, el protocolo debe pausar operaciones sensibles durante la sync
    function updateCollateralRatio(uint newRatio) external onlyGovernance {
        pendingRatio = newRatio;
        pendingRatioEffectiveTime = block.timestamp + CROSS_CHAIN_SYNC_BUFFER;
        // No aplicar hasta que TODAS las chains confirmen la actualizacion
    }
  que_mirar:
    - "Parametros criticos se sincronizan cross-chain? Con que latencia?"
    - "Hay grace period entre anunciar el cambio y aplicarlo en todas las chains?"
    - "grep: lzReceive, _nonblockingLzReceive, ccipReceive, onMessageReceived"
    - "grep: setCollateralRatio, setOracle, setFee cross-chain dispatch"
  como_se_arregla: |
    Buffer de sincronizacion: no aplicar cambio hasta timestamp + MAX_BRIDGE_DELAY.
    Pausar operaciones sensibles durante el periodo de sincronizacion cross-chain.
    Usar un patron de "commit-reveal" cross-chain: commit en todas las chains, luego
    reveal simultaneo cuando todas confirmaron.
  trampas:
    - "Los bridges canonicos de L2 (Optimism, Arbitrum) tienen 7 dias de delay para mensajes L2→L1 — enorme ventana"
    - "Venus Multichain Governance — orden de ejecucion de propuestas no garantizado entre chains"
    - "onlyGovernance modifier de OZ no funciona en satellite chains (gov-011) — vector relacionado"
  solodit_ids:
    - "proposal-execution-order-not-guaranteed-in-venus-multichain-governance-quantstamp-venus-mutichain-governance-markdown"
  incidentes:
    - "Venus (Quantstamp L) — orden de ejecucion de propuestas no garantizado en governance multichain"
```

---

## 11. Timelock Admin Takeover via Propuesta Maliciosa

```yaml
- id: tl-011
  titulo: Propuesta de governance que transfiere el admin role del timelock al atacante
  causa_raiz: |
    El TimelockController tiene un TIMELOCK_ADMIN_ROLE que puede grant/revoke cualquier
    otro rol (PROPOSER, EXECUTOR, CANCELLER). Si una propuesta de governance incluye una
    accion que llama timelock.grantRole(TIMELOCK_ADMIN_ROLE, attacker) — ya sea explicitamente
    o enterrada entre muchas acciones "legitimas" — el atacante obtiene control total.
    En particular, si el admin puede ejecutar acciones sin delay, el takeover es inmediato.
  como_funciona: |
    1. Atacante crea propuesta con 20 acciones. Acciones 1-19: cambios legitimos (fees, params).
    2. Accion 20 (oculta al final): timelock.grantRole(TIMELOCK_ADMIN_ROLE, attacker).
    3. Votantes revisan superficialmente — las primeras acciones parecen legitimas.
    4. Propuesta pasa, se ejecuta via timelock.
    5. Accion 20 se ejecuta: atacante ahora tiene TIMELOCK_ADMIN_ROLE.
    6. Atacante revoca todos los otros admins, proposers, cancellers.
    7. Atacante controla el timelock → controla todos los contratos que el timelock administra.
  invariante: |
    // El timelock NO debe poder ejecutar grantRole/revokeRole sobre si mismo via propuestas
    // O: restriccion explicita que previene auto-role-change
    function execute(bytes32 id, address target, ...) internal {
        if (target == address(this)) {
            require(
                !_isRoleAdminChange(calldata_),
                "CannotChangeOwnRoles"
            );
        }
    }
  que_mirar:
    - "La propuesta puede incluir llamadas al propio timelock (target == address(timelock))?"
    - "Se pueden hacer grant/revokeRole via propuesta?"
    - "grep: grantRole, revokeRole, TIMELOCK_ADMIN_ROLE, DEFAULT_ADMIN_ROLE"
    - "Batch proposals: verificar CADA accion, no solo las primeras"
  como_se_arregla: |
    Prohibir que propuestas ejecuten grantRole/revokeRole en el timelock.
    O: requerir supermajority (>66%) para propuestas que modifican roles del timelock.
    Herramienta de verificacion de propuestas (como la de ZKSync) para que votantes
    puedan inspeccionar TODAS las acciones antes de votar.
  trampas:
    - "Origin Dollar (Trail of Bits H) — propuestas podrian permitir takeover del Timelock.admin"
    - "En batch proposals, la accion maliciosa puede estar al final de una lista larga"
    - "Si el timelock ES el admin de si mismo (patron de OZ), las propuestas SI pueden cambiar roles"
  solodit_ids:
    - "proposals-could-allow-timelockadmin-takeover-trailofbits-origin-dollar-pdf"
  incidentes:
    - "Origin Dollar (Trail of Bits H) — propuestas de governance podrian tomar control del Timelock.admin"
```

---

## 12. Transacciones Queued No Cancelables — DoS de Governance

```yaml
- id: tl-012
  titulo: Transacciones queued en el timelock no pueden cancelarse — bloquean governance
  causa_raiz: |
    Si la funcion cancelTransaction() del timelock esta rota, restringida incorrectamente, o
    no existe, las transacciones queued maliciosas no se pueden remover. Esto bloquea el
    governance: (1) la tx maliciosa se ejecutara cuando expire el delay, o (2) el hash de la
    tx ocupa el slot y previene re-queue de la misma accion con parametros corregidos.
    El resultado es un DoS del sistema de governance.
  como_funciona: |
    1. Proposer malicioso crea propuesta A con accion danina y la queuea en el timelock.
    2. Comunidad detecta la propuesta maliciosa y quiere cancelarla.
    3. cancelTransaction() tiene un bug: solo el proposer original puede cancelar (no el guardian).
    4. O: cancelTransaction() no existe en esta implementacion del timelock.
    5. La propuesta maliciosa se ejecutara automaticamente cuando expire el delay.
    6. La unica defensa: deployear un nuevo timelock y migrar todo antes de que expire el delay.
  invariante: |
    // Debe existir un CANCELLER_ROLE con acceso a cancel()
    // Y el guardian/multisig debe tenerlo
    function cancel(bytes32 id) public onlyRole(CANCELLER_ROLE) {
        require(isOperationPending(id), "NotPending");
        delete _timestamps[id];
        emit Cancelled(id);
    }
  que_mirar:
    - "Existe funcion cancel/cancelTransaction en el timelock?"
    - "Quien puede llamar cancel? Solo el proposer, o tambien guardian/canceller?"
    - "grep: cancel, cancelTransaction, CANCELLER_ROLE, onlyCanceller"
    - "Si no hay cancel: cual es el plan B si se queuea una tx maliciosa?"
  como_se_arregla: |
    Implementar cancel() con CANCELLER_ROLE asignado al guardian/multisig.
    El canceller debe ser diferente del proposer para evitar conflicto de intereses.
    En OZ TimelockController: CANCELLER_ROLE existe por defecto — verificar que esta asignado.
  trampas:
    - "Origin Dollar (Trail of Bits H) — queued transactions no podian cancelarse"
    - "Compound Timelock original no tenia cancel facil — admin tenia que 'emergency' redeployar"
    - "Si el canceller es el mismo que el proposer, el ataque es trivial"
  solodit_ids:
    - "queued-transactions-cannot-be-canceled-trailofbits-origin-dollar-pdf"
  incidentes:
    - "Origin Dollar (Trail of Bits H) — transacciones queued no podian cancelarse en el timelock"
```

---

## 13. Quorum Manipulation — Reducir Total Supply para Pasar Propuestas

```yaml
- id: tl-013
  titulo: Manipulacion del quorum reduciendo total supply o inflando votos relativos
  causa_raiz: |
    Si el quorum se calcula como porcentaje del totalSupply ACTUAL (no snapshot), un atacante
    puede reducir temporalmente el supply (burn tokens, lock en contratos) para que un numero
    menor de votos cumpla el quorum. O puede inflar el proposalThreshold del oponente para
    que no pueda crear contra-propuestas. El efecto: propuestas pasan con menos apoyo real
    del que el quorum deberia requerir.
  como_funciona: |
    1. Quorum = 4% del totalSupply = 4M tokens (de 100M total supply).
    2. Atacante lockea 50M tokens en un contrato que no delega votos.
    3. Effective supply reducido a 50M → nuevo quorum de 4% = 2M tokens.
    4. Atacante con 2M tokens vota a favor de propuesta maliciosa → pasa quorum.
    5. Con el supply real de 100M, habria necesitado 4M tokens → no habria pasado.
  invariante: |
    // Quorum debe basarse en totalSupply SNAPSHOT al momento de crear la propuesta
    function quorum(uint256 blockNumber) public view returns (uint256) {
        return token.getPastTotalSupply(blockNumber) * quorumNumerator / quorumDenominator;
    }
    // NUNCA: return token.totalSupply() * quorumNumerator / quorumDenominator;
  que_mirar:
    - "Quorum usa totalSupply() actual o getPastTotalSupply(snapshotBlock)?"
    - "Se puede reducir el supply efectivo (burn, lock sin delegation)?"
    - "grep: quorum, totalSupply, getPastTotalSupply, quorumNumerator"
    - "Bridge/staking contracts que holdan tokens pero no delegan — reducen quorum efectivo"
  como_se_arregla: |
    Usar getPastTotalSupply(proposalSnapshot) para el denominador del quorum.
    Excluir de totalSupply los tokens que no pueden votar (treasury, bridge escrow).
    OZ GovernorVotesQuorumFraction usa snapshot por defecto — verificar que se usa correctamente.
  trampas:
    - "RAAC (CodeHawks) — grupo coordinado puede bajar quorum artificialmente durante propuestas activas"
    - "Tokens en bridges cross-chain cuentan en totalSupply pero no pueden votar — bajan quorum real"
    - "Tokens en vesting que no delegan tambien distorsionan el calculo de quorum"
  solodit_ids:
    - "cordinated-group-of-attacker-can-artificially-lower-quorum-threshold-during-active-proposals-forcing-malicious-proposals-to-pass-without-true-majority-support-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "it-is-possible-to-lower-the-quorum-requirements-that-will-lead-to-the-past-unmet-proposals-become-executable-immunefi-alchemix-git"
    - "m-19-governor-quorum-could-be-less-than-intended-code4rena-nouns-builder-nouns-builder-git"
    - "missing-quorum-requirement-in-governance-voting-cyfrin-none-deriverse-dex-markdown"
  incidentes:
    - "RAAC (CodeHawks M) — grupo coordinado baja quorum artificialmente, fuerza propuestas maliciosas"
    - "Alchemix (Immunefi) — bajar quorum hace ejecutables propuestas antes derrotadas"
    - "Nouns Builder (C4 M-19) — quorum menos estricto de lo pretendido"
    - "Deriverse DEX (Cyfrin M) — falta de quorum requirement en governance voting"
```

---

## 14. Checkpoint No Escribe en el Mismo Bloque — Delegate Manipulation

```yaml
- id: tl-014
  titulo: _writeCheckpoint no actualiza storage en el mismo bloque — delegate/vote en un tx
  causa_raiz: |
    ERC20Votes usa checkpoints indexados por block.number. Si _writeCheckpoint tiene un bug
    donde no actualiza el checkpoint cuando ya existe uno en el mismo bloque (overwrite
    fallido), el voting power snapshot queda incorrecto. Un atacante puede: delegatar,
    votar, y undelegatar en el mismo bloque, y el checkpoint no refleja los cambios,
    permitiendo votar con tokens que ya no estan delegados, o no poder votar con tokens
    que SI estan delegados.
  como_funciona: |
    1. _writeCheckpoint: si checkpoint[account].blockNumber == block.number, DEBERIA
       overwrite el value existente. Pero en implementaciones buggy, no lo hace.
    2. Tx1 en bloque N: Alice delega a Bob (checkpoint escribe Bob.votes=100).
    3. Tx2 en bloque N: Alice delega a Carol. _writeCheckpoint para Bob deberia escribir
       Bob.votes=0, pero el bug impide la escritura (mismo bloque).
    4. Bob tiene votes=100 en el checkpoint de bloque N aunque Alice ya no le delega.
    5. Bob puede votar con 100 tokens fantasma. Carol no puede votar con sus tokens.
  invariante: |
    // _writeCheckpoint DEBE overwrite cuando blockNumber coincide
    function _writeCheckpoint(address account, uint256 newValue) internal {
        uint256 pos = _checkpoints[account].length;
        if (pos > 0 && _checkpoints[account][pos-1].fromBlock == block.number) {
            _checkpoints[account][pos-1].votes = newValue; // OVERWRITE, not skip
        } else {
            _checkpoints[account].push(Checkpoint(block.number, newValue));
        }
    }
  que_mirar:
    - "Implementacion custom de _writeCheckpoint — el caso de mismo bloque esta manejado?"
    - "Usar OZ ERC20Votes estandar que SI maneja este caso"
    - "grep: _writeCheckpoint, _checkpoints, Checkpoint, fromBlock, block.number"
    - "delegate() y castVote() en el mismo bloque — que pasa?"
  como_se_arregla: |
    Usar OZ ERC20Votes sin modificaciones. Si es custom, verificar que _writeCheckpoint
    overwrite cuando fromBlock == block.number. Tests: delegate + delegate en mismo bloque,
    verificar que el ultimo valor gana.
  trampas:
    - "Golom (C4 H-07) — _writeCheckpoint no escribe a storage en el mismo bloque"
    - "Golom (C4 H-10) — cambio de delegate actualiza checkpoints previo Y actual incorrectamente"
    - "ERC20Votes de OZ esta correcto desde 4.x — el riesgo es implementaciones custom o forks"
  solodit_ids:
    - "h-07-_writecheckpoint-does-not-write-to-storage-on-same-block-code4rena-golom-golom-contest-git"
    - "h-10-upon-changing-of-delegate-votedelegation-updates-both-the-previous-and-the-current-checkpoint-code4rena-golom-golom-contest-git"
    - "h-04-duplicate-tokenid-in-delegate-list-may-inflate-votes-pashov-audit-group-none-kittenswap_2025-05-07-markdown"
  incidentes:
    - "Golom (C4 H-07) — _writeCheckpoint no actualiza storage en el mismo bloque"
    - "Golom (C4 H-10) — cambio de delegado actualiza checkpoints previo y actual incorrectamente"
    - "KittenSwap (Pashov H-04) — tokenIds duplicados en lista de delegates inflan votos"
```

---

## 15. Skip de Veto Period — Propuesta Ejecutada sin Periodo de Veto Completo

```yaml
- id: tl-015
  titulo: Propuesta ejecutada sin completar el periodo de veto — host/guardian bypaseado
  causa_raiz: |
    Algunos protocolos tienen un periodo de veto despues de que la propuesta pasa la votacion
    pero antes de la ejecucion. Este periodo permite que un guardian o super-majority cancele
    propuestas daninas. Si la implementacion permite skipear este periodo (e.g., un host
    individual puede forzar ejecucion inmediata sin unanimidad), el veto se neutraliza.
  como_funciona: |
    1. Propuesta pasa la votacion. Periodo de veto: 3 dias antes de ejecucion.
    2. Requiere aprobacion de todos los hosts (e.g., 3 multisig signers).
    3. Bug: un solo host puede marcar la propuesta como "urgent" y skipear el veto period.
    4. Propuesta se ejecuta inmediatamente — los otros 2 hosts no pudieron vetarla.
    5. Si la propuesta era maliciosa, los fondos se pierden sin que el veto funcionara.
  invariante: |
    // La ejecucion DEBE respetar el veto period completo
    function execute(uint proposalId) external {
        require(block.timestamp >= proposals[proposalId].vetoDeadline, "VetoPeriodActive");
        // Verificar que ningun vetoer la cancelo
        require(!proposals[proposalId].vetoed, "Vetoed");
    }
  que_mirar:
    - "Existe un periodo de veto entre aprobacion y ejecucion?"
    - "Puede un actor individual skipear el veto period?"
    - "grep: veto, vetoDeadline, vetoPeriod, skipVeto, urgent, forceExecute"
    - "grep: allHostsAgree, unanimousApproval, hostVote"
  como_se_arregla: |
    El veto period debe ser hardcodeado y no skipeable por ningun actor individual.
    Solo supermajority (>66%) de hosts puede acortar el veto period, nunca un solo host.
    Verificar vetoDeadline en execute() con require.
  trampas:
    - "Party Protocol (C4 H-02) — un solo host puede skipear el veto period sin apoyo completo"
    - "El 'skip' puede estar disfrazado como 'emergency' — misma consecuencia"
    - "Si el veto period es configurable, verificar que no se pueda poner a 0"
  solodit_ids:
    - "h-02-single-host-can-unfairly-skip-veto-period-for-proposal-that-does-not-have-full-host-support-code4rena-party-protocol-party-protocol-git"
  incidentes:
    - "Party Protocol (C4 H-02) — un solo host puede skipear injustamente el periodo de veto de una propuesta"
```

---

## 16. Proposal State Machine Bug — Transiciones de Estado Incorrectas

```yaml
- id: tl-016
  titulo: State machine de propuestas permite transiciones invalidas (e.g., Defeated → Executed)
  causa_raiz: |
    Las propuestas tienen un ciclo de vida: Pending → Active → Succeeded/Defeated →
    Queued → Executed (o Cancelled). Si la funcion state() tiene un bug en la logica de
    transicion (e.g., no chequea votos negativos correctamente, o permite re-queue de una
    propuesta cancelada), propuestas en estados invalidos pueden ejecutarse. Especialmente
    peligroso cuando la actualizacion de parametros (e.g., expiration period) cambia
    retroactivamente el estado de propuestas existentes.
  como_funciona: |
    1. Propuesta A esta en estado Active con deadline en 3 dias.
    2. Governance cambia expirationPeriod de 7 dias a 1 dia via otra propuesta.
    3. Propuesta A tenia 5 dias desde la creacion → con la nueva expiracion de 1 dia, esta "expirada".
    4. Pero la logica de state() evalua expiracion con el NUEVO parametro, no el original.
    5. Propuesta A pasa de Active a Expired sin completar la votacion.
    6. O al reves: propuesta ya expirada se vuelve Active si el period se extiende.
  invariante: |
    // El estado de una propuesta NUNCA debe depender de parametros que cambian despues de su creacion
    function state(uint256 proposalId) public view returns (ProposalState) {
        Proposal storage p = proposals[proposalId];
        // Usar p.startBlock, p.deadline — valores fijados al crear
        // NUNCA recalcular deadline con parametros actuales
    }
  que_mirar:
    - "La deadline de la propuesta se calcula con parametros actuales o snapshot?"
    - "Cambiar votingPeriod/expirationPeriod afecta propuestas ya creadas?"
    - "grep: state, proposalState, ProposalState, deadline, expirationPeriod"
    - "grep: votingPeriod, setVotingPeriod, updateVotingPeriod"
  como_se_arregla: |
    Almacenar deadline como valor absoluto al crear la propuesta:
    proposals[id].deadline = block.number + votingPeriod.
    Nunca recalcular usando parametros actuales.
    Tests: cambiar votingPeriod mientras hay propuestas activas — no debe afectarlas.
  trampas:
    - "Kleidi (C4 [04]) — actualizar expiration period hace que propuestas activas expiren prematuramente"
    - "Notional (OZ H01) — el proceso de propuesta puede resultar en outcome incorrecto"
    - "OZ Governor SI usa snapshot de parametros — el riesgo es en implementaciones custom"
  solodit_ids:
    - "04-with-the-expiration-period-update-the-proposals-will-become-expired-code4rena-kleidi-kleidi-git"
    - "h01-proposal-process-could-result-in-the-wrong-outcome-openzeppelin-notional-governance-contracts-v2-audit-markdown"
    - "m02-proposals-update-can-assume-prior-states-openzeppelin-the-graph-governance-upgrade-audit-markdown"
  incidentes:
    - "Kleidi (C4 [04]) — actualizacion de expiration period hace propuestas expire prematuramente"
    - "Notional (OZ H01) — proceso de propuesta resulta en outcome incorrecto"
    - "The Graph (OZ M02) — propuestas pueden asumir estados previos incorrectamente"
```

---

## 17. Vote Buying via Dark DAO — Soborno Trustless On-Chain

```yaml
- id: tl-017
  titulo: Contratos de soborno trustless que compran votos de governance sin intermediarios
  causa_raiz: |
    Un contrato inteligente puede ofrecer pagos automaticos a cambio de votos en una direccion
    especifica. El votante deposita sus tokens en el contrato, el contrato vota por la opcion
    deseada por el comprador, y paga al votante automaticamente. Es trustless (sin necesidad
    de confianza entre partes) y puede ejecutarse de forma anonima via TEEs o cadenas privadas
    (concepto de "Dark DAO"). No es un bug de codigo sino de mecanismo — pero el auditor
    debe evaluar si el protocolo es susceptible.
  como_funciona: |
    1. Atacante deployea BribeContract: "Deposita tus GOV tokens, yo voto por Propuesta X,
       te pago 0.1 ETH por token".
    2. BribeContract.deposit(amount): transfiere GOV tokens al contrato.
    3. BribeContract vota en Propuesta X con todos los tokens depositados.
    4. Despues de la votacion: BribeContract.claim(): votante recibe 0.1 ETH por token.
    5. Propuesta X pasa gracias a los votos comprados.
    6. Dark DAO variant: el contrato corre en una cadena privada (Oasis Sapphire) para
       que la participacion sea confidencial — nadie sabe quien vendio su voto.
  invariante: |
    // No hay invariante de codigo — es un problema de diseno de mecanismo
    // Mitigaciones a nivel de protocolo:
    // 1. Voto secreto (commit-reveal) para que el briber no pueda verificar el voto
    // 2. Delegation revocable en cualquier momento (el votante puede cambiar de opinion)
    // 3. Tiempo de lock post-voto para que el votante no pueda vender y recuperar inmediatamente
    // 4. Conviction voting (peso del voto crece con el tiempo) — desincentiva soborno puntual
  que_mirar:
    - "El protocolo tiene mecanismo de voto secreto (commit-reveal)?"
    - "Los tokens se pueden delegar a un contrato y re-delegar antes de que el contrato vote?"
    - "Hay time-lock post-delegacion que previene redelegate inmediato?"
    - "grep: delegate, transfer, castVote — se pueden encadenar en un contrato externo?"
  como_se_arregla: |
    Commit-reveal voting: votos encriptados durante la votacion, revelados despues.
    Conviction voting: peso del voto proporcional al tiempo de stake — desincentiva sobornos.
    Rate-limited delegation: cooldown de N bloques entre delegation changes.
    No hay solucion perfecta — es un problema abierto en mecanismo de governance.
  trampas:
    - "LobbyFi ya opera un mercado de compra de votos para Curve — no es teoria, es real"
    - "8-14% de los votos en propuestas grandes de Arbitrum pasan por LobbyFi"
    - "Voto privado via Oasis Sapphire elimina accountability social — Dark DAO puro"
    - "No es un 'bug' reportable a bug bounties — es un riesgo de diseno"
  solodit_ids: []
  incidentes:
    - "Curve Wars / LobbyFi — mercado de soborno de votos de varios cientos de millones de dolares"
    - "IC3 Research (Cornell) — Dark DAO prototype usando Intel SGX en Oasis Sapphire"
    - "Arbitrum — 8-14% de votos en propuestas mayores via vote buying services"
```

---

## 18. Double Execution de Transacciones en Timelock

```yaml
- id: tl-018
  titulo: Una transaccion del timelock puede ejecutarse dos veces pasando el delay period
  causa_raiz: |
    Despues de ejecutar una operacion, el timelock debe marcarla como Done para prevenir
    re-ejecucion. Si la marca no se aplica atomicamente con la ejecucion (e.g., se marca
    antes de ejecutar y el call externo falla, o se marca en _afterCall que puede ser
    reentered), la operacion puede ejecutarse multiples veces. Cada ejecucion duplica
    el efecto: doble transfer de fondos, doble upgrade, etc.
  como_funciona: |
    1. Operacion A: transferir 100 ETH del timelock al treasury.
    2. Executor llama execute(A). Timelock transfiere 100 ETH.
    3. Bug: la marca Done se aplica en _afterCall, pero el receptor reentra antes de _afterCall.
    4. Receptor llama execute(A) de nuevo — la operacion aun esta "Ready" (no Done).
    5. Timelock transfiere otros 100 ETH. Total: 200 ETH transferidos, solo 100 autorizados.
  invariante: |
    // La operacion debe marcarse como Done ANTES de la llamada externa (CEI pattern)
    function _execute(bytes32 id, address target, uint256 value, bytes calldata data) internal {
        _timestamps[id] = _DONE_TIMESTAMP; // Marcar ANTES de la llamada
        (bool success,) = target.call{value: value}(data);
        require(success, "CallFailed");
    }
  que_mirar:
    - "En que momento se marca la operacion como Done — antes o despues de la llamada externa?"
    - "Hay reentrancy guard en execute/executeBatch?"
    - "grep: _DONE_TIMESTAMP, _afterCall, _beforeCall, timestamps"
    - "grep: nonReentrant, ReentrancyGuard en el timelock"
  como_se_arregla: |
    Checks-Effects-Interactions: marcar Done ANTES de la llamada externa.
    O: reentrancy guard en execute() y executeBatch().
    OZ >= 4.3.1 tiene ambos checks (_beforeCall + _afterCall) como defensa en profundidad.
  trampas:
    - "Relacionado con tl-001 (reentrancia) pero el vector es diferente: tl-001 es escalation, tl-018 es repetition"
    - "Puffer Finance (Immunefi L) — double execution de transaccion posible pasando delay period"
    - "executeBatch es mas vulnerable porque hay multiples llamadas donde reentrar"
  solodit_ids:
    - "double-spending-or-double-execution-of-transaction-is-possible-by-passing-delay-period-of-timelock-contract-immunefi-puffer-finance-git"
  incidentes:
    - "Puffer Finance (Immunefi L) — double execution de transaccion del timelock posible pasando delay period"
```

---

## Fuzzing Priorities — Timelock & DAO Execution

```
Priority 1 — Timelock Delay Enforcement:
  Invariant: execute(id) must revert if block.timestamp < queueTime[id] + minDelay
  How: schedule operation, immediately call execute() — must revert.
  Warp to delay-1 second — must revert. Warp to delay — must succeed.
  Extra: call updateDelay(0) from non-admin — must revert.

Priority 2 — Reentrancy in Execute:
  Invariant: execute(id) must set operation to Done before external call
  How: deploy malicious target that re-enters execute() with same or different id.
  Must revert on re-entry. Use forge test with reentrancy contract.

Priority 3 — Double Execution Prevention:
  Invariant: after execute(id) succeeds, calling execute(id) again must revert
  How: schedule, wait for delay, execute, try execute again — must revert.

Priority 4 — Guardian Scope:
  Invariant: guardian can only call pause() and cancel(), never upgrade/transfer
  How: try calling setOracle, setFee, transferOwnership from guardian address — all must revert.

Priority 5 — Quorum Snapshot:
  Invariant: quorum(proposalId) must return same value before and after quorum parameter change
  How: create proposal, change quorumNumerator, check quorum for original proposal — must be unchanged.

Priority 6 — Operation ID Uniqueness:
  Invariant: two proposals with same calldata but different proposalIds must have different operationIds
  How: schedule two identical actions with different salts, verify both can coexist.

Priority 7 — Veto Period Enforcement:
  Invariant: execute(id) must revert during veto period, even if all votes are in favor
  How: create proposal, vote unanimously, try execute before vetoDeadline — must revert.
```

---

## Grep Workflow — Timelock & DAO Execution Audits

```bash
# Timelock core functions
grep -rn "schedule\|scheduleBatch\|execute\|executeBatch\|cancel" src/
grep -rn "TimelockController\|Timelock\|timelock" src/
grep -rn "minDelay\|updateDelay\|setDelay\|MINIMUM_DELAY\|MAXIMUM_DELAY" src/

# Delay enforcement
grep -rn "isOperationReady\|isOperationPending\|isOperationDone\|getTimestamp" src/
grep -rn "_beforeCall\|_afterCall\|_DONE_TIMESTAMP" src/
grep -rn "require.*block.timestamp.*delay\|require.*eta\|require.*deadline" src/

# Roles and access
grep -rn "EXECUTOR_ROLE\|PROPOSER_ROLE\|CANCELLER_ROLE\|TIMELOCK_ADMIN_ROLE" src/
grep -rn "grantRole\|revokeRole\|renounceRole\|DEFAULT_ADMIN_ROLE" src/
grep -rn "guardian\|GUARDIAN_ROLE\|breakGlass\|emergencyAction\|fastTrack" src/

# Proposal execution
grep -rn "executeProposal\|queue\|queueTransaction\|cancelTransaction" src/
grep -rn "proposalState\|ProposalState\|state(" src/
grep -rn "eta\|GRACE_PERIOD\|vetoDeadline\|vetoPeriod" src/

# Hash / salt / collision
grep -rn "hashOperation\|hashOperationBatch\|operationId" src/
grep -rn "salt\|predecessor\|keccak256.*target.*value" src/

# Quorum and voting power interaction with execution
grep -rn "quorum\|quorumNumerator\|quorumDenominator\|getPastTotalSupply" src/
grep -rn "getPastVotes\|getPriorVotes\|_checkpoints\|_writeCheckpoint" src/

# CREATE2 + selfdestruct (Tornado Cash pattern)
grep -rn "selfdestruct\|create2\|CREATE2\|codehash\|extcodehash" src/

# Cross-chain governance
grep -rn "lzReceive\|ccipReceive\|onMessageReceived\|bridgeGovernance" src/
grep -rn "satellite\|hubChain\|crossChainExecute\|relayGovernance" src/
```
