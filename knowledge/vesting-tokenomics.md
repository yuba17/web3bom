grep_targets:
  - "vesting"
  - "cliff"
  - "vestingSchedule"
  - "release"
  - "claimable"
  - "vestedAmount"
  - "startTime"
  - "endTime"
  - "vestingPeriod"
  - "linearVesting"
  - "revoke"
  - "accelerate"
  - "allocate"
  - "emission"
  - "inflate"
  - "totalSupply"
  - "mint"
  - "ERC20Votes"
  - "getPastVotes"
  - "delegate"
  - "checkpoint"
  - "Snapshot"

# Briefing: Vesting & Tokenomics

## Contexto del dominio
Los contratos de vesting distribuyen tokens a lo largo del tiempo (inversores, equipo, advisors).
Los sistemas de tokenomics controlan la emisión de nuevos tokens (minting, rewards, inflación).
Los bugs más explotables son:
- Bypass de cliff o de la curva de vesting (cobrar antes de tiempo)
- Manipulación del totalSupply o de los votes para governance
- Doble claim en la misma period
- Dilución inesperada del supply por minting sin cap

---

patterns:

- id: vest-001
  titulo: Vesting Calculation Overflow / Integer Division — Tokens Extras o Insuficientes
  causa_raiz: |
    El cálculo de tokens vested generalmente es: vested = total * elapsed / duration.
    Si `elapsed` puede exceder `duration` (sin clamping), `vested` supera `total`.
    Si hay integer division sin rounding cuidadoso, el último claim puede fallar por
    un wei faltante, o acreditarse más de lo correcto.
  como_funciona: |
    Variante A — Elapsed > duration (no clamped):
    1. vestingSchedule: total=1000, duration=365 días, startTime=T0
    2. Usuario llama release() en T0 + 400 días (35 días después del fin)
    3. elapsed = 400 días, pero no hay clamp a duration=365
    4. vested = 1000 * 400 / 365 = 1095 → se acreditan 95 tokens extras

    Variante B — División trunca el último pago:
    1. total=1000 tokens, duration=3 períodos
    2. Period 1: 1000 * 1 / 3 = 333. Period 2: 666. Period 3: 1000 * 3 / 3 = 1000.
    3. Si el cálculo es incremental (cada período acredita el delta), la suma puede ser 999 o 1001
  invariante: |
    function check_vesting_never_exceeds_allocation(address beneficiary) internal view {
        uint256 totalAllocated = schedule[beneficiary].totalAmount;
        uint256 totalReleased = schedule[beneficiary].released;
        uint256 vestedNow = calculateVested(beneficiary, block.timestamp);
        t(vestedNow <= totalAllocated, "VEST-001: vested > allocated amount");
        t(totalReleased <= totalAllocated, "VEST-001: released > allocated amount");
    }
  que_mirar:
    - "¿El cálculo de elapsed tiene `min(elapsed, duration)` antes de la multiplicación?"
    - "¿Los tokens ya released se descuentan del `vested` calculation?"
    - "¿La función revoca correctamente el remanente en un revoke()?"
    - "¿Hay overflow en `total * elapsed` si ambos son grandes?"
  como_se_arregla: |
    - Siempre: clamp elapsed a min(block.timestamp - start, duration)
    - La cantidad claimable = calculateVested(now) - alreadyReleased
    - Para el último claim: liberar exactamente lo que queda (no recalcular)
  trampas:
    - "Los cálculos con 18 decimales en el numerador ayudan con precision, pero `total * elapsed` puede overflow con uint256 si no se usa mulDiv"
    - "Algunos vesting tienen cliff: si se olvida el cliff en el cálculo, se pueden sacar tokens antes del cliff"
  solodit_ids:
    - "h-1-vesting-calculation-is-wrong-code4rena-tapioca-dao-tapioca-dao-git"
    - "m-01-incorrect-vesting-calculation-can-result-in-over-or-under-payment-of-vested-tokens-recon-audits-none-dao-maker-markdown"

- id: vest-002
  titulo: Cliff Bypass — Claim Antes del Período de Bloqueo
  causa_raiz: |
    El cliff es el tiempo mínimo que debe pasar antes de que empiece el vesting.
    Si el check del cliff usa `>=` donde debería usar `>`, o si el cliff no se
    verifica en todas las rutas de claim, los beneficiarios pueden sacar tokens
    antes de que termine el cliff.
  como_funciona: |
    1. vestingSchedule: cliff=6 meses, duration=2 años
    2. La función release() verifica: if (block.timestamp >= startTime + cliff)
    3. Un atacante llama exactamente a startTime + cliff (mismo bloque que el cliff termina)
    4. Con >= en vez de >, puede sacar en el mismo bloque que el cliff (¿intencional?)

    Variante más seria:
    1. El contrato tiene dos rutas: release() y emergencyRelease()
    2. release() verifica el cliff correctamente
    3. emergencyRelease() solo verifica que el beneficiario sea válido, no el cliff
    4. Beneficiario usa emergencyRelease() antes del cliff → bypass completo
  invariante: |
    function check_cliff_respected(address beneficiary) internal view {
        VestingSchedule memory s = schedule[beneficiary];
        if (block.timestamp < s.startTime + s.cliffDuration) {
            // Durante el cliff: nada debería haberse released
            t(s.released == 0,
              "VEST-002: tokens released before cliff end");
        }
    }
  que_mirar:
    - "¿Hay múltiples funciones de claim/release? ¿Todas verifican el cliff?"
    - "¿El cliff se verifica con < o con <=?"
    - "¿Hay un override de admin que puede liberar tokens sin verificar cliff?"
    - "¿El cliff se incluye en el cálculo del vested o es un check separado?"
  como_se_arregla: |
    - Centralizar la lógica de cliff en una función interna `_isCliffPassed()` usada por todas las rutas
    - `require(block.timestamp >= startTime + cliffDuration, "cliff not passed")`
    - No hacer funciones "emergency" que eviten checks de cliff
  trampas:
    - "Cliff = 0 es válido (sin cliff) — debe ser tratado correctamente (no como 'cliff no verificado')"
    - "Si el vesting es mensual/discreto, el cliff puede alinearse con un epoch boundary"
  solodit_ids:
    - "h-2-cliff-not-enforced-on-vesting-schedule-sherlock-teller-finance-git"
    - "m-03-beneficiaries-can-claim-vested-tokens-before-cliff-period-sherlock-none-git"

- id: vest-003
  titulo: Double Claim en Mismo Período — Falta de Checkpoint de Último Claim
  causa_raiz: |
    Los contratos de vesting que permiten claim periódico (mensual, semanal) deben
    registrar cuándo fue el último claim para evitar claims dobles. Si el estado
    `lastClaimTime` o `alreadyVested` no se actualiza antes de la transferencia
    (CEI violado), o si el cálculo del período ignora el último claim, se pueden
    sacar doble.
  como_funciona: |
    Variante A — CEI violado:
    1. Beneficiario llama claim()
    2. Contrato calcula `pending = vested(now) - released`
    3. Contrato hace transfer(pending) ANTES de actualizar released
    4. En el callback del token (ERC777 o reentrancy), beneficiario llama claim() de nuevo
    5. `released` aún no se actualizó → `pending` es el mismo → doble pago

    Variante B — Epoch boundary exacto:
    1. Vesting por epochs de 30 días. lastClaim = epoch 5.
    2. Usuario llama claim() en el primer segundo del epoch 6
    3. Vested = total * 6 / numEpochs, released = total * 5 / numEpochs → correcto
    4. Usuario inmediatamente vuelve a llamar en el mismo bloque (mismo timestamp)
    5. Mismo cálculo → mismo pending → si no hay revert en la segunda llamada, cobra doble
  invariante: |
    // Ghost: claimable amount should drop to 0 immediately after claim
    uint256 internal ghost_claimableBefore;

    function handler_claim(address beneficiary) external {
        ghost_claimableBefore = getClaimable(beneficiary);
        vm.prank(beneficiary);
        vesting.claim();
        uint256 claimableAfter = getClaimable(beneficiary);
        t(claimableAfter == 0 || claimableAfter < ghost_claimableBefore,
          "VEST-003: claimable did not decrease after claim");
    }
  que_mirar:
    - "¿La función claim actualiza released ANTES de hacer transfer?"
    - "¿Qué pasa si se llama claim() dos veces en el mismo bloque?"
    - "¿El contrato tiene nonReentrant?"
    - "¿El cálculo de pending usa `released` del storage (que puede ser stale en reentrancy)?"
  como_se_arregla: |
    - Actualizar `schedule.released += pending` ANTES de la transferencia (CEI)
    - Añadir nonReentrant a todas las funciones de claim/release
    - Si `pending == 0`, revertir para ahorrar gas y evitar double-claim sin valor
  trampas:
    - "Incluso sin reentrancy, dos llamadas en el mismo bloque pueden ser un problema si el cálculo es timestamp-based y no hay checkpoint"
    - "En Foundry, `vm.warp` y luego dos calls en el mismo fuzz step pueden triggear este bug"
  solodit_ids:
    - "m-21-concurrewardpool-possible-reentrancy-when-claiming-rewards-code4rena-concur-finance-concur-finance-contest-git"
    - "h-3-users-can-claim-rewards-twice-due-to-missing-update-sherlock-git"

- id: vest-004
  titulo: Revoke Con Acounting Incorrecto — Beneficiario Cobra Más de lo Vested
  causa_raiz: |
    La función revoke() cancela el vesting y devuelve los tokens no vested al owner.
    Si revoke() no llama primero a release() (o no calcula correctamente cuánto ha
    vested hasta el momento del revoke), el beneficiario pierde tokens ya vested,
    o el owner recupera tokens que ya pertenecen al beneficiario.
  como_funciona: |
    Variante A — Beneficiario pierde tokens vested:
    1. Vesting de 1000 tokens a 2 años. Después de 1 año, 500 tokens están vested.
    2. Admin llama revoke() antes de que el beneficiario haga claim.
    3. revoke() calcula: "tokens no vested = 500, devolver al treasury"
    4. Pero devuelve los 1000 completos (bug: no descuenta los 500 ya vested)
    5. Beneficiario pierde sus 500 tokens → pérdida de fondos del usuario

    Variante B — Owner pierde tokens:
    1. revoke() primero hace release(vested_so_far) → beneficiario recibe 500
    2. Luego calcula "restante para devolver" = balance del contrato
    3. Si hay otros beneficiarios en el mismo contrato, el balance incluye sus tokens
    4. revoke() devuelve demasiado al treasury → otros beneficiarios pierden fondos
  invariante: |
    function check_revoke_conservation(address beneficiary) internal {
        uint256 alreadyReleased = schedule[beneficiary].released;
        uint256 vestedAtRevoke = calculateVested(beneficiary, block.timestamp);
        uint256 totalAllocated = schedule[beneficiary].totalAmount;

        uint256 expectedForBeneficiary = vestedAtRevoke;
        uint256 expectedForOwner = totalAllocated - vestedAtRevoke;

        vesting.revoke(beneficiary);

        // La suma de lo que recibe el beneficiario + el owner debe ser el total
        t(beneficiaryReceived + ownerReceived == totalAllocated - alreadyReleased,
          "VEST-004: revoke does not conserve total allocation");
    }
  que_mirar:
    - "¿revoke() calcula el vested-at-revoke correctamente?"
    - "¿revoke() hace release() al beneficiario ANTES de calcular el retorno al owner?"
    - "¿El contrato es per-beneficiary o multi-beneficiary? (el balance del contrato puede no ser solo de un beneficiario)"
    - "¿Hay un período de gracia entre revoke y el claim del beneficiario?"
  como_se_arregla: |
    - En revoke(): calcular vestedAtRevoke, hacer release(vestedAtRevoke) al beneficiario,
      luego devolver exactamente (totalAmount - vestedAtRevoke) al owner
    - Nunca usar balance del contrato como "amount to return" — calcular desde el schedule
    - Si el contrato es multi-beneficiary, mantener contabilidad separada por beneficiario
  trampas:
    - "OpenZeppelin VestingWallet no tiene revoke — cada implementación custom lo hace diferente"
    - "Algunos protocolos tienen 'soft revoke' (pausa el vesting) vs 'hard revoke' (cancela) — los bugs son distintos"
  solodit_ids:
    - "h-02-revoke-can-take-already-vested-tokens-from-beneficiary-sherlock-git"
    - "m-04-revoke-does-not-settle-pending-vested-tokens-code4rena-git"

- id: vest-005
  titulo: Front-run de Revoke — Beneficiario Drena Antes de Ser Revoked
  causa_raiz: |
    Cuando el owner envía la transacción revoke(beneficiary), el beneficiario puede
    ver la tx en mempool y front-runearla para reclamar todos los tokens vested
    (posiblemente combinado con un flash loan para acelerar el vesting si hay
    un componente de supply-based vesting).
  como_funciona: |
    1. Admin envía revoke(alice) al mempool
    2. Alice ve la tx, immediatamente envía claim() con gas price más alto
    3. Alice's claim() se ejecuta primero → cobra todos los tokens vested hasta ahora
    4. revoke() se ejecuta → ya no hay tokens para recobrar (o muy pocos)
    5. Alice cobra sus tokens merecidos (los vested) — esto puede ser por diseño
    6. El problema es si hay tokens "cliff-pending" o "future-vested" que Alice no debería cobrar
    Variante peligrosa: el vesting es acelerado por alguien que stake tokens → Alice
    puede hacerlo para inflar sus vested-amount antes de que el revoke llegue
  invariante: |
    function check_revoke_frontrun_protection() internal {
        // Si el beneficiario acaba de hacer claim Y el vesting es revoked en el mismo bloque,
        // el owner debería poder recuperar tokens NO vested
        uint256 unvested = schedule[alice].totalAmount - calculateVested(alice, block.timestamp);
        t(ownerRecovered >= unvested * 95 / 100,  // tolerancia 5% para rounding
          "VEST-005: owner recovered less than unvested amount after revoke");
    }
  que_mirar:
    - "¿El vesting puede acelerarse haciendo alguna acción (staking, governance)?"
    - "¿La revocación es instantánea o tiene un delay (timelock)?"
    - "¿El beneficiario puede ver la tx de revoke en mempool (no MEV-protected)?"
    - "¿Hay diferencia entre 'vested' y 'earned' que permite cobrar más de lo vested?"
  como_se_arregla: |
    - Usar commit-reveal para revocaciones (no exponible en mempool)
    - O: timelock en el vesting que da X días de aviso antes de que el revoke sea efectivo
    - Diseño defensivo: separar "vested" (por tiempo) de "earned" (por trabajo/milestone)
  trampas:
    - "En chains con mempool privado (Arbitrum con Sequencer), el frontrun es mucho más difícil"
    - "El frontrun de revoke puede ser legítimo (el beneficiario tiene derecho a sus tokens vested)"
    - "El bug real es si el vesting puede acelerarse artificialmente antes del revoke"
  solodit_ids:
    - "m-frontrun-revoke-allows-beneficiary-to-claim-all-vested-tokens-sherlock-git"

- id: vest-006
  titulo: ERC20Votes / Snapshot — Manipulación de Power de Voto Pre-Cliff
  causa_raiz: |
    Los tokens con snapshot de voto (ERC20Votes, ERC20Snapshot, Compound COMP) registran
    el poder de voto en un bloque específico. Si los tokens de vesting se delegan o
    se "acreditan" al beneficiario antes de ser efectivamente disponibles, el beneficiario
    tiene poder de voto sobre tokens que no puede transferir — lo cual puede ser intencional,
    pero si no, permite governance attacks con tokens que no han "ganado" todavía.
  como_funciona: |
    Variante A — Vested pero no claimable con vote power:
    1. Token de vesting (ERC20Votes) asigna shares al beneficiario desde el día 0
    2. El beneficiario tiene vote power proporcional a su asignación total (no al vested)
    3. Antes del cliff, el beneficiario tiene el 100% del vote power pero 0% es claimable
    4. Con vote power artificial, puede votar propuestas que cambien las reglas de vesting

    Variante B — Delegation antes de cliff:
    1. El contrato de vesting delega el vote power al beneficiario desde el deploy
    2. El beneficiario usa ese vote power para votar un proposal que elimina su cliff
    3. Proposal pasa → beneficiario cobra todo sin esperar el cliff
  invariante: |
    function check_vote_power_matches_vested(address beneficiary) internal view {
        uint256 vestedNow = calculateVested(beneficiary, block.timestamp);
        uint256 votePower = token.getVotes(beneficiary);
        // Vote power no debería exceder tokens disponibles (vested)
        t(votePower <= vestedNow + TOLERANCE,
          "VEST-006: vote power exceeds vested amount");
    }
  que_mirar:
    - "¿Cuándo se delega el vote power al beneficiario? ¿Al crear el schedule o al hacer claim?"
    - "¿Los tokens locked en el vesting contract contribuyen a quórum o a vote power?"
    - "¿Hay una propuesta de governance que pueda modificar el propio contrato de vesting?"
    - "¿El contrato de vesting vota con los tokens que tiene en custodia?"
  como_se_arregla: |
    - Delegar vote power gradualmente: solo los tokens efectivamente vested se delegan
    - El vesting contract debe delegar sus votos a una address fija (no al beneficiario)
    - Segregar tokens de vesting de tokens de governance cuando sea posible
  trampas:
    - "Muchos protocolos quieren que el equipo/inversores tengan vote power ANTES de la liquidez — es by design pero crea riesgo"
    - "Si el contrato de vesting vota automáticamente en governance, puede ser usado para DoS de proposals"
  solodit_ids:
    - "m-04-vesting-tokens-delegated-before-cliff-allow-premature-voting-code4rena-git"
    - "h-01-lock-bypass-via-governance-vote-before-cliff-sherlock-git"

- id: vest-007
  titulo: Dilución Infinita — Minting Sin Cap o Con Cap Bypasseable
  causa_raiz: |
    Los contratos de minting de tokens (emission schedules, staking rewards, inflation)
    tienen un totalSupply cap para prevenir dilución infinita. Si el cap no se verifica
    correctamente (off-by-one, no considera pending mints, o hay un path que no verifica
    el cap), se pueden mintear más tokens de los prometidos.
  como_funciona: |
    Variante A — Cap off-by-one:
    1. Token tiene MAX_SUPPLY = 1_000_000e18
    2. mint() verifica: require(totalSupply() + amount <= MAX_SUPPLY)
    3. Con ERC20Votes o ERC20Snapshot, puede haber un snapshot que no refleja el mint aún
    4. Dos mints concurrentes (mismo bloque) pueden pasar el check individualmente
    5. Pero la suma supera MAX_SUPPLY

    Variante B — Inflación acelerada por governance:
    1. emissionRate es configurable por governance
    2. No hay cap en emissionRate
    3. Governance vota emissionRate = type(uint256).max
    4. En el siguiente bloque, el minting drena el supply al máximo posible
    5. Dilución masiva de los holders actuales
  invariante: |
    function check_supply_cap() internal view {
        t(token.totalSupply() <= token.MAX_SUPPLY(),
          "VEST-007: totalSupply exceeds cap");
    }

    function check_emission_rate_bounded() internal view {
        t(emissionRate <= MAX_EMISSION_RATE,
          "VEST-007: emission rate exceeds safe maximum");
    }
  que_mirar:
    - "¿El MAX_SUPPLY está en el propio token o en el minter?"
    - "¿El check usa <= o <?"
    - "¿Pueden concurrir dos calls de mint en el mismo bloque?"
    - "¿El emissionRate tiene un cap hardcodeado o es infinitamente configurable?"
    - "¿La función mint usa totalSupply() on-chain o una variable cacheada?"
  como_se_arregla: |
    - El cap debe estar en el contrato del token (no en el minter), como immutable
    - `require(totalSupply() + amount <= MAX_SUPPLY, "cap exceeded")` en el token mismo
    - emissionRate con cap: `require(newRate <= MAX_RATE)` con MAX_RATE hardcodeado
    - Para protocolos multi-minter: llevar cuenta del "minted by each minter"
  trampas:
    - "Los tokens con fee-on-transfer no reducen totalSupply en transfers — el cap es siempre correcto ahí"
    - "Los tokens con burn pueden acercarse al cap múltiples veces — el cap debe ser de 'ever minted', no 'current supply', si se quiere limitar dilución histórica"
  solodit_ids:
    - "h-03-mint-cap-not-enforced-allowing-infinite-supply-sherlock-git"
    - "m-01-emission-rate-can-be-set-to-max-uint256-bypassing-supply-cap-code4rena-git"

- id: vest-008
  titulo: Token Allocation Race Condition — Misma Address Puede Crear Múltiples Schedules
  causa_raiz: |
    En contratos que permiten crear vesting schedules para una address, si no hay
    verificación de unicidad (o la verificación se puede bypassear), una address
    puede tener múltiples schedules activos simultáneamente. Si el claim suma
    todos los schedules sin límite, el beneficiario cobra más de lo asignado.
  como_funciona: |
    1. Admin llama createVestingSchedule(alice, 1000) — alice tiene schedule ID 0
    2. Admin llama createVestingSchedule(alice, 1000) de nuevo — alice tiene schedule ID 1
    3. alice llama claimAll() → cobra 2000 tokens
    4. Si el admin cometió el error por duplicación, alice cobra el doble

    Variante más peligrosa (sin admin):
    1. createVestingSchedule() es callable por alice si alice "paga" o tiene NFT
    2. Alice llama múltiples veces con el mismo parámetro → schedules duplicados
    3. Cada schedule genera tokens independientes → inflación del supply
  invariante: |
    function check_no_duplicate_schedules(address beneficiary) internal view {
        // Cada beneficiario debe tener un único total allocation
        uint256 totalAllocatedForBeneficiary = 0;
        for (uint i = 0; i < scheduleCount[beneficiary]; i++) {
            totalAllocatedForBeneficiary += schedule[beneficiary][i].totalAmount;
        }
        t(totalAllocatedForBeneficiary <= maxAllocationPerAddress[beneficiary],
          "VEST-008: beneficiary has more allocated than maximum");
    }
  que_mirar:
    - "¿createVestingSchedule() verifica si ya existe un schedule para esa address?"
    - "¿El claim acumula todos los schedules o solo el activo?"
    - "¿Quién puede llamar a createVestingSchedule()?"
    - "¿Hay un mapping de 'total allocated per address' separado del schedule?"
  como_se_arregla: |
    - Mantener `mapping(address => uint256) public totalAllocated` y verificar antes de crear
    - O: un schedule único por address (revert si ya existe sin revoke previo)
    - Si se permite múltiples schedules: cap explícito en totalAllocated acumulado
  trampas:
    - "Algunos protocolos crean schedules por tranche (seed, private, public) — múltiples schedules son by design, pero el total debe estar capado"
  solodit_ids:
    - "m-duplicate-vesting-schedule-allows-double-claim-sherlock-git"

- id: vest-009
  titulo: Cliff / Vesting Bypassed via Token Transfer — Wrapper o Liquid Vesting
  causa_raiz: |
    Algunos protocolos crean "liquid vesting tokens" — tokens ERC20 que representan
    tokens en vesting y son transferibles. Si el precio de estos wrappers puede
    manipularse, o si el wrapper permite redeem sin verificar el cliff del subyacente,
    se puede convertir tokens en vesting a liquidez antes del cliff.
  como_funciona: |
    1. Protocolo A tiene vesting de TOKENA (1 año, 6 meses cliff)
    2. Protocolo B crea veTOKENA = ERC20 wrapper de TOKENA en vesting
    3. veTOKENA es tradeable en un DEX desde el día 1
    4. Atacante vende veTOKENA a precio con descuento → transforma illiquid vesting en liquid
    5. No hay bypass técnico del contrato, pero el cliff se "bypasea" económicamente

    Variante técnica (bug real):
    1. El wrapper veTOKENA hace redeem(amount) → verifica que holder tiene suficiente veTOKENA
    2. Pero no verifica si el subyacente ya está vested o aún en cliff
    3. Si alguien dona TOKENA al wrapper, el redeem puede entregar TOKENA no vested
  invariante: |
    function check_wrapper_backed_by_vested(address wrapper) internal view {
        uint256 wrapperSupply = IERC20(wrapper).totalSupply();
        uint256 actuallyVested = calculateTotalVested(); // de todos los schedules
        t(wrapperSupply <= actuallyVested,
          "VEST-009: liquid vesting wrapper supply > actually vested amount");
    }
  que_mirar:
    - "¿El wrapper hace redeem sin verificar el estado de vesting del subyacente?"
    - "¿Hay una función de 'early redeem' con penalización que puede ser más beneficiosa que esperar?"
    - "¿El precio del wrapper en el DEX puede manipularse para hacer arbitraje con el redeem?"
    - "¿El wrapper tiene un redeem rate fijo o variable?"
  como_se_arregla: |
    - El redeem del wrapper debe verificar que los tokens subyacentes están efectivamente vested
    - El wrapper solo debe emitir tokens proporcionales a los tokens efectivamente vested
    - No crear wrappers transferibles de tokens pre-cliff
  trampas:
    - "Curve veCRV, Convex vlCVX — estos son ejemplos de liquid vesting que funcionan correctamente por diseño"
    - "El riesgo de liquid vesting es especulativo (precio) vs técnico (bug) — separar los dos"
  solodit_ids:
    - "m-liquid-vesting-wrapper-allows-redeem-of-unvested-tokens-sherlock-git"

- id: vest-010
  titulo: Unlock Prematuro por Timestamp Manipulation en L2
  causa_raiz: |
    En L2s (Arbitrum, Optimism, Base), el `block.timestamp` es controlado por el
    sequencer con cierta flexibilidad. Si el vesting usa solo `block.timestamp`
    para calcular elapsed time, el sequencer puede (en principio) avanzar el timestamp
    más allá de lo real para desbloquear tokens antes de tiempo. Más relevante: si
    el vesting usa `block.number` en vez de `block.timestamp`, la velocidad de los
    bloques en L2 puede diferir de lo esperado.
  como_funciona: |
    Variante A — block.number incorrecto:
    1. Protocolo asume 1 bloque por segundo para el cálculo de vesting
    2. En Arbitrum, los bloques pueden ser mucho más frecuentes (~0.25s por bloque)
    3. Con 4x más bloques/segundo, el vesting se completa en 1/4 del tiempo esperado
    4. Después de 3 meses reales, el vesting de 1 año ya está completo según block.number

    Variante B — Timestamp permitido con drift:
    1. El sequencer de Optimism puede ajustar el timestamp hasta DRIFT_TOLERANCE (actualmente 600s)
    2. Para vesting de corta duración (horas) esto puede ser explotable
    3. Para vesting de meses/años, el drift no es suficiente para un bypass real
  invariante: |
    function check_vesting_uses_timestamp_not_blocknumber() internal view {
        // Si el vesting usa block.number: verificar que la velocidad de bloques es la esperada
        // No debería haberse completado antes del expected completion timestamp
        uint256 expectedCompletionTimestamp = startTimestamp + vestingDuration;
        if (usesBlockNumber) {
            uint256 blocksExpected = vestingDuration / EXPECTED_BLOCK_TIME;
            t(block.number < startBlock + blocksExpected || block.timestamp >= expectedCompletionTimestamp,
              "VEST-010: vesting completed faster than expected due to block speed");
        }
    }
  que_mirar:
    - "¿El vesting usa block.timestamp o block.number?"
    - "¿Si usa block.number, hay un conversion rate hardcodeado (segundos por bloque)?"
    - "¿El protocolo está deployado en L2 con diferentes block speeds que mainnet?"
    - "¿El contrato fue migrado desde mainnet a L2 sin ajustar la lógica de time?"
  como_se_arregla: |
    - Siempre usar block.timestamp para vesting, nunca block.number
    - Si block.number es necesario (para gas estimations), convertir a timestamp: expectedTimestamp = block.timestamp + (targetBlock - block.number) * BLOCK_TIME
    - Documentar la chain target del deploy en comentarios
  trampas:
    - "El timestamp drift en L2 es generalmente demasiado pequeño para explotar vesting de largo plazo"
    - "El caso de block.number es mucho más real — varios protocolos migraron de Ethereum a Arbitrum y olvidaron esto"
  solodit_ids:
    - "m-05-vesting-uses-block-number-instead-of-timestamp-causing-incorrect-unlock-times-on-l2-sherlock-git"
    - "m-vesting-period-shorter-than-expected-due-to-faster-block-time-on-l2-code4rena-git"
