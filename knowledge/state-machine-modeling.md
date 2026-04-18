# State Machine Modeling — Pre-Audit Technique Briefing

> Modelar un smart contract como una Finite State Machine (FSM) ANTES de huntar bugs.
> Fuentes: Certora CVL docs, Solidity docs (common patterns), Trail of Bits (Echidna),
> Nascent (FREI-PI), Zellic (formal verification WETH), PropertyGPT (NDSS 2025),
> Ethereum.org (formal verification), Act specification language.

---

## 0. Qué es y por qué importa

Un smart contract ES una máquina de estados: storage variables definen el estado,
funciones externas son transiciones, y `require`/`revert` son guardas que restringen
qué transiciones son válidas. El problema es que la mayoría de auditors NO modelan
esto explícitamente — van directamente al código y buscan pattern-matching.

**Modelar la FSM primero cambia el juego:**
- Hace visibles las transiciones ilegales ANTES de leer el código
- Los invariantes salen naturalmente del modelo (no hay que inventarlos)
- Los reentrancy bugs se mapean directamente a "estado intermedio observable"
- Los flash loan attacks son "transiciones que no deberían ocurrir en un solo tx"

---

## 1. Cómo Modelar un Contrato como FSM

### Paso 1: Identificar las variables de estado relevantes

No TODAS las storage variables definen "el estado" de la FSM. Filtrar:
- Variables que cambian el COMPORTAMIENTO del contrato (no solo datos)
- Enums explícitos de stage/phase
- Flags booleanos (paused, initialized, locked)
- Balances y shares que determinan qué operaciones son válidas

### Paso 2: Definir estados abstractos

Agrupar combinaciones de variables en estados con nombre. Ejemplo lending:

```
ESTADOS DE UNA POSICIÓN EN LENDING:
┌─────────────┐
│   EMPTY     │  debtShares == 0, collateral == 0
└──────┬──────┘
       │ deposit()
       ▼
┌─────────────┐
│ COLLATERAL  │  debtShares == 0, collateral > 0
│   ONLY      │
└──────┬──────┘
       │ borrow()
       ▼
┌─────────────┐     healthFactor < 1
│  BORROWED   │ ──────────────────────┐
│  (HEALTHY)  │                       ▼
└──────┬──────┘              ┌─────────────┐
       │ repay()             │ LIQUIDATABLE │
       ▼                     └──────┬──────┘
┌─────────────┐                     │ liquidate()
│   REPAID    │                     ▼
│  (= EMPTY)  │              ┌─────────────┐
└─────────────┘              │ LIQUIDATED  │
                             │ (parcial o  │
                             │   total)    │
                             └─────────────┘
```

### Paso 3: Definir transiciones válidas

Para CADA función pública/external:
- ¿Desde qué estado(s) se puede llamar?
- ¿A qué estado lleva?
- ¿Qué condiciones deben cumplirse? (guardas)

### Paso 4: Identificar transiciones ILEGALES

**Aquí es donde están los bugs.** Las transiciones que NO deberían existir:

```
TRANSICIONES ILEGALES EN LENDING (ejemplos concretos):

1. LIQUIDATED → BORROWED (sin repago completo + nuevo deposit)
   Bug: si después de liquidación parcial, el usuario puede seguir
   pidiendo prestado sin devolver la deuda restante.

2. BORROWED → EMPTY (sin repago)
   Bug: bypass de repago — usuario retira todo el collateral sin
   devolver la deuda. Típico en bugs de accounting donde
   debtShares se reduce sin que el pool reciba tokens.

3. EMPTY → BORROWED (sin collateral)
   Bug: borrow sin collateral — si una función permite crear deuda
   sin verificar que hay collateral suficiente.

4. HEALTHY → LIQUIDATABLE (en un solo tx, sin cambio de precio)
   Bug: manipulación — alguien puede forzar una liquidación sin
   que el precio del oracle cambie legitimamente.

5. COLLATERAL_ONLY → EMPTY (por alguien que no es el owner)
   Bug: robo de collateral — alguien retira el collateral de otro usuario.
```

---

## 2. Estados en un Lending Protocol Típico

### Por posición (nivel usuario):
| Estado | Condición | Operaciones válidas |
|--------|-----------|-------------------|
| EMPTY | debt=0, collateral=0 | deposit, (no borrow, no repay) |
| DEPOSITED | debt=0, collateral>0 | borrow, withdraw (total), deposit más |
| BORROWED_HEALTHY | debt>0, collateral>0, HF>=1 | repay, deposit más, borrow más (si HF ok) |
| BORROWED_UNHEALTHY | debt>0, collateral>0, HF<1 | repay, liquidate (por tercero), deposit más |
| LIQUIDATABLE | HF < liquidation_threshold | liquidate (por tercero), repay (por user) |

### Por pool (nivel protocolo):
| Estado | Condición | Significado |
|--------|-----------|-------------|
| EMPTY_POOL | totalSupply=0, totalBorrow=0 | Sin actividad |
| ACTIVE | totalSupply>0, utilization<100% | Operación normal |
| FULLY_UTILIZED | utilization=100% | Sin liquidez para withdrawals |
| PAUSED | paused=true | Solo operaciones de emergency |
| INSOLVENT | totalAssets < totalLiabilities | Bug o ataque — pérdida de fondos |

### Por auction/liquidation:
| Estado | Condición |
|--------|-----------|
| NOT_STARTED | auction no existe |
| ACTIVE | startTime <= now < endTime |
| EXPIRED | now >= endTime |
| SETTLED | deuda cubierta, colateral distribuido |
| CANCELLED | posición devuelta a healthy antes de settlement |

---

## 3. Reentrancy como Transición Ilegal de Estado

**Insight clave**: un reentrancy bug es un estado intermedio observable desde fuera.

```
TRANSICIÓN NORMAL (sin reentrancy):
  STATE_A ──[función]──→ STATE_B
  (atómica: nadie ve el estado intermedio)

TRANSICIÓN CON REENTRANCY:
  STATE_A ──[función, parte 1]──→ STATE_INTERMEDIO
                                       │
                                       │ external call (callback)
                                       ▼
                              Atacante ve STATE_INTERMEDIO
                              y ejecuta otra transición
                              que NO debería ser posible
                              desde STATE_INTERMEDIO
                                       │
                          ──[función, parte 2]──→ STATE_C (corrupto)
```

**Ejemplo concreto (The DAO hack como FSM):**
```
Estado: {balance[user]=100, totalBalance=100}

withdraw() empieza:
  1. Lee balance[user] = 100 ✓
  2. Envía 100 ETH al user (external call)
     ─── ESTADO INTERMEDIO: balance[user]=100, totalBalance=0 ───
     │   El atacante re-entra en withdraw()
     │   Ve balance[user]=100 (NO actualizado aún)
     │   Envía otros 100 ETH
     │   ─── ESTADO INTERMEDIO²: balance aún =100, totalBalance=-100 ───
  3. Actualiza balance[user] = 0

Resultado: user recibió 200 ETH con balance de 100
```

**La transición ilegal**: `{balance=100, sent=0} → {balance=100, sent=200}`
Esto viola el invariante: `totalSent[user] <= balance[user]` en todo momento.

**Cómo modelar esto como propiedad testeable:**
```solidity
// Ghost variable que trackea cuánto se ha enviado
uint256 ghost_totalSent;

// Invariante: nunca se envía más de lo que el balance permite
// Si esta propiedad se rompe en un estado intermedio, hay reentrancy
function invariant_noOverSend() public returns (bool) {
    return ghost_totalSent <= ghost_totalBalance;
}
```

---

## 4. Flash Loans como Transiciones Imposibles en un Solo TX

**Un flash loan permite transiciones de estado que deberían ser imposibles
dentro de una sola transacción.**

```
SIN flash loan:
  TX1: User deposita collateral
  TX2: User pide prestado
  TX3: User manipula oracle
  TX4: User liquida a otro
  TX5: User repaga y retira profit

  → Cada TX es una transición válida individualmente
  → Pero la SECUENCIA completa produce un resultado que no debería
     ser alcanzable porque requiere capital que el user no tiene.

CON flash loan (TODO en 1 TX):
  1. Flash borrow $10M
  2. Manipular pool/oracle con $10M
  3. Explotar el estado manipulado
  4. Devolver $10M + fee
  5. Quedarse con el profit

  → El estado ANTES y DESPUÉS del TX son "válidos"
  → Pero los estados INTERMEDIOS violaron invariantes
```

**Transiciones "imposibles" que flash loans habilitan:**
```
1. PRICE_NORMAL → PRICE_MANIPULATED → PRICE_NORMAL (en 1 tx)
   - El oracle TWAP ve el precio normal antes y después
   - Pero durante el TX, el spot price fue manipulado

2. POOL_BALANCED → POOL_DRAINED → POOL_BALANCED (en 1 tx)
   - El pool termina con los mismos balances
   - Pero durante el TX, la liquidez fue usada para arbitraje

3. USER_NO_COLLATERAL → USER_WHALE → USER_NO_COLLATERAL (en 1 tx)
   - El user nunca tuvo los fondos realmente
   - Pero durante el TX, actuó como whale para manipular governance/liquidations
```

**Propiedad FSM para detectar flash loan attacks:**
```solidity
// Al inicio de cada tx, snapshot del estado
// Al final de cada tx, verificar que no se violaron invariantes DURANTE el tx
// Esto requiere ghost variables que trackeen los extremos (max/min) durante la ejecución

ghost uint256 ghost_minCollateralRatio;

function handler_anyOperation() public {
    uint256 currentRatio = getCollateralRatio();
    if (currentRatio < ghost_minCollateralRatio) {
        ghost_minCollateralRatio = currentRatio;
    }
}

// El invariante checkea el MÍNIMO durante toda la secuencia, no solo el final
function invariant_neverUndercollateralized() public returns (bool) {
    return ghost_minCollateralRatio >= MIN_COLLATERAL_RATIO;
}
```

---

## 5. Certora CVL — State Machine Specs (Formal)

Certora es la herramienta que MÁS explícitamente modela contratos como state machines.

### 5.1 Ghost Variables como State Trackers

```cvl
// Ghost que trackea el estado de cada posición
ghost mapping(uint256 => uint8) positionState;

// Hook: cada vez que debtShares cambia, actualizar estado
hook Sstore loans[KEY uint256 tokenId].debtShares uint256 newDebt (uint256 oldDebt) {
    if (oldDebt == 0 && newDebt > 0) {
        positionState[tokenId] = 2; // BORROWED
    }
    if (oldDebt > 0 && newDebt == 0) {
        positionState[tokenId] = 0; // REPAID
    }
}
```

### 5.2 Invariantes sobre Estados

```cvl
// Invariante: una posición LIQUIDATED no puede tener deuda
invariant liquidatedHasNoDebt(uint256 tokenId)
    positionState[tokenId] == 3 => loans(tokenId).debtShares == 0
```

### 5.3 Rules como Transición Guards

```cvl
// Rule: borrow solo desde estado DEPOSITED o BORROWED_HEALTHY
rule borrowOnlyFromValidState(uint256 tokenId, uint256 amount) {
    uint8 stateBefore = positionState[tokenId];

    env e;
    borrow(e, tokenId, amount);

    // Solo válido si estaba en DEPOSITED o BORROWED_HEALTHY
    assert stateBefore == 1 || stateBefore == 2,
        "borrow from invalid state";
}
```

### 5.4 Persistent Ghosts para Reentrancy

```cvl
// Persistent ghost: NO se revierte aunque la llamada revierta
// Útil para detectar que un ghost fue modificado durante reentrancy
persistent ghost bool wasReentered;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength,
          uint retOffset, uint retLength) uint rc {
    if (addr == currentContract) {
        wasReentered = true;
    }
}

rule noReentrancy(method f) {
    wasReentered = false;
    env e; calldataarg args;
    f(e, args);
    assert !wasReentered, "reentrancy detected";
}
```

### 5.5 Categorías de Properties (framework de Certora)

Certora clasifica las propiedades en 5 tipos (de su material educativo "Categorizing Properties"):

1. **Valid States** — ¿Qué combinaciones de variables son válidas?
   - `totalSupply > 0 => totalAssets > 0`
   - `debtShares[user] > 0 => collateral[user] > 0`

2. **State Transitions** — ¿Qué transiciones son legales?
   - `balance puede decrecer solo via withdraw o liquidate`
   - `paused solo puede cambiar via owner`

3. **Variable Transitions** — ¿Cómo cambian variables individuales?
   - `totalSupply solo crece via deposit, solo decrece via withdraw`
   - `balance[user] cambia solo si msg.sender == user || msg.sender == approved`

4. **High-Level Properties** — Propiedades del sistema completo
   - `sum(balances) == totalSupply` (siempre)
   - `no user can extract more than they deposited + earned`

5. **Unit Tests as Properties** — Comportamiento específico de funciones
   - `deposit(x) incrementa balance en exactamente x`
   - `withdraw reverts si amount > balance`

### 5.6 Caso Real: Lido Dual Governance

Certora usó TLA+ (Temporal Logic of Actions) para verificar la máquina de estados
del dual governance de Lido. Estados verificados:
- Normal → vetoSignaling (45 días) → vetoSignalingDeactivation (24h) → vetoCooldown → Normal
- vetoSignaling → RageQuit (emergency exit)

Transiciones ilegales verificadas:
- No se puede saltar de Normal a RageQuit sin pasar por vetoSignaling
- No se puede ciclar rápidamente entre estados para bypass de timelock
- Flash loans no pueden manipular el stake para triggear transiciones

---

## 6. Echidna/Medusa — Testing State Machine Properties

### 6.1 Echidna: Stateful Fuzzing = Exploración de FSM Implícita

Echidna genera **secuencias de transacciones** y mantiene el estado entre calls.
Esto es literalmente exploración de la FSM del contrato:

```solidity
contract StateMachineTest {
    enum State { EMPTY, DEPOSITED, BORROWED, LIQUIDATABLE, LIQUIDATED }

    // Ghost: estado derivado (no storage del contrato)
    function _deriveState(uint256 tokenId) internal view returns (State) {
        uint256 debt = vault.debtShares(tokenId);
        uint256 coll = vault.collateral(tokenId);
        if (debt == 0 && coll == 0) return State.EMPTY;
        if (debt == 0 && coll > 0) return State.DEPOSITED;
        if (debt > 0 && vault.isHealthy(tokenId)) return State.BORROWED;
        if (debt > 0 && !vault.isHealthy(tokenId)) return State.LIQUIDATABLE;
        return State.LIQUIDATED; // post-liquidation cleanup
    }

    // Mapear qué transiciones ocurrieron
    State lastState;
    mapping(uint8 => mapping(uint8 => bool)) transitionOccurred;

    // Después de cada handler, registrar la transición
    function _recordTransition(uint256 tokenId) internal {
        State current = _deriveState(tokenId);
        transitionOccurred[uint8(lastState)][uint8(current)] = true;
        lastState = current;
    }

    // INVARIANTES: transiciones ilegales
    function echidna_no_empty_to_borrowed() public view returns (bool) {
        // EMPTY → BORROWED no debería ocurrir (requiere pasar por DEPOSITED)
        return !transitionOccurred[uint8(State.EMPTY)][uint8(State.BORROWED)];
    }

    function echidna_no_liquidated_to_borrowed() public view returns (bool) {
        // LIQUIDATED → BORROWED no debería ser posible sin repago
        return !transitionOccurred[uint8(State.LIQUIDATED)][uint8(State.BORROWED)];
    }
}
```

### 6.2 Medusa: Secuencias Largas para Alcanzar Estados Profundos

Medusa es superior a Echidna en encontrar secuencias multi-step porque:
- Tiene corpus persistente (guarda secuencias interesantes)
- Coverage-guided: sigue explorando paths que alcanzan código nuevo
- Paralelizado: explora más del espacio de estados en el mismo tiempo

Configuración para state machine testing:
```json
{
  "fuzzing": {
    "testLimit": 100000,
    "callSequenceLength": 50,
    "corpusDirectory": "corpus/state_machine",
    "testing": {
      "propertyTesting": {
        "enabled": true
      },
      "assertionTesting": {
        "enabled": true
      }
    }
  }
}
```

### 6.3 Pattern: Transition Matrix Testing

```solidity
// Definir la MATRIZ de transiciones válidas
// true = transición permitida, false = ILEGAL
bool[5][5] validTransitions;

constructor() {
    // EMPTY → DEPOSITED (via deposit)
    validTransitions[0][1] = true;
    // DEPOSITED → BORROWED (via borrow)
    validTransitions[1][2] = true;
    // DEPOSITED → EMPTY (via withdraw all)
    validTransitions[1][0] = true;
    // BORROWED → DEPOSITED (via repay all)
    validTransitions[2][1] = true;
    // BORROWED → LIQUIDATABLE (via price drop)
    validTransitions[2][3] = true;
    // BORROWED → BORROWED (via partial repay, more borrow)
    validTransitions[2][2] = true;
    // LIQUIDATABLE → BORROWED (via repay enough)
    validTransitions[3][2] = true;
    // LIQUIDATABLE → LIQUIDATED (via liquidate)
    validTransitions[3][4] = true;
    // LIQUIDATABLE → DEPOSITED (via repay all)
    validTransitions[3][1] = true;
    // LIQUIDATED → EMPTY (post-liquidation cleanup)
    validTransitions[4][0] = true;
    // Self-loops permitidos para estados estables
    validTransitions[0][0] = true;
    validTransitions[1][1] = true;
    validTransitions[3][3] = true;
    validTransitions[4][4] = true;
}

function echidna_only_valid_transitions() public view returns (bool) {
    for (uint8 i = 0; i < 5; i++) {
        for (uint8 j = 0; j < 5; j++) {
            if (transitionOccurred[i][j] && !validTransitions[i][j]) {
                return false; // TRANSICIÓN ILEGAL DETECTADA
            }
        }
    }
    return true;
}
```

---

## 7. Herramientas para Extracción/Análisis de FSM

### 7.1 Herramientas Existentes

| Herramienta | Qué hace | Estado |
|-------------|----------|--------|
| **Certora CVL** | Verificación formal con ghost variables + hooks para modelar estados. Lo más cercano a FSM formal. | Producción, comercial |
| **Act** (Ethereum) | Lenguaje de especificación que modela contratos como sistemas de transición de estados. Se extrae a Rocq para pruebas. | Activo, open source |
| **Octopus** | Extrae CFG (Control Flow Graphs) de bytecode EVM/WASM. No es FSM de negocio, pero muestra flujo de ejecución. | Mantenimiento bajo |
| **Slither** | Printers como `call-graph`, `cfg`, `data-dependency`. No modela FSM de negocio directamente pero da la materia prima. | Producción, open source |
| **Mythril** | Symbolic execution que explora estados alcanzables. Detecta estados "malos" (ether leak, suicide, etc.) | Producción |
| **KEVM** | Semántica formal del EVM en K framework. Modela EVM como sistema de transición. Muy bajo nivel. | Research |
| **hevm** | Symbolic execution + equivalence checking. Puede verificar specs de Act contra bytecode. | Producción |
| **Securify2** | Análisis Datalog, no FSM explícito pero sus patterns implican restricciones de estado. | Mantenimiento bajo |

### 7.2 ¿Se puede automatizar la extracción de FSM desde Solidity?

**Parcialmente, sí. Pero la FSM útil para auditing es la de NEGOCIO, no la de EVM.**

Lo que SÍ se puede automatizar:
- Extraer el CFG (Control Flow Graph) → Slither, Octopus
- Identificar variables de estado que cambian en cada función → Slither data-dependency
- Detectar enums/flags que actúan como stages → pattern matching en AST
- Listar todas las transiciones posibles (función → cambios de storage)

Lo que NO se puede automatizar fácilmente:
- **Nombrar los estados en términos de negocio** (qué significa "HEALTHY" vs "LIQUIDATABLE")
- **Determinar qué transiciones son ilegales** (requiere entender la INTENCIÓN del protocolo)
- **Modelar estados implícitos** (estados derivados de combinaciones de variables, no enums explícitos)
- **Cross-contract states** (estado distribuido entre múltiples contratos)

### 7.3 Approach Recomendado: Semi-Automático

```
1. SLITHER: Extraer datos crudos
   slither . --print call-graph
   slither . --print data-dependency
   slither . --print human-summary

2. HUMANO/AI: Interpretar datos y crear modelo FSM
   - Agrupar variables en estados con nombre
   - Identificar transiciones válidas vs ilegales
   - Documentar invariantes de cada estado

3. CERTORA/ECHIDNA: Formalizar y verificar
   - Escribir ghost variables + hooks (Certora)
   - O escribir transition matrix test (Echidna/Medusa)
   - Fuzzear para encontrar transiciones ilegales
```

---

## 8. PropertyGPT — Auto-Generación de Invariantes

**Paper**: "PropertyGPT: LLM-driven Formal Verification of Smart Contracts through
Retrieval-Augmented Property Generation" (NDSS 2025)

### Metodología:
1. **Vector DB de properties existentes**: Embeddings de invariantes escritos por humanos
   en auditorías previas
2. **Retrieval**: Dado un nuevo contrato, buscar properties similares como contexto
3. **LLM (GPT-4)**: Generar properties customizadas usando in-context learning
4. **Iterative refinement**: Compilar → errores → feedback al LLM → re-generar
5. **Verificación formal**: Prover dedicado verifica las properties generadas

### Resultados:
- 80% recall vs ground truth (properties escritas por humanos)
- 26 CVEs detectados de 37 casos
- 12 zero-days encontrados ($8,256 en bounties)

### Implicación para nuestro sistema:
PropertyGPT valida que un LLM PUEDE generar invariantes útiles si tiene:
- Base de datos de ejemplos verificados (nuestra knowledge base)
- Feedback loop de compilación (nuestro pipeline Chimera)
- Contexto del protocolo específico (nuestro run_benchmark.py)

**Gap a cerrar**: No hace FSM modeling explícito. Genera properties "flat" sin
modelo de estados. Combinar FSM + RAG sería el siguiente paso.

---

## 9. Cómo Top Auditors Usan State Diagrams

### En Reportes Públicos:
- **Trail of Bits**: Incluyen diagramas de estados en sus audit reports cuando el
  protocolo tiene lifecycle complejo (governance, auctions, vesting).
- **Certora**: Sus reports formales siempre incluyen el modelo de estados verificado.
  El caso de Lido Dual Governance es ejemplar — verificaron la FSM completa con TLA+.
- **OpenZeppelin**: Sus Solidity docs oficiales incluyen el State Machine pattern
  como un "common pattern" con código de ejemplo completo.

### Pattern de los Mejores:
1. **Día 1**: Dibujar la FSM del protocolo antes de leer código detallado
2. **Día 2**: Verificar que el código implementa exactamente esas transiciones
3. **Día 3**: Buscar transiciones FALTANTES (estados que el dev no consideró)
4. **Finding**: "El contrato permite la transición X→Y que debería ser imposible"

### Nascent FREI-PI Pattern:
El patrón más práctico para pensar en estado:
```
Function-level:
  F - Function Requirements (precondiciones)
  R - (reserved)
  E - Effects (cambios de estado)
  I - Interactions (llamadas externas)

Protocol-level:
  P - Protocol Invariants (postcondiciones globales)
  I - (reserved)
```

La clave de FREI-PI: no pensar en `require` como "validación de input de esta función"
sino como "verificación de que el estado del PROTOCOLO es válido después de TODOS
los cambios". Esto es exactamente modelar el contrato como FSM donde cada función
es una transición y los `require` finales verifican que el estado destino es válido.

---

## 10. Aplicación Práctica: Template para Nuestro Pipeline

### Pre-Hunt FSM Modeling (añadir como Layer 0.5)

```markdown
## FSM Model: [Nombre del Componente]

### Estados
| ID | Nombre | Condición | Variables clave |
|----|--------|-----------|-----------------|
| S0 | EMPTY | ... | ... |
| S1 | ACTIVE | ... | ... |

### Transiciones Válidas
| From | To | Función | Guarda |
|------|----|---------|--------|
| S0 | S1 | deposit() | amount > 0 |

### Transiciones ILEGALES (hipótesis de bugs)
| From | To | Por qué es ilegal | Severidad si ocurre |
|------|----|-------------------|-------------------|
| S3 | S1 | Skip repayment | CRITICAL |

### Invariantes derivados del modelo
| Invariante | Estado(s) donde aplica | Tier |
|------------|----------------------|------|
| debt > 0 → collateral > 0 | S2, S3 | 1 |
```

### Integración con Echidna/Medusa

```solidity
// Template: StateMachineProperties.sol
// Heredar junto con Properties.sol en el setup de Chimera

abstract contract StateMachineProperties {
    // Enum de estados derivados
    enum FSMState { /* definir por componente */ }

    // Tracking de transiciones
    mapping(uint8 => mapping(uint8 => bool)) public transitionSeen;
    FSMState public lastObservedState;

    // Override por componente: derivar estado actual
    function _currentState() internal view virtual returns (FSMState);

    // Override por componente: matriz de transiciones válidas
    function _isValidTransition(FSMState from, FSMState to)
        internal view virtual returns (bool);

    // Llamar después de cada handler
    function _recordAndCheckTransition() internal {
        FSMState current = _currentState();
        transitionSeen[uint8(lastObservedState)][uint8(current)] = true;

        // ASSERT: solo transiciones válidas
        assert(_isValidTransition(lastObservedState, current));

        lastObservedState = current;
    }

    // Echidna property: chequeo global
    function echidna_no_illegal_transitions() public view returns (bool) {
        // Iteración sobre todas las transiciones observadas
        // Verificar contra la matriz de válidas
        return true; // implementar por componente
    }
}
```

---

## 11. Referencia: Papers y Recursos Académicos

### Papers Relevantes:
1. **PropertyGPT** (NDSS 2025) — LLM-driven property generation via RAG.
   arxiv.org/abs/2405.02580
2. **Zellic: Formal Verification of WETH** — CHC + BMC para modelar transiciones.
   zellic.io/blog/formal-verification-weth
3. **Act specification language** — Contratos como sistemas de transición de estados.
   github.com/ethereum/act
4. **Ethereum.org: Formal Verification** — Referencia completa de model checking,
   temporal logic, symbolic execution para smart contracts.
   ethereum.org/en/developers/docs/smart-contracts/formal-verification/

### Recursos Prácticos:
5. **Certora CVL docs** — Ghosts, hooks, invariants, rules.
   docs.certora.com/en/latest/docs/cvl/
6. **Certora Tutorials Lesson 6** — "Thinking Properties" + categorías de properties.
   github.com/Certora/Tutorials/tree/master/06.Lesson_ThinkingProperties
7. **Certora Examples** — DeFi verification examples + real bugs (MakerDAO Flop).
   github.com/Certora/Examples
8. **Crytic Properties** — 168 properties para ERC20/ERC721/ERC4626.
   github.com/crytic/properties
9. **Solidity Docs: State Machine Pattern** — Pattern oficial con enums + modifiers.
   docs.soliditylang.org/en/latest/common-patterns.html
10. **Nascent FREI-PI** — Protocol-level invariants como guardas de estado.
    nascent.xyz/idea/youre-writing-require-statements-wrong
11. **Certora Blog: Lido Dual Governance** — TLA+ para verificar FSM de governance.
    certora.com/blog/the-double-edged-dao-sword
12. **SmartBugs** — Framework con 25 herramientas de análisis.
    github.com/smartbugs/smartbugs

### Herramientas de Extracción:
13. **Slither** — CFG, call-graph, data-dependency printers.
    github.com/crytic/slither
14. **Octopus** — CFG extraction de bytecode EVM/WASM.
    github.com/pventuzelo/octopus
15. **Mythril** — Symbolic execution, state space exploration.
    github.com/Consensys/mythril

---

## 12. Gaps y Siguiente Pasos para Nuestro Sistema

### Lo que NO existe y podríamos construir:

1. **FSM Extractor semi-automático**: Script que usa Slither AST + LLM para proponer
   un modelo FSM inicial dado un contrato Solidity. Input: source code. Output:
   tabla de estados + transiciones + invariantes candidatos.

2. **Transition Matrix Tester genérico**: Template Chimera que genera tests de
   transición automáticamente desde una matriz JSON de estados válidos.

3. **Cross-Component FSM**: Modelo que capture el estado CONJUNTO de múltiples
   contratos (e.g., V3Vault × GaugeManager × V3Oracle). Hoy cada componente se
   modela aislado pero los bugs más valiosos están en las interacciones.

4. **Temporal Properties para Echidna**: Propiedades que verifican secuencias
   de estados (e.g., "si la posición pasa por LIQUIDATABLE, eventualmente debe
   llegar a LIQUIDATED o HEALTHY, nunca quedarse en LIQUIDATABLE para siempre").

### Prioridad:
- **INMEDIATO**: Añadir FSM modeling como paso explícito del pipeline (Layer 0.5)
  antes de generar invariantes. El modelo FSM alimenta DIRECTAMENTE los invariantes.
- **CORTO PLAZO**: Template StateMachineProperties.sol para Chimera.
- **MEDIO PLAZO**: Semi-automated FSM extraction con Slither + LLM.
