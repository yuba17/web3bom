# FlowHunter — AbstractInterchainAccountRouter Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

## Tu Objetivo
Analizar `AbstractInterchainAccountRouter` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/middleware/AbstractInterchainAccountRouter.sol`
**Dominio**: trust


## Asset Flow Map
### Money IN (deposits/receives)
- L107 receive(): accepts ETH via payable receive
- L218 callRemoteWithOverrides(): msg.value
- L241 _dispatchMessageWithValue(): IERC20(_feeToken).safeTransferFrom(msg.sender, address(this), _fee);

### Approvals (attack surface)
- L110 approveFeeTokenForHook(): IERC20(_feeToken).forceApprove(_hook, type(uint256).max);
- L242 _dispatchMessageWithValue(): IERC20(_feeToken).forceApprove(address(_hook), type(uint256).max);
```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

/*@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@  HYPERLANE  @@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
@@@@@@@@@       @@@@@@@@*/

// ============ Internal Imports ============
import {OwnableMulticall} from "./libs/OwnableMulticall.sol";
import {InterchainAccountMessage} from "./libs/InterchainAccountMessage.sol";
import {CallLib} from "./libs/Call.sol";
import {MinimalProxy} from "../libs/MinimalProxy.sol";
import {TypeCasts} from "../libs/TypeCasts.sol";
import {StandardHookMetadata} from "../hooks/libs/StandardHookMetadata.sol";
import {Router} from "../client/Router.sol";
import {IPostDispatchHook} from "../interfaces/hooks/IPostDispatchHook.sol";
import {IInterchainSecurityModule} from "../interfaces/IInterchainSecurityModule.sol";

// ============ External Imports ============
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// solhint-disable-next-line hyperlane/enumerable-domain-mapping
abstract contract AbstractInterchainAccountRouter is Router {
    using TypeCasts for address;
    using TypeCasts for bytes32;
    using StandardHookMetadata for bytes;
    using SafeERC20 for IERC20;

    // ============ Constants ============

    address public immutable implementation;
    bytes32 public immutable bytecodeHash;

    // ============ Public Storage ============
    mapping(uint32 destinationDomain => bytes32 ism) public isms;

    // ============ Upgrade Gap ============

    uint256[47] private __GAP;

    // ============ Events ============

    event RemoteIsmEnrolled(uint32 indexed domain, bytes32 ism);

    event RemoteCallDispatched(
        uint32 indexed destination,
        address indexed owner,
        bytes32 router,
        bytes32 ism,
        bytes32 salt
    );

    event InterchainAccountCreated(
        address indexed account,
        uint32 origin,
        bytes32 router,
        bytes32 owner,
        address ism,
        bytes32 salt
    );

    // solhint-disable-next-line hyperlane/no-virtual-override
    function interchainSecurityModule()
        external
        view
        virtual
        override
        returns (IInterchainSecurityModule)
    {
        return IInterchainSecurityModule(address(this));
    }

    function enrollRemoteRouterAndIsm(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism
    ) external onlyOwner {
        _enrollRemoteRouterAndIsm(_destination, _router, _ism);
    }

    function enrollRemoteRouterAndIsms(
        uint32[] calldata _destinations,
        bytes32[] calldata _routers,
        bytes32[] calldata _isms
    ) external onlyOwner {
        require(
            _destinations.length == _routers.length &&
                _destinations.length == _isms.length,
            "length mismatch"
        );
        for (uint256 i = 0; i < _destinations.length; i++) {
            _enrollRemoteRouterAndIsm(_destinations[i], _routers[i], _isms[i]);
        }
    }

    receive() external payable {}

    function approveFeeTokenForHook(address _feeToken, address _hook) external {
        IERC20(_feeToken).forceApprove(_hook, type(uint256).max);
    }

    function getDeployedInterchainAccount(
        uint32 _origin,
        address _owner,
        address _router,
        address _ism
    ) public virtual returns (OwnableMulticall) {
        return
            getDeployedInterchainAccount(
                _origin,
                _owner.addressToBytes32(),
                _router.addressToBytes32(),
                _ism,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    function getDeployedInterchainAccount(
        uint32 _origin,
        bytes32 _owner,
        bytes32 _router,
        address _ism,
        bytes32 _userSalt
    ) public virtual returns (OwnableMulticall) {
        bytes32 _deploySalt = _getSalt(
            _origin,
            _owner,
            _router,
            _ism.addressToBytes32(),
            _userSalt
        );
        address payable _account = _getLocalInterchainAccount(_deploySalt);
        if (!Address.isContract(_account)) {
            bytes memory _bytecode = MinimalProxy.bytecode(implementation);
            _account = payable(Create2.deploy(0, _deploySalt, _bytecode));
            emit InterchainAccountCreated(
                _account,
                _origin,
                _router,
                _owner,
                _ism,
                _userSalt
            );
        }
        return OwnableMulticall(_account);
    }

    function getLocalInterchainAccount(
        uint32 _origin,
        address _owner,
        address _router,
        address _ism
    ) external view virtual returns (OwnableMulticall) {
        return
            OwnableMulticall(
                _getLocalInterchainAccount(
                    _getSalt(
                        _origin,
                        _owner.addressToBytes32(),
                        _router.addressToBytes32(),
                        _ism.addressToBytes32(),
                        InterchainAccountMessage.EMPTY_SALT
                    )
                )
            );
    }

    function quoteGasPayment(
        uint32 _destination,
        uint256 _gasLimit
    ) public view virtual returns (uint256 _gasPayment) {
        return
            _Router_quoteDispatch(
                _destination,
                new bytes(0),
                StandardHookMetadata.overrideGasLimit(_gasLimit),
                address(hook)
            );
    }

    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls,
        bytes memory _hookMetadata
    ) public payable virtual returns (bytes32) {
        emit RemoteCallDispatched(
            _destination,
            msg.sender,
            _router,
            _ism,
            InterchainAccountMessage.EMPTY_SALT
        );
        bytes memory _body = InterchainAccountMessage.encode(
            msg.sender,
            _ism,
            _calls
        );
        return
            _dispatchMessageWithValue(
                _destination,
                _router,
                _body,
                _hookMetadata,
                hook,
                msg.value
            );
    }

    function _dispatchMessageWithValue(
        uint32 _destination,
        bytes32 _router,
        bytes memory _body,
        bytes memory _hookMetadata,
        IPostDispatchHook _hook,
        uint256 _value
    ) internal returns (bytes32) {
        require(_router != bytes32(0), "no router specified for destination");

        address _feeToken = _hookMetadata.feeToken();
        if (_feeToken != address(0)) {
            uint256 _fee = _Router_quoteDispatch(
                _destination,
                bytes(""),
                _hookMetadata,
                address(_hook)
            );

            IERC20(_feeToken).safeTransferFrom(msg.sender, address(this), _fee);
            IERC20(_feeToken).forceApprove(address(_hook), type(uint256).max);
        }

        return
            mailbox.dispatch{value: _value}(
                _destination,
                _router,
                _body,
                _hookMetadata,
                _hook
            );
    }

    function _implementationBytecode(
        address router
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                type(OwnableMulticall).creationCode,
                abi.encode(router)
            );
    }

    function _proxyBytecodeHash(
        address _implementation
    ) internal pure returns (bytes32) {
        return keccak256(MinimalProxy.bytecode(_implementation));
    }

    /// @dev Required for use of Router, compiler will not include this function in the bytecode
    function _handle(uint32, bytes32, bytes calldata) internal pure override {
        assert(false);
    }

    // solhint-disable-next-line hyperlane/no-virtual-override
    function _enrollRemoteRouter(
        uint32 _destination,
        bytes32 _address
    ) internal virtual override {
        _enrollRemoteRouterAndIsm(
            _destination,
            _address,
            InterchainAccountMessage.EMPTY_SALT
        );
    }

    function _enrollRemoteIsm(uint32 _destination, bytes32 _ism) internal {
        isms[_destination] = _ism;
        emit RemoteIsmEnrolled(_destination, _ism);
    }

    function _enrollRemoteRouterAndIsm(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism
    ) internal {
        require(
            routers(_destination) == InterchainAccountMessage.EMPTY_SALT &&
                isms[_destination] == InterchainAccountMessage.EMPTY_SALT,
            "router and ISM defaults are immutable once set"
        );
        Router._enrollRemoteRouter(_destination, _router);
        _enrollRemoteIsm(_destination, _ism);
    }

    function _getSalt(
        uint32 _origin,
        bytes32 _owner,
        bytes32 _router,
        bytes32 _ism,
        bytes32 _userSalt
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(_origin, _owner, _router, _ism, _userSalt)
            );
    }

    function _getLocalInterchainAccount(
        bytes32 _salt
    ) internal view returns (address payable) {
        return payable(Create2.computeAddress(_salt, bytecodeHash));
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre AbstractInterchainAccountRouter
Buscando 'AbstractInterchainAccountRouter' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (6ms)


### HIGH findings en dominio trust
Buscando 'AbstractInterchainAccountRouter interchainSecurityModule enrollRemoteRouterAndIs' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (26ms)

### Cross-domain HIGH relevantes
Buscando 'AbstractInterchainAccountRouter interchainSecurityModule enr' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (6ms)

## Briefing del Dominio (trust)
### Briefing principal: trust

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ La mayoría de protocolos DeFi mainstream usan USDC/WETH — no son FoT.
  ⚠ El impacto real depende de si el token en scope puede ser FoT (verificar docs del protocolo).
  ⚠ Algunos auditores marcan esto como LOW/INFO si el protocolo explícitamente excluye FoT.
  ⚠ ERC777 ya no es popular post-2022, pero sigue siendo un vector con tokens heredados.
  ⚠ USDC/USDT no son ERC777, pero protocolos con reward tokens configurables sí son vulnerables.
  ⚠ GearBox demostró que ERC777 como colateral puede bloquear liquidaciones (DOS, no drain).
  ⚠ Circle rara vez bloquea direcciones de contratos DeFi — el riesgo es real pero bajo.
  ⚠ El riesgo más práctico es el griefing de liquidaciones en lending protocols.
  ⚠ Verificar si el protocolo tiene USDC como único colateral o tiene alternativas.
  ⚠ cToken de Compound NO es rebasing — su balance es fijo, sube el exchangeRate.
  ⚠ wstETH NO es rebasing — el precio sube, no el balance.
  ⚠ Sólo stETH "nativo" y aToken son rebasing en el sentido estricto.

## CHECKLIST DE INVARIANTES
```yaml
- id: tb-003
  titulo: Blocklist de USDC/USDT bloquea retiros o liquidaciones del protocolo
  causa_raiz: |
    USDC y USDT tienen función de blacklist/blocklist: el emisor puede bloquear cualquier
    address. Si el contrato o un usuario clave es bloqueado, transfer() revierte → función
    de retiro o liquidación revierte → fondos quedan congelados indefinidamente.
  como_funciona: |
    Path A (usuario bloqueado): Ganador de lotería/subasta bloqueado → transfer() revierte
    → nadie puede completar la distribución → protocolo atascado.
    Path B (protocolo bloqueado): Circle bloquea el propio contrato del protocolo →
    todos los usuarios pierden acceso a sus fondos.
    Path C (griefing): Atacante fuerza al lender/borrower a ser blacklisted → DoS de
    liquidaciones → bad debt acumula.
  invariante: |
    // No se puede invariar on-chain, pero arquitecturalmente:
    // nunca push tokens a usuarios en flujos críticos — usar pull pattern
    // mapping(address => uint256) public claimable;
    // function claim() external { ... token.safeTransfer(msg.sender, amount); }
  que_mirar:

## GREP TARGETS
```yaml
- id: tb-004
  titulo: Tokens rebasing (aToken, stETH) rompen contabilidad si se cachea el balance
  causa_raiz: |
    Tokens como aToken de Aave o stETH de Lido incrementan su balance automáticamente
    con el tiempo (rebasing positivo) sin emitir Transfer events. Si el contrato cachea
    el balance en storage en vez de llamar a balanceOf() cada vez, el valor cacheado
    queda desactualizado → underestima activos → shares sobreemitidas o pérdida de yield.
  como_funciona: |
    1. Vault deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea balance=1000.
    2. 30 días pasan: balance real de aUSDC = 1050 (5% yield).
    3. totalAssets() retorna 1000 en vez de 1050 → pricePerShare subestimado.
    4. Usuario que deposita en este momento recibe shares de más → diluye a los existentes.
    5. Cuando alguien hace harvest, los 50 USDC "extra" aparecen como profit inesperado.
  invariante: |

## Contexto Chimera (OBLIGATORIO — lee antes de escribir Solidity)

Tu código se insertará en un archivo `PropertiesX.sol` que hereda de `Properties.sol`.
Properties.sol hereda del Setup (variables de estado, contratos, actores).
NO escribas `function invariant_...()` — solo el BODY. merge_invariants.py genera el wrapper.

### Variables y contratos disponibles (heredados de Setup):
```solidity
  MockHyperlaneEnvironment internal environment;
  uint32 internal constant ORIGIN = 1;
  uint32 internal constant DESTINATION = 2;
  TestInterchainGasPaymaster internal igp;
  InterchainAccountRouter internal originRouter;
  InterchainAccountRouter internal destRouter;
  bytes32 internal routerOverride;
  bytes32 internal ismOverride;
  ERC20Test internal feeToken;
  OwnableMulticall internal ica;
  MockMailbox internal originMailbox;
  MockMailbox internal destMailbox;
  uint256 internal ghost_totalMsgValueSent;
  uint256 internal ghost_routerBalanceBefore;
  uint256 internal ghost_callRemoteCount;
  uint256 internal ghost_handleCount;
  uint256 internal ghost_commitRevealCount;
  address internal constant ATTACKER = address(0xbabe);
  address internal constant USER1 = address(0x1111);
  address internal constant USER2 = address(0x2222);
```

### Funciones públicas del contrato target (getters y setters disponibles):
```solidity
  function interchainSecurityModule() external view virtual override returns (IInterchainSecurityModule);
  function enrollRemoteRouterAndIsm(uint32 _destination, bytes32 _router, bytes32 _ism) external;
  function enrollRemoteRouterAndIsms(uint32[] calldata _destinations, bytes32[] calldata _routers, bytes32[] calldata _isms) external;
  function approveFeeTokenForHook(address _feeToken, address _hook) external;
  function getDeployedInterchainAccount(uint32 _origin, address _owner, address _router, address _ism) public virtual returns (OwnableMulticall);
  function getDeployedInterchainAccount(uint32 _origin, bytes32 _owner, bytes32 _router, address _ism, bytes32 _userSalt) public virtual returns (OwnableMulticall);
  function getLocalInterchainAccount(uint32 _origin, address _owner, address _router, address _ism) external view virtual returns (OwnableMulticall);
  function quoteGasPayment(uint32 _destination, uint256 _gasLimit) public view virtual returns (uint256 _gasPayment);
  function callRemoteWithOverrides(uint32 _destination, bytes32 _router, bytes32 _ism, CallLib.Call[] calldata _calls, bytes memory _hookMetadata) public payable virtual returns (bytes32);
```

### Ghost variables existentes (ya declaradas, puedes usarlas):
```solidity
  ghost_routerBalanceBefore = address(originRouter).balance;
```

### Helpers internos disponibles:
```solidity
  _setupChimera() internal;
```

### Assertion helpers (de chimera/Asserts.sol):
```solidity
t(bool condition, string memory msg)    // assert true
eq(uint256 a, uint256 b, string memory msg)  // assert ==
gte(uint256 a, uint256 b, string memory msg) // assert >=
lte(uint256 a, uint256 b, string memory msg) // assert <=
gt(uint256 a, uint256 b, string memory msg)  // assert >
lt(uint256 a, uint256 b, string memory msg)  // assert <
```

### REGLAS para tu código Solidity:
1. **Solo el body** — NO escribas `function invariant_...()`. Solo las líneas internas.
2. **Usa EXACTAMENTE las variables de arriba** — NO inventes nombres. Si no está listado, NO existe.
3. **Usa los getters listados arriba** — Si necesitas un valor del contrato, busca en la lista de funciones públicas.
4. **Usa helpers Chimera** — `t()`, `eq()`, `gte()`, NO `require()` ni `assert()`.
5. **Sin caracteres unicode** en strings — usa `--` en vez de `—`, ASCII puro.
6. **Si necesitas ghost vars nuevas**, declara en el campo `ghost_vars` del YAML, NO en el body.
7. **Si una función no está en la lista de arriba, NO LA USES.** Compilará mal.

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Reentrancy) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `AIAR` (ej: AIAR-01, AIAR-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_AbstractInterchainAccountRouter_FlowHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: AIAR-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "AIAR-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Flash Loan Hypothesis (OBLIGATORIO — responde para CADA función que modifica estado)
Después de tu análisis libre, pasa por estas 12 preguntas para cada función relevante:
1. ¿Lee estado manipulable? (getReserves, slot0, balanceOf, get_virtual_price)
2. ¿Ese estado afecta movimiento de fondos?
3. ¿Se puede leer y consumir en la misma tx? (sin delays/timelocks)
4. ¿Hay verificación post-acción? (patrón FREI-PI)
5. ¿Tiene reentrancy guard?
6. ¿Si es callback, verifica initiator? (no solo msg.sender == pool)
7. ¿Usa spot price (manipulable) o TWAP (más seguro)?
8. ¿Reward/share se calcula por balance instantáneo?
9. ¿Hay cap/threshold cruzable atómicamente? (pasar de "sano" a "liquidable" en 1 tx)
10. ¿Permite self-liquidation con bonus > flash fee?
11. ¿Fee rounding a zero con montos pequeños?
12. ¿Checkpoint usa storage (persistente) o memory (se pierde)?

>80% de los exploits flash loan siguen: FLASH → MANIPULATE STATE → EXTRACT VALUE → RESTORE → REPAY.
Si una función responde "sí" a las preguntas 1+2+3, es un candidato fuerte.

## Tabla de Tokens con Callbacks (REFERENCIA — consulta al analizar transfers/mints)
| Estándar | Función que dispara callback | Callback en receptor |
|----------|------------------------------|---------------------|
| ERC-721 | safeMint, safeTransferFrom | onERC721Received |
| ERC-1155 | safeTransferFrom, safeBatchTransferFrom | onERC1155Received, onERC1155BatchReceived |
| ERC-777 | send, transfer (DEPRECADO pero existe) | tokensReceived (via ERC-1820 registry) |
| ERC-677 | transferAndCall (LINK, xDAI) | onTokenTransfer |
| ETH nativo | transfer, call{value} | receive(), fallback() |

⚠ Las funciones "safe" son PARADÓJICAMENTE más peligrosas — ejecutan callbacks al receptor.
⚠ Read-only reentrancy: funciones view que leen state de un pool durante callback cuando el state es inconsistente (ChainSecurity/Curve).

## State Machine Model (OBLIGATORIO — output incluido en hyp_*.yaml)
Modela el componente como una máquina de estados finita (FSM). Este output es CRÍTICO — lo usará DeepDiveHunter.

**Paso 1 — Identificar estados:**
Lista TODOS los estados posibles del contrato/posición/usuario. Ejemplos:
  - Vault: EMPTY → ACTIVE → PAUSED → MIGRATING
  - Position: OPEN → HEALTHY → UNDERWATER → LIQUIDATABLE → LIQUIDATED → CLOSED
  - Order: PENDING → FILLED → PARTIALLY_FILLED → CANCELLED → EXPIRED

**Paso 2 — Mapear transiciones:**
Para CADA par de estados, identifica qué función(es) ejecutan la transición:
```
HEALTHY → UNDERWATER: price drop (oracle update, no función directa)
UNDERWATER → LIQUIDATABLE: cuando ltv > lltv (automático por precio)
LIQUIDATABLE → LIQUIDATED: liquidate() / preLiquidate()
OPEN → CLOSED: withdraw() con amount=totalBalance
```

**Paso 3 — Buscar anomalías (AQUÍ ESTÁN LOS BUGS):**
1. **Transiciones ilegales**: ¿Se puede ir de LIQUIDATED → ACTIVE? ¿De CLOSED → OPEN sin nuevo depósito?
2. **Estados stuck (fondos atrapados)**: ¿Hay algún estado sin transición de salida? ¿Puede un usuario quedar atrapado?
3. **Race conditions**: ¿Dos transiciones concurrentes pueden dejar el estado inconsistente?
4. **Transiciones faltantes**: ¿Debería existir PAUSED → EMERGENCY_WITHDRAW pero no existe?
5. **Bypass de estados**: ¿Se puede saltar de PENDING directamente a FILLED sin validación intermedia?

**Output requerido en el YAML:**
```yaml
state_machine:
  states: [EMPTY, ACTIVE, UNDERWATER, LIQUIDATABLE, LIQUIDATED]
  transitions:
    - from: EMPTY, to: ACTIVE, via: "deposit()", guard: "amount > 0"
    - from: ACTIVE, to: UNDERWATER, via: "oracle price drop", guard: "none (automatic)"
  anomalies:
    - type: stuck_state, state: LIQUIDATED, description: "residual dust puede quedar atrapado"
    - type: illegal_transition, from: LIQUIDATED, to: ACTIVE, via: "deposit() no verifica estado"
```

Bug real: Rari Fuse — posición liquidada podía re-depositarse y crear deuda fantasma.
Bug real: Compound v2 — cToken stuck en PAUSED sin función de unpause por admin key loss.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
