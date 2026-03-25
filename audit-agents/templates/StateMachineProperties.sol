// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title StateMachineProperties — Template para verificación de transiciones de estado
 *
 * @notice Template genérico para modelar un contrato como FSM (Finite State Machine).
 *         Cada transición ilegal que el fuzzer logre ejecutar = bug potencial.
 *
 * CÓMO USAR:
 * 1. Define tus estados en el enum State (reemplaza los de ejemplo)
 * 2. Configura la matriz de transiciones válidas en _initTransitions()
 * 3. Llama _checkAndUpdateState() después de cada acción en tus handlers
 * 4. El fuzzer intentará todas las combinaciones — las ilegales fallan la assertion
 *
 * EJEMPLO (Lending):
 *   Estados: EMPTY → DEPOSITED → BORROWED → LIQUIDATED
 *   Transiciones ilegales: EMPTY→BORROWED (sin colateral), LIQUIDATED→BORROWED (sin nuevo depósito)
 */

// Import Chimera assertion helpers
// import {Asserts} from "@chimera/Asserts.sol";

abstract contract StateMachineProperties {

    // ═══════════════════════════════════════════════════════════
    //  PASO 1: Define los estados del protocolo
    // ═══════════════════════════════════════════════════════════

    enum State {
        EMPTY,              // 0: Sin posición
        DEPOSITED,          // 1: Colateral depositado, sin deuda
        BORROWED_HEALTHY,   // 2: Deuda activa, posición sana
        BORROWED_UNHEALTHY, // 3: Deuda activa, posición insana (near liquidation)
        LIQUIDATABLE,       // 4: Puede ser liquidada
        LIQUIDATED          // 5: Ya fue liquidada
        // Añade más estados según el protocolo
    }

    uint8 constant NUM_STATES = 6; // Actualizar si añades/quitas estados

    // ═══════════════════════════════════════════════════════════
    //  Ghost variables
    // ═══════════════════════════════════════════════════════════

    /// @notice Estado actual por actor (para fuzzing multi-actor)
    mapping(address => State) internal ghost_currentState;

    /// @notice Historial de transiciones (para debugging)
    uint256 internal ghost_transitionCount;

    /// @notice Última transición registrada
    State internal ghost_lastFromState;
    State internal ghost_lastToState;

    /// @notice Matriz de transiciones válidas: validTransitions[from][to] = true/false
    bool[NUM_STATES][NUM_STATES] internal validTransitions;

    // ═══════════════════════════════════════════════════════════
    //  PASO 2: Configura transiciones válidas
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Configura qué transiciones son legales.
     *         Llamar en el constructor o setup del test.
     *
     * Formato: validTransitions[FROM][TO] = true
     * Todo lo que NO esté marcado como true es ILEGAL.
     */
    function _initTransitions() internal {
        // EMPTY → DEPOSITED (depositar colateral)
        validTransitions[uint8(State.EMPTY)][uint8(State.DEPOSITED)] = true;

        // DEPOSITED → EMPTY (retirar todo el colateral)
        validTransitions[uint8(State.DEPOSITED)][uint8(State.EMPTY)] = true;

        // DEPOSITED → BORROWED_HEALTHY (pedir préstamo con colateral sano)
        validTransitions[uint8(State.DEPOSITED)][uint8(State.BORROWED_HEALTHY)] = true;

        // BORROWED_HEALTHY → DEPOSITED (repagar toda la deuda)
        validTransitions[uint8(State.BORROWED_HEALTHY)][uint8(State.DEPOSITED)] = true;

        // BORROWED_HEALTHY → BORROWED_UNHEALTHY (precio del colateral baja)
        validTransitions[uint8(State.BORROWED_HEALTHY)][uint8(State.BORROWED_UNHEALTHY)] = true;

        // BORROWED_UNHEALTHY → BORROWED_HEALTHY (precio sube o repago parcial)
        validTransitions[uint8(State.BORROWED_UNHEALTHY)][uint8(State.BORROWED_HEALTHY)] = true;

        // BORROWED_UNHEALTHY → LIQUIDATABLE (pasa threshold de liquidación)
        validTransitions[uint8(State.BORROWED_UNHEALTHY)][uint8(State.LIQUIDATABLE)] = true;

        // BORROWED_UNHEALTHY → DEPOSITED (repagar toda la deuda)
        validTransitions[uint8(State.BORROWED_UNHEALTHY)][uint8(State.DEPOSITED)] = true;

        // LIQUIDATABLE → LIQUIDATED (alguien ejecuta liquidación)
        validTransitions[uint8(State.LIQUIDATABLE)][uint8(State.LIQUIDATED)] = true;

        // LIQUIDATABLE → BORROWED_HEALTHY (repago de emergencia antes de liquidación)
        validTransitions[uint8(State.LIQUIDATABLE)][uint8(State.BORROWED_HEALTHY)] = true;

        // LIQUIDATED → EMPTY (posición reseteada post-liquidación)
        validTransitions[uint8(State.LIQUIDATED)][uint8(State.EMPTY)] = true;

        // === TRANSICIONES ILEGALES (no listadas arriba) ===
        // EMPTY → BORROWED (sin colateral) — BUG SI OCURRE
        // LIQUIDATED → BORROWED (sin nuevo depósito) — BUG SI OCURRE
        // DEPOSITED → LIQUIDATED (sin deuda) — BUG SI OCURRE
    }

    // ═══════════════════════════════════════════════════════════
    //  PASO 3: Verificación de transiciones
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Verifica que la transición es legal y actualiza el estado.
     *         Llamar DESPUÉS de cada acción en los handlers de TargetFunctions.
     *
     * @param actor La dirección del actor cuyo estado cambió
     * @param newState El nuevo estado después de la acción
     *
     * Ejemplo de uso en handler:
     *   function handler_deposit(uint256 amount) internal {
     *       vault.deposit(amount);
     *       _checkAndUpdateState(msg.sender, State.DEPOSITED);
     *   }
     */
    function _checkAndUpdateState(address actor, State newState) internal {
        State currentState = ghost_currentState[actor];

        // Self-transition is always valid (no state change)
        if (currentState == newState) return;

        // Check transition legality
        bool isValid = validTransitions[uint8(currentState)][uint8(newState)];
        assert(isValid); // "SM: Illegal state transition"

        // Update ghost state
        ghost_lastFromState = currentState;
        ghost_lastToState = newState;
        ghost_currentState[actor] = newState;
        ghost_transitionCount++;
    }

    /**
     * @notice Determina el estado actual basado en el estado on-chain.
     *         OVERRIDE esta función para cada protocolo.
     *
     * @param actor La dirección a evaluar
     * @return El estado actual del actor según el contrato
     *
     * Ejemplo para lending:
     *   function _deriveState(address actor) internal view override returns (State) {
     *       uint256 collateral = vault.getCollateral(actor);
     *       uint256 debt = vault.getDebt(actor);
     *       if (collateral == 0 && debt == 0) return State.EMPTY;
     *       if (collateral > 0 && debt == 0) return State.DEPOSITED;
     *       uint256 health = vault.healthFactor(actor);
     *       if (health > 1.5e18) return State.BORROWED_HEALTHY;
     *       if (health > 1.0e18) return State.BORROWED_UNHEALTHY;
     *       return State.LIQUIDATABLE;
     *   }
     */
    function _deriveState(address actor) internal view virtual returns (State);

    /**
     * @notice Property: el estado derivado on-chain debe coincidir con el ghost state.
     *         Si divergen, hay un bug de sincronización de estado.
     */
    function property_state_consistency(address actor) public view {
        State derived = _deriveState(actor);
        State ghost = ghost_currentState[actor];
        assert(derived == ghost); // "SM: Ghost state diverged from on-chain state"
    }

    // ═══════════════════════════════════════════════════════════
    //  Properties de transiciones ilegales específicas
    // ═══════════════════════════════════════════════════════════

    /**
     * @notice Invariante: nadie puede tener deuda sin colateral.
     *         Transición ilegal: EMPTY → BORROWED
     */
    function property_no_unsecured_debt(address actor) public view {
        State s = _deriveState(actor);
        // If state is any BORROWED variant, they must have gone through DEPOSITED first
        if (s == State.BORROWED_HEALTHY || s == State.BORROWED_UNHEALTHY) {
            assert(ghost_currentState[actor] != State.EMPTY);
            // "SM: Unsecured debt — borrowed without depositing"
        }
    }

    /**
     * @notice Invariante: posición liquidada no puede volver a BORROWED sin nuevo depósito.
     *         Transición ilegal: LIQUIDATED → BORROWED
     */
    function property_no_zombie_debt(address actor) public view {
        if (ghost_lastFromState == State.LIQUIDATED) {
            State current = ghost_currentState[actor];
            assert(
                current == State.EMPTY ||
                current == State.DEPOSITED ||
                current == State.LIQUIDATED
            );
            // "SM: Zombie debt — borrowed after liquidation without new deposit"
        }
    }
}
