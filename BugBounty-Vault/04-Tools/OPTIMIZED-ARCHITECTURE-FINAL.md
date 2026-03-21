# Arquitectura Optimizada Final — Proving Engine
## 20 expertos × 3 iteraciones — 19 Marzo 2026

## TOP 10 OPTIMIZATIONS (ranked by bug-finding impact)

1. **Echidna optimization mode con profit functions** — maximiza profit del atacante automáticamente
2. **Prompt estructurado 5 fases** — map → trust → invariants → handlers → ghosts
3. **Boundary value injection** (0, 1, max, balance±1) — 37% de criticals son rounding
4. **Registry pruning: 288 → ~60 invariantes gradeadas** — menos = más cycles fuzzing
5. **Compile-fix loop** (generate → compile → fix → retry ×3) — elimina runs inútiles
6. **Corpus persistente + seeding con attack patterns** — 20min de ventaja por target
7. **Ghost variables per-user acumulativas** — atrapa fund extraction y slow leaks
8. **Tiered fuzzing 4 fases × 30min** — diversidad de estrategia > duración
9. **Auto-detección de tipo + template libraries** — setup en 5min vs 30min
10. **Attacker callback contract para reentrancy** — fuzzers estándar no testean callbacks

## 5 FAMILIAS DE INVARIANTES QUE ATRAPAN 80% DE BUGS

1. **Solvency**: token balance >= accounting (SIEMPRE)
2. **Monotonicity**: share price solo sube por user actions
3. **Round-trip**: withdraw(deposit(x)) <= x
4. **Conservation**: totalBefore + deposits - withdrawals == totalAfter
5. **No-profit-from-nothing**: zero-deposit user cannot have positive balance

## WORKFLOW: Code In → Bugs Out (30 min)

```
Phase 1 - Quick Scan [5 min]:
  Medusa, sequences=5, Tier 1 invariants only

Phase 2 - Deep Scan [10 min]:
  Medusa, sequences=20, all invariants, seeded corpus

Phase 3 - Economic Optimization [10 min]:
  Echidna optimization mode → maximize attacker profit

Phase 4 - Mathematical Proof [5 min]:
  Halmos on pure math (share conversion, fees)
```

## PRINCIPIOS CLAVE

- 15 invariantes precisas > 200 vagas
- Optimization mode es la mayor capacidad sin desbloquear
- Rounding bugs necesitan valores pequeños (1 wei), no random uint256
- Corpus es un asset compuesto — cada sesión construye sobre la anterior
- 3 actores óptimo: honest user, attacker (high balance), keeper
- Ghost vars deben trackear flujos ACUMULATIVOS per-user
- Cada invariante DEBE tener un escenario de ataque descrito
- Regression: correr contra 10 bugs conocidos, target 7+/10
