# Benchmark V2 — Yieldoor Runbook

## Reglas
- Pipeline completo por componente (RULE #0)
- NO report_finding.py — nada se sube a Bounty Radar ni Telegram
- Anti-contaminación: tratar como contest nuevo, sin mirar ground truth
- Scoring DESPUÉS de completar todo con benchmark_score.py

## Componentes (en orden)
1. Strategy (~600 LOC)
2. Leverager (~400 LOC)
3. Vault (~300 LOC)
4. LendingPool (~200 LOC) + libraries (ReserveLogic, InterestRateUtils)

## Pipeline por componente

### 0. Scope
```bash
cd /home/kali/Documents/Web3/benchmarks/yieldoor/repo/yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_benchmark.py --components <Component> --protocol yieldoor --repo .
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate scope --protocol yieldoor
```

### 1. Prepass (Slither + Aderyn + Exploit Patterns)
```bash
python3 /home/kali/Documents/Web3/audit-agents/detection_engine.py \
  --prepass --source ./src --name <Component> \
  --output /home/kali/Documents/Web3/hunt_session/results/
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate prepass --protocol yieldoor
```

### 2. Hunters (9 paralelos)
Lanzar como Agent tool: AccessHunter, DomainHunter, FlowHunter, MathHunter, OracleHunter, TrustBoundaryHunter, WildcardHunter, SignatureHunter, DoSHunter.
```bash
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate hunters --protocol yieldoor
```

### 3. CrossChain Hunter
Skip — Yieldoor es single-chain.

### 4. DeepDive Hunter (secuencial)
Lee convergencias de los 9 hunters, genera hipótesis profundas.
```bash
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate deepdive --protocol yieldoor
```

### 5. Merge Invariants
```bash
python3 /home/kali/Documents/Web3/audit-agents/merge_invariants.py --component <Component> --protocol yieldoor
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate merge --protocol yieldoor
```

### 6. Compile
```bash
forge build
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate compile --protocol yieldoor
```

### 7. Phase 1 — Foundry 5K runs
```bash
FOUNDRY_PROFILE=chimera forge test --match-contract FoundryTester --fuzz-runs 5000 -vv
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate phase1 --protocol yieldoor
```
Tolerance tuning entre Phase 1 y 2.

### 8. Phase 2 — Medusa 15 min
```bash
medusa fuzz --config test/chimera/medusa-yieldoor.json --timeout 900
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate phase2 --protocol yieldoor
```

### 9. Phase 3 — Fork PoC (si hay findings)
Para cada finding con PoC:
```bash
ETH_RPC_URL=... forge test --match-contract ForkTester --fuzz-runs 10000
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate phase3 --protocol yieldoor
```

### 10. Finding Pipeline (por finding)
Para cada finding detectado:
1. RedTeam (/redteam) — obligatorio toda severidad
2. EscalationHunter (/escalation-hunter) — obligatorio Medium+
3. VariantHunt (/variant-hunt) — obligatorio siempre
4. ReportWriter (/report-writer) — si RedTeam = REPORT

**⚠️ NO ejecutar report_finding.py — esto es benchmark, no submission real**

### 11. Completar componente
```bash
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --status --protocol yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_benchmark.py --complete <Component>
```

## Cross-Component (después de 2-3 componentes)
Rule #0.5 — ejecutar hunt cross-component.

## Scoring Final
```bash
python3 /home/kali/Documents/Web3/audit-agents/benchmark_score.py \
  --ground-truth /home/kali/Documents/Web3/benchmarks/yieldoor/benchmark.yaml \
  --findings-dir /home/kali/Documents/Web3/hunt_session/hypotheses/yieldoor-bench/
```

## Archivos de referencia
- Ground truth: `benchmarks/yieldoor/benchmark.yaml` (17 findings: 7H + 10M)
- v1 baseline: `hunt_session/archive/yieldoor-bench-v1/benchmark_final_score_yieldoor-bench.yaml` (41.2%)
- Reglas: `benchmarks/yieldoor/BENCHMARK_RULES.md`
- Repo: `benchmarks/yieldoor/repo/yieldoor/src/`
