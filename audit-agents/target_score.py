#!/usr/bin/env python3
"""
target_score.py — Scoring de Bounty antes de invertir pipeline
Evalúa si un bounty merece el pipeline completo, hunt estándar, o grep rápido.

Uso:
    python3 target_score.py --interactive
    python3 target_score.py --payout 50000 --deadline 7 --domain lending --locs 5000
    python3 target_score.py --url https://cantina.xyz/competitions/xxx

Factores:
    payout_potential × (1/competition_density) × domain_strength × time_remaining × code_novelty
"""

import sys
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

# Dominios donde somos fuertes (basado en briefings y experiencia)
DOMAIN_STRENGTH = {
    "lending":        0.90,  # V3Vault confirmado, Maple V2 + Euler en registry
    "vault":          0.90,  # ERC4626, share inflation, rounding
    "oracle":         0.85,  # 8 patrones, 21 incidentes verificados
    "access-control": 0.80,  # 8 patrones, 33 incidentes verificados
    "staking":        0.80,  # GaugeManager en progreso
    "flash-loan":     0.75,  # 6 patrones, 16 incidentes
    "token":          0.75,  # ERC20, fee-on-transfer, rebasing
    "dex":            0.60,  # briefing existe pero registry vacío
    "amm":            0.60,
    "bridge":         0.55,  # 9 patrones pero validación difícil
    "zk":             0.45,  # briefing escaso
    "proxy":          0.70,  # 8 patrones de Solodit
    "signature":      0.70,  # 8 patrones de Solodit
    "general":        0.65,  # desconocido
}

# Ajustes por plataforma (basado en experiencia de competencia)
PLATFORM_COMPETITION = {
    "cantina":    0.75,   # más selectivo, menos hunters
    "code4rena":  0.50,   # muy competido
    "sherlock":   0.55,   # competido pero más estructurado
    "immunefi":   0.80,   # bounty abierto, menos presión de tiempo
    "codehawks":  0.65,
    "hackenproof": 0.70,
}


def score_payout(payout_usd: float) -> float:
    """0-1 score basado en el payout máximo."""
    if payout_usd >= 500_000:  return 1.00
    if payout_usd >= 100_000:  return 0.90
    if payout_usd >= 50_000:   return 0.80
    if payout_usd >= 20_000:   return 0.65
    if payout_usd >= 10_000:   return 0.50
    if payout_usd >= 5_000:    return 0.35
    return 0.20


def score_time(days_remaining: int) -> float:
    """0-1 score basado en tiempo restante."""
    if days_remaining <= 0:    return 0.00
    if days_remaining <= 2:    return 0.30  # casi imposible
    if days_remaining <= 5:    return 0.65
    if days_remaining <= 10:   return 0.85
    if days_remaining <= 21:   return 1.00
    if days_remaining <= 60:   return 0.80  # bounty abierto, mucha competencia acumulada
    return 0.60


def score_locs(total_locs: int) -> float:
    """0-1 score — preferimos targets de tamaño manejable."""
    if total_locs <= 500:    return 0.90  # pequeño, cubre todo
    if total_locs <= 2000:   return 1.00  # óptimo
    if total_locs <= 5000:   return 0.85  # manejable
    if total_locs <= 10000:  return 0.65  # grande, difícil cobertura total
    return 0.45  # muy grande


def score_novelty(is_new_code: bool, has_audit: bool) -> float:
    """0-1 score basado en qué tan nuevo es el código."""
    if is_new_code and not has_audit:  return 1.00  # código nuevo sin audit = máxima oportunidad
    if is_new_code and has_audit:      return 0.80  # nuevo pero ya auditado
    if not is_new_code and not has_audit: return 0.70  # antiguo sin audit (raro)
    return 0.50  # antiguo + auditado = bajísima probabilidad


def compute_final_score(
    payout: float,
    days: int,
    domain: str,
    locs: int,
    platform: str,
    is_new_code: bool,
    has_previous_audit: bool,
    competition_hunters: int = 0,
) -> dict:
    """Calcula el score final ponderado y la recomendación."""

    s_payout   = score_payout(payout)
    s_time     = score_time(days)
    s_domain   = DOMAIN_STRENGTH.get(domain.lower(), DOMAIN_STRENGTH["general"])
    s_locs     = score_locs(locs)
    s_novelty  = score_novelty(is_new_code, has_previous_audit)
    s_platform = PLATFORM_COMPETITION.get(platform.lower(), 0.65)

    # Ajuste por hunters registrados (si > 50 hunters = muy competido)
    competition_penalty = 1.0
    if competition_hunters > 100: competition_penalty = 0.60
    elif competition_hunters > 50: competition_penalty = 0.75
    elif competition_hunters > 20: competition_penalty = 0.90

    # Pesos (suman 1.0)
    score = (
        s_payout   * 0.30 +
        s_time     * 0.20 +
        s_domain   * 0.20 +
        s_novelty  * 0.15 +
        s_locs     * 0.10 +
        s_platform * 0.05
    ) * competition_penalty * 100  # 0-100

    # Recomendación
    if score >= 70:
        recommendation = "FULL_HUNT"
        action = "Desplegar Agent Team completo (6+ hunters, pipeline completo)"
        color = "🟢"
    elif score >= 45:
        recommendation = "STANDARD_HUNT"
        action = "Hunt estándar (un agente, checklist completo)"
        color = "🟡"
    elif score >= 25:
        recommendation = "QUICK_SCAN"
        action = "Grep arsenal 30 min + lectura rápida. Decidir si profundizar."
        color = "🟠"
    else:
        recommendation = "SKIP"
        action = "No invertir tiempo. Mover al siguiente target."
        color = "🔴"

    return {
        "final_score": round(score, 1),
        "recommendation": recommendation,
        "action": action,
        "color": color,
        "breakdown": {
            "payout":    round(s_payout * 100, 1),
            "time":      round(s_time * 100, 1),
            "domain":    round(s_domain * 100, 1),
            "novelty":   round(s_novelty * 100, 1),
            "locs":      round(s_locs * 100, 1),
            "platform":  round(s_platform * 100, 1),
            "competition_penalty": round(competition_penalty * 100, 1),
        }
    }


def interactive_mode():
    """Modo interactivo paso a paso."""
    print("\n" + "="*60)
    print("  TARGET SCORER — Web3 Bug Bounty")
    print("="*60 + "\n")

    try:
        payout = float(input("Payout máximo ($USD): ").replace(",", "").replace("K", "000").replace("k", "000"))
    except:
        payout = 50000

    try:
        deadline_str = input("Días hasta deadline (o fecha YYYY-MM-DD): ")
        if "-" in deadline_str:
            deadline = datetime.strptime(deadline_str, "%Y-%m-%d")
            days = (deadline - datetime.now()).days
        else:
            days = int(deadline_str)
    except:
        days = 7

    domain = input("Dominio principal (lending/vault/oracle/staking/dex/bridge/zk/...): ").strip() or "general"

    try:
        locs = int(input("LOC en scope (aprox): "))
    except:
        locs = 3000

    platform = input("Plataforma (cantina/code4rena/sherlock/immunefi/codehawks): ").strip() or "cantina"
    is_new = input("¿Código nuevo desde último audit? (s/n): ").strip().lower() == "s"
    has_audit = input("¿Tiene audit previo? (s/n): ").strip().lower() == "s"

    try:
        hunters = int(input("Hunters registrados (0 si no sabes): "))
    except:
        hunters = 0

    result = compute_final_score(payout, days, domain, locs, platform, is_new, has_audit, hunters)
    print_result(result, payout, days, domain, locs, platform)


def print_result(result: dict, payout: float, days: int, domain: str, locs: int, platform: str):
    print("\n" + "="*60)
    print(f"  RESULTADO: {result['color']} {result['final_score']}/100 — {result['recommendation']}")
    print("="*60)
    print(f"\n  Acción recomendada:")
    print(f"  → {result['action']}\n")
    print("  Desglose de factores:")
    b = result["breakdown"]
    print(f"    Payout ($):       {b['payout']:5.1f}/100  (${payout:,.0f})")
    print(f"    Tiempo:           {b['time']:5.1f}/100  ({days} días restantes)")
    print(f"    Dominio ({domain[:10]:10}): {b['domain']:5.1f}/100")
    print(f"    Novedad código:   {b['novelty']:5.1f}/100")
    print(f"    Tamaño ({locs} LOC): {b['locs']:5.1f}/100")
    print(f"    Plataforma:       {b['platform']:5.1f}/100  ({platform})")
    print(f"    Penaliz. compet.: {b['competition_penalty']:5.1f}/100")
    print()

    # Recomendaciones adicionales
    if result["recommendation"] == "FULL_HUNT":
        print("  Tips para este target:")
        print("    • Lanzar Agent Team completo desde L0")
        print("    • Priorizar código nuevo con DiffHunter")
        print("    • Usar fork mainnet desde el primer día")
    elif result["recommendation"] == "QUICK_SCAN":
        print("  Tips para este target:")
        print("    • 30 min de grep arsenal primero")
        print("    • Si encuentras algo prometedor, upgrade a STANDARD_HUNT")
        print("    • No gastar más de 2h sin un finding claro")
    elif result["recommendation"] == "SKIP":
        print("  Razones para skip:")
        if days <= 2:  print("    • Tiempo insuficiente para hunt de calidad")
        if payout < 5000: print("    • Payout muy bajo para el esfuerzo")


def main():
    parser = argparse.ArgumentParser(description="Score de target para bug bounty")
    parser.add_argument("--interactive", "-i", action="store_true")
    parser.add_argument("--payout", type=float, help="Payout máximo en USD")
    parser.add_argument("--deadline", type=int, help="Días hasta deadline")
    parser.add_argument("--domain", type=str, default="general")
    parser.add_argument("--locs", type=int, default=3000)
    parser.add_argument("--platform", type=str, default="cantina")
    parser.add_argument("--new-code", action="store_true", help="Código nuevo desde último audit")
    parser.add_argument("--no-audit", action="store_true", help="Sin audit previo")
    parser.add_argument("--hunters", type=int, default=0, help="Hunters registrados")
    parser.add_argument("--json", action="store_true", help="Output en JSON")
    args = parser.parse_args()

    if args.interactive or not args.payout:
        interactive_mode()
        return 0

    result = compute_final_score(
        payout=args.payout,
        days=args.deadline or 7,
        domain=args.domain,
        locs=args.locs,
        platform=args.platform,
        is_new_code=args.new_code,
        has_previous_audit=not args.no_audit,
        competition_hunters=args.hunters,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result, args.payout, args.deadline or 7, args.domain, args.locs, args.platform)

    return 0


if __name__ == "__main__":
    sys.exit(main())
