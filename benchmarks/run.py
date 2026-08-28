"""Benchmark L4: Adversarial Red Teamer"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from redteam.nodes.attacker import attacker_node
from redteam.nodes.evaluator import evaluator_node
from redteam.nodes.judge import judge_node
from redteam.state import AttackCategory, RedTeamState


def run_benchmark() -> dict:
    results: dict = {"timestamp": datetime.now(timezone.utc).isoformat(), "steps": {}}

    state: RedTeamState = {
        "target_guardrail": "benchmark-guardrail",
        "attack_categories": [
            AttackCategory.LLM01_PROMPT_INJECTION,
            AttackCategory.LLM06_SENSITIVE_INFO_DISCLOSURE,
            AttackCategory.LLM08_EXCESSIVE_AGENCY,
            AttackCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
        ],
        "max_attacks": 20,
        "iterations": 0,
        "evaluation_results": [],
        "verdicts": [],
        "status_messages": [],
        "is_complete": False,
    }

    t0 = time.perf_counter()
    r1 = attacker_node(state)
    results["steps"]["attacker_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    state = {**state, **r1}

    t0 = time.perf_counter()
    r2 = evaluator_node(state)
    results["steps"]["evaluator_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    state = {**state, **r2}

    t0 = time.perf_counter()
    r3 = judge_node(state)
    results["steps"]["judge_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    total = sum(results["steps"].values())
    results["total_pipeline_ms"] = total
    results["probes_generated"] = len(r1.get("probes", []))
    results["report_generated"] = r3.get("report") is not None
    if r3.get("report"):
        results["evasion_rate"] = r3["report"].evasion_rate
        results["is_certified"] = r3["report"].is_certified_secure
    results["performance_ok"] = total < 500.0

    print(f"📊 Benchmark Red Teamer: {total:.2f}ms total")
    for step, ms in results["steps"].items():
        print(f"   {step}: {ms:.2f}ms")
    print(f"   Probes: {results['probes_generated']}, Report: {results['report_generated']}")
    print(f"   ✅ Performance OK: {results['performance_ok']}")

    return results


if __name__ == "__main__":
    r = run_benchmark()
    out = Path(__file__).parent / "resultados.json"
    out.write_text(json.dumps(r, indent=2))
    print(f"\n💾 {out}")
