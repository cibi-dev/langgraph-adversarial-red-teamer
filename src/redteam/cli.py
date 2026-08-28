"""CLI entry-point para Adversarial Red Teamer."""
from __future__ import annotations

import sys
from typing import Any

from redteam.graph import compile_graph
from redteam.state import AttackCategory, RedTeamState


def main() -> None:
    if len(sys.argv) < 2:
        print("Uso: red-teamer <target_guardrail> [max_attacks]")
        sys.exit(1)

    target = sys.argv[1]
    max_attacks = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    state: RedTeamState = {
        "target_guardrail": target,
        "attack_categories": [
            AttackCategory.LLM01_PROMPT_INJECTION,
            AttackCategory.LLM06_SENSITIVE_INFO_DISCLOSURE,
            AttackCategory.LLM08_EXCESSIVE_AGENCY,
            AttackCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
        ],
        "max_attacks": max_attacks,
        "iterations": 0,
        "evaluation_results": [],
        "verdicts": [],
        "status_messages": [],
        "is_complete": False,
    }

    app: Any = compile_graph()
    config = {"configurable": {"thread_id": f"rt-{target}"}}

    print(f"\n🔴 Iniciando Red Teaming contra: {target}")
    try:
        for step in app.stream(state, config=config):
            node_name, node_state = next(iter(step.items()))
            for msg in (node_state.get("status_messages") or []):
                print(f"  {msg}")
    except Exception as e:
        print(f"  [WARN] {e}")

    print("\n✅ Red Teaming finalizado.")


if __name__ == "__main__":
    main()
