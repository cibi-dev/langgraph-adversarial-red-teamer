"""
Red Teaming State Models — state.py
=====================================
Modelos Pydantic v2 para el framework de Red Teaming adversario.

Guardrails:
  - Pydantic v2 `extra='forbid'` (#15).
  - #17 (Anti-DoS): max_attacks fijado en 100 (matriz acotada).
  - #15 (Sanitización): Los ataques se etiquetan y contienen en el estado.
"""
from __future__ import annotations

import operator
from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations — OWASP LLM Top 10
# ---------------------------------------------------------------------------


class AttackCategory(str, Enum):
    """Categorías de ataque OWASP LLM Top 10."""
    LLM01_PROMPT_INJECTION = "LLM01_prompt_injection"
    LLM02_INSECURE_OUTPUT = "LLM02_insecure_output_handling"
    LLM03_TRAINING_DATA_POISONING = "LLM03_training_data_poisoning"
    LLM04_MODEL_DENIAL_OF_SERVICE = "LLM04_model_dos"
    LLM05_SUPPLY_CHAIN = "LLM05_supply_chain"
    LLM06_SENSITIVE_INFO_DISCLOSURE = "LLM06_sensitive_info_disclosure"
    LLM07_INSECURE_PLUGIN = "LLM07_insecure_plugin_design"
    LLM08_EXCESSIVE_AGENCY = "LLM08_excessive_agency"
    LLM09_OVERRELIANCE = "LLM09_overreliance"
    LLM10_MODEL_THEFT = "LLM10_model_theft"


class AttackResult(str, Enum):
    """Resultado de un ataque adversario contra el guardrail."""
    BLOCKED = "blocked"           # El guardrail bloqueó el ataque ✅
    EVADED = "evaded"             # El ataque evadió el guardrail ❌
    PARTIAL_BLOCK = "partial_block"  # Bloqueo parcial ⚠️
    ERROR = "error"               # Error en evaluación


class MutationStrategy(str, Enum):
    """Estrategias de mutación para generar variantes de ataque."""
    DIRECT = "direct"
    ROLEPLAY_BYPASS = "roleplay_bypass"
    MULTILINGUAL = "multilingual"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    CONTEXT_INJECTION = "context_injection"
    JAILBREAK = "jailbreak"
    INDIRECT_INJECTION = "indirect_injection"


# ---------------------------------------------------------------------------
# Attack Models
# ---------------------------------------------------------------------------


class AttackProbe(BaseModel):
    """Sonda de ataque adversaria contra un guardrail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[A-Z0-9\-]+$")
    category: AttackCategory
    mutation_strategy: MutationStrategy
    payload: str = Field(..., min_length=1, max_length=2048)
    language: str = Field(default="es", max_length=10)
    target_behavior: str = Field(..., min_length=5, max_length=512)


class EvaluationResult(BaseModel):
    """Resultado de la evaluación de un probe contra el guardrail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(..., min_length=2, max_length=64)
    result: AttackResult
    guardrail_response: str = Field(..., min_length=1, max_length=2048)
    evasion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    notes: str = Field(default="", max_length=1024)


class JudgeVerdict(BaseModel):
    """Veredicto del juez determinista sobre la efectividad del guardrail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(..., min_length=2, max_length=64)
    is_evasion: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    category: AttackCategory
    explanation: str = Field(..., min_length=5, max_length=1024)


class RedTeamReport(BaseModel):
    """Reporte final de red teaming con estadísticas y veredictos."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str = Field(..., min_length=3, max_length=64)
    target_guardrail: str = Field(..., min_length=1, max_length=128)
    total_probes: int = Field(..., ge=0)
    blocked_count: int = Field(..., ge=0)
    evaded_count: int = Field(..., ge=0)
    partial_block_count: int = Field(..., ge=0)
    evasion_rate: float = Field(..., ge=0.0, le=1.0)
    verdicts: list[JudgeVerdict]
    recommendations: list[str]
    is_certified_secure: bool = Field(default=False)


# ---------------------------------------------------------------------------
# LangGraph RedTeamState (TypedDict)
# ---------------------------------------------------------------------------

from typing import TypedDict  # noqa: E402


class RedTeamState(TypedDict, total=False):
    """Estado principal del grafo de Red Teaming."""

    # Configuración del objetivo
    target_guardrail: str
    attack_categories: list[AttackCategory]
    max_attacks: int  # Anti-DoS: máximo 100 (#17)

    # Probes generados por el Attacker
    probes: list[AttackProbe]

    # Resultados de evaluación
    evaluation_results: Annotated[list[EvaluationResult], operator.add]

    # Veredictos del juez
    verdicts: Annotated[list[JudgeVerdict], operator.add]

    # Control de ciclo
    current_probe_index: int
    iterations: Annotated[int, operator.add]

    # Reporte final
    report: Optional[RedTeamReport]

    # Estado general
    status_messages: Annotated[list[str], operator.add]
    is_complete: bool
