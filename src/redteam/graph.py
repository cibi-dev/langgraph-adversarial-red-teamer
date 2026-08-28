"""
Grafo Red Teamer — graph.py
==============================
StateGraph: attacker → evaluator → judge → END.
"""
from __future__ import annotations

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from redteam.nodes.attacker import attacker_node
from redteam.nodes.evaluator import evaluator_node
from redteam.nodes.judge import judge_node
from redteam.state import RedTeamState


def build_graph() -> StateGraph:
    graph = StateGraph(RedTeamState)
    graph.add_node("attacker", attacker_node)
    graph.add_node("evaluator", evaluator_node)
    graph.add_node("judge", judge_node)
    graph.add_edge(START, "attacker")
    graph.add_edge("attacker", "evaluator")
    graph.add_edge("evaluator", "judge")
    graph.add_edge("judge", END)
    return graph


def compile_graph() -> object:
    graph = build_graph()
    memory = InMemorySaver()
    return graph.compile(checkpointer=memory)
