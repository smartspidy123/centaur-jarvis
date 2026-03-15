"""
Chain Attack Module — Centaur-Jarvis VAPT Agent
================================================
Multi-step exploitation engine with knowledge graph, AI planner, and executor.

Architecture:
    findings → KnowledgeGraph → AIPlanner → Executor → task queues
    
All status strings are UPPERCASE per TaskStatus schema.
All results include mandatory `data` field.
"""

__version__ = "1.0.0"
__module_name__ = "chain_attack"
