"""
modules/ai_routing/__init__.py

Exposes the RAG-enhanced AI Router, TaskRequest, and TaskComplexity
for use by other Centaur-Jarvis modules.
"""

from modules.ai_routing.router import (
    AIRouter,
    GenerationResult,
    RAGConfig,
    RAGContext,
    TaskComplexity,
    TaskRequest,
)

__all__ = [
    "AIRouter",
    "GenerationResult",
    "RAGConfig",
    "RAGContext",
    "TaskComplexity",
    "TaskRequest",
]