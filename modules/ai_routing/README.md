# AI Router Module

## Overview

The AI Router is the **intelligent gateway** for all AI operations in Centaur-Jarvis.
It detects available local LLMs (via Ollama) and external AI APIs (Gemini, DeepSeek, Groq),
then routes tasks based on context length, complexity, and availability.

## Quick Start

```python
from modules.ai_routing import AIRouter, TaskRequest, TaskComplexity, NoAIAvailableError

# Initialize (auto-detects all backends)
router = AIRouter()

# Send a request
try:
    result = router.generate(TaskRequest(
        task_type="vuln_analysis",
        prompt="Analyze this HTTP response for XSS vulnerabilities:\n\n" + response_text,
        context_length=5000,  # estimated tokens
        complexity=TaskComplexity.MEDIUM,
    ))
    print(result)
except NoAIAvailableError as e:
    print(f"No AI available: {e}")
    # Fall back to deterministic mode



Architecture
text

┌────────────────────────────────────────────────────┐
│                    CALLER MODULE                    │
│  (recon, scanner, payload_gen, report_gen, etc.)   │
└─────────────────────┬──────────────────────────────┘
                      │ TaskRequest
                      ▼
┌────────────────────────────────────────────────────┐
│                    AI ROUTER                        │
│                                                    │
│   ┌──────────────────────────────────────────┐     │
│   │         ROUTING DECISION TREE            │     │
│   │                                          │     │
│   │  context > 100k? ──→ Force Gemini        │     │
│   │  simple + local? ──→ Use Local           │     │
│   │  external avail? ──→ Priority Order      │     │
│   │  nothing avail?  ──→ NoAIAvailableError  │     │
│   └──────────────────────────────────────────┘     │
│                      │                             │
│         ┌────────────┼────────────┐                │
│         ▼            ▼            ▼                │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│   │  Ollama  │ │  Gemini  │ │ DeepSeek │  ...     │
│   │  Client  │ │  Client  │ │  Client  │         │
│   └──────────┘ └──────────┘ └──────────┘         │
│         │            │            │                │
│    Rate Limit   Rate Limit   Rate Limit           │
│    + Retry      + Retry      + Retry              │
└────────────────────────────────────────────────────┘
Configuration
Default config is in config.yaml. Override via config/modules.yaml
under key ai_routing.

Environment Variables Required
Variable	Provider	Required
GEMINI_API_KEY	Google Gemini	For Gemini usage
DEEPSEEK_API_KEY	DeepSeek	For DeepSeek usage
GROQ_API_KEY	Groq	For Groq usage
Priority Order
Default: gemini → deepseek → groq

Configurable in config.yaml:

YAML

external_apis:
  priority: ["gemini", "deepseek", "groq"]
Routing Rules
Condition	Action
Context > 100k tokens	Force Gemini (2M context)
Simple task + local available + context ≤ 8k	Use local Ollama
Context > 32k	External API only
Context > 8k	External preferred, local fallback
Context ≤ 8k	Local if available, else external
Fallback Behavior
If the primary provider fails (5xx, timeout, rate limit after retries):

Each client retries up to 3 times with exponential backoff
If all retries fail, router tries next provider in priority list
If all providers fail, raises NoAIAvailableError
Edge Cases Handled
Ollama not running → graceful degradation
API key missing → provider marked unavailable
Rate limit hit → token bucket + backoff + fallback
Malformed API response → retry then fallback
Context too large for all APIs → ContextTooLargeError
Network timeout → retry with backoff
User interrupts model selection → use default
All AI unavailable → explicit error for caller to handle
