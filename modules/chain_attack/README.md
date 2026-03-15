# Chain Attack Module — Centaur-Jarvis

## Overview

The Chain Attack module enables **multi-step exploitation** by maintaining a
**knowledge graph** of discovered assets, using an **AI planner** to suggest
attack chains, and an **executor** to carry them out autonomously.

## Architecture

text

                ┌─────────────────────┐
                │  results:incoming    │  ← Other modules push findings
                │  (Redis Queue)       │
                └────────┬────────────┘
                         │
                         ▼
                ┌─────────────────────┐
                │  Knowledge Graph     │  ← Ingests findings, builds graph
                │  (knowledge_graph.py)│
                └────────┬────────────┘
                         │ Graph state
                         ▼
                ┌─────────────────────┐
                │    AI Planner        │  ← Proposes attack chains
                │  (ai_planner.py)     │     (AI Router or static templates)
                └────────┬────────────┘
                         │ Attack Plan
                         ▼
           ┌──────────────────────────────┐
           │  Human Approval (optional)    │
           └──────────────┬───────────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │     Executor         │  ← Dispatches steps to queues
                │   (executor.py)      │
                └────────┬────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │queue:recon│  │queue:fuzz│  │queue:nuke│  ← Existing module queues
    └──────────┘  └──────────┘  └──────────┘

text


## Quick Start

### 1. Start the Graph Listener
```bash
python -m modules.chain_attack.knowledge_graph

2. Generate a Plan

Bash

CHAIN_ATTACK_GOAL="Gain admin access" python -m modules.chain_attack.ai_planner

3. Start the Executor

Bash

python -m modules.chain_attack.executor

Configuration

Edit config.yaml to adjust:

    Redis connection settings (prefix, queues)
    Graph storage mode (redis/memory)
    AI planner settings (enabled, temperature, retries)
    Executor settings (auto-approve, step timeout, max steps)

Components
Component	File	Purpose
Models	models.py	Data structures (Node, Edge, Plan)
Knowledge Graph	knowledge_graph.py	Graph storage & query engine
AI Planner	ai_planner.py	Attack chain proposal via AI
Executor	executor.py	Step dispatch & result tracking
Config	config.yaml	Module configuration
Edge Cases Handled
#	Edge Case	Mitigation
1	Graph data too large	TTL-based expiry, pagination in queries
2	AI returns invalid JSON	Retry + fallback to static templates
3	Step fails (wrong creds, etc.)	Mark FAILED, retry, or replan
4	Circular plan dependencies	Cycle detection, dependency removal
5	Concurrent plans	Plan IDs + Redis-based locking
6	Human approval timeout	Plan stays pending until approved
7	Redis connection lost	In-memory fallback with periodic retry
8	AI unavailable	Static attack template fallback
9	Step needs human interaction	HUMAN_INTERVENTION_REQUIRED status
10	HTTP client unavailable	Graceful failure for direct actions
