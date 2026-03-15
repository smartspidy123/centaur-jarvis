# Smart Fuzzer Module — Centaur-Jarvis

## Overview

The Smart Fuzzer is Centaur-Jarvis's intelligent payload delivery engine. It uses AI
(via the AI Router) to generate contextual, mutation-based payloads for various
vulnerability classes (SQLi, XSS, SSTI, Command Injection, etc.), executes them with
strict rate limiting, and **adapts** based on server responses.

## Architecture Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     SMART FUZZER MODULE                          │
│                                                                 │
│  Redis Queue                                                    │
│  ┌──────────────────┐                                           │
│  │queue:smart_fuzzer │──BLPOP──►┌──────────────┐                │
│  └──────────────────┘           │  TASK INGEST  │                │
│                                 │  (validate)   │                │
│                                 └──────┬───────┘                │
│                                        │                        │
│                                        ▼                        │
│                        ┌───────────────────────────┐            │
│                        │  FOR EACH PARAM × VULN    │            │
│                        └───────────┬───────────────┘            │
│                                    │                            │
│                                    ▼                            │
│                        ┌───────────────────────┐                │
│                        │   PAYLOAD GENERATOR   │                │
│                        │   (AI Router call)    │                │
│                        │                       │                │
│                        │  ┌─────────────────┐  │                │
│                        │  │ AI Available?   │  │                │
│                        │  │ YES → AI Gen    │  │                │
│                        │  │ NO  → Fallback  │  │                │
│                        │  └─────────────────┘  │                │
│                        └───────────┬───────────┘                │
│                                    │ payloads[]                 │
│                                    ▼                            │
│              ┌────────────────────────────────────┐             │
│              │       FOR EACH PAYLOAD             │             │
│              │                                    │             │
│              │  ┌──────────────────────────────┐  │             │
│              │  │      EXECUTOR (HTTP)         │  │             │
│              │  │  ┌────────────────────────┐  │  │             │
│              │  │  │ Rate Limit (Token      │  │  │             │
│              │  │  │ Bucket per host)       │  │  │             │
│              │  │  └────────────────────────┘  │  │             │
│              │  │  ┌────────────────────────┐  │  │             │
│              │  │  │ HttpClient.request()   │  │  │             │
│              │  │  │ (proxy rotation)       │  │  │             │
│              │  │  └────────────────────────┘  │  │             │
│              │  └──────────┬───────────────────┘  │             │
│              │             │ FuzzResponse          │             │
│              │             ▼                       │             │
│              │  ┌──────────────────────────────┐  │             │
│              │  │      RESPONSE ANALYZER       │  │             │
│              │  │                              │  │             │
│              │  │  Timeout? ──────► SKIP       │  │             │
│              │  │  ConnErr? ──────► SKIP       │  │             │
│              │  │  WAF(403/429)? ──► MUTATE ◄──┤  │             │
│              │  │  Suspicious? ───► FINDING    │  │             │
│              │  │  Clean? ────────► NEXT       │  │             │
│              │  └──────────────────────────────┘  │             │
│              │                                    │             │
│              │  ┌──────────────────────────────┐  │             │
│              │  │  MUTATION LOOP (if WAF)      │  │             │
│              │  │                              │  │             │
│              │  │  iter < max_iterations?      │  │             │
│              │  │  YES → AI mutate → EXECUTE   │  │             │
│              │  │  NO  → GIVE UP on payload    │  │             │
│              │  └──────────────────────────────┘  │             │
│              └────────────────────────────────────┘             │
│                                    │                            │
│                                    ▼                            │
│                        ┌───────────────────────┐                │
│                        │  AI VERIFICATION      │                │
│                        │  (if enabled)          │                │
│                        │                       │                │
│                        │  For each finding:    │                │
│                        │  Ask AI: "Is this     │                │
│                        │  truly vulnerable?"   │                │
│                        │  Max 1 attempt each   │                │
│                        │                       │                │
│                        │  YES → verified=True  │                │
│                        │  NO  → confidence↓    │                │
│                        └───────────┬───────────┘                │
│                                    │                            │
│                                    ▼                            │
│                        ┌───────────────────────┐                │
│                        │  PUSH RESULT          │                │
│                        │  → results:incoming   │                │
│                        └───────────────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

modules/smart_fuzzer/
├── __init__.py
├── fuzzer.py
├── payload_generator.py
├── executor.py
├── config.yaml
└── README.md

## AI Interaction & Mutation Logic

### Initial Generation
1. For each parameter + vuln type, the generator sends a structured prompt to the
   AI Router with `TaskComplexity.MEDIUM`.
2. The prompt includes: target URL, HTTP method, parameter name/type, vuln type.
3. AI returns a JSON array of 3-5 diverse payloads.
4. If AI is unavailable (import error, network error, `NoAIAvailableError`), we
   fall back to static payload lists from `config.yaml`.
5. Invalid AI responses trigger up to 2 retries before falling back to static.

### Mutation on WAF Block
1. When a payload receives a 403/429 (detected as WAF block), the fuzzer asks
   the AI to mutate the blocked payload.
2. The mutation prompt includes: the original payload, a 2000-char snippet of
   the server response, and the vulnerability type.
3. AI uses a **higher temperature** (0.9) for creative bypass generation.
4. Mutations loop up to `max_iterations` times per payload.
5. If mutation fails (AI unavailable or returns None), the payload is abandoned.

### Verification
1. After all payloads are tested, potential findings are optionally verified.
2. Each finding gets exactly **ONE** AI verification call (prevents infinite loops).
3. The AI analyzes the payload + response snippet and returns a structured
   verdict: `{is_vulnerable, confidence, evidence}`.
4. Confirmed findings get `verified=True` and boosted confidence.
5. Rejected findings get dramatically reduced confidence (×0.3).

## Edge Cases Mitigated

| # | Edge Case | Mitigation |
|---|-----------|------------|
| 1 | AI Router unavailable | Fallback to static payloads; WARNING logged |
| 2 | Rate limit 429 from target | Respect Retry-After; exponential backoff; proxy rotation via HttpClient |
| 3 | WAF block (403) | Mutation loop with AI; max_iterations cap |
| 4 | Invalid AI response format | 2 retries; then static fallback |
| 5 | Executor timeout/conn error | Log + skip payload; continue with next |
| 6 | Missing param type hints | Default to "string"; AI generates generic payloads |
| 7 | Large number of parameters | Sequential processing; parallel support planned |
| 8 | Duplicate payloads | Deduplication set in PayloadGenerator |
| 9 | Malformed server response | Truncate to 2000 chars for AI; safe text extraction |
| 10 | Verification loop | Hard cap: 1 verification attempt per finding |
| 11 | Redis connection lost | In-memory buffer (max 50); reconnect with retry |
| 12 | Out-of-scope redirects | Configurable scope checking in executor |
| 13 | Blind/second-order vulns | Not handled v1; OAST integration planned |
| 14 | JSON body injection | Automatic JSON/form detection; AI generates valid JSON |

## Running

### As a standalone process:
```bash
REDIS_URL=redis://localhost:6379/0 python -m modules.smart_fuzzer.fuzzer
```

### Programmatically:
```python
from modules.smart_fuzzer import SmartFuzzer
fuzzer = SmartFuzzer(redis_url="redis://localhost:6379/0")
fuzzer.run()  # Blocking
```

### Single task (for testing):
```python
from modules.smart_fuzzer import SmartFuzzer
fuzzer = SmartFuzzer()
result = fuzzer.process_single_task({
    "task_id": "test-001",
    "target": "http://localhost:42000/rest/products/search",
    "method": "GET",
    "params": {"q": "test"},
    "vuln_types": ["xss", "sqli"],
})
print(result)
```

## Testing with redis-cli

```bash
redis-cli RPUSH queue:smart_fuzzer '{"task_id":"fuzz-001","type":"FUZZ","target":"http://localhost:42000/rest/products/search","method":"GET","params":{"q":"test"},"param_type_hints":{"q":"string"},"vuln_types":["xss","sqli"],"max_iterations":2}'

# Check results:
redis-cli BLPOP results:incoming 30

# Check status:
redis-cli GET task:status:fuzz-001
```

## Configuration

See `config.yaml` for all tunable parameters. Key settings:

- `max_iterations`: Max AI mutation cycles (default: 3)
- `verify_with_ai`: Enable/disable AI verification (default: true)
- `rate_limit.default_rate`: Requests/second per target (default: 5)
- `executor.timeout`: HTTP timeout in seconds (default: 10)

## Future Improvements

1. **OAST Integration**: Blind/second-order detection via out-of-band callbacks
2. **Parameter Prioritization**: AI-based ranking of which params to fuzz first
3. **Parallel Fuzzing**: Async/threaded parameter testing with shared rate limiter
4. **Confidence Scoring**: Use AI confidence thresholds to auto-filter findings
5. **Payload Caching**: Cache successful payloads per vuln type for reuse
6. **Smarter WAF Fingerprinting**: Identify WAF type and select targeted bypasses
7. **DOM XSS Detection**: Browser-based payload execution verification
8. **Time-based Detection**: Measure response time deltas for blind SQLi/CMDi
