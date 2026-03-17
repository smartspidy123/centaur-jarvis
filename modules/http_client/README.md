# Centaur-Jarvis Advanced HTTP Client Module

## Overview

This module provides a **shared HTTP client** for all Centaur-Jarvis VAPT modules,
designed to evade modern WAFs (Cloudflare, Akamai, etc.) through:

- **TLS Fingerprint Randomisation** (JA3/JA4 via `curl_cffi`)
- **HTTP/2 Multiplexing** (via `httpx`)
- **Proxy Rotation** (HTTP/HTTPS/SOCKS5 with health tracking)
- **Per-Domain Rate Limiting** (Redis-backed token bucket)
- **Circuit Breaker** (per-domain fail-fast)
- **Header Spoofing** (browser-realistic headers with randomised order)

## Quick Start

```python
from modules.http_client import HttpClient

# Basic usage
client = HttpClient()
resp = client.get("https://example.com")
print(resp.status_code, resp.text[:100])

# With context manager (recommended)
with HttpClient() as client:
    resp = client.get("https://example.com")

# With custom proxies
client = HttpClient(proxies=[
    "http://proxy1:8080",
    "socks5h://user:pass@proxy2:1080",
])
Architecture
text

                    ┌─────────────────────────────────────────────┐
                    │              HttpClient.request()           │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │          1. Circuit Breaker Check           │
                    │    ┌─ OPEN? → CircuitOpenError (fail-fast)  │
                    │    └─ CLOSED/HALF_OPEN → proceed            │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │          2. Rate Limiter (Token Bucket)     │
                    │    ┌─ No token? → Wait / RateLimitError    │
                    │    └─ Token acquired → proceed              │
                    │    (Redis Lua atomic | In-memory fallback)  │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │          3. Proxy Selection                 │
                    │    ProxyRotator.get_proxy()                 │
                    │    ┌─ ACTIVE proxy → use it                │
                    │    ├─ All DEAD → DIRECT (CRITICAL log)     │
                    │    └─ Resurrect expired cooldowns           │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │       4. TLS Fingerprint Selection          │
                    │    TLSFingerprinter.get_profile()           │
                    │    (e.g., "chrome110", "safari15_5")        │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │       5. UA + Header Forging                │
                    │    UserAgentRotator + HeaderForger           │
                    │    Browser-consistent Sec-Fetch-*, Accept   │
                    │    Randomised header order                   │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │       6. Dispatch (Backend Selection)       │
                    │    Priority:                                │
                    │      ① curl_cffi (TLS impersonation)       │
                    │      ② httpx (HTTP/2 multiplexing)          │
                    │      ③ requests (HTTP/1.1 fallback)         │
                    └────────────────────┬────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────┐
                    │       7. Response Handling                  │
                    │    ┌─ 2xx → success → record_success()     │
                    │    ├─ 429 → parse Retry-After → wait/retry │
                    │    ├─ 403 → rotate proxy+FP → retry        │
                    │    ├─ 5xx → record_failure() → retry       │
                    │    └─ Connection error → rotate → retry     │
                    │    Exponential backoff with jitter           │
                    └─────────────────────────────────────────────┘
Installation
Bash

pip install requests[socks] curl_cffi httpx[http2] redis pyyaml tenacity
Configuration
Edit config.yaml or pass a custom path:

Python

client = HttpClient(config_path="/path/to/config.yaml")
Testing
Bash

# Self-test
python -m modules.http_client.client --url https://httpbin.org/get

# Against Cloudflare
python -m modules.http_client.client --url https://www.cloudflare.com

# With proxies (set in config.yaml or pass programmatically)
Edge Cases Handled
#	Edge Case	Mitigation
1	Cloudflare JA3 detection	curl_cffi browser impersonation
2	Missing HTTP/2 fingerprint	httpx HTTP/2 backend
3	Invalid proxy response	Mark DEAD, rotate, log
4	All proxies dead	Direct connection + CRITICAL log
5	Redis down	In-memory rate limiter fallback
6	429 + Retry-After	Parse header, wait, backoff
7	Repeated timeouts	Circuit breaker → OPEN
8	curl_cffi missing	Fall back to requests
9	httpx missing	Fall back to HTTP/1.1
10	Many domains	Redis keys auto-expire (TTL)
11	Concurrent domain access	Atomic Redis Lua scripts
12	Proxy auth required	URL-encoded user:pass
13	DNS leaks via SOCKS5	Auto-rewrite socks5:// → socks5h://
text


---

## Deep Dive Post-Mortem (DNA)

### ASCII Diagram — Full Request Flow
USER CODE
│
▼
┌──────────────────────────────────────────────────────────────────────────┐
│ HttpClient.request() │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │ STEP 1: CIRCUIT BREAKER CHECK │ │
│ │ CircuitBreaker.allow_request(domain) │ │
│ │ CLOSED ──────► proceed │ │
│ │ OPEN ──────► (elapsed > recovery?) ──► HALF_OPEN (proceed)│ │
│ │ (else) ──► raise CircuitOpenError │ │
│ │ HALF_OPEN ────► proceed (limited probes) │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 2: RATE LIMITER │ │
│ │ RateLimiter.acquire(domain) │ │
│ │ ┌─ Redis? ─── Lua EVALSHA (atomic) ──┐ │ │
│ │ └─ Memory? ── _InMemoryBucket ────────┤ │ │
│ │ │ │ │
│ │ Tokens ≥ 1? → consume, proceed │ │ │
│ │ Tokens < 1? → return (False, wait_s) │ │ │
│ │ → sleep(wait) → retry loop│ │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 3: PROXY SELECTION │ │
│ │ ProxyRotator.get_proxy() │ │
│ │ Round-robin active proxies │ │
│ │ Resurrect expired-cooldown DEAD proxies │ │
│ │ All DEAD → None (direct) + CRITICAL log │ │
│ │ socks5:// auto-rewritten to socks5h:// │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 4: TLS FINGERPRINT │ │
│ │ TLSFingerprinter.get_profile_and_family() │ │
│ │ → ("chrome110", "chrome") │ │
│ │ Rotate per request or per session (configurable) │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 5: HEADER FORGING │ │
│ │ UserAgentRotator.get_for_browser("chrome") │ │
│ │ HeaderForger.forge(url, ua, "chrome") │ │
│ │ Sec-Ch-Ua, Sec-Fetch-*, Accept, Accept-Language... │ │
│ │ Header order randomised │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 6: DISPATCH │ │
│ │ Priority: curl_cffi → httpx → requests │ │
│ │ │ │
│ │ curl_cffi: TLS impersonation (JA3 match), HTTP/1.1 │ │
│ │ httpx: HTTP/2 multiplexing, standard TLS │ │
│ │ requests: HTTP/1.1, standard TLS (last resort) │ │
│ │ │ │
│ │ Each backend failure cascades to the next │ │
│ └───────────────────────────────┬──────────────────────────────────┘ │
│ │ │
│ ┌───────────────────────────────▼──────────────────────────────────┐ │
│ │ STEP 7: RESPONSE HANDLING │ │
│ │ Normalise → HttpResponse │ │
│ │ │ │
│ │ 200-399: SUCCESS │ │
│ │ → proxy.report_success(), circuit.record_success() │ │
│ │ → return HttpResponse │ │
│ │ │ │
│ │ 429: RATE LIMITED │ │
│ │ → parse Retry-After, drain tokens, proxy.report_failure() │ │
│ │ → sleep → retry │ │
│ │ │ │
│ │ 403: WAF BLOCK │ │
│ │ → proxy.report_failure() → rotate FP+proxy → retry │ │
│ │ │ │
│ │ 5xx: SERVER ERROR │ │
│ │ → circuit.record_failure(), proxy.report_failure() │ │
│ │ → exponential backoff → retry │ │
│ │ │ │
│ │ Connection/Timeout Error: │ │
│ │ → circuit.record_failure(), proxy.report_failure() │ │
│ │ → backoff → retry │ │
│ │ │ │
│ │ All retries exhausted → raise RequestFailedError │ │
│ └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘

text


### JA3 Impersonation Explained

**JA3** is a TLS client fingerprinting method that hashes the following fields from
the TLS ClientHello message:
- TLS version
- Cipher suites
- Extensions
- Elliptic curves
- Elliptic curve point formats

WAFs like Cloudflare compute the JA3 hash of incoming connections and compare it
against known browser fingerprints. Standard Python `requests`/`urllib3` produce a
distinctive JA3 that is trivially identifiable as "Python bot."

**curl_cffi** solves this by using a patched version of `curl` that can replicate
the exact TLS ClientHello of real browsers (Chrome, Safari, Edge). When we call
`curl_requests.get(url, impersonate="chrome110")`, the library:
1. Constructs a TLS ClientHello matching Chrome 110's cipher suite order, extensions, etc.
2. Sends the request using the same HTTP/2 SETTINGS frame as Chrome (if HTTP/2)
3. Produces a JA3 hash indistinguishable from a real Chrome 110 browser

**JA4** is the next-generation fingerprint (includes ALPN, SNI, signature algorithms).
curl_cffi's impersonation also handles JA4 because it replicates the full ClientHello.

### HTTP/2 Multiplexing

HTTP/2 multiplexing allows multiple requests to be sent concurrently over a single TCP
connection, interleaved as frames. Benefits for VAPT:
- **Fingerprint evasion**: Some WAFs flag HTTP/1.1-only clients as suspicious
- **Performance**: Reduced latency from eliminated TCP/TLS handshakes
- **Header compression** (HPACK): Smaller wire format

We use `httpx` with `http2=True` for this. Note: `curl_cffi` also supports HTTP/2
when impersonating browsers that default to it, but its Python API currently doesn't
expose explicit HTTP/2 control, so we use httpx as a complementary backend.

### Edge Cases Mitigated

| # | Edge Case | Mitigation | Component |
|---|-----------|------------|-----------|
| 1 | Cloudflare JA3 fingerprint block | curl_cffi impersonation with 10+ browser profiles | TLSFingerprinter |
| 2 | WAF detects missing HTTP/2 | httpx HTTP/2 backend | HttpClient._send_httpx |
| 3 | Proxy returns garbage (non-HTTP) | Exception caught → mark DEAD → rotate | ProxyRotator |
| 4 | All proxies dead | Fallback to DIRECT + CRITICAL log | ProxyRotator.get_proxy |
| 5 | Redis connection lost | In-memory token bucket fallback | RateLimiter |
| 6 | 429 with Retry-After header | Parse header → drain tokens → wait | HttpClient.request |
| 7 | Target times out repeatedly | Circuit breaker OPEN → fail-fast | CircuitBreaker |
| 8 | curl_cffi not installed | Graceful fallback to httpx/requests | HttpClient._dispatch |
| 9 | httpx not installed | Graceful fallback to requests | HttpClient._dispatch |
| 10 | Many domains (memory) | Redis keys auto-expire (TTL); in-memory GC via dict | RateLimiter |
| 11 | Concurrent same-domain requests | Redis Lua script atomicity; threading locks | RateLimiter |
| 12 | Proxy auth required | Parsed from URL (user:pass@host) | ProxyRotator |
| 13 | DNS leaks over SOCKS5 | Auto-rewrite socks5:// → socks5h:// | ProxyRotator.__init__ |
| 14 | Signal in non-main thread | try/except ValueError on signal registration | HttpClient |
| 15 | Header order fingerprinting | random.shuffle on header dict | HeaderForger |
| 16 | Browser UA / header mismatch | Correlated UA ↔ Sec-Ch-Ua via browser_family | HeaderForger + UserAgentRotator |

### Remaining Loopholes & Future Improvements

1. **curl_cffi HTTP/2 frames**: While curl_cffi replicates TLS fingerprints, the HTTP/2
   SETTINGS/WINDOW_UPDATE frames may differ from real browsers. Future work: validate
   HTTP/2 frame fingerprints (Akamai's passive fingerprinting).

2. **Canvas/JS fingerprinting**: This module handles network-level evasion only.
   For sites with JavaScript challenges (Cloudflare Turnstile, PerimeterX), a headless
   browser integration (Playwright) would be needed.

3. **Custom JA3 generation**: Instead of relying on curl_cffi profiles, we could
   construct arbitrary JA3 fingerprints via custom `ssl.SSLContext` configuration.
   This would allow generating novel fingerprints not tied to known browsers.

4. **HTTP/3 (QUIC)**: Some CDNs now use HTTP/3. Neither curl_cffi nor httpx currently
   support QUIC in Python. Future integration with `aioquic` could address this.

5. **Proxy sourcing**: Currently proxies come from static config. Future improvement:
   fetch from proxy APIs (ProxyScrape, BrightData) or Redis queues populated by
   a separate proxy harvester module.

6. **Adaptive rate limiting**: Currently uses fixed token bucket rates. Could implement
   adaptive rates based on observed 429 frequency using a PID controller.

7. **Connection fingerprinting beyond TLS**: TCP window size, MSS, and other OS-level
   fingerprints (p0f) could be detected. Mitigation requires OS-level tuning.

8. **In-memory bucket cleanup**: Currently the `_mem_buckets` dict grows unbounded for
   many domains. Should implement LRU eviction.

### Performance Considerations

| Aspect | Impact | Mitigation |
|--------|--------|------------|
| TLS handshake (curl_cffi) | ~50-100ms overhead per new connection | Connection reuse via session |
| Proxy latency | +20-500ms per hop | Round-robin selection of fastest proxies |
| Rate limiter Redis RTT | ~1ms per acquire (Lua script) | In-memory fallback adds 0ms |
| Circuit breaker check | ~0.001ms (in-memory dict lookup) | Negligible |
| Header randomisation | ~0.01ms (shuffle + dict build) | Negligible |
| Exponential backoff | Sleeps on retry (by design) | Jitter prevents thundering herd |

### Integration Notes

Other Centaur-Jarvis modules should use HttpClient as follows:

```python
# In any module (e.g., modules/scanner/engine.py)
from modules.http_client import HttpClient

# Shared instance (recommended: create once, reuse)
client = HttpClient()

# Simple GET
resp = client.get("https://target.com/api/v1/users")
if resp.ok:
    data = resp.json()

# POST with JSON body
resp = client.post("https://target.com/login", json={"user": "admin", "pass": "test"})

# Force specific TLS impersonation
resp = client.get("https://target.com", impersonate="safari15_5")

# Without proxy (e.g., for internal targets)
resp = client.get("http://internal-api:8080/health", use_proxy=False)

# Access response metadata
print(resp.proxy_used)    # "http://proxy1:8080" or None
print(resp.tls_profile)   # "chrome110"
print(resp.http_version)  # "HTTP/2"
print(resp.elapsed_ms)    # 234.5
print(resp.data)          # Mandatory dict with status_code, url, etc.

# Diagnostics
print(client.diagnostics)

# Cleanup
client.close()
Key integration rules:

Create one HttpClient instance per worker/thread (it's thread-safe internally).
Use with HttpClient() as client: for automatic cleanup.
Handle CircuitOpenError if you need to know when targets are down.
Handle RateLimitExceededError if rate limits are critical to your flow.
Handle RequestFailedError for exhausted retries.
All response objects include the mandatory data dict field.
The client respects SIGTERM for graceful shutdown.
