#!/usr/bin/env python3
"""
intercept.py – Playwright‑based SPA renderer & network interceptor.

Designed to be invoked as a **subprocess** by renderer.py.
Outputs structured JSON lines to stdout.
Outputs log/error messages to stderr.

Usage:
    python intercept.py --target <URL> [OPTIONS]

Exit codes:
    0 – success
    1 – navigation / timeout error
    2 – browser launch failure
    3 – unexpected error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
import traceback
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _emit(record: Dict[str, Any]) -> None:
    """Write a single JSON line to stdout (the communication channel)."""
    try:
        sys.stdout.write(json.dumps(record, default=str) + "\n")
        sys.stdout.flush()
    except Exception:
        pass  # stdout broken – nothing we can do


def _log_stderr(level: str, msg: str, **kwargs: Any) -> None:
    """Structured log line to stderr (for the parent worker to capture)."""
    payload = {"level": level, "msg": msg, "ts": time.time()}
    payload.update(kwargs)
    try:
        sys.stderr.write(json.dumps(payload, default=str) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _detect_tokens(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Scan headers for authentication tokens."""
    tokens: List[Dict[str, str]] = []
    for name, value in headers.items():
        lower_name = name.lower()
        # Bearer / JWT in Authorization header
        if lower_name == "authorization":
            if value.lower().startswith("bearer "):
                token_val = value[7:].strip()
                token_type = "jwt" if JWT_RE.match(token_val) else "bearer"
                tokens.append({
                    "type": token_type,
                    "value": token_val,
                    "source": "Authorization header",
                })
            else:
                tokens.append({
                    "type": "authorization",
                    "value": value,
                    "source": "Authorization header",
                })
        # Cookies
        elif lower_name == "cookie":
            tokens.append({
                "type": "cookie",
                "value": value,
                "source": "Cookie header",
            })
        # Custom token headers
        elif "token" in lower_name or "x-api-key" == lower_name:
            tokens.append({
                "type": "custom_token",
                "value": value,
                "source": f"{name} header",
            })
    return tokens


def _parse_params(url: str) -> Dict[str, Any]:
    """Extract query string parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten single‑value lists
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def _is_text_content(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    text_indicators = [
        "text/", "application/json", "application/xml",
        "application/javascript", "application/x-www-form-urlencoded",
        "application/graphql",
    ]
    ct_lower = content_type.lower()
    return any(ind in ct_lower for ind in text_indicators)


# ---------------------------------------------------------------------------
# Main async logic
# ---------------------------------------------------------------------------

async def run(args: argparse.Namespace) -> int:  # noqa: C901
    """Core interception routine. Returns exit code."""

    # Lazy import so the module can be parsed even without playwright
    try:
        from playwright.async_api import async_playwright, Error as PWError
    except ImportError:
        _log_stderr("CRITICAL", "playwright is not installed")
        return 2

    request_counter = 0
    max_requests: int = args.max_requests
    max_body: int = args.max_response_body
    redirect_counter = 0
    max_redirects: int = args.max_redirects

    captured_endpoints: List[Dict[str, Any]] = []
    captured_tokens: List[Dict[str, str]] = []

    # ------------------------------------------------------------------
    # Request / Response handlers
    # ------------------------------------------------------------------

    async def on_request(request) -> None:  # noqa: ANN001
        nonlocal request_counter
        if request_counter >= max_requests:
            return

        rtype = request.resource_type
        if rtype not in ("xhr", "fetch"):
            if args.intercept_all:
                pass  # capture everything if flag set
            else:
                return

        request_counter += 1

        headers = dict(request.headers) if request.headers else {}
        body: Optional[str] = None
        try:
            body = request.post_data
        except Exception:
            pass

        tokens = _detect_tokens(headers)
        if tokens:
            captured_tokens.extend(tokens)

        endpoint_record = {
            "type": "endpoint",
            "url": request.url,
            "method": request.method,
            "params": _parse_params(request.url),
            "headers": headers,
            "request_body": body,
            "resource_type": rtype,
        }
        captured_endpoints.append(endpoint_record)
        _emit(endpoint_record)

    async def on_response(response) -> None:  # noqa: ANN001
        nonlocal redirect_counter
        # Track redirects
        if 300 <= response.status < 400:
            redirect_counter += 1
            if redirect_counter > max_redirects:
                _log_stderr("WARN", "Max redirects exceeded", count=redirect_counter)
                return

        # Match to a captured endpoint and enrich it
        url = response.url
        matching = [ep for ep in captured_endpoints if ep["url"] == url]
        if not matching:
            return

        ep = matching[-1]  # most recent match
        ep["response_status"] = response.status

        resp_headers = dict(response.headers) if response.headers else {}
        ep["response_headers"] = resp_headers

        content_type = resp_headers.get("content-type", "")
        if _is_text_content(content_type):
            try:
                raw_body = await response.body()
                ep["response_body"] = raw_body[:max_body].decode("utf-8", errors="replace")
            except Exception:
                ep["response_body"] = None
        else:
            ep["response_body"] = f"[binary: {content_type}]"

        # Detect tokens in response headers too
        resp_tokens = _detect_tokens(resp_headers)
        if resp_tokens:
            captured_tokens.extend(resp_tokens)

        # Re‑emit enriched record
        ep["type"] = "endpoint_enriched"
        _emit(ep)

    # ------------------------------------------------------------------
    # Browser automation
    # ------------------------------------------------------------------

    pw = None
    browser = None
    exit_code = 0

    try:
        pw = await async_playwright().start()

        launch_args = json.loads(args.launch_args) if args.launch_args else []
        browser = await pw.chromium.launch(
            headless=args.headless,
            args=launch_args,
        )

        context_params: Dict[str, Any] = {
            "viewport": {"width": args.viewport_width, "height": args.viewport_height},
            "user_agent": args.user_agent,
            "ignore_https_errors": True,
        }

        # Inject cookies if provided
        if args.cookies:
            try:
                cookie_list = json.loads(args.cookies)
                if isinstance(cookie_list, list):
                    context_params["storage_state"] = {"cookies": cookie_list, "origins": []}
            except (json.JSONDecodeError, TypeError):
                _log_stderr("WARN", "Invalid cookies JSON, ignoring")

        context = await browser.new_context(**context_params)

        # Inject extra headers if provided
        if args.extra_headers:
            try:
                extra_h = json.loads(args.extra_headers)
                if isinstance(extra_h, dict):
                    await context.set_extra_http_headers(extra_h)
            except (json.JSONDecodeError, TypeError):
                _log_stderr("WARN", "Invalid extra_headers JSON, ignoring")

        page = await context.new_page()

        # Register interceptors
        page.on("request", on_request)
        page.on("response", on_response)

        # Navigate
        _log_stderr("INFO", "Navigating", url=args.target, timeout_ms=args.timeout)
        try:
            await page.goto(
                args.target,
                wait_until="networkidle",
                timeout=args.timeout,
            )
        except Exception as nav_err:
            err_str = str(nav_err).lower()
            if "timeout" in err_str or "navigation" in err_str:
                _log_stderr("ERROR", "Navigation timeout/error", error=str(nav_err))
                _emit({"type": "error", "error_type": "TIMEOUT", "detail": str(nav_err)})
                exit_code = 1
            else:
                _log_stderr("ERROR", "Navigation failed", error=str(nav_err))
                _emit({"type": "error", "error_type": "NAVIGATION_ERROR", "detail": str(nav_err)})
                exit_code = 1

        # Even on partial failure we continue to capture whatever loaded

        # Wait for optional selector
        if args.wait_for_selector and exit_code == 0:
            try:
                await page.wait_for_selector(
                    args.wait_for_selector,
                    timeout=min(args.timeout, 15000),
                )
            except Exception as sel_err:
                _log_stderr("WARN", "wait_for_selector failed", selector=args.wait_for_selector, error=str(sel_err))

        # Click elements to trigger dynamic content
        if args.click_elements and exit_code == 0:
            try:
                click_selectors = json.loads(args.click_elements)
            except (json.JSONDecodeError, TypeError):
                click_selectors = []

            await _click_recurse(page, click_selectors, depth=0, max_depth=args.depth)

        # Extract forms from the DOM
        if args.extract_forms:
            forms = await _extract_forms(page)
            for form in forms:
                _emit(form)

        # Small settling delay for any trailing network calls
        await asyncio.sleep(1.5)

        # Emit aggregated tokens (deduplicated)
        seen_tokens = set()
        for tok in captured_tokens:
            key = (tok["type"], tok["value"])
            if key not in seen_tokens:
                seen_tokens.add(key)
                _emit({"type": "token", **tok})

        await context.close()

    except Exception as outer_err:
        _log_stderr("CRITICAL", "Unhandled error in intercept", error=str(outer_err), tb=traceback.format_exc())
        _emit({"type": "error", "error_type": "UNEXPECTED", "detail": str(outer_err)})
        exit_code = 3

    finally:
        try:
            if browser:
                await browser.close()
        except Exception:
            pass
        try:
            if pw:
                await pw.stop()
        except Exception:
            pass

    return exit_code


async def _click_recurse(
    page,  # noqa: ANN001
    selectors: List[str],
    depth: int,
    max_depth: int,
) -> None:
    """Click the specified selectors, recursing up to max_depth."""
    if depth > max_depth:
        return
    for sel in selectors:
        try:
            elements = await page.query_selector_all(sel)
            for i, el in enumerate(elements[:20]):  # cap clicks per selector
                try:
                    await el.click(timeout=3000)
                    await page.wait_for_timeout(800)
                except Exception:
                    pass  # element may have disappeared
        except Exception as click_err:
            _log_stderr("WARN", "click_elements error", selector=sel, depth=depth, error=str(click_err))

    # Recurse if deeper exploration requested
    if depth < max_depth:
        await _click_recurse(page, selectors, depth + 1, max_depth)


async def _extract_forms(page) -> List[Dict[str, Any]]:  # noqa: ANN001
    """Extract <form> structures from the DOM."""
    try:
        forms_raw = await page.evaluate("""() => {
            const forms = document.querySelectorAll('form');
            return Array.from(forms).map(f => {
                const inputs = Array.from(f.querySelectorAll('input, select, textarea'));
                return {
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    id: f.id || null,
                    name: f.name || null,
                    inputs: inputs.map(inp => ({
                        name: inp.name || inp.id || '',
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required || false,
                    })).filter(inp => inp.name),
                };
            });
        }""")

        result = []
        for f in (forms_raw or []):
            record = {
                "type": "form",
                "action": f.get("action", ""),
                "method": f.get("method", "GET"),
                "id": f.get("id"),
                "name": f.get("name"),
                "inputs": [inp.get("name", "") for inp in f.get("inputs", [])],
                "inputs_detailed": f.get("inputs", []),
            }
            result.append(record)
        return result

    except Exception as form_err:
        _log_stderr("WARN", "Form extraction failed", error=str(form_err))
        return []


# ---------------------------------------------------------------------------
# CLI entry‑point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Playwright SPA interceptor")
    p.add_argument("--target", required=True, help="URL to navigate to")
    p.add_argument("--headless", type=lambda x: x.lower() in ("true", "1", "yes"), default=True)
    p.add_argument("--timeout", type=int, default=30000, help="Navigation timeout (ms)")
    p.add_argument("--viewport-width", type=int, default=1280)
    p.add_argument("--viewport-height", type=int, default=800)
    p.add_argument("--user-agent", type=str, default="Mozilla/5.0")
    p.add_argument("--launch-args", type=str, default="[]", help="JSON list of browser args")
    p.add_argument("--wait-for-selector", type=str, default=None)
    p.add_argument("--click-elements", type=str, default=None, help="JSON list of CSS selectors")
    p.add_argument("--extract-forms", type=lambda x: x.lower() in ("true", "1", "yes"), default=True)
    p.add_argument("--intercept-all", type=lambda x: x.lower() in ("true", "1", "yes"), default=False)
    p.add_argument("--max-requests", type=int, default=500)
    p.add_argument("--max-response-body", type=int, default=10240)
    p.add_argument("--max-redirects", type=int, default=10)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--cookies", type=str, default=None, help="JSON list of cookie objects")
    p.add_argument("--extra-headers", type=str, default=None, help="JSON dict of extra headers")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = asyncio.run(run(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
