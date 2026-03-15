"""
comparators.py — Deterministic response comparison engine.

Given two HTTP responses (from User A and User B against the *same*
endpoint), this module determines:
    1. Whether the responses are meaningfully different.
    2. Whether the difference pattern suggests an IDOR/BOLA vulnerability.

Design philosophy:
    • Purely deterministic — no ML, no LLM calls.
    • Configurable field/header ignore lists (regex‑based).
    • Deep JSON diffing with recursive key traversal.
    • Similarity ratio via ``difflib.SequenceMatcher`` for text bodies.
    • Explicit ``ComparisonResult`` dataclass for structured output.
"""

from __future__ import annotations

import re
import json
import hashlib
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# ---------------------------------------------------------------------------
# Logger — graceful fallback
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("idor_analyzer.comparators")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}',
    )
    logger = logging.getLogger("idor_analyzer.comparators")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class ResponseData:
    """
    Normalised HTTP response wrapper.

    The analyzer converts ``requests.Response`` objects into this
    container before handing them to the comparator — decoupling
    HTTP‑library internals from comparison logic.
    """
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_json: Optional[Any] = None
    content_type: str = ""
    body_hash: str = ""       # SHA‑256 of raw body bytes
    body_size: int = 0
    is_json: bool = False
    error: Optional[str] = None  # non‑None if request itself failed

    @classmethod
    def from_requests_response(cls, resp: Any, max_bytes: int = 5 * 1024 * 1024) -> "ResponseData":
        """Build from a ``requests.Response`` object."""
        content_type = resp.headers.get("Content-Type", "")
        raw_bytes = resp.content[:max_bytes] if resp.content else b""
        body_text = raw_bytes.decode("utf-8", errors="replace")
        body_hash = hashlib.sha256(raw_bytes).hexdigest()

        body_json = None
        is_json = False
        if "json" in content_type.lower() or "javascript" in content_type.lower():
            try:
                body_json = resp.json()
                is_json = True
            except (ValueError, TypeError):
                pass

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        return cls(
            status_code=resp.status_code,
            headers=headers_lower,
            body_text=body_text,
            body_json=body_json,
            content_type=content_type,
            body_hash=body_hash,
            body_size=len(raw_bytes),
            is_json=is_json,
        )

    @classmethod
    def from_error(cls, error_msg: str) -> "ResponseData":
        return cls(error=error_msg)


@dataclass
class ComparisonResult:
    """Structured output of response comparison."""
    is_different: bool = False
    suspicious: bool = False
    confidence: float = 0.0       # 0.0 – 1.0
    status_code_match: bool = True
    body_similarity: float = 1.0  # 1.0 = identical
    differences: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_different": self.is_different,
            "suspicious": self.suspicious,
            "confidence": round(self.confidence, 4),
            "status_code_match": self.status_code_match,
            "body_similarity": round(self.body_similarity, 4),
            "differences": self.differences,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Comparator
# ---------------------------------------------------------------------------
class ResponseComparator:
    """
    Stateless comparator engine.

    Instantiate once with config, then call ``compare_responses``
    for each endpoint pair.
    """

    def __init__(
        self,
        ignore_fields: Optional[List[str]] = None,
        ignore_headers: Optional[List[str]] = None,
        diff_threshold: float = 0.80,
        max_diff_keys: int = 200,
    ):
        self._ignore_field_patterns: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE)
            for p in (ignore_fields or [])
        ]
        self._ignore_header_patterns: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE)
            for p in (ignore_headers or [])
        ]
        self._diff_threshold = diff_threshold
        self._max_diff_keys = max_diff_keys
        logger.info(
            "ResponseComparator initialised",
            extra={
                "ignore_fields": len(self._ignore_field_patterns),
                "ignore_headers": len(self._ignore_header_patterns),
                "diff_threshold": diff_threshold,
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def compare_responses(
        self,
        resp_a: ResponseData,
        resp_b: ResponseData,
    ) -> ComparisonResult:
        """
        Compare two responses and return a ``ComparisonResult``.

        The IDOR suspicion heuristic:
            • Both requests succeed (2xx) → bodies are very similar
              (above threshold) → User B can see User A's data
              → **suspicious**.
            • User B gets 403/401 while User A gets 200 → proper
              authz → **not suspicious**.
            • Both get identical error → endpoint doesn't exist or
              both lack access → **not suspicious**.
        """
        result = ComparisonResult()

        # Handle error responses
        if resp_a.error or resp_b.error:
            result.notes.append(
                f"Request error(s): A={resp_a.error}, B={resp_b.error}"
            )
            result.is_different = True
            result.suspicious = False
            result.differences["request_errors"] = {
                "userA": resp_a.error,
                "userB": resp_b.error,
            }
            return result

        # 1. Status code comparison
        result.status_code_match = resp_a.status_code == resp_b.status_code
        if not result.status_code_match:
            result.is_different = True
            result.differences["status_code"] = {
                "userA": resp_a.status_code,
                "userB": resp_b.status_code,
            }

        # 2. Header comparison
        header_diffs = self._compare_headers(resp_a.headers, resp_b.headers)
        if header_diffs:
            result.is_different = True
            result.differences["headers"] = header_diffs

        # 3. Body comparison
        if resp_a.is_json and resp_b.is_json and resp_a.body_json is not None and resp_b.body_json is not None:
            body_diffs = self._compare_json(resp_a.body_json, resp_b.body_json)
            if body_diffs:
                result.is_different = True
                result.differences["body_json"] = body_diffs
            # Compute similarity via text fallback for a ratio
            result.body_similarity = self._text_similarity(
                json.dumps(self._strip_ignored_fields(resp_a.body_json), sort_keys=True, default=str),
                json.dumps(self._strip_ignored_fields(resp_b.body_json), sort_keys=True, default=str),
            )
        else:
            # Text comparison
            result.body_similarity = self._text_similarity(
                resp_a.body_text, resp_b.body_text
            )
            if resp_a.body_hash != resp_b.body_hash:
                result.is_different = True
                result.differences["body_text_hash"] = {
                    "userA": resp_a.body_hash[:16] + "…",
                    "userB": resp_b.body_hash[:16] + "…",
                }

        # 4. IDOR suspicion heuristics
        result.suspicious, result.confidence, suspicion_notes = (
            self._evaluate_suspicion(resp_a, resp_b, result)
        )
        result.notes.extend(suspicion_notes)

        return result

    # ------------------------------------------------------------------
    # Header comparison
    # ------------------------------------------------------------------
    def _compare_headers(
        self,
        headers_a: Dict[str, str],
        headers_b: Dict[str, str],
    ) -> Dict[str, Any]:
        diffs: Dict[str, Any] = {}
        all_keys = set(headers_a.keys()) | set(headers_b.keys())
        for key in all_keys:
            if self._is_ignored_header(key):
                continue
            val_a = headers_a.get(key)
            val_b = headers_b.get(key)
            if val_a != val_b:
                diffs[key] = {"userA": val_a, "userB": val_b}
                if len(diffs) >= self._max_diff_keys:
                    break
        return diffs

    # ------------------------------------------------------------------
    # JSON deep comparison
    # ------------------------------------------------------------------
    def _compare_json(
        self,
        json_a: Any,
        json_b: Any,
        path: str = "$",
        _depth: int = 0,
    ) -> Dict[str, Any]:
        """Recursive JSON diff, ignoring configured fields."""
        diffs: Dict[str, Any] = {}
        if _depth > 50:
            # Safety: prevent infinite recursion
            diffs[path] = {"note": "max_depth_exceeded"}
            return diffs

        if len(diffs) >= self._max_diff_keys:
            return diffs

        if isinstance(json_a, dict) and isinstance(json_b, dict):
            all_keys = set(json_a.keys()) | set(json_b.keys())
            for key in sorted(all_keys):
                if self._is_ignored_field(key):
                    continue
                child_path = f"{path}.{key}"
                if key not in json_a:
                    diffs[child_path] = {"change": "added_in_B", "value": self._safe_repr(json_b[key])}
                elif key not in json_b:
                    diffs[child_path] = {"change": "missing_in_B", "value": self._safe_repr(json_a[key])}
                else:
                    child_diffs = self._compare_json(
                        json_a[key], json_b[key], child_path, _depth + 1
                    )
                    diffs.update(child_diffs)
                if len(diffs) >= self._max_diff_keys:
                    break

        elif isinstance(json_a, list) and isinstance(json_b, list):
            max_len = max(len(json_a), len(json_b))
            for i in range(min(max_len, self._max_diff_keys)):
                child_path = f"{path}[{i}]"
                if i >= len(json_a):
                    diffs[child_path] = {"change": "added_in_B", "value": self._safe_repr(json_b[i])}
                elif i >= len(json_b):
                    diffs[child_path] = {"change": "missing_in_B", "value": self._safe_repr(json_a[i])}
                else:
                    child_diffs = self._compare_json(
                        json_a[i], json_b[i], child_path, _depth + 1
                    )
                    diffs.update(child_diffs)
                if len(diffs) >= self._max_diff_keys:
                    break
        else:
            if json_a != json_b:
                diffs[path] = {
                    "userA": self._safe_repr(json_a),
                    "userB": self._safe_repr(json_b),
                }

        return diffs

    # ------------------------------------------------------------------
    # Suspicion evaluation
    # ------------------------------------------------------------------
    def _evaluate_suspicion(
        self,
        resp_a: ResponseData,
        resp_b: ResponseData,
        result: ComparisonResult,
    ) -> Tuple[bool, float, List[str]]:
        """
        Determine if the comparison result suggests IDOR.

        Returns (suspicious, confidence, notes).
        """
        notes: List[str] = []
        suspicious = False
        confidence = 0.0

        a_success = 200 <= resp_a.status_code < 300
        b_success = 200 <= resp_b.status_code < 300
        a_forbidden = resp_a.status_code in (401, 403)
        b_forbidden = resp_b.status_code in (401, 403)

        # ── Scenario 1: Both succeed with similar bodies ──
        if a_success and b_success:
            if result.body_similarity >= self._diff_threshold:
                suspicious = True
                confidence = result.body_similarity
                notes.append(
                    f"Both responses returned 2xx with body similarity "
                    f"{result.body_similarity:.2%} (≥ threshold "
                    f"{self._diff_threshold:.2%}). Possible IDOR — "
                    f"User B can access User A's resource."
                )
            elif result.body_similarity >= 0.5:
                suspicious = True
                confidence = result.body_similarity * 0.7
                notes.append(
                    f"Both responses 2xx but moderate similarity "
                    f"{result.body_similarity:.2%}. Partial IDOR possible."
                )
            else:
                notes.append(
                    "Both responses 2xx but low similarity — "
                    "likely different resources (not IDOR)."
                )

        # ── Scenario 2: A succeeds, B gets 403/401 → proper authz ──
        elif a_success and b_forbidden:
            notes.append(
                "User A succeeded, User B was denied — authorization "
                "appears to be enforced correctly."
            )

        # ── Scenario 3: A forbidden, B succeeds → reverse IDOR ──
        elif a_forbidden and b_success:
            suspicious = True
            confidence = 0.85
            notes.append(
                "User A was denied but User B succeeded — possible "
                "reverse privilege escalation or mis‑configured ACL."
            )

        # ── Scenario 4: Both forbidden ──
        elif a_forbidden and b_forbidden:
            notes.append(
                "Both users denied access — endpoint properly restricted "
                "or resource doesn't exist."
            )

        # ── Scenario 5: Unexpected status codes ──
        else:
            notes.append(
                f"Unexpected status codes: A={resp_a.status_code}, "
                f"B={resp_b.status_code}. Manual review recommended."
            )
            if a_success or b_success:
                confidence = 0.3
                suspicious = True

        return suspicious, confidence, notes

    # ------------------------------------------------------------------
    # Field stripping for normalized comparison
    # ------------------------------------------------------------------
    def _strip_ignored_fields(self, obj: Any, _depth: int = 0) -> Any:
        """Recursively remove ignored fields from a JSON‑like object."""
        if _depth > 50:
            return obj
        if isinstance(obj, dict):
            return {
                k: self._strip_ignored_fields(v, _depth + 1)
                for k, v in obj.items()
                if not self._is_ignored_field(k)
            }
        if isinstance(obj, list):
            return [self._strip_ignored_fields(item, _depth + 1) for item in obj]
        return obj

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_ignored_field(self, field_name: str) -> bool:
        return any(p.fullmatch(field_name) for p in self._ignore_field_patterns)

    def _is_ignored_header(self, header_name: str) -> bool:
        return any(p.fullmatch(header_name) for p in self._ignore_header_patterns)

    @staticmethod
    def _text_similarity(text_a: str, text_b: str) -> float:
        """Return ratio in [0.0, 1.0] via SequenceMatcher."""
        if not text_a and not text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0
        # For very large texts, sample to keep CPU bounded
        max_len = 500_000
        return SequenceMatcher(
            None, text_a[:max_len], text_b[:max_len]
        ).ratio()

    @staticmethod
    def _safe_repr(value: Any, max_len: int = 200) -> Any:
        """Truncate large values for safe inclusion in diffs."""
        if isinstance(value, str) and len(value) > max_len:
            return value[:max_len] + "…[truncated]"
        if isinstance(value, (dict, list)):
            s = json.dumps(value, default=str)
            if len(s) > max_len:
                return s[:max_len] + "…[truncated]"
            return value
        return value


# ---------------------------------------------------------------------------
# Module‑level convenience (backward compat)
# ---------------------------------------------------------------------------
_default_comparator: Optional[ResponseComparator] = None


def compare_responses(
    resp_a: ResponseData,
    resp_b: ResponseData,
    ignore_fields: Optional[List[str]] = None,
    ignore_headers: Optional[List[str]] = None,
    diff_threshold: float = 0.80,
) -> ComparisonResult:
    """Functional convenience wrapper."""
    global _default_comparator
    if _default_comparator is None:
        _default_comparator = ResponseComparator(
            ignore_fields=ignore_fields or [],
            ignore_headers=ignore_headers or [],
            diff_threshold=diff_threshold,
        )
    return _default_comparator.compare_responses(resp_a, resp_b)
