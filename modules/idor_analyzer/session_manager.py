"""
session_manager.py — Authentication session management for IDOR testing.

Responsibilities:
    1. Accept auth tokens from task payload OR fetch from Redis key store.
    2. Build ready‑to‑use ``requests``‑compatible headers/cookies dicts.
    3. Validate that both sessions (User A & User B) are available before
       any endpoint testing begins.

Design decisions:
    • Tokens can be bearer tokens (``Authorization: Bearer …``) or raw
      cookies (``Cookie: session=…``).  The task payload's
      ``auth_tokens`` dict may include an optional ``type`` key
      (``"bearer"`` | ``"cookie"``; default ``"bearer"``).
    • If tokens are missing from the payload, we attempt to read them
      from Redis keys ``auth:token:<session_id>``.
    • All failures raise ``SessionError`` so the caller can map them
      to proper TaskResult error types.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Logger — graceful fallback
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("idor_analyzer.session_manager")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}',
    )
    logger = logging.getLogger("idor_analyzer.session_manager")


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------
class SessionError(Exception):
    """Raised when session/auth tokens are missing or invalid."""

    def __init__(self, message: str, error_type: str = "AUTH_MISSING"):
        super().__init__(message)
        self.error_type = error_type


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------
@dataclass
class SessionAuth:
    """Immutable auth material for a single session."""
    session_id: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    token_type: str = "bearer"  # "bearer" | "cookie"
    raw_token: str = ""


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
class SessionManager:
    """Manages two user sessions for IDOR comparison testing."""

    # Canonical session IDs
    USER_A = "userA"
    USER_B = "userB"

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        token_key_prefix: str = "auth:token:",
    ):
        self._redis = redis_client
        self._token_key_prefix = token_key_prefix
        self._sessions: Dict[str, SessionAuth] = {}
        logger.info(
            "SessionManager initialised",
            extra={"redis_available": redis_client is not None},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def load_sessions(
        self,
        auth_tokens: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Populate internal session store from task payload or Redis.

        ``auth_tokens`` layout (from task payload)::

            {
                "userA": "token_string_a",
                "userB": "token_string_b",
                "type": "bearer"          # optional; default bearer
            }

        Or richer form::

            {
                "userA": {"token": "...", "type": "cookie", "cookie_name": "session"},
                "userB": {"token": "...", "type": "bearer"}
            }
        """
        token_type_global = "bearer"
        if auth_tokens and isinstance(auth_tokens, dict):
            token_type_global = auth_tokens.get("type", "bearer")

        for sid in (self.USER_A, self.USER_B):
            token_raw: Optional[str] = None
            token_type = token_type_global
            cookie_name = "session"

            # --- Try task payload first ---
            if auth_tokens and sid in auth_tokens:
                entry = auth_tokens[sid]
                if isinstance(entry, dict):
                    token_raw = entry.get("token")
                    token_type = entry.get("type", token_type_global)
                    cookie_name = entry.get("cookie_name", "session")
                elif isinstance(entry, str):
                    token_raw = entry
                else:
                    logger.warning(
                        f"Unexpected token format for {sid}: {type(entry)}"
                    )

            # --- Fallback to Redis ---
            if not token_raw:
                token_raw = self._fetch_token_from_redis(sid)

            if not token_raw:
                raise SessionError(
                    f"Auth token missing for session '{sid}'. "
                    f"Provide in task payload or populate Redis key "
                    f"'{self._token_key_prefix}{sid}'.",
                    error_type="AUTH_MISSING",
                )

            # Build auth material
            session_auth = self._build_session_auth(
                sid, token_raw, token_type, cookie_name
            )
            self._sessions[sid] = session_auth
            logger.info(
                f"Session loaded for {sid}",
                extra={"token_type": token_type, "token_len": len(token_raw)},
            )

    def get_session_auth(self, session_id: str) -> SessionAuth:
        """
        Return ``SessionAuth`` for the given session ID.

        Raises ``SessionError`` if session was never loaded.
        """
        if session_id not in self._sessions:
            raise SessionError(
                f"Session '{session_id}' not loaded. Call load_sessions() first.",
                error_type="AUTH_MISSING",
            )
        return self._sessions[session_id]

    def get_both_sessions(self) -> Tuple[SessionAuth, SessionAuth]:
        """Convenience: returns (userA_auth, userB_auth)."""
        return (
            self.get_session_auth(self.USER_A),
            self.get_session_auth(self.USER_B),
        )

    def has_sessions(self) -> bool:
        return self.USER_A in self._sessions and self.USER_B in self._sessions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _fetch_token_from_redis(self, session_id: str) -> Optional[str]:
        """Try reading token from Redis key ``<prefix><session_id>``."""
        if self._redis is None:
            logger.debug("No Redis client — cannot fetch token from store.")
            return None
        key = f"{self._token_key_prefix}{session_id}"
        try:
            value = self._redis.get(key)
            if value:
                logger.info(f"Token fetched from Redis for {session_id}")
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                return value
        except Exception as exc:
            logger.warning(
                f"Redis read failed for key '{key}': {exc}"
            )
        return None

    @staticmethod
    def _build_session_auth(
        session_id: str,
        token: str,
        token_type: str,
        cookie_name: str = "session",
    ) -> SessionAuth:
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

        if token_type == "cookie":
            cookies[cookie_name] = token
        else:
            # Default: bearer
            headers["Authorization"] = f"Bearer {token}"

        return SessionAuth(
            session_id=session_id,
            headers=headers,
            cookies=cookies,
            token_type=token_type,
            raw_token=token,
        )
