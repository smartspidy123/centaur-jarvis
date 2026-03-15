"""
harvester.py — Core Token Harvester Logic
==========================================

Contains:
  - TokenHarvester: mitmproxy addon class with request()/response() hooks.
  - RedisTokenStore: Redis-backed persistent token store with in-memory buffer.
  - Token extraction functions for JWTs, cookies, Authorization headers, CSRF.
  - Helper functions for downstream module consumption.
"""

import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import yaml

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

# ---------------------------------------------------------------------------
# Attempt to use shared logger; fall back to stdlib logging
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("token_harvester")
except (ImportError, ModuleNotFoundError):
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    logger = logging.getLogger("token_harvester")

# ---------------------------------------------------------------------------
# Attempt to import shared schemas; define fallback dataclass
# ---------------------------------------------------------------------------
try:
    from shared.schemas import TokenRecord  # type: ignore
except (ImportError, ModuleNotFoundError):
    TokenRecord = None  # We define our own below

# =========================================================================
#  CONSTANTS & DEFAULTS
# =========================================================================

DEFAULT_REDIS_HOST = "127.0.0.1"
DEFAULT_REDIS_PORT = 6379
DEFAULT_REDIS_DB = 0
DEFAULT_REDIS_PASSWORD = None
DEFAULT_MEMORY_BUFFER_MAX = 5000
DEFAULT_CLEANUP_INTERVAL_SECS = 300  # 5 min
DEFAULT_TOKEN_TTL_SECS = 86400 * 7   # 7 days fallback

REDIS_KEY_PREFIX = "token"
REDIS_DOMAINS_SET = "tokens:domains"
REDIS_DOMAIN_INDEX_PREFIX = "tokens:domain"
REDIS_STATS_KEY = "tokens:stats"

# JSON keys commonly containing tokens in response bodies
DEFAULT_TOKEN_JSON_KEYS = [
    "access_token",
    "accessToken",
    "token",
    "id_token",
    "idToken",
    "refresh_token",
    "refreshToken",
    "auth_token",
    "authToken",
    "jwt",
    "session_token",
    "sessionToken",
    "api_key",
    "apiKey",
    "api_token",
    "apiToken",
    "x-auth-token",
    "bearer",
]

# Headers that may contain CSRF tokens
CSRF_HEADER_NAMES = [
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrftoken",
    "csrf-token",
    "xsrf-token",
    "__requestverificationtoken",
    "x-anti-forgery-token",
]

# Regex for finding tokens in non-JSON response bodies
DEFAULT_BODY_TOKEN_PATTERNS = [
    # Hidden input fields with CSRF tokens
    r'<input[^>]+name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|__RequestVerificationToken|_token|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
    r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|__RequestVerificationToken|_token|authenticity_token)["\']',
    # Meta tags with CSRF
    r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
]

# =========================================================================
#  TOKEN TYPE ENUM
# =========================================================================

class TokenType(str, Enum):
    JWT = "jwt"
    BEARER = "bearer"
    BASIC = "basic"
    COOKIE = "cookie"
    CSRF = "csrf"
    API_KEY = "api_key"
    OAUTH = "oauth"
    CUSTOM = "custom"


# =========================================================================
#  TOKEN DATA CLASS  (fallback if shared.schemas not available)
# =========================================================================

@dataclass
class _TokenRecord:
    """Internal token record structure."""
    id: str = ""
    type: str = ""
    value: str = ""
    domain: str = ""
    path: str = "/"
    expiry: float = 0.0  # Unix timestamp; 0 means no expiry
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    created_at: float = 0.0
    last_seen: float = 0.0
    source: str = ""  # "request_header", "response_header", "response_body"
    raw_name: str = ""  # original cookie name or header name
    expired: bool = False
    extra: str = ""  # JSON-encoded additional metadata

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Redis stores strings; convert booleans/floats
        for k, v in d.items():
            if isinstance(v, bool):
                d[k] = "1" if v else "0"
            elif isinstance(v, (int, float)):
                d[k] = str(v)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "_TokenRecord":
        bool_fields = {"secure", "httponly", "expired"}
        float_fields = {"expiry", "created_at", "last_seen"}
        clean: Dict[str, Any] = {}
        for f_name in cls.__dataclass_fields__:  # type: ignore[attr-defined]
            val = d.get(f_name, "")
            if f_name in bool_fields:
                clean[f_name] = val in ("1", "True", "true", True, 1)
            elif f_name in float_fields:
                try:
                    clean[f_name] = float(val) if val else 0.0
                except (ValueError, TypeError):
                    clean[f_name] = 0.0
            else:
                clean[f_name] = str(val) if val is not None else ""
        return cls(**clean)

    def is_expired(self) -> bool:
        if self.expiry == 0.0:
            return False
        return time.time() > self.expiry


# Use shared schema if available, else our fallback
if TokenRecord is None:
    TokenRecord = _TokenRecord  # type: ignore[misc]


# =========================================================================
#  CONFIGURATION LOADER
# =========================================================================

class HarvesterConfig:
    """Loads and merges configuration from multiple sources."""

    def __init__(self, config_path: Optional[str] = None):
        self.redis_host: str = DEFAULT_REDIS_HOST
        self.redis_port: int = DEFAULT_REDIS_PORT
        self.redis_db: int = DEFAULT_REDIS_DB
        self.redis_password: Optional[str] = DEFAULT_REDIS_PASSWORD
        self.memory_buffer_max: int = DEFAULT_MEMORY_BUFFER_MAX
        self.cleanup_interval: int = DEFAULT_CLEANUP_INTERVAL_SECS
        self.default_ttl: int = DEFAULT_TOKEN_TTL_SECS
        self.ignored_domains: Set[str] = set()
        self.token_json_keys: List[str] = list(DEFAULT_TOKEN_JSON_KEYS)
        self.body_token_patterns: List[str] = list(DEFAULT_BODY_TOKEN_PATTERNS)
        self.extract_from_response_body: bool = True
        self.max_response_body_size: int = 1024 * 1024  # 1 MB
        self.log_token_values: bool = False  # Security: don't log actual token values by default

        self._load(config_path)

    def _load(self, config_path: Optional[str]) -> None:
        """Load configuration from YAML files. Merge order:
        1. config/modules.yaml (global)
        2. modules/token_harvester/config.yaml (module-local)
        3. Environment variables (override)
        """
        # --- Global config ---
        global_config_path = Path("config/modules.yaml")
        self._load_yaml(global_config_path, section="token_harvester")

        # --- Module-local config ---
        local_config_path = Path(__file__).parent / "config.yaml"
        if config_path:
            local_config_path = Path(config_path)
        self._load_yaml(local_config_path, section=None)

        # --- Environment overrides ---
        self._load_env()

        logger.info(
            "HarvesterConfig loaded — Redis=%s:%d/%d, ignored_domains=%d, json_keys=%d",
            self.redis_host,
            self.redis_port,
            self.redis_db,
            len(self.ignored_domains),
            len(self.token_json_keys),
        )

    def _load_yaml(self, path: Path, section: Optional[str]) -> None:
        if not path.exists():
            logger.debug("Config file not found (skipping): %s", path)
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                logger.warning("Config file %s is not a mapping; skipping.", path)
                return
            data = raw.get(section, raw) if section else raw
            if not isinstance(data, dict):
                return
            self._apply(data)
            logger.debug("Loaded config from %s", path)
        except yaml.YAMLError as exc:
            logger.error("YAML parse error in %s: %s", path, exc)
        except OSError as exc:
            logger.error("Cannot read config %s: %s", path, exc)

    def _apply(self, data: Dict[str, Any]) -> None:
        redis_cfg = data.get("redis", {})
        if isinstance(redis_cfg, dict):
            self.redis_host = redis_cfg.get("host", self.redis_host)
            self.redis_port = int(redis_cfg.get("port", self.redis_port))
            self.redis_db = int(redis_cfg.get("db", self.redis_db))
            self.redis_password = redis_cfg.get("password", self.redis_password)

        if "memory_buffer_max" in data:
            self.memory_buffer_max = int(data["memory_buffer_max"])
        if "cleanup_interval" in data:
            self.cleanup_interval = int(data["cleanup_interval"])
        if "default_ttl" in data:
            self.default_ttl = int(data["default_ttl"])
        if "ignored_domains" in data and isinstance(data["ignored_domains"], list):
            self.ignored_domains = set(data["ignored_domains"])
        if "token_json_keys" in data and isinstance(data["token_json_keys"], list):
            self.token_json_keys = data["token_json_keys"]
        if "body_token_patterns" in data and isinstance(data["body_token_patterns"], list):
            self.body_token_patterns = data["body_token_patterns"]
        if "extract_from_response_body" in data:
            self.extract_from_response_body = bool(data["extract_from_response_body"])
        if "max_response_body_size" in data:
            self.max_response_body_size = int(data["max_response_body_size"])
        if "log_token_values" in data:
            self.log_token_values = bool(data["log_token_values"])

    def _load_env(self) -> None:
        env_map = {
            "JARVIS_REDIS_HOST": ("redis_host", str),
            "JARVIS_REDIS_PORT": ("redis_port", int),
            "JARVIS_REDIS_DB": ("redis_db", int),
            "JARVIS_REDIS_PASSWORD": ("redis_password", str),
            "JARVIS_HARVESTER_BUFFER_MAX": ("memory_buffer_max", int),
            "JARVIS_HARVESTER_CLEANUP_INTERVAL": ("cleanup_interval", int),
            "JARVIS_HARVESTER_LOG_TOKEN_VALUES": ("log_token_values", lambda v: v.lower() in ("1", "true", "yes")),
        }
        for env_key, (attr, cast) in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    setattr(self, attr, cast(val))
                    logger.debug("Env override: %s -> %s", env_key, attr)
                except (ValueError, TypeError) as exc:
                    logger.warning("Invalid env value %s=%s: %s", env_key, val, exc)


# =========================================================================
#  REDIS TOKEN STORE
# =========================================================================

class RedisTokenStore:
    """Persistent token storage backed by Redis with in-memory fallback buffer."""

    def __init__(self, config: HarvesterConfig):
        self.config = config
        self._redis: Optional[Any] = None
        self._buffer: deque = deque(maxlen=config.memory_buffer_max)
        self._buffer_lock = threading.Lock()
        self._connected = False
        self._stats = {
            "tokens_stored": 0,
            "tokens_updated": 0,
            "tokens_expired_cleaned": 0,
            "redis_errors": 0,
            "buffer_flushes": 0,
        }
        self._connect()

    # ---- Connection Management ----

    def _connect(self) -> bool:
        if redis_lib is None:
            logger.error(
                "redis-py library not installed. Token storage will use "
                "memory-only buffer (NOT persistent). Install: pip install redis"
            )
            self._connected = False
            return False
        try:
            self._redis = redis_lib.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            self._redis.ping()
            self._connected = True
            logger.info(
                "Redis connected: %s:%d/%d",
                self.config.redis_host,
                self.config.redis_port,
                self.config.redis_db,
            )
            # Flush any buffered tokens
            self._flush_buffer()
            return True
        except Exception as exc:
            self._connected = False
            logger.error("Redis connection failed: %s. Tokens buffered in memory.", exc)
            self._stats["redis_errors"] += 1
            return False

    def _ensure_connection(self) -> bool:
        if self._connected and self._redis is not None:
            try:
                self._redis.ping()
                return True
            except Exception:
                self._connected = False
                logger.warning("Redis connection lost. Attempting reconnect…")
        return self._connect()

    # ---- Core Operations ----

    def store_token(self, token: "_TokenRecord") -> bool:  # type: ignore[name-defined]
        """Store a token record. Returns True if stored in Redis, False if buffered."""
        if not self._ensure_connection():
            self._buffer_token(token)
            return False

        try:
            redis_key = self._make_key(token)
            pipe = self._redis.pipeline(transaction=True)

            # Check if this is an update
            existing = self._redis.exists(redis_key)

            # Store as hash
            pipe.hset(redis_key, mapping=token.to_dict())

            # Set TTL if token has expiry
            if token.expiry > 0:
                ttl = int(token.expiry - time.time())
                if ttl > 0:
                    pipe.expireat(redis_key, int(token.expiry))
                else:
                    # Already expired; store briefly for record then expire
                    pipe.expire(redis_key, 60)
            elif self.config.default_ttl > 0:
                pipe.expire(redis_key, self.config.default_ttl)

            # Add to domain index set
            domain_index_key = f"{REDIS_DOMAIN_INDEX_PREFIX}:{token.domain}"
            pipe.sadd(domain_index_key, redis_key)
            pipe.sadd(REDIS_DOMAINS_SET, token.domain)

            pipe.execute()

            if existing:
                self._stats["tokens_updated"] += 1
                logger.info(
                    "Token UPDATED: type=%s domain=%s source=%s key=%s",
                    token.type, token.domain, token.source, redis_key,
                )
            else:
                self._stats["tokens_stored"] += 1
                logger.info(
                    "Token STORED: type=%s domain=%s source=%s key=%s",
                    token.type, token.domain, token.source, redis_key,
                )

            if self.config.log_token_values:
                logger.debug("Token value: %s", token.value[:80] + ("…" if len(token.value) > 80 else ""))

            return True

        except Exception as exc:
            logger.error("Redis store failed for %s: %s", token.domain, exc)
            self._stats["redis_errors"] += 1
            self._connected = False
            self._buffer_token(token)
            return False

    def get_tokens(self, domain: str, token_type: Optional[str] = None,
                   path: Optional[str] = None, include_expired: bool = False) -> List[Dict[str, Any]]:
        """Retrieve tokens for a domain, optionally filtered by type and path."""
        results: List[Dict[str, Any]] = []

        if not self._ensure_connection():
            # Return from buffer if Redis is down
            return self._get_from_buffer(domain, token_type, path, include_expired)

        try:
            domain_index_key = f"{REDIS_DOMAIN_INDEX_PREFIX}:{domain}"
            token_keys = self._redis.smembers(domain_index_key)

            stale_keys: List[str] = []

            for key in token_keys:
                data = self._redis.hgetall(key)
                if not data:
                    stale_keys.append(key)
                    continue

                record = _TokenRecord.from_dict(data)

                # Filter by type
                if token_type and record.type != token_type:
                    continue

                # Filter by path (most specific match)
                if path and record.path and record.path != "/":
                    if not path.startswith(record.path):
                        continue

                # Check expiry
                if record.is_expired():
                    if not include_expired:
                        stale_keys.append(key)
                        continue
                    record.expired = True

                results.append(record.to_dict())

            # Cleanup stale keys from index
            if stale_keys:
                pipe = self._redis.pipeline()
                for sk in stale_keys:
                    pipe.srem(domain_index_key, sk)
                    pipe.delete(sk)
                pipe.execute()
                self._stats["tokens_expired_cleaned"] += len(stale_keys)
                logger.debug("Cleaned %d stale token keys for domain %s", len(stale_keys), domain)

        except Exception as exc:
            logger.error("Redis get_tokens failed for %s: %s", domain, exc)
            self._stats["redis_errors"] += 1
            self._connected = False
            return self._get_from_buffer(domain, token_type, path, include_expired)

        return results

    def get_all_domains(self) -> List[str]:
        """Return list of all domains that have stored tokens."""
        if not self._ensure_connection():
            with self._buffer_lock:
                return list({t.domain for t in self._buffer})
        try:
            return list(self._redis.smembers(REDIS_DOMAINS_SET))
        except Exception as exc:
            logger.error("Redis get_all_domains failed: %s", exc)
            self._stats["redis_errors"] += 1
            return []

    def cleanup_expired(self) -> int:
        """Scan and remove expired tokens. Returns count removed."""
        if not self._ensure_connection():
            return 0

        removed = 0
        try:
            domains = self._redis.smembers(REDIS_DOMAINS_SET)
            for domain in domains:
                domain_index_key = f"{REDIS_DOMAIN_INDEX_PREFIX}:{domain}"
                token_keys = self._redis.smembers(domain_index_key)
                stale: List[str] = []
                for key in token_keys:
                    data = self._redis.hgetall(key)
                    if not data:
                        stale.append(key)
                        continue
                    record = _TokenRecord.from_dict(data)
                    if record.is_expired():
                        stale.append(key)

                if stale:
                    pipe = self._redis.pipeline()
                    for sk in stale:
                        pipe.srem(domain_index_key, sk)
                        pipe.delete(sk)
                    pipe.execute()
                    removed += len(stale)

                # If no tokens left for domain, remove from domains set
                if self._redis.scard(domain_index_key) == 0:
                    self._redis.srem(REDIS_DOMAINS_SET, domain)

        except Exception as exc:
            logger.error("cleanup_expired failed: %s", exc)
            self._stats["redis_errors"] += 1

        if removed:
            self._stats["tokens_expired_cleaned"] += removed
            logger.info("Expired token cleanup: removed %d tokens", removed)
        return removed

    def get_stats(self) -> Dict[str, Any]:
        stats = dict(self._stats)
        stats["buffer_size"] = len(self._buffer)
        stats["redis_connected"] = self._connected
        return stats

    # ---- Internal Helpers ----

    def _make_key(self, token: "_TokenRecord") -> str:  # type: ignore[name-defined]
        """Generate a deterministic Redis key for a token.
        Key pattern: token:{domain}:{unique_id}
        unique_id is derived from type + raw_name + value hash to enable dedup.
        """
        value_hash = hashlib.sha256(token.value.encode("utf-8", errors="replace")).hexdigest()[:16]
        unique_part = f"{token.type}:{token.raw_name}:{value_hash}"
        unique_id = hashlib.md5(unique_part.encode()).hexdigest()[:12]
        return f"{REDIS_KEY_PREFIX}:{token.domain}:{unique_id}"

    def _buffer_token(self, token: "_TokenRecord") -> None:  # type: ignore[name-defined]
        with self._buffer_lock:
            if len(self._buffer) >= self.config.memory_buffer_max:
                logger.warning(
                    "Memory buffer full (%d). Oldest token evicted.",
                    self.config.memory_buffer_max,
                )
            self._buffer.append(token)
            logger.debug(
                "Token buffered in memory: type=%s domain=%s (buffer=%d)",
                token.type, token.domain, len(self._buffer),
            )

    def _flush_buffer(self) -> None:
        with self._buffer_lock:
            count = len(self._buffer)
            if count == 0:
                return
            logger.info("Flushing %d buffered tokens to Redis…", count)
            flushed = 0
            while self._buffer:
                token = self._buffer.popleft()
                try:
                    redis_key = self._make_key(token)
                    self._redis.hset(redis_key, mapping=token.to_dict())
                    if token.expiry > 0:
                        ttl = int(token.expiry - time.time())
                        if ttl > 0:
                            self._redis.expireat(redis_key, int(token.expiry))
                        else:
                            self._redis.expire(redis_key, 60)
                    elif self.config.default_ttl > 0:
                        self._redis.expire(redis_key, self.config.default_ttl)

                    domain_index_key = f"{REDIS_DOMAIN_INDEX_PREFIX}:{token.domain}"
                    self._redis.sadd(domain_index_key, redis_key)
                    self._redis.sadd(REDIS_DOMAINS_SET, token.domain)
                    flushed += 1
                except Exception as exc:
                    logger.error("Buffer flush failed for token: %s", exc)
                    self._buffer.appendleft(token)
                    break
            self._stats["buffer_flushes"] += 1
            logger.info("Buffer flush complete: %d/%d tokens flushed", flushed, count)

    def _get_from_buffer(self, domain: str, token_type: Optional[str],
                         path: Optional[str], include_expired: bool) -> List[Dict[str, Any]]:
        """Retrieve tokens from in-memory buffer (fallback when Redis is down)."""
        results = []
        with self._buffer_lock:
            for token in self._buffer:
                if token.domain != domain:
                    continue
                if token_type and token.type != token_type:
                    continue
                if path and token.path and token.path != "/":
                    if not path.startswith(token.path):
                        continue
                if not include_expired and token.is_expired():
                    continue
                results.append(token.to_dict())
        return results


# =========================================================================
#  TOKEN EXTRACTION UTILITIES
# =========================================================================

def _generate_token_id() -> str:
    return uuid.uuid4().hex[:12]


def _is_jwt(value: str) -> bool:
    """Heuristic: JWT has 3 base64url-encoded parts separated by dots."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    for part in parts[:2]:  # Header and payload must be valid base64url
        # Add padding
        padded = part + "=" * (4 - len(part) % 4) if len(part) % 4 else part
        try:
            decoded = base64.urlsafe_b64decode(padded)
            json.loads(decoded)
        except (ValueError, json.JSONDecodeError, Exception):
            return False
    return True


def _decode_jwt_expiry(jwt_str: str) -> float:
    """Attempt to decode the exp claim from a JWT. Returns 0.0 if not found."""
    try:
        parts = jwt_str.split(".")
        if len(parts) < 2:
            return 0.0
        payload = parts[1]
        # Add padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        exp = claims.get("exp")
        if exp is not None:
            return float(exp)
    except Exception as exc:
        logger.debug("JWT decode failed (non-critical): %s", exc)
    return 0.0


def _extract_domain_from_url(url: str) -> str:
    """Extract domain (host) from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        if host:
            return host.lower().strip()
    except Exception:
        pass
    return "unknown"


def _parse_cookie_attributes(set_cookie_value: str) -> Dict[str, Any]:
    """Parse a Set-Cookie header value into name, value, and attributes."""
    result: Dict[str, Any] = {
        "name": "",
        "value": "",
        "domain": "",
        "path": "/",
        "expires": 0.0,
        "secure": False,
        "httponly": False,
        "samesite": "",
        "max_age": None,
    }

    parts = set_cookie_value.split(";")
    if not parts:
        return result

    # First part is name=value
    name_value = parts[0].strip()
    eq_idx = name_value.find("=")
    if eq_idx > 0:
        result["name"] = name_value[:eq_idx].strip()
        result["value"] = name_value[eq_idx + 1:].strip()
    else:
        result["name"] = name_value
        result["value"] = ""

    # Remaining parts are attributes
    for attr in parts[1:]:
        attr = attr.strip()
        if not attr:
            continue
        attr_lower = attr.lower()

        if attr_lower == "secure":
            result["secure"] = True
        elif attr_lower == "httponly":
            result["httponly"] = True
        elif "=" in attr:
            attr_name, attr_val = attr.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_val = attr_val.strip()

            if attr_name == "domain":
                result["domain"] = attr_val.lstrip(".").lower()
            elif attr_name == "path":
                result["path"] = attr_val
            elif attr_name == "expires":
                try:
                    dt = parsedate_to_datetime(attr_val)
                    result["expires"] = dt.timestamp()
                except Exception:
                    pass
            elif attr_name == "max-age":
                try:
                    result["max_age"] = int(attr_val)
                except ValueError:
                    pass
            elif attr_name == "samesite":
                result["samesite"] = attr_val.lower()

    # max-age overrides expires
    if result["max_age"] is not None:
        if result["max_age"] > 0:
            result["expires"] = time.time() + result["max_age"]
        elif result["max_age"] <= 0:
            result["expires"] = time.time() - 1  # already expired

    return result


def _mask_token(value: str, show_chars: int = 8) -> str:
    """Mask a token value for safe logging."""
    if len(value) <= show_chars:
        return "***"
    return value[:show_chars] + "***" + value[-4:]


# =========================================================================
#  MAIN TOKEN HARVESTER (MITMPROXY ADDON)
# =========================================================================

class TokenHarvester:
    """
    Mitmproxy addon that intercepts HTTP(S) traffic and extracts
    authentication tokens, storing them in Redis.
    """

    def __init__(self, config_path: Optional[str] = None):
        logger.info("=" * 60)
        logger.info("  Centaur-Jarvis Token Harvester — Initializing")
        logger.info("=" * 60)

        self.config = HarvesterConfig(config_path)
        self.store = RedisTokenStore(self.config)

        # Compiled body token patterns
        self._body_patterns: List[re.Pattern] = []
        for pattern in self.config.body_token_patterns:
            try:
                self._body_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                logger.error("Invalid regex pattern '%s': %s", pattern, exc)

        # Build set of lowercase JSON keys for fast lookup
        self._json_key_set: Set[str] = {k.lower() for k in self.config.token_json_keys}

        # Cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._start_cleanup_thread()

        logger.info("Token Harvester initialized successfully.")

    # ---- Mitmproxy Hooks ----

    def request(self, flow: Any) -> None:
        """Called for each intercepted HTTP request."""
        try:
            request = flow.request
            domain = _extract_domain_from_url(request.pretty_url)

            if self._should_ignore(domain):
                return

            now = time.time()

            # 1. Authorization header
            auth_header = request.headers.get("Authorization", "")
            if auth_header:
                self._process_authorization_header(auth_header, domain, now, "request_header")

            # 2. Cookie header
            cookie_header = request.headers.get("Cookie", "")
            if cookie_header:
                self._process_cookie_header(cookie_header, domain, now)

            # 3. CSRF headers in request
            for header_name in CSRF_HEADER_NAMES:
                csrf_val = request.headers.get(header_name, "")
                if csrf_val:
                    token_record = _TokenRecord(
                        id=_generate_token_id(),
                        type=TokenType.CSRF.value,
                        value=csrf_val,
                        domain=domain,
                        path="/",
                        expiry=0.0,
                        secure=request.scheme == "https",
                        httponly=False,
                        created_at=now,
                        last_seen=now,
                        source="request_header",
                        raw_name=header_name,
                    )
                    self.store.store_token(token_record)

        except Exception as exc:
            logger.error("Error in request hook: %s", exc, exc_info=True)

    def response(self, flow: Any) -> None:
        """Called for each intercepted HTTP response."""
        try:
            request = flow.request
            response = flow.response
            domain = _extract_domain_from_url(request.pretty_url)

            if self._should_ignore(domain):
                return

            now = time.time()

            # 1. Set-Cookie headers
            set_cookie_headers = response.headers.get_all("Set-Cookie")
            if set_cookie_headers:
                for sc in set_cookie_headers:
                    self._process_set_cookie(sc, domain, now)

            # 2. CSRF headers in response
            for header_name in CSRF_HEADER_NAMES:
                csrf_val = response.headers.get(header_name, "")
                if csrf_val:
                    token_record = _TokenRecord(
                        id=_generate_token_id(),
                        type=TokenType.CSRF.value,
                        value=csrf_val,
                        domain=domain,
                        path="/",
                        expiry=0.0,
                        secure=request.scheme == "https",
                        httponly=False,
                        created_at=now,
                        last_seen=now,
                        source="response_header",
                        raw_name=header_name,
                    )
                    self.store.store_token(token_record)

            # 3. Authorization header echoed in response (rare but possible)
            auth_resp = response.headers.get("Authorization", "")
            if auth_resp:
                self._process_authorization_header(auth_resp, domain, now, "response_header")

            # 4. Response body — JSON tokens and regex patterns
            if self.config.extract_from_response_body:
                self._process_response_body(response, domain, now)

        except Exception as exc:
            logger.error("Error in response hook: %s", exc, exc_info=True)

    # ---- Extraction Methods ----

    def _process_authorization_header(self, auth_value: str, domain: str,
                                      now: float, source: str) -> None:
        """Extract token from Authorization header."""
        auth_value = auth_value.strip()
        if not auth_value:
            return

        parts = auth_value.split(None, 1)
        scheme = parts[0].lower() if parts else ""
        token_value = parts[1] if len(parts) > 1 else auth_value

        if scheme == "bearer":
            token_type = TokenType.JWT.value if _is_jwt(token_value) else TokenType.BEARER.value
            expiry = _decode_jwt_expiry(token_value) if token_type == TokenType.JWT.value else 0.0
        elif scheme == "basic":
            token_type = TokenType.BASIC.value
            expiry = 0.0
            token_value = auth_value  # store full "Basic <base64>"
        else:
            token_type = TokenType.BEARER.value
            expiry = _decode_jwt_expiry(token_value) if _is_jwt(token_value) else 0.0
            if _is_jwt(token_value):
                token_type = TokenType.JWT.value

        token_record = _TokenRecord(
            id=_generate_token_id(),
            type=token_type,
            value=token_value,
            domain=domain,
            path="/",
            expiry=expiry,
            secure=True,
            httponly=False,
            created_at=now,
            last_seen=now,
            source=source,
            raw_name="Authorization",
        )
        self.store.store_token(token_record)

    def _process_cookie_header(self, cookie_header: str, domain: str, now: float) -> None:
        """Extract individual cookies from the Cookie request header.
        Note: Cookie request header does NOT include attributes (Secure, HttpOnly, etc.)
        — those are only in Set-Cookie. We store what we have.
        """
        cookies = cookie_header.split(";")
        for cookie in cookies:
            cookie = cookie.strip()
            if not cookie:
                continue
            eq_idx = cookie.find("=")
            if eq_idx <= 0:
                continue
            name = cookie[:eq_idx].strip()
            value = cookie[eq_idx + 1:].strip()

            if not value:
                continue

            # Check if cookie value is a JWT
            token_type = TokenType.COOKIE.value
            expiry = 0.0
            if _is_jwt(value):
                token_type = TokenType.JWT.value
                expiry = _decode_jwt_expiry(value)

            token_record = _TokenRecord(
                id=_generate_token_id(),
                type=token_type,
                value=value,
                domain=domain,
                path="/",
                expiry=expiry,
                secure=False,  # Unknown from request Cookie header
                httponly=False,  # Unknown from request Cookie header
                created_at=now,
                last_seen=now,
                source="request_header",
                raw_name=name,
            )
            self.store.store_token(token_record)

    def _process_set_cookie(self, set_cookie_value: str, request_domain: str, now: float) -> None:
        """Parse and store a Set-Cookie response header."""
        attrs = _parse_cookie_attributes(set_cookie_value)

        if not attrs["name"] or not attrs["value"]:
            return

        # Use cookie's Domain attribute if present; else default to request domain
        domain = attrs["domain"] if attrs["domain"] else request_domain

        value = attrs["value"]
        token_type = TokenType.COOKIE.value
        expiry = attrs["expires"]

        # Detect JWT stored as cookie
        if _is_jwt(value):
            token_type = TokenType.JWT.value
            jwt_exp = _decode_jwt_expiry(value)
            if jwt_exp > 0:
                expiry = jwt_exp

        token_record = _TokenRecord(
            id=_generate_token_id(),
            type=token_type,
            value=value,
            domain=domain,
            path=attrs["path"],
            expiry=expiry,
            secure=attrs["secure"],
            httponly=attrs["httponly"],
            samesite=attrs["samesite"],
            created_at=now,
            last_seen=now,
            source="response_header",
            raw_name=attrs["name"],
        )
        self.store.store_token(token_record)

    def _process_response_body(self, response: Any, domain: str, now: float) -> None:
        """Extract tokens from response body — JSON and regex patterns."""
        content_type = response.headers.get("Content-Type", "").lower()

        # Get body content
        try:
            raw_content = response.get_content()
        except Exception:
            return

        if not raw_content:
            return

        # Size guard
        if len(raw_content) > self.config.max_response_body_size:
            logger.debug(
                "Response body too large (%d bytes) for domain %s; skipping body extraction.",
                len(raw_content), domain,
            )
            return

        try:
            body_text = raw_content.decode("utf-8", errors="replace")
        except Exception:
            return

        # --- JSON extraction ---
        if "json" in content_type or "javascript" in content_type:
            self._extract_json_tokens(body_text, domain, now)

        # --- Regex extraction (HTML, XML, etc.) ---
        self._extract_regex_tokens(body_text, domain, now)

    def _extract_json_tokens(self, body: str, domain: str, now: float) -> None:
        """Recursively search JSON for token keys."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return

        found_tokens: List[Tuple[str, str]] = []
        self._walk_json(data, found_tokens)

        for key_name, value in found_tokens:
            token_type = TokenType.BEARER.value
            expiry = 0.0

            if _is_jwt(value):
                token_type = TokenType.JWT.value
                expiry = _decode_jwt_expiry(value)
            elif "csrf" in key_name.lower() or "xsrf" in key_name.lower():
                token_type = TokenType.CSRF.value
            elif "api" in key_name.lower():
                token_type = TokenType.API_KEY.value
            elif "refresh" in key_name.lower():
                token_type = TokenType.OAUTH.value

            token_record = _TokenRecord(
                id=_generate_token_id(),
                type=token_type,
                value=value,
                domain=domain,
                path="/",
                expiry=expiry,
                secure=False,
                httponly=False,
                created_at=now,
                last_seen=now,
                source="response_body",
                raw_name=key_name,
            )
            self.store.store_token(token_record)

    def _walk_json(self, obj: Any, results: List[Tuple[str, str]], depth: int = 0) -> None:
        """Recursively walk JSON structure looking for token keys."""
        if depth > 10:  # prevent infinite recursion on deeply nested data
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(val, str) and key.lower() in self._json_key_set:
                    if len(val) >= 8:  # token must be at least 8 chars
                        results.append((key, val))
                elif isinstance(val, (dict, list)):
                    self._walk_json(val, results, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._walk_json(item, results, depth + 1)

    def _extract_regex_tokens(self, body: str, domain: str, now: float) -> None:
        """Extract tokens using regex patterns (e.g., CSRF tokens in HTML forms)."""
        for pattern in self._body_patterns:
            try:
                matches = pattern.findall(body)
                for match in matches:
                    value = match if isinstance(match, str) else match[0] if match else ""
                    if not value or len(value) < 8:
                        continue

                    token_record = _TokenRecord(
                        id=_generate_token_id(),
                        type=TokenType.CSRF.value,
                        value=value,
                        domain=domain,
                        path="/",
                        expiry=0.0,
                        secure=False,
                        httponly=False,
                        created_at=now,
                        last_seen=now,
                        source="response_body_regex",
                        raw_name="csrf_html",
                    )
                    self.store.store_token(token_record)
            except Exception as exc:
                logger.debug("Regex pattern match error: %s", exc)

    # ---- Helpers ----

    def _should_ignore(self, domain: str) -> bool:
        """Check if a domain should be ignored."""
        if domain in self.config.ignored_domains:
            return True
        # Also check if any ignored domain is a suffix (subdomain matching)
        for ignored in self.config.ignored_domains:
            if domain.endswith("." + ignored):
                return True
        return False

    # ---- Cleanup Thread ----

    def _start_cleanup_thread(self) -> None:
        """Start background thread for periodic expired token cleanup."""
        def _cleanup_loop():
            logger.info("Cleanup thread started (interval=%ds)", self.config.cleanup_interval)
            while not self._stop_event.is_set():
                self._stop_event.wait(self.config.cleanup_interval)
                if self._stop_event.is_set():
                    break
                try:
                    removed = self.store.cleanup_expired()
                    if removed:
                        logger.info("Periodic cleanup: removed %d expired tokens", removed)
                except Exception as exc:
                    logger.error("Cleanup thread error: %s", exc)

        self._cleanup_thread = threading.Thread(
            target=_cleanup_loop,
            name="token-harvester-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("Token Harvester shutting down…")
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        stats = self.store.get_stats()
        logger.info("Final stats: %s", json.dumps(stats, indent=2))
        logger.info("Token Harvester shutdown complete.")


# =========================================================================
#  MODULE-LEVEL HELPER FUNCTIONS (for use by other modules)
# =========================================================================

# Module-level store instance (lazy-init)
_module_store: Optional[RedisTokenStore] = None
_module_store_lock = threading.Lock()


def _get_store() -> RedisTokenStore:
    global _module_store
    if _module_store is None:
        with _module_store_lock:
            if _module_store is None:
                config = HarvesterConfig()
                _module_store = RedisTokenStore(config)
    return _module_store


def get_tokens_for_domain(
    domain: str,
    token_type: Optional[str] = None,
    path: Optional[str] = None,
    include_expired: bool = False,
) -> List[Dict[str, Any]]:
    """
    Public API: Retrieve all valid tokens for a given domain.

    Usage by other modules:
        from modules.token_harvester import get_tokens_for_domain
        tokens = get_tokens_for_domain("example.com")
        # tokens is a list of dicts with keys: type, value, domain, path, expiry, etc.

    Args:
        domain: Target domain
        token_type: Optional filter (e.g., "jwt", "cookie", "bearer")
        path: Optional URL path for path-specific cookie matching
        include_expired: Whether to include expired tokens

    Returns:
        List of token dictionaries
    """
    store = _get_store()
    tokens = store.get_tokens(domain, token_type, path, include_expired)
    logger.debug("get_tokens_for_domain(%s): returned %d tokens", domain, len(tokens))
    return tokens


def get_all_harvested_domains() -> List[str]:
    """Return all domains for which tokens have been harvested."""
    store = _get_store()
    return store.get_all_domains()


def cleanup_expired_tokens() -> int:
    """Manually trigger cleanup of expired tokens. Returns count removed."""
    store = _get_store()
    return store.cleanup_expired()


def get_token_stats() -> Dict[str, Any]:
    """Return harvester statistics."""
    store = _get_store()
    return store.get_stats()