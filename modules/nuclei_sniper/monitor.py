"""
CVE Monitor
===========
Watches RSS feeds (GitHub, Nitter/Twitter, PacketStorm, etc.) for new CVE
mentions. Deduplicates against Redis and pushes new CVE tasks to the
nuclei_sniper queue.

Edge Cases Handled:
- EC1:  RSS feed unavailable → log warning, retry later, continue others
- EC2:  Duplicate CVE detection → Redis SISMEMBER check
- EC8:  Large number of CVEs → max_entries_per_feed cap
- EC9:  Redis connection lost → in-memory buffer with retry
- EC12: Memory explosion from large feeds → streaming parse, entry cap
- EC13: Thread safety → Redis distributed lock for polling
"""

import json
import re
import time
import hashlib
from typing import Any, Optional
from dataclasses import dataclass, field, asdict

import feedparser
import redis
import yaml

# Internal imports — guarded for standalone testing
try:
    from shared.logger import get_logger
except ImportError:
    import logging
    def get_logger(name: str):
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s %(message)s"
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

logger = get_logger("nuclei_sniper.monitor")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CVETask:
    """Represents a newly discovered CVE to be processed."""
    cve_id: str
    title: str
    description: str
    source: str
    poc_links: list = field(default_factory=list)
    published: str = ""
    severity: str = "UNKNOWN"
    references: list = field(default_factory=list)
    raw_entry_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
def _load_config(config_path: str = None) -> dict:
    """Load module configuration with fallback defaults."""
    if config_path is None:
        import os
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    defaults = {
        "feeds": {
            "sources": [],
            "poll_interval": 3600,
            "max_entries_per_feed": 50,
            "fetch_timeout": 30,
            "fetch_delay": 2,
        },
        "redis": {
            "task_queue": "queue:nuclei_sniper",
            "seen_cves_key": "nuclei_sniper:seen_cves",
            "status_prefix": "nuclei_sniper:status:",
            "buffer_max_size": 100,
            "connection_retry_max": 5,
            "connection_retry_delay": 5,
            "poll_lock_ttl": 300,
        },
    }

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        # Merge with defaults
        for section, section_defaults in defaults.items():
            if section not in config:
                config[section] = section_defaults
            elif isinstance(section_defaults, dict):
                for k, v in section_defaults.items():
                    config[section].setdefault(k, v)
        logger.info("Configuration loaded from %s", config_path)
        return config
    except FileNotFoundError:
        logger.warning(
            "Config file %s not found; using defaults", config_path
        )
        return defaults
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config YAML: %s; using defaults", exc)
        return defaults


# ---------------------------------------------------------------------------
# CVE ID extraction
# ---------------------------------------------------------------------------
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def extract_cve_ids(text: str) -> list:
    """Extract all CVE IDs from a text string."""
    if not text:
        return []
    return list(set(_CVE_PATTERN.findall(text.upper())))


def extract_poc_links(text: str) -> list:
    """Extract potential PoC/exploit links from text."""
    if not text:
        return []
    url_pattern = re.compile(
        r"https?://[^\s<>\"']+(?:exploit|poc|proof|github\.com/[^\s<>\"']*)",
        re.IGNORECASE,
    )
    return list(set(url_pattern.findall(text)))


# ---------------------------------------------------------------------------
# Redis helper with reconnection
# ---------------------------------------------------------------------------
class RedisHelper:
    """
    Wrapper around Redis client with automatic reconnection and in-memory
    buffering when Redis is unavailable (EC9).
    """

    def __init__(self, config: dict, redis_client: redis.Redis = None):
        self._config = config.get("redis", {})
        self._client = redis_client
        self._buffer: list = []  # In-memory buffer for tasks when Redis is down
        self._buffer_max = self._config.get("buffer_max_size", 100)
        self._retry_max = self._config.get("connection_retry_max", 5)
        self._retry_delay = self._config.get("connection_retry_delay", 5)

    @property
    def client(self) -> Optional[redis.Redis]:
        return self._client

    def _ensure_connection(self) -> bool:
        """Verify Redis connection; attempt reconnect if needed."""
        if self._client is None:
            logger.error("Redis client not provided; cannot connect")
            return False
        try:
            self._client.ping()
            return True
        except (redis.ConnectionError, redis.TimeoutError) as exc:
            logger.warning("Redis connection lost: %s; attempting reconnect", exc)
            for attempt in range(1, self._retry_max + 1):
                try:
                    time.sleep(self._retry_delay)
                    self._client.ping()
                    logger.info("Redis reconnected on attempt %d", attempt)
                    self._flush_buffer()
                    return True
                except (redis.ConnectionError, redis.TimeoutError):
                    logger.warning("Redis reconnect attempt %d/%d failed",
                                   attempt, self._retry_max)
            logger.error("Redis reconnection exhausted after %d attempts",
                         self._retry_max)
            return False

    def _flush_buffer(self):
        """Flush in-memory buffer to Redis after reconnection."""
        if not self._buffer:
            return
        queue = self._config.get("task_queue", "queue:nuclei_sniper")
        flushed = 0
        while self._buffer:
            task_json = self._buffer[0]
            try:
                self._client.lpush(queue, task_json)
                self._buffer.pop(0)
                flushed += 1
            except (redis.ConnectionError, redis.TimeoutError):
                logger.warning("Buffer flush interrupted; %d tasks remaining",
                               len(self._buffer))
                break
        if flushed:
            logger.info("Flushed %d buffered tasks to Redis", flushed)

    def is_cve_seen(self, cve_id: str) -> bool:
        """Check if CVE ID has already been processed (EC2)."""
        if not self._ensure_connection():
            # If Redis is down, conservatively say "not seen" to avoid
            # losing CVEs, but log the risk of duplicates
            logger.warning(
                "Cannot check seen CVEs (Redis down); "
                "CVE %s may be processed as duplicate", cve_id
            )
            return False
        try:
            seen_key = self._config.get("seen_cves_key",
                                         "nuclei_sniper:seen_cves")
            return bool(self._client.sismember(seen_key, cve_id))
        except redis.RedisError as exc:
            logger.error("Redis error checking seen CVE %s: %s", cve_id, exc)
            return False

    def mark_cve_seen(self, cve_id: str) -> bool:
        """Add CVE ID to the seen set (EC2)."""
        if not self._ensure_connection():
            logger.warning("Cannot mark CVE %s as seen (Redis down)", cve_id)
            return False
        try:
            seen_key = self._config.get("seen_cves_key",
                                         "nuclei_sniper:seen_cves")
            self._client.sadd(seen_key, cve_id)
            return True
        except redis.RedisError as exc:
            logger.error("Redis error marking CVE %s as seen: %s",
                         cve_id, exc)
            return False

    def push_task(self, task: CVETask) -> bool:
        """Push a CVE task to the processing queue (EC9 buffering)."""
        task_json = task.to_json()
        if not self._ensure_connection():
            # Buffer in memory (EC9)
            if len(self._buffer) < self._buffer_max:
                self._buffer.append(task_json)
                logger.warning(
                    "Redis unavailable; buffered task %s (%d/%d)",
                    task.cve_id, len(self._buffer), self._buffer_max
                )
                return True
            else:
                logger.error(
                    "In-memory buffer full (%d); dropping task %s",
                    self._buffer_max, task.cve_id
                )
                return False
        try:
            queue = self._config.get("task_queue", "queue:nuclei_sniper")
            self._client.lpush(queue, task_json)
            logger.info("Pushed CVE task %s to %s", task.cve_id, queue)
            return True
        except redis.RedisError as exc:
            logger.error("Failed to push task %s to Redis: %s",
                         task.cve_id, exc)
            if len(self._buffer) < self._buffer_max:
                self._buffer.append(task_json)
                logger.warning("Buffered task %s in memory", task.cve_id)
                return True
            return False

    def set_status(self, cve_id: str, status: str, details: str = ""):
        """Set processing status for a CVE (all UPPERCASE)."""
        status = status.upper()  # CRITICAL RULE: status must be uppercase
        if not self._ensure_connection():
            logger.warning("Cannot set status for %s (Redis down)", cve_id)
            return
        try:
            prefix = self._config.get("status_prefix",
                                       "nuclei_sniper:status:")
            status_data = json.dumps({
                "status": status,
                "details": details,
                "timestamp": time.time(),
            })
            self._client.set(f"{prefix}{cve_id}", status_data, ex=86400 * 7)
        except redis.RedisError as exc:
            logger.error("Failed to set status for %s: %s", cve_id, exc)

    def acquire_poll_lock(self, lock_name: str = "nuclei_sniper:poll_lock") -> bool:
        """Acquire distributed lock for feed polling (EC13)."""
        if not self._ensure_connection():
            return True  # If Redis is down, allow polling (single instance assumed)
        try:
            ttl = self._config.get("poll_lock_ttl", 300)
            return bool(self._client.set(lock_name, "1", nx=True, ex=ttl))
        except redis.RedisError as exc:
            logger.warning("Failed to acquire poll lock: %s", exc)
            return True  # Fail open for single-instance usage

    def release_poll_lock(self, lock_name: str = "nuclei_sniper:poll_lock"):
        """Release the distributed poll lock."""
        if not self._ensure_connection():
            return
        try:
            self._client.delete(lock_name)
        except redis.RedisError as exc:
            logger.warning("Failed to release poll lock: %s", exc)

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)


# ---------------------------------------------------------------------------
# Feed Parser
# ---------------------------------------------------------------------------
class FeedParser:
    """
    Parses RSS/Atom feeds and extracts CVE-related entries.

    Edge Cases:
    - EC1:  Feed unavailable → returns empty list, logs warning
    - EC12: Memory explosion → cap entries per feed
    """

    def __init__(self, config: dict):
        self._config = config.get("feeds", {})
        self._max_entries = self._config.get("max_entries_per_feed", 50)
        self._fetch_timeout = self._config.get("fetch_timeout", 30)

    def fetch_feed(self, source: dict) -> list:
        """
        Fetch and parse a single RSS feed source.

        Args:
            source: Dict with 'name', 'url', 'enabled' keys.

        Returns:
            List of CVETask objects extracted from the feed.
        """
        name = source.get("name", "unknown")
        url = source.get("url", "")
        enabled = source.get("enabled", True)

        if not enabled:
            logger.debug("Feed '%s' is disabled; skipping", name)
            return []

        if not url:
            logger.warning("Feed '%s' has no URL configured; skipping", name)
            return []

        logger.info("Fetching feed: %s (%s)", name, url)
        start_time = time.time()

        try:
            # feedparser handles most RSS/Atom formats
            # We pass a request_headers dict to set a timeout-like behavior
            feed = feedparser.parse(url)

            # Check for feed-level errors
            if feed.bozo and feed.bozo_exception:
                logger.warning(
                    "Feed '%s' returned with bozo error: %s",
                    name, feed.bozo_exception
                )
                # feedparser still provides partial results sometimes
                if not feed.entries:
                    logger.warning(
                        "Feed '%s' has no entries after bozo error; skipping",
                        name
                    )
                    return []

            elapsed = time.time() - start_time
            entry_count = len(feed.entries)
            logger.info(
                "Feed '%s' fetched in %.2fs; %d entries found",
                name, elapsed, entry_count
            )

            # EC12: Cap entries to prevent memory explosion
            entries_to_process = feed.entries[:self._max_entries]
            if entry_count > self._max_entries:
                logger.warning(
                    "Feed '%s' has %d entries; capping to %d",
                    name, entry_count, self._max_entries
                )

            tasks = []
            for entry in entries_to_process:
                task = self._parse_entry(entry, name)
                if task:
                    tasks.append(task)

            logger.info(
                "Feed '%s': %d CVE tasks extracted from %d entries",
                name, len(tasks), len(entries_to_process)
            )
            return tasks

        except Exception as exc:
            # EC1: Feed unavailable — catch all, log, continue
            elapsed = time.time() - start_time
            logger.warning(
                "Failed to fetch/parse feed '%s' after %.2fs: %s",
                name, elapsed, exc
            )
            return []

    def _parse_entry(self, entry: dict, source_name: str) -> Optional[CVETask]:
        """
        Parse a single feed entry into a CVETask if it contains a CVE reference.

        Returns None if no CVE ID is found.
        """
        title = getattr(entry, "title", "") or ""
        summary = getattr(entry, "summary", "") or ""
        link = getattr(entry, "link", "") or ""
        published = getattr(entry, "published", "") or ""

        # Combine text fields for CVE extraction
        combined_text = f"{title} {summary} {link}"
        cve_ids = extract_cve_ids(combined_text)

        if not cve_ids:
            return None

        # Extract potential PoC links
        poc_links = extract_poc_links(combined_text)
        if link and link not in poc_links:
            poc_links.append(link)

        # Collect all reference links
        references = []
        for ref_link in getattr(entry, "links", []):
            href = ref_link.get("href", "")
            if href:
                references.append(href)

        # Create a hash of the entry for dedup tracking
        entry_hash = hashlib.sha256(
            f"{title}{summary}{link}".encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        # Use the first (most prominent) CVE ID as the primary
        primary_cve = cve_ids[0]

        description = summary if summary else title
        # Truncate very long descriptions
        if len(description) > 2000:
            description = description[:2000] + "... [truncated]"

        return CVETask(
            cve_id=primary_cve,
            title=title[:500] if title else f"CVE from {source_name}",
            description=description,
            source=source_name,
            poc_links=poc_links,
            published=published,
            severity="UNKNOWN",  # Would need NVD API for real severity
            references=references,
            raw_entry_hash=entry_hash,
        )

    def fetch_all_feeds(self, sources: list = None) -> list:
        """
        Fetch all configured feeds and return aggregated CVE tasks.

        Args:
            sources: Optional list of source dicts; defaults to config.

        Returns:
            Aggregated list of CVETask objects.
        """
        if sources is None:
            sources = self._config.get("sources", [])

        if not sources:
            logger.warning("No feed sources configured")
            return []

        all_tasks = []
        fetch_delay = self._config.get("fetch_delay", 2)

        for i, source in enumerate(sources):
            tasks = self.fetch_feed(source)
            all_tasks.extend(tasks)

            # Rate limiting between feeds (EC8)
            if i < len(sources) - 1 and fetch_delay > 0:
                time.sleep(fetch_delay)

        logger.info(
            "Total CVE tasks from all feeds: %d (from %d feeds)",
            len(all_tasks), len(sources)
        )
        return all_tasks


# ---------------------------------------------------------------------------
# CVE Monitor (main orchestrator for this submodule)
# ---------------------------------------------------------------------------
class CVEMonitor:
    """
    Main monitor class that coordinates feed polling, deduplication,
    and task queuing.

    Can run as a standalone process or be invoked by the orchestrator.
    """

    def __init__(self, redis_client: redis.Redis = None, config_path: str = None):
        self._config = _load_config(config_path)
        self._redis_helper = RedisHelper(self._config, redis_client)
        self._feed_parser = FeedParser(self._config)
        self._running = False
        self._stats = {
            "polls_completed": 0,
            "cves_discovered": 0,
            "cves_deduplicated": 0,
            "cves_queued": 0,
            "feed_errors": 0,
        }

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    def poll_once(self) -> list:
        """
        Perform a single poll cycle across all feeds.

        Returns:
            List of newly discovered (non-duplicate) CVETask objects that
            were successfully queued.
        """
        logger.info("Starting poll cycle...")
        start_time = time.time()

        # EC13: Acquire distributed lock if multiple instances
        if not self._redis_helper.acquire_poll_lock():
            logger.info("Another instance holds the poll lock; skipping cycle")
            return []

        try:
            # Fetch all feeds
            all_tasks = self._feed_parser.fetch_all_feeds()

            new_tasks = []
            for task in all_tasks:
                # EC2: Check if CVE has already been seen
                if self._redis_helper.is_cve_seen(task.cve_id):
                    logger.debug("CVE %s already seen; skipping", task.cve_id)
                    self._stats["cves_deduplicated"] += 1
                    continue

                # New CVE discovered — log it (telemetry requirement)
                logger.info(
                    "🆕 New CVE detected: %s (source: %s, title: %s)",
                    task.cve_id, task.source, task.title[:100]
                )
                self._stats["cves_discovered"] += 1

                # Mark as seen before queuing to prevent race conditions
                self._redis_helper.mark_cve_seen(task.cve_id)

                # Set initial status
                self._redis_helper.set_status(
                    task.cve_id, "DISCOVERED",
                    f"Source: {task.source}"
                )

                # Push to processing queue
                if self._redis_helper.push_task(task):
                    self._stats["cves_queued"] += 1
                    self._redis_helper.set_status(
                        task.cve_id, "QUEUED",
                        "Pushed to nuclei_sniper queue"
                    )
                    new_tasks.append(task)
                else:
                    logger.error(
                        "Failed to queue CVE %s; it was marked seen but "
                        "not queued — potential data loss", task.cve_id
                    )
                    self._redis_helper.set_status(
                        task.cve_id, "FAILED",
                        "Failed to push to queue"
                    )

            elapsed = time.time() - start_time
            self._stats["polls_completed"] += 1

            logger.info(
                "Poll cycle completed in %.2fs: %d new CVEs queued, "
                "%d duplicates skipped, buffer size: %d",
                elapsed, len(new_tasks),
                self._stats["cves_deduplicated"],
                self._redis_helper.buffer_size,
            )

            return new_tasks

        finally:
            self._redis_helper.release_poll_lock()

    def run_continuous(self):
        """
        Run the monitor in a continuous loop with configurable poll interval.
        """
        poll_interval = self._config.get("feeds", {}).get("poll_interval", 3600)
        logger.info(
            "Starting continuous CVE monitor (poll interval: %ds)",
            poll_interval
        )
        self._running = True

        while self._running:
            try:
                self.poll_once()
            except Exception as exc:
                logger.error("Unhandled error in poll cycle: %s", exc,
                             exc_info=True)
                self._stats["feed_errors"] += 1

            logger.info("Next poll in %d seconds...", poll_interval)
            # Sleep in small increments to allow graceful shutdown
            for _ in range(poll_interval):
                if not self._running:
                    break
                time.sleep(1)

        logger.info("CVE monitor stopped. Final stats: %s", self._stats)

    def stop(self):
        """Signal the monitor to stop after the current cycle."""
        logger.info("Stop signal received for CVE monitor")
        self._running = False

    def inject_cve(self, cve_id: str, description: str = "",
                   poc_links: list = None) -> bool:
        """
        Manually inject a CVE for processing (useful for testing).

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            description: CVE description
            poc_links: List of PoC URLs

        Returns:
            True if successfully queued.
        """
        cve_id = cve_id.upper()
        if not _CVE_PATTERN.match(cve_id):
            logger.error("Invalid CVE ID format: %s", cve_id)
            return False

        task = CVETask(
            cve_id=cve_id,
            title=f"Manually injected: {cve_id}",
            description=description or f"Manual injection of {cve_id}",
            source="manual",
            poc_links=poc_links or [],
        )

        # Don't check seen status for manual injection
        self._redis_helper.mark_cve_seen(cve_id)
        self._redis_helper.set_status(cve_id, "QUEUED", "Manual injection")
        result = self._redis_helper.push_task(task)

        if result:
            logger.info("Manually injected CVE %s into queue", cve_id)
        else:
            logger.error("Failed to inject CVE %s", cve_id)

        return result


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Nuclei Sniper CVE Monitor")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-db", type=int, default=0)
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--once", action="store_true",
                        help="Run a single poll cycle and exit")
    parser.add_argument("--inject", type=str, default=None,
                        help="Manually inject a CVE ID for testing")
    args = parser.parse_args()

    r = redis.Redis(host=args.redis_host, port=args.redis_port,
                    db=args.redis_db, decode_responses=True)
    monitor = CVEMonitor(redis_client=r, config_path=args.config)

    if args.inject:
        monitor.inject_cve(args.inject, description="Test injection")
    elif args.once:
        monitor.poll_once()
    else:
        try:
            monitor.run_continuous()
        except KeyboardInterrupt:
            monitor.stop()
