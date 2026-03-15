"""
Knowledge Graph — Centaur-Jarvis Chain Attack Module
=====================================================
Manages a graph of discovered assets (URLs, credentials, sessions, vulnerabilities, etc.).
Supports Redis-backed storage with in-memory fallback.
Listens to results:incoming and auto-populates graph from findings.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logger — shared.logger with fallback
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("chain_attack.knowledge_graph")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}'
    )
    logger = logging.getLogger("chain_attack.knowledge_graph")

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
try:
    import redis
except ImportError:
    redis = None  # type: ignore

# ---------------------------------------------------------------------------
# NetworkX (optional — for path-finding)
# ---------------------------------------------------------------------------
try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    nx = None  # type: ignore
    HAS_NX = False

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------
from modules.chain_attack.models import (
    GraphNode, GraphEdge, NodeType, EdgeRelation
)

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
try:
    import yaml
    _cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(_cfg_path):
        with open(_cfg_path, "r") as _f:
            _CONFIG = yaml.safe_load(_f) or {}
    else:
        _CONFIG = {}
except Exception:
    _CONFIG = {}

_REDIS_CFG = _CONFIG.get("redis", {})
_GRAPH_CFG = _CONFIG.get("graph", {})

GRAPH_PREFIX = _REDIS_CFG.get("graph_prefix", "chain:graph")
RESULT_QUEUE = _REDIS_CFG.get("result_queue", "results:incoming")
GRAPH_STORAGE = _GRAPH_CFG.get("storage", "redis")
GRAPH_TTL = int(_GRAPH_CFG.get("ttl", 604800))


class KnowledgeGraph:
    """
    Thread-safe knowledge graph with Redis or in-memory storage.

    Nodes and edges are uniquely identified. Deduplication is done via
    node fingerprints. Supports path-finding when networkx is available.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        storage: str = GRAPH_STORAGE,
        prefix: str = GRAPH_PREFIX,
        ttl: int = GRAPH_TTL,
    ):
        self._storage_mode = storage  # "redis" or "memory"
        self._prefix = prefix
        self._ttl = ttl
        self._lock = threading.RLock()

        # In-memory structures (used when storage="memory" or as Redis fallback)
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adj: Dict[str, Set[str]] = defaultdict(set)  # node_id -> set of edge_keys
        self._fingerprints: Dict[str, str] = {}  # fingerprint -> node_id

        # Redis
        self._redis: Optional[Any] = None
        if storage == "redis" and redis_client is not None:
            self._redis = redis_client
        elif storage == "redis" and redis is not None:
            try:
                self._redis = redis.Redis(
                    host=os.getenv("REDIS_HOST", "localhost"),
                    port=int(os.getenv("REDIS_PORT", 6379)),
                    db=int(os.getenv("REDIS_DB", 0)),
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                )
                self._redis.ping()
                logger.info("KnowledgeGraph connected to Redis.")
            except Exception as exc:
                logger.warning(
                    f"Redis unavailable, falling back to in-memory storage: {exc}"
                )
                self._redis = None
                self._storage_mode = "memory"
        else:
            self._storage_mode = "memory"
            logger.info("KnowledgeGraph using in-memory storage.")

        # NetworkX mirror (always maintained if available, for path queries)
        self._nxg: Optional[Any] = nx.DiGraph() if HAS_NX else None

        logger.info(
            f"KnowledgeGraph initialized. storage={self._storage_mode}, "
            f"prefix={self._prefix}, ttl={self._ttl}s, networkx={HAS_NX}"
        )

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> GraphNode:
        """
        Add a node to the graph. Deduplicates by fingerprint.
        Returns the existing node if a duplicate is found.
        """
        with self._lock:
            fp = node.fingerprint()

            # Check for existing node with same fingerprint
            existing_id = self._get_fingerprint_owner(fp)
            if existing_id:
                logger.debug(f"Deduplicated node {node.id} -> existing {existing_id}")
                existing = self.get_node(existing_id)
                if existing:
                    # Merge attributes (new attributes take precedence for non-empty values)
                    for k, v in node.attributes.items():
                        if v:
                            existing.attributes[k] = v
                    self._persist_node(existing)
                    return existing
                # Fingerprint points to missing node — clean up
                self._remove_fingerprint(fp)

            # Store new node
            self._persist_node(node)
            self._set_fingerprint(fp, node.id)

            # NetworkX mirror
            if self._nxg is not None:
                self._nxg.add_node(
                    node.id,
                    node_type=node.node_type,
                    label=node.label,
                    **node.attributes,
                )

            logger.info(
                f"Node added: type={node.node_type}, id={node.id[:12]}, label={node.label}"
            )
            return node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by ID."""
        with self._lock:
            if self._storage_mode == "redis" and self._redis:
                try:
                    key = f"{self._prefix}:node:{node_id}"
                    data = self._redis.hgetall(key)
                    if data:
                        return GraphNode.from_dict(data)
                except Exception as exc:
                    logger.warning(f"Redis get_node failed, trying memory: {exc}")
            return self._nodes.get(node_id)

    def remove_node(self, node_id: str) -> bool:
        """Remove a node and all connected edges."""
        with self._lock:
            node = self.get_node(node_id)
            if not node:
                return False

            # Remove edges
            edge_keys = list(self._get_node_edges(node_id))
            for ek in edge_keys:
                edge = self._get_edge_by_key(ek)
                if edge:
                    self._remove_edge_internal(ek, edge)

            # Remove fingerprint
            fp = node.fingerprint()
            self._remove_fingerprint(fp)

            # Remove node
            if self._storage_mode == "redis" and self._redis:
                try:
                    self._redis.delete(f"{self._prefix}:node:{node_id}")
                    self._redis.srem(f"{self._prefix}:node_ids", node_id)
                except Exception as exc:
                    logger.warning(f"Redis remove_node error: {exc}")
            self._nodes.pop(node_id, None)

            if self._nxg is not None and node_id in self._nxg:
                self._nxg.remove_node(node_id)

            logger.info(f"Node removed: {node_id[:12]}")
            return True

    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """Return all nodes of a given type."""
        with self._lock:
            results = []
            for node_id in self._all_node_ids():
                node = self.get_node(node_id)
                if node and node.node_type == node_type:
                    results.append(node)
            return results

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self,
        from_id: str,
        to_id: str,
        relation: str,
        attributes: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> Optional[GraphEdge]:
        """Add a directed edge between two nodes."""
        with self._lock:
            # Validate nodes exist
            if not self.get_node(from_id):
                logger.warning(f"add_edge: source node {from_id[:12]} not found.")
                return None
            if not self.get_node(to_id):
                logger.warning(f"add_edge: target node {to_id[:12]} not found.")
                return None

            edge = GraphEdge(
                from_id=from_id,
                to_id=to_id,
                relation=relation,
                attributes=attributes or {},
                confidence=confidence,
            )
            ek = edge.edge_key()

            # Check for existing edge (deduplicate)
            existing = self._get_edge_by_key(ek)
            if existing:
                # Update confidence to max
                existing.confidence = max(existing.confidence, confidence)
                if attributes:
                    existing.attributes.update(attributes)
                self._persist_edge(existing)
                return existing

            self._persist_edge(edge)
            self._register_edge_for_node(from_id, ek)
            self._register_edge_for_node(to_id, ek)

            if self._nxg is not None:
                self._nxg.add_edge(
                    from_id, to_id,
                    relation=relation,
                    confidence=confidence,
                    **(attributes or {}),
                )

            logger.info(
                f"Edge added: {from_id[:8]}-[{relation}]->{to_id[:8]}"
            )
            return edge

    def get_related(
        self, node_id: str, relation: Optional[str] = None, direction: str = "outgoing"
    ) -> List[Tuple[GraphNode, GraphEdge]]:
        """
        Get nodes related to `node_id`.
        direction: 'outgoing', 'incoming', or 'both'.
        """
        with self._lock:
            results = []
            edge_keys = self._get_node_edges(node_id)
            for ek in edge_keys:
                edge = self._get_edge_by_key(ek)
                if not edge:
                    continue
                if relation and edge.relation != relation:
                    continue

                other_id = None
                if direction in ("outgoing", "both") and edge.from_id == node_id:
                    other_id = edge.to_id
                if direction in ("incoming", "both") and edge.to_id == node_id:
                    other_id = edge.from_id

                if other_id:
                    other_node = self.get_node(other_id)
                    if other_node:
                        results.append((other_node, edge))
            return results

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------

    def find_path(
        self,
        start_type: str,
        end_type: str,
        max_paths: int = 5,
    ) -> List[List[str]]:
        """
        Find possible attack paths from nodes of start_type to nodes of end_type.
        Returns list of paths (each path is a list of node IDs).
        Uses NetworkX if available; otherwise BFS fallback.
        """
        with self._lock:
            start_nodes = self.get_nodes_by_type(start_type)
            end_nodes = self.get_nodes_by_type(end_type)

            if not start_nodes or not end_nodes:
                return []

            end_ids = {n.id for n in end_nodes}
            paths: List[List[str]] = []

            if HAS_NX and self._nxg is not None:
                for sn in start_nodes:
                    for en in end_nodes:
                        try:
                            for p in nx.all_simple_paths(
                                self._nxg, sn.id, en.id, cutoff=10
                            ):
                                paths.append(list(p))
                                if len(paths) >= max_paths:
                                    return paths
                        except (nx.NetworkXNoPath, nx.NodeNotFound):
                            continue
            else:
                # BFS fallback
                for sn in start_nodes:
                    found = self._bfs_paths(sn.id, end_ids, max_depth=10)
                    paths.extend(found)
                    if len(paths) >= max_paths:
                        break

            return paths[:max_paths]

    def _bfs_paths(
        self, start: str, targets: Set[str], max_depth: int = 10
    ) -> List[List[str]]:
        """Simple BFS path finder."""
        queue: List[Tuple[str, List[str]]] = [(start, [start])]
        visited: Set[str] = set()
        results: List[List[str]] = []

        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            if current in targets and current != start:
                results.append(path)
                if len(results) >= 5:
                    return results
                continue
            if current in visited:
                continue
            visited.add(current)

            for node, edge in self.get_related(current, direction="outgoing"):
                if node.id not in visited:
                    queue.append((node.id, path + [node.id]))

        return results

    # ------------------------------------------------------------------
    # Graph summary (for AI planner)
    # ------------------------------------------------------------------

    def summary(self, max_nodes: int = 100, max_edges: int = 200) -> Dict[str, Any]:
        """Generate a summary of the graph suitable for AI consumption."""
        with self._lock:
            all_ids = list(self._all_node_ids())[:max_nodes]
            nodes_summary = []
            for nid in all_ids:
                node = self.get_node(nid)
                if node:
                    nodes_summary.append({
                        "id": node.id,
                        "type": node.node_type,
                        "label": node.label,
                        "attrs": {
                            k: v for k, v in node.attributes.items()
                            if k not in ("password", "token", "secret")
                        },
                    })

            edges_summary = []
            seen_edges: Set[str] = set()
            for nid in all_ids:
                for ek in self._get_node_edges(nid):
                    if ek in seen_edges:
                        continue
                    seen_edges.add(ek)
                    edge = self._get_edge_by_key(ek)
                    if edge:
                        edges_summary.append({
                            "from": edge.from_id,
                            "to": edge.to_id,
                            "relation": edge.relation,
                            "confidence": edge.confidence,
                        })
                    if len(edges_summary) >= max_edges:
                        break

            type_counts: Dict[str, int] = defaultdict(int)
            for n in nodes_summary:
                type_counts[n["type"]] += 1

            return {
                "total_nodes": len(all_ids),
                "total_edges": len(seen_edges),
                "type_counts": dict(type_counts),
                "nodes": nodes_summary,
                "edges": edges_summary,
            }

    def stats(self) -> Dict[str, Any]:
        """Quick stats without full serialization."""
        with self._lock:
            all_ids = list(self._all_node_ids())
            type_counts: Dict[str, int] = defaultdict(int)
            for nid in all_ids:
                node = self.get_node(nid)
                if node:
                    type_counts[node.node_type] += 1

            edge_count = 0
            seen: Set[str] = set()
            for nid in all_ids:
                for ek in self._get_node_edges(nid):
                    if ek not in seen:
                        seen.add(ek)
                        edge_count += 1

            return {
                "total_nodes": len(all_ids),
                "total_edges": edge_count,
                "type_counts": dict(type_counts),
                "storage": self._storage_mode,
            }

    # ------------------------------------------------------------------
    # Findings ingestion
    # ------------------------------------------------------------------

    def ingest_findings(self, task_result: Dict[str, Any]) -> int:
        """
        Ingest findings from a task result and add relevant nodes/edges.
        Returns the number of nodes added or updated.
        """
        added = 0
        module = task_result.get("module", "unknown")
        task_id = task_result.get("task_id", "")
        data = task_result.get("data", {})

        if not isinstance(data, dict):
            logger.warning(f"ingest_findings: 'data' is not a dict, skipping.")
            return 0

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = [findings] if findings else []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            try:
                nodes_added = self._ingest_single_finding(finding, module, task_id)
                added += nodes_added
            except Exception as exc:
                logger.error(f"Error ingesting finding: {exc}", exc_info=True)

        # Also try to extract URLs, credentials, etc. from top-level data
        try:
            added += self._ingest_from_data(data, module, task_id)
        except Exception as exc:
            logger.error(f"Error ingesting from data: {exc}", exc_info=True)

        if added > 0:
            logger.info(f"Ingested {added} nodes from task {task_id} (module={module})")

        return added

    def _ingest_single_finding(
        self, finding: Dict[str, Any], module: str, task_id: str
    ) -> int:
        """Parse a single finding dict and add nodes + edges."""
        added = 0

        # Vulnerability node
        vuln_type = finding.get("type") or finding.get("vuln_type") or finding.get("name")
        url = finding.get("url") or finding.get("target") or finding.get("endpoint")
        severity = finding.get("severity", "info")
        cve = finding.get("cve", "")

        if vuln_type:
            vuln_node = GraphNode(
                node_type=NodeType.VULNERABILITY.value,
                label=f"Vuln:{vuln_type}",
                attributes={
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "cve": cve,
                    "url": url or "",
                    "details": finding.get("details", ""),
                    "payload": finding.get("payload", ""),
                },
                source_module=module,
                source_task_id=task_id,
            )
            vuln_node = self.add_node(vuln_node)
            added += 1

            # If we have a URL, create URL node and link
            if url:
                url_node = GraphNode(
                    node_type=NodeType.URL.value,
                    label=url[:80],
                    attributes={"url": url},
                    source_module=module,
                    source_task_id=task_id,
                )
                url_node = self.add_node(url_node)
                added += 1
                self.add_edge(
                    url_node.id, vuln_node.id,
                    EdgeRelation.VULNERABLE_TO.value,
                    confidence=0.9,
                )

        # Credential
        username = finding.get("username")
        password = finding.get("password")
        if username:
            cred_node = GraphNode(
                node_type=NodeType.CREDENTIAL.value,
                label=f"Cred:{username}",
                attributes={
                    "username": username,
                    "password": password or "",
                    "target": url or "",
                },
                source_module=module,
                source_task_id=task_id,
            )
            cred_node = self.add_node(cred_node)
            added += 1

            if url:
                url_node_for_cred = GraphNode(
                    node_type=NodeType.URL.value,
                    label=url[:80],
                    attributes={"url": url},
                    source_module=module,
                    source_task_id=task_id,
                )
                url_node_for_cred = self.add_node(url_node_for_cred)
                self.add_edge(
                    url_node_for_cred.id, cred_node.id,
                    EdgeRelation.HAS_CREDENTIAL.value,
                )

        # Endpoint / Parameter
        params = finding.get("parameters") or finding.get("params")
        if isinstance(params, list):
            for p in params:
                pname = p if isinstance(p, str) else p.get("name", "")
                if pname:
                    param_node = GraphNode(
                        node_type=NodeType.PARAMETER.value,
                        label=f"Param:{pname}",
                        attributes={"name": pname, "url": url or ""},
                        source_module=module,
                        source_task_id=task_id,
                    )
                    param_node = self.add_node(param_node)
                    added += 1

        return added

    def _ingest_from_data(
        self, data: Dict[str, Any], module: str, task_id: str
    ) -> int:
        """Extract top-level URLs, endpoints, etc. from data dict."""
        added = 0

        # endpoints list
        endpoints = data.get("endpoints", [])
        if isinstance(endpoints, list):
            for ep in endpoints[:200]:  # cap to avoid runaway
                if isinstance(ep, str):
                    node = GraphNode(
                        node_type=NodeType.ENDPOINT.value,
                        label=ep[:80],
                        attributes={"url": ep},
                        source_module=module,
                        source_task_id=task_id,
                    )
                    self.add_node(node)
                    added += 1
                elif isinstance(ep, dict) and ep.get("url"):
                    node = GraphNode(
                        node_type=NodeType.ENDPOINT.value,
                        label=ep["url"][:80],
                        attributes=ep,
                        source_module=module,
                        source_task_id=task_id,
                    )
                    self.add_node(node)
                    added += 1

        # technologies
        techs = data.get("technologies", [])
        if isinstance(techs, list):
            for t in techs[:50]:
                name = t if isinstance(t, str) else t.get("name", "")
                if name:
                    node = GraphNode(
                        node_type=NodeType.TECHNOLOGY.value,
                        label=f"Tech:{name}",
                        attributes={"name": name, "version": t.get("version", "") if isinstance(t, dict) else ""},
                        source_module=module,
                        source_task_id=task_id,
                    )
                    self.add_node(node)
                    added += 1

        # ports
        ports = data.get("ports", [])
        if isinstance(ports, list):
            host = data.get("host", data.get("target", "unknown"))
            for p in ports[:500]:
                port_num = p if isinstance(p, (int, str)) else p.get("port", "")
                if port_num:
                    node = GraphNode(
                        node_type=NodeType.PORT.value,
                        label=f"Port:{port_num}",
                        attributes={"port": str(port_num), "host": host},
                        source_module=module,
                        source_task_id=task_id,
                    )
                    self.add_node(node)
                    added += 1

        return added

    # ------------------------------------------------------------------
    # Internal persistence helpers
    # ------------------------------------------------------------------

    def _persist_node(self, node: GraphNode):
        self._nodes[node.id] = node
        if self._storage_mode == "redis" and self._redis:
            try:
                key = f"{self._prefix}:node:{node.id}"
                self._redis.hset(key, mapping=node.to_dict())
                if self._ttl > 0:
                    self._redis.expire(key, self._ttl)
                self._redis.sadd(f"{self._prefix}:node_ids", node.id)
            except Exception as exc:
                logger.warning(f"Redis persist_node failed: {exc}")

    def _persist_edge(self, edge: GraphEdge):
        ek = edge.edge_key()
        self._edges[ek] = edge
        if self._storage_mode == "redis" and self._redis:
            try:
                key = f"{self._prefix}:edge:{ek}"
                self._redis.hset(key, mapping=edge.to_dict())
                if self._ttl > 0:
                    self._redis.expire(key, self._ttl)
                self._redis.sadd(f"{self._prefix}:edge_keys", ek)
            except Exception as exc:
                logger.warning(f"Redis persist_edge failed: {exc}")

    def _get_edge_by_key(self, ek: str) -> Optional[GraphEdge]:
        if ek in self._edges:
            return self._edges[ek]
        if self._storage_mode == "redis" and self._redis:
            try:
                data = self._redis.hgetall(f"{self._prefix}:edge:{ek}")
                if data:
                    edge = GraphEdge.from_dict(data)
                    self._edges[ek] = edge
                    return edge
            except Exception:
                pass
        return None

    def _remove_edge_internal(self, ek: str, edge: GraphEdge):
        self._edges.pop(ek, None)
        self._adj.get(edge.from_id, set()).discard(ek)
        self._adj.get(edge.to_id, set()).discard(ek)
        if self._storage_mode == "redis" and self._redis:
            try:
                self._redis.delete(f"{self._prefix}:edge:{ek}")
                self._redis.srem(f"{self._prefix}:edge_keys", ek)
                self._redis.srem(f"{self._prefix}:node:{edge.from_id}:edges", ek)
                self._redis.srem(f"{self._prefix}:node:{edge.to_id}:edges", ek)
            except Exception:
                pass

    def _register_edge_for_node(self, node_id: str, edge_key: str):
        self._adj[node_id].add(edge_key)
        if self._storage_mode == "redis" and self._redis:
            try:
                self._redis.sadd(f"{self._prefix}:node:{node_id}:edges", edge_key)
            except Exception:
                pass

    def _get_node_edges(self, node_id: str) -> Set[str]:
        edges = set(self._adj.get(node_id, set()))
        if self._storage_mode == "redis" and self._redis:
            try:
                redis_edges = self._redis.smembers(
                    f"{self._prefix}:node:{node_id}:edges"
                )
                if redis_edges:
                    edges.update(redis_edges)
            except Exception:
                pass
        return edges

    def _all_node_ids(self) -> Set[str]:
        ids = set(self._nodes.keys())
        if self._storage_mode == "redis" and self._redis:
            try:
                redis_ids = self._redis.smembers(f"{self._prefix}:node_ids")
                if redis_ids:
                    ids.update(redis_ids)
            except Exception:
                pass
        return ids

    def _set_fingerprint(self, fp: str, node_id: str):
        self._fingerprints[fp] = node_id
        if self._storage_mode == "redis" and self._redis:
            try:
                self._redis.hset(f"{self._prefix}:fingerprints", fp, node_id)
            except Exception:
                pass

    def _get_fingerprint_owner(self, fp: str) -> Optional[str]:
        owner = self._fingerprints.get(fp)
        if not owner and self._storage_mode == "redis" and self._redis:
            try:
                owner = self._redis.hget(f"{self._prefix}:fingerprints", fp)
                if owner:
                    self._fingerprints[fp] = owner
            except Exception:
                pass
        return owner

    def _remove_fingerprint(self, fp: str):
        self._fingerprints.pop(fp, None)
        if self._storage_mode == "redis" and self._redis:
            try:
                self._redis.hdel(f"{self._prefix}:fingerprints", fp)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def clear(self):
        """Remove all graph data."""
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._adj.clear()
            self._fingerprints.clear()
            if self._nxg is not None:
                self._nxg.clear()
            if self._storage_mode == "redis" and self._redis:
                try:
                    cursor = 0
                    while True:
                        cursor, keys = self._redis.scan(
                            cursor, match=f"{self._prefix}:*", count=500
                        )
                        if keys:
                            self._redis.delete(*keys)
                        if cursor == 0:
                            break
                except Exception as exc:
                    logger.warning(f"Redis clear error: {exc}")
            logger.info("KnowledgeGraph cleared.")


# ---------------------------------------------------------------------------
# Standalone listener mode
# ---------------------------------------------------------------------------

class GraphListener:
    """
    Listens to results:incoming queue and feeds findings into KnowledgeGraph.
    Can be run as a standalone process.
    """

    def __init__(
        self,
        graph: Optional[KnowledgeGraph] = None,
        redis_client: Optional[Any] = None,
        result_queue: str = RESULT_QUEUE,
        poll_interval: float = 1.0,
    ):
        self._graph = graph or KnowledgeGraph(redis_client=redis_client)
        self._result_queue = result_queue
        self._poll_interval = poll_interval
        self._running = False
        self._redis = redis_client

        if not self._redis and redis is not None:
            try:
                self._redis = redis.Redis(
                    host=os.getenv("REDIS_HOST", "localhost"),
                    port=int(os.getenv("REDIS_PORT", 6379)),
                    db=int(os.getenv("REDIS_DB", 0)),
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
                self._redis.ping()
            except Exception as exc:
                logger.error(f"GraphListener cannot connect to Redis: {exc}")
                self._redis = None

    def start(self):
        """Start listening loop (blocking)."""
        if not self._redis:
            logger.error("GraphListener: No Redis connection. Cannot listen.")
            return

        self._running = True
        logger.info(f"GraphListener started. Listening on '{self._result_queue}'.")

        while self._running:
            try:
                # Use BRPOP for blocking pop (with timeout so we can check _running)
                result = self._redis.brpop(
                    self._result_queue, timeout=int(self._poll_interval)
                )
                if result is None:
                    continue

                _, raw = result
                try:
                    task_result = json.loads(raw) if isinstance(raw, str) else raw
                except (json.JSONDecodeError, TypeError):
                    logger.warning("GraphListener: invalid JSON in result queue.")
                    continue

                if not isinstance(task_result, dict):
                    continue

                count = self._graph.ingest_findings(task_result)
                if count > 0:
                    logger.info(
                        f"GraphListener ingested {count} nodes from "
                        f"task={task_result.get('task_id', 'unknown')}"
                    )
            except Exception as exc:
                logger.error(f"GraphListener error: {exc}", exc_info=True)
                time.sleep(2)

        logger.info("GraphListener stopped.")

    def stop(self):
        self._running = False


# ---------------------------------------------------------------------------
# Main (standalone execution)
# ---------------------------------------------------------------------------

def main():
    """Run the Knowledge Graph listener as a standalone process."""
    listener = GraphListener()

    def _signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down GraphListener...")
        listener.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    listener.start()


if __name__ == "__main__":
    main()
