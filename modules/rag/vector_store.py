"""
Vector Store Client for Zilliz Cloud (Milvus)
Handles connections, collection management, and CRUD operations
"""
import os
import time
import yaml
import json
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Import only what is available at the top level
from pymilvus import MilvusClient, DataType

# Load environment variables
load_dotenv()

# Placeholder for your shared logger
try:
    from shared.logger import get_logger
    logger = get_logger("rag.vector_store")
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("rag.vector_store")

class ZillizClient:
    """Thread-safe client for Zilliz Cloud operations"""

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        
        # Override with environment variables
        env_endpoint = os.getenv('ZILLIZ_ENDPOINT')
        env_token = os.getenv('ZILLIZ_TOKEN')
        if env_endpoint:
            self.config['zilliz']['endpoint'] = env_endpoint
        if env_token:
            self.config['zilliz']['token'] = env_token

        self.uri = self.config['zilliz']['endpoint']
        self.token = self.config['zilliz']['token']
        self.collection_name = self.config['zilliz']['collection_name']
        self.dimension = self.config['embedding']['dimension']

        if not self.uri or not self.token:
            raise ValueError("Zilliz endpoint and token must be set via config or env vars")

        self.client = None
        self._connect()
        self._ensure_collection()

    def _load_config(self, config_path):
        default_config = {
            'zilliz': {
                'endpoint': '',
                'token': '',
                'collection_name': 'security_knowledge_base',
            },
            'embedding': {
                'dimension': 384,
                'model': 'sentence-transformers/all-MiniLM-L6-v2'
            },
            'index': {
                'metric_type': 'COSINE',
                'index_type': 'AUTOINDEX'
            }
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
                    for k, v in file_config.items():
                        if k in default_config and isinstance(v, dict):
                            default_config[k].update(v)
                        else:
                            default_config[k] = v
            except Exception as e:
                logger.warning(f"Could not load config from {config_path}: {e}")
        return default_config

    def _connect(self):
        try:
            self.client = MilvusClient(uri=self.uri, token=self.token)
            self.client.list_collections()
            logger.info(f"✅ Connected to Zilliz Cloud at {self.uri}")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Zilliz: {e}")
            raise

    def _ensure_collection(self):
        """Create collection and index if they don't exist."""
        # 1. Create collection if missing
        if not self.client.has_collection(self.collection_name):
            schema = self.client.create_schema(auto_id=True, enable_dynamic_field=True)
            schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True)
            schema.add_field(field_name="vector", datatype=DataType.FLOAT_VECTOR, dim=self.dimension)
            schema.add_field(field_name="text", datatype=DataType.VARCHAR, max_length=65535)
            schema.add_field(field_name="source", datatype=DataType.VARCHAR, max_length=512)
            schema.add_field(field_name="category", datatype=DataType.VARCHAR, max_length=128)
            schema.add_field(field_name="tags", datatype=DataType.JSON)
            schema.add_field(field_name="created_at", datatype=DataType.INT64)
            
            self.client.create_collection(
                collection_name=self.collection_name, 
                schema=schema
            )
            logger.info(f"Created collection '{self.collection_name}'")
        else:
            logger.info(f"Collection '{self.collection_name}' already exists")

        # 2. Ensure Index exists (This fixes your Code 700 error)
        res = self.client.list_indexes(collection_name=self.collection_name)
        # If no index exists on the 'vector' field, create it
        if "vector" not in res:
            logger.info(f"Index not found. Creating index for {self.collection_name}...")
            index_params = self.client.prepare_index_params()
            index_params.add_index(
                field_name="vector",
                metric_type=self.config['index']['metric_type'],
                index_type=self.config['index']['index_type']
            )
            self.client.create_index(
                collection_name=self.collection_name,
                index_params=index_params
            )
            logger.info("✅ Index created successfully")

    def _ensure_loaded(self):
        """Ensure collection is loaded in memory."""
        try:
            # Check load status first to avoid redundant calls
            status = self.client.get_load_state(collection_name=self.collection_name)
            if status.get("state") != "Loaded":
                logger.info(f"Loading collection {self.collection_name}...")
                self.client.load_collection(self.collection_name)
                # Small wait for Zilliz to finalize load
                time.sleep(1) 
        except Exception as e:
            logger.error(f"❌ Load failed: {e}")
            raise # Raise so the search doesn't attempt to run on an empty load

    def search(self, query_vector: List[float], limit: int = 10, filter_expr: str = "") -> List[Dict]:
        self._ensure_loaded()
        try:
            results = self.client.search(
                collection_name=self.collection_name,
                data=[query_vector],
                limit=limit,
                output_fields=["text", "source", "category", "tags"],
                filter=filter_expr
            )

            formatted = []
            for hits in results:
                for hit in hits:
                    # Accessing entity fields correctly for MilvusClient
                    entity = hit.get('entity', {})
                    formatted.append({
                        'id': hit.get('id'),
                        'score': hit.get('distance'),
                        'text': entity.get('text', ''),
                        'source': entity.get('source', 'unknown'),
                        'category': entity.get('category', 'unknown'),
                        'tags': entity.get('tags', [])
                    })
            return formatted
        except Exception as e:
            logger.error(f"❌ Search failed: {e}")
            return []

    def insert(self, vectors: List[List[float]], texts: List[str], metadata: List[Dict]) -> bool:
        if not (len(vectors) == len(texts) == len(metadata)):
            raise ValueError("Input lists must have the same length")

        data = []
        for vec, txt, meta in zip(vectors, texts, metadata):
            row = {
                "vector": vec,
                "text": txt,
                "created_at": int(time.time())
            }
            row.update(meta)
            data.append(row)

        try:
            res = self.client.insert(collection_name=self.collection_name, data=data)
            logger.info(f"✅ Inserted {len(res['ids'])} vectors")
            return True
        except Exception as e:
            logger.error(f"❌ Insert failed: {e}")
            return False

    def delete_by_source(self, source: str) -> bool:
        try:
            self.client.delete(
                collection_name=self.collection_name,
                filter=f"source == '{source}'"
            )
            logger.info(f"✅ Deleted vectors from source '{source}'")
            return True
        except Exception as e:
            logger.error(f"❌ Delete failed: {e}")
            return False

    def get_stats(self) -> Dict:
        try:
            stats = self.client.get_collection_stats(self.collection_name)
            return {
                'row_count': stats.get('row_count', 0),
                'collection': self.collection_name,
                'connected': True
            }
        except Exception as e:
            logger.error(f"❌ Stats failed: {e}")
            return {'connected': False, 'error': str(e)}