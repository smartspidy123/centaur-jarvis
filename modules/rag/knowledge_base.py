"""
Security Knowledge Base Manager
Handles loading/processing security resources and searching
"""
import os
import json
from typing import List, Dict, Optional
from pathlib import Path

import yaml

from shared.logger import get_logger
from .vector_store import ZillizClient
from .embedder import LocalEmbedder

logger = get_logger("rag.knowledge_base")

class SecurityKnowledgeBase:
    """Main interface for RAG operations"""
    
    def __init__(self, config_path: str = None):
        self.vector_store = ZillizClient(config_path)
        self.embedder = LocalEmbedder()
        
        # Load config
        with open(config_path or Path(__file__).parent / 'config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
    
    def add_text(self, text: str, source: str, category: str, tags: List[str] = None):
        """Add a single text chunk to knowledge base"""
        embedding = self.embedder.encode(text)
        metadata = {
            'source': source,
            'category': category,
            'tags': tags or []
        }
        self.vector_store.insert([embedding], [text], [metadata])
    
    def add_batch(self, items: List[Dict]):
        """
        Add multiple items at once
        Each item: {'text': str, 'source': str, 'category': str, 'tags': List[str]}
        """
        texts = [item['text'] for item in items]
        embeddings = self.embedder.encode_batch(texts)
        
        metadata = []
        for item in items:
            metadata.append({
                'source': item['source'],
                'category': item['category'],
                'tags': item.get('tags', [])
            })
        
        self.vector_store.insert(embeddings, texts, metadata)
    
    def search(self, query: str, limit: int = 5, category: str = None) -> List[Dict]:
        """Search knowledge base"""
        query_vector = self.embedder.encode(query)[0]
        filter_expr = f"category == '{category}'" if category else ""
        
        results = self.vector_store.search(query_vector, limit, filter_expr)
        return results
    
    def load_hacktricks(self, file_path: str):
        """
        Load pre-processed HackTricks data
        Expected format: JSONL with 'text', 'category', 'tags' fields
        """
        logger.info(f"Loading HackTricks from {file_path}")
        batch = []
        count = 0
        
        with open(file_path, 'r') as f:
            for line in f:
                item = json.loads(line)
                batch.append({
                    'text': item['text'],
                    'source': 'hacktricks',
                    'category': item.get('category', 'general'),
                    'tags': item.get('tags', [])
                })
                
                if len(batch) >= 100:
                    self.add_batch(batch)
                    count += len(batch)
                    batch = []
                    logger.info(f"Processed {count} items...")
        
        if batch:
            self.add_batch(batch)
            count += len(batch)
        
        logger.info(f"✅ Loaded {count} HackTricks items")
    
    def stats(self) -> Dict:
        """Get knowledge base stats"""
        return self.vector_store.get_stats()
