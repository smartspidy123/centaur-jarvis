#!/usr/bin/env python3
"""
RAG Data Ingestion Script
Loads security knowledge sources, chunks, embeds, and inserts into Zilliz.
"""
import os
import sys
import glob
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.rag.vector_store import ZillizClient
from modules.rag.embedder import LocalEmbedder
from shared.logger import get_logger

logger = get_logger("rag.ingest")

def chunk_text(text, chunk_size=500, overlap=50):
    """Split text into overlapping chunks."""
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size - overlap):
        chunk = ' '.join(words[i:i+chunk_size])
        if chunk:
            chunks.append(chunk)
    return chunks

def process_hacktricks_files(data_dir):
    """Process HackTricks markdown files."""
    files = glob.glob(f"{data_dir}/**/*.md", recursive=True)
    items = []
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            # Extract category from file path
            category = Path(file_path).parent.name
            chunks = chunk_text(content)
            for chunk in chunks:
                items.append({
                    'text': chunk,
                    'source': 'hacktricks',
                    'category': category,
                    'tags': []
                })
            logger.info(f"Processed {file_path}: {len(chunks)} chunks")
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
    return items

def main():
    # Configuration
    data_dir = os.path.join(Path(__file__).parent.parent.parent, 'data')
    config_path = os.path.join(Path(__file__).parent, 'config.yaml')
    
    # Initialize clients
    embedder = LocalEmbedder()
    vector_store = ZillizClient(config_path)
    
    # Gather all items
    all_items = []
    
    # Process HackTricks if present
    hacktricks_dir = os.path.join(data_dir, 'hacktricks')
    if os.path.exists(hacktricks_dir):
        logger.info("Processing HackTricks...")
        items = process_hacktricks_files(hacktricks_dir)
        all_items.extend(items)
    
    # You can add similar functions for PortSwigger, Payloads, etc.
    
    if not all_items:
        logger.warning("No items found to ingest.")
        return
    
    logger.info(f"Total chunks to ingest: {len(all_items)}")
    
    # Insert in batches
    batch_size = 100
    for i in range(0, len(all_items), batch_size):
        batch = all_items[i:i+batch_size]
        texts = [item['text'] for item in batch]
        metadata = [{'source': item['source'], 'category': item['category'], 'tags': item['tags']} for item in batch]
        
        # Generate embeddings
        embeddings = embedder.encode_batch(texts)
        
        # Insert
        success = vector_store.insert(embeddings, texts, metadata)
        if not success:
            logger.error(f"Batch {i//batch_size + 1} failed")
        else:
            logger.info(f"Batch {i//batch_size + 1} inserted")
    
    logger.info("Ingestion complete.")

if __name__ == "__main__":
    main()
