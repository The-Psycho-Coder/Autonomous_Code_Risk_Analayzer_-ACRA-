"""
The Librarian: RAG-based vector store using FAISS.
This module loads OWASP patterns and provides similarity search
to ground LLM responses against known vulnerability patterns.
"""

import json
from typing import Optional, List
from pathlib import Path

from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings


class KnowledgeBase:
    """Manages the FAISS vector store for OWASP vulnerability patterns."""
    
    def __init__(self, embeddings_model: str = "text-embedding-3-small"):
        """
        Initialize the knowledge base with OpenAI embeddings.
        
        Args:
            embeddings_model: OpenAI embedding model to use
        """
        # Use model parameter (standard in langchain-openai)
        self.embeddings = OpenAIEmbeddings(model=embeddings_model)
        self.vector_db: Optional[FAISS] = None
        self.patterns: List[dict] = []
    
    def load_patterns(self, json_path: str):
        """
        Loads OWASP patterns from JSON and creates the FAISS vector index.
        
        Args:
            json_path: Path to the OWASP patterns JSON file
        """
        json_path = Path(json_path)
        
        if not json_path.exists():
            raise FileNotFoundError(f"Patterns file not found: {json_path}")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            self.patterns = json.load(f)
        
        # Prepare texts and metadata for vectorization
        texts = []
        metadatas = []
        
        for item in self.patterns:
            # Combine category, description, and bad pattern for better matching
            text = f"{item['category']}: {item['description']}\nBad Pattern: {item['bad_code_pattern']}"
            texts.append(text)
            metadatas.append({
                "category": item['category'],
                "description": item['description'],
                "bad_code_pattern": item['bad_code_pattern'],
                "fix": item['fix']
            })
        
        # Create FAISS Index
        if texts:
            self.vector_db = FAISS.from_texts(
                texts,
                self.embeddings,
                metadatas=metadatas
            )
            print(f"✓ Knowledge Base loaded with {len(self.patterns)} OWASP patterns.")
        else:
            raise ValueError("No patterns found in JSON file")
    
    def search_similar_vulnerability(self, code_snippet: str, k: int = 1) -> Optional[dict]:
        """
        Search for similar vulnerability patterns in the knowledge base.
        
        Args:
            code_snippet: Code to search for similar patterns
            k: Number of similar patterns to retrieve
            
        Returns:
            Dictionary with similar pattern info, or None if no matches
        """
        if self.vector_db is None:
            raise ValueError("Knowledge base not loaded. Call load_patterns() first.")
        
        # Search for similar patterns
        results = self.vector_db.similarity_search_with_score(code_snippet, k=k)
        
        if results and len(results) > 0:
            # Return the most similar result
            doc, score = results[0]
            return {
                "category": doc.metadata.get("category", "Unknown"),
                "description": doc.metadata.get("description", ""),
                "bad_code_pattern": doc.metadata.get("bad_code_pattern", ""),
                "fix": doc.metadata.get("fix", ""),
                "similarity_score": float(score),
                "page_content": doc.page_content
            }
        
        return None
    
    def search_multiple_similar(self, code_snippet: str, k: int = 3) -> List[dict]:
        """
        Search for multiple similar vulnerability patterns.
        
        Args:
            code_snippet: Code to search for similar patterns
            k: Number of similar patterns to retrieve
            
        Returns:
            List of dictionaries with similar pattern info
        """
        if self.vector_db is None:
            raise ValueError("Knowledge base not loaded. Call load_patterns() first.")
        
        results = self.vector_db.similarity_search_with_score(code_snippet, k=k)
        
        similar_patterns = []
        for doc, score in results:
            similar_patterns.append({
                "category": doc.metadata.get("category", "Unknown"),
                "description": doc.metadata.get("description", ""),
                "bad_code_pattern": doc.metadata.get("bad_code_pattern", ""),
                "fix": doc.metadata.get("fix", ""),
                "similarity_score": float(score),
                "page_content": doc.page_content
            })
        
        return similar_patterns

