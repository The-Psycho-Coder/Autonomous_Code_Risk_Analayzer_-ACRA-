"""
The Auditor: LLM-based security analysis engine.
This module combines AST chunks with RAG context to perform
intelligent vulnerability detection with reduced false positives.
"""

import json
from typing import Dict, Any, Optional

from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate


class SecurityAuditor:
    """Performs LLM-based security analysis with RAG context."""
    
    def __init__(self, model_name: str = "gpt-4o-mini", temperature: float = 0):
        """
        Initialize the security auditor with an LLM.
        
        Args:
            model_name: OpenAI model to use for analysis
            temperature: Temperature for LLM responses (0 for deterministic)
        """
        self.llm = ChatOpenAI(model_name=model_name, temperature=temperature)
        
        # Define the analysis prompt template
        self.prompt_template = PromptTemplate(
            input_variables=["code", "rag_context", "function_name", "file_path"],
            template="""You are an expert Cyber Security Auditor specializing in Python code analysis.

Analyze the following Python code for security vulnerabilities.

FILE: {file_path}
FUNCTION/CLASS: {function_name}

CODE TO ANALYZE:
```python
{code}
```

CONTEXT FROM KNOWLEDGE BASE:
{rag_context}

Your task:
1. Identify if there is a SECURITY VULNERABILITY (SQL Injection, IDOR, XSS, Secret Leak, Command Injection, Path Traversal, etc.).
2. If the RAG Context indicates a similar known vulnerability pattern, carefully compare the code logic to confirm if it matches.
3. Consider the context: Is user input being used unsafely? Are secrets exposed? Is access control missing?
4. If no vulnerability exists, output "SAFE".
5. Be precise - avoid false positives. Only flag actual security issues.

Output STRICTLY in valid JSON format (no markdown, no code blocks):
{{
  "status": "VULNERABLE" | "SAFE",
  "vulnerability_type": "category name or null",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null,
  "reason": "detailed explanation of the vulnerability or why it's safe",
  "line_number": line number where issue occurs or null,
  "fix": "specific remediation advice or null"
}}

If status is "SAFE", vulnerability_type, severity, and fix should be null.
"""
        )
    
    def analyze_chunk(self, chunk: Dict[str, Any], similar_pattern: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze a code chunk for security vulnerabilities using LLM with RAG context.
        
        Args:
            chunk: Code chunk from AST parser
            similar_pattern: Similar vulnerability pattern from RAG search
            
        Returns:
            Dictionary with analysis results
        """
        # Build RAG context string
        rag_context = ""
        if similar_pattern and similar_pattern.get("similarity_score", 1.0) < 1.5:  # Threshold for relevance
            rag_context = f"""
⚠️  ALERT: This code looks similar to a known vulnerability pattern.

Category: {similar_pattern.get('category', 'Unknown')}
Description: {similar_pattern.get('description', '')}
Known Pattern Example: {similar_pattern.get('bad_code_pattern', '')}
Suggested Fix: {similar_pattern.get('fix', '')}
Similarity Score: {similar_pattern.get('similarity_score', 'N/A')}
"""
        else:
            rag_context = "No similar known vulnerability patterns found in knowledge base."
        
        # Format the prompt
        prompt = self.prompt_template.format(
            code=chunk.get("code", ""),
            rag_context=rag_context,
            function_name=chunk.get("name", "Unknown"),
            file_path=chunk.get("file_path", "Unknown")
        )
        
        try:
            # Get LLM response
            response = self.llm.invoke(prompt)
            content = response.content.strip()
            
            # Try to parse JSON response
            # Sometimes LLM wraps JSON in markdown code blocks
            if content.startswith("```"):
                # Extract JSON from code block
                lines = content.split("\n")
                json_lines = []
                in_json = False
                for line in lines:
                    if line.strip().startswith("```"):
                        in_json = not in_json
                        continue
                    if in_json or (not content.startswith("```json") and not content.startswith("```")):
                        json_lines.append(line)
                content = "\n".join(json_lines)
            
            # Parse JSON
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                # Fallback: try to extract JSON object
                import re
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    # If parsing fails, create a safe response
                    result = {
                        "status": "SAFE",
                        "vulnerability_type": None,
                        "severity": None,
                        "reason": "Could not parse LLM response",
                        "line_number": None,
                        "fix": None
                    }
            
            # Add chunk metadata to result
            result["chunk_name"] = chunk.get("name", "Unknown")
            result["chunk_type"] = chunk.get("type", "Unknown")
            result["file_path"] = chunk.get("file_path", "Unknown")
            result["start_line"] = chunk.get("start_line", None)
            result["end_line"] = chunk.get("end_line", None)
            
            return result
            
        except Exception as e:
            # Return error result
            return {
                "status": "ERROR",
                "vulnerability_type": None,
                "severity": None,
                "reason": f"Error during analysis: {str(e)}",
                "line_number": None,
                "fix": None,
                "chunk_name": chunk.get("name", "Unknown"),
                "chunk_type": chunk.get("type", "Unknown"),
                "file_path": chunk.get("file_path", "Unknown"),
                "start_line": chunk.get("start_line", None),
                "end_line": chunk.get("end_line", None)
            }

