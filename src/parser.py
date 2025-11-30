"""
The Surgeon: AST-based code parser that extracts context-aware chunks.
This module isolates function and class scopes to reduce token processing
and improve analysis accuracy.
"""

import ast
from typing import List, Dict, Any


class CodeChunker(ast.NodeVisitor):
    """AST visitor that extracts functions and classes as isolated chunks."""
    
    def __init__(self, source_code: str, file_path: str):
        self.code = source_code
        self.file_path = file_path
        self.chunks: List[Dict[str, Any]] = []
        self.lines = source_code.splitlines()
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Extract function definitions as isolated code chunks.
        This isolates the scope so the LLM isn't distracted by other code.
        """
        start_line = node.lineno - 1  # AST line numbers are 1-indexed
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
        
        # Extract just this function's source code
        function_source = "\n".join(self.lines[start_line:end_line])
        
        # Get function signature and docstring for context
        docstring = ast.get_docstring(node)
        
        self.chunks.append({
            "name": node.name,
            "type": "function",
            "start_line": node.lineno,
            "end_line": end_line,
            "file_path": self.file_path,
            "code": function_source,
            "docstring": docstring,
            "args": [arg.arg for arg in node.args.args]
        })
        
        # Continue walking the tree for nested functions
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """
        Extract class definitions as isolated code chunks.
        """
        start_line = node.lineno - 1
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
        
        class_source = "\n".join(self.lines[start_line:end_line])
        docstring = ast.get_docstring(node)
        
        self.chunks.append({
            "name": node.name,
            "type": "class",
            "start_line": node.lineno,
            "end_line": end_line,
            "file_path": self.file_path,
            "code": class_source,
            "docstring": docstring,
            "bases": [ast.unparse(base) if hasattr(ast, 'unparse') else str(base) for base in node.bases]
        })
        
        # Continue to visit methods within the class
        self.generic_visit(node)


def get_code_chunks(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse a Python file and extract function/class chunks using AST.
    
    Args:
        file_path: Path to the Python file to analyze
        
    Returns:
        List of code chunks, each containing function or class definitions
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []
    
    try:
        tree = ast.parse(source, filename=file_path)
        chunker = CodeChunker(source, file_path)
        chunker.visit(tree)
        return chunker.chunks
    except SyntaxError as e:
        print(f"Syntax error in {file_path}: {e}")
        return []
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return []


def get_code_chunks_from_directory(directory_path: str) -> List[Dict[str, Any]]:
    """
    Recursively parse all Python files in a directory.
    
    Args:
        directory_path: Path to directory containing Python files
        
    Returns:
        List of all code chunks from all Python files
    """
    import os
    from pathlib import Path
    
    all_chunks = []
    directory = Path(directory_path)
    
    # Find all Python files
    python_files = list(directory.rglob("*.py"))
    
    # Filter out common directories to ignore
    ignore_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}
    
    for py_file in python_files:
        # Skip if in ignored directory
        if any(ignore_dir in py_file.parts for ignore_dir in ignore_dirs):
            continue
            
        chunks = get_code_chunks(str(py_file))
        all_chunks.extend(chunks)
    
    return all_chunks

