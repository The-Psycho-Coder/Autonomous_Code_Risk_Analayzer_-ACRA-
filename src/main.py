"""
ACRA - Autonomous Code Risk Analyzer
Main CLI entry point for the security analysis pipeline.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from dotenv import load_dotenv

# Import ACRA modules
# Handle both direct execution and module execution
try:
    from parser import get_code_chunks, get_code_chunks_from_directory
    from vector_store import KnowledgeBase
    from analyzer import SecurityAuditor
except ImportError:
    # If running as module, use absolute imports
    from src.parser import get_code_chunks, get_code_chunks_from_directory
    from src.vector_store import KnowledgeBase
    from src.analyzer import SecurityAuditor

# Load environment variables
load_dotenv()


def check_openai_key():
    """Verify OpenAI API key is set."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ ERROR: OPENAI_API_KEY not found in environment variables.")
        print("   Please set it in your .env file or export it.")
        sys.exit(1)
    return api_key


def generate_report(results: List[Dict[str, Any]], output_file: str = None) -> Dict[str, Any]:
    """
    Generate a comprehensive security analysis report.
    
    Args:
        results: List of analysis results
        output_file: Optional path to save JSON report
        
    Returns:
        Dictionary containing the full report
    """
    # Categorize results
    vulnerable = [r for r in results if r.get("status") == "VULNERABLE"]
    safe = [r for r in results if r.get("status") == "SAFE"]
    errors = [r for r in results if r.get("status") == "ERROR"]
    
    # Count by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    
    for result in vulnerable:
        severity = result.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Count by vulnerability type
    vuln_types = {}
    for result in vulnerable:
        vuln_type = result.get("vulnerability_type", "Unknown")
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_chunks_analyzed": len(results),
            "vulnerable": len(vulnerable),
            "safe": len(safe),
            "errors": len(errors),
            "severity_breakdown": severity_counts,
            "vulnerability_types": vuln_types
        },
        "vulnerabilities": vulnerable,
        "safe_chunks": safe,
        "errors": errors
    }
    
    # Save to file if requested
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Report saved to: {output_file}")
    
    return report


def print_summary(report: Dict[str, Any]):
    """Print a human-readable summary of the analysis."""
    summary = report["summary"]
    
    print("\n" + "="*70)
    print("🔍 ACRA Security Analysis Report")
    print("="*70)
    print(f"\n📊 Summary:")
    print(f"   Total Code Chunks Analyzed: {summary['total_chunks_analyzed']}")
    print(f"   ⚠️  Vulnerabilities Found: {summary['vulnerable']}")
    print(f"   ✓ Safe: {summary['safe']}")
    if summary['errors'] > 0:
        print(f"   ❌ Errors: {summary['errors']}")
    
    if summary['vulnerable'] > 0:
        print(f"\n🎯 Severity Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                print(f"   {severity}: {count}")
        
        print(f"\n📋 Vulnerability Types:")
        for vuln_type, count in summary['vulnerability_types'].items():
            print(f"   • {vuln_type}: {count}")
        
        print(f"\n⚠️  Vulnerabilities:")
        print("-" * 70)
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            print(f"\n{i}. {vuln.get('file_path')}:{vuln.get('start_line')}")
            print(f"   Function/Class: {vuln.get('chunk_name')}")
            print(f"   Type: {vuln.get('vulnerability_type')}")
            print(f"   Severity: {vuln.get('severity')}")
            print(f"   Reason: {vuln.get('reason')}")
            if vuln.get('fix'):
                print(f"   Fix: {vuln.get('fix')}")
    
    print("\n" + "="*70)


def main():
    """Main entry point for ACRA CLI."""
    parser = argparse.ArgumentParser(
        description="ACRA - Autonomous Code Risk Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/main.py test_vuln.py
  python src/main.py /path/to/project --output report.json
  python src/main.py . --recursive
        """
    )
    
    parser.add_argument(
        "target",
        help="Target file or directory to analyze"
    )
    
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively analyze all Python files in directory"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path for JSON report"
    )
    
    parser.add_argument(
        "--patterns",
        type=str,
        default="data/owasp_patterns.json",
        help="Path to OWASP patterns JSON file (default: data/owasp_patterns.json)"
    )
    
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o-mini",
        help="OpenAI model to use (default: gpt-4o-mini)"
    )
    
    args = parser.parse_args()
    
    # Check for API key
    check_openai_key()
    
    # Initialize components
    print("🚀 Initializing ACRA...")
    print("   Loading knowledge base...")
    kb = KnowledgeBase()
    
    patterns_path = Path(args.patterns)
    if not patterns_path.exists():
        print(f"❌ ERROR: Patterns file not found: {patterns_path}")
        print(f"   Please ensure {patterns_path} exists.")
        sys.exit(1)
    
    try:
        kb.load_patterns(str(patterns_path))
    except Exception as e:
        print(f"❌ ERROR loading patterns: {e}")
        sys.exit(1)
    
    print("   Initializing security auditor...")
    auditor = SecurityAuditor(model_name=args.model)
    
    # Parse code
    target_path = Path(args.target)
    if not target_path.exists():
        print(f"❌ ERROR: Target not found: {target_path}")
        sys.exit(1)
    
    print(f"\n📂 Scanning: {target_path}")
    
    if target_path.is_file():
        if target_path.suffix != ".py":
            print("❌ ERROR: Target must be a Python file (.py)")
            sys.exit(1)
        chunks = get_code_chunks(str(target_path))
    elif target_path.is_dir():
        if args.recursive:
            chunks = get_code_chunks_from_directory(str(target_path))
        else:
            print("❌ ERROR: Target is a directory. Use --recursive flag to analyze all files.")
            sys.exit(1)
    else:
        print(f"❌ ERROR: Invalid target: {target_path}")
        sys.exit(1)
    
    if not chunks:
        print("⚠️  No code chunks found to analyze.")
        sys.exit(0)
    
    print(f"   Found {len(chunks)} code chunks to analyze.\n")
    
    # Analyze each chunk
    results = []
    for i, chunk in enumerate(chunks, 1):
        chunk_name = chunk.get("name", "Unknown")
        file_path = chunk.get("file_path", "Unknown")
        print(f"[{i}/{len(chunks)}] Analyzing: {file_path}::{chunk_name}...", end=" ", flush=True)
        
        # RAG Step: Search for similar vulnerabilities
        similar_vuln = kb.search_similar_vulnerability(chunk['code'])
        
        # LLM Step: Analyze with context
        result = auditor.analyze_chunk(chunk, similar_vuln)
        results.append(result)
        
        # Print quick status
        status = result.get("status", "UNKNOWN")
        if status == "VULNERABLE":
            severity = result.get("severity", "UNKNOWN")
            vuln_type = result.get("vulnerability_type", "Unknown")
            print(f"⚠️  {severity} - {vuln_type}")
        elif status == "SAFE":
            print("✓ Safe")
        else:
            print(f"❌ {status}")
    
    # Generate and display report
    output_file = args.output or "acra_report.json"
    report = generate_report(results, output_file)
    print_summary(report)
    
    # Exit with appropriate code
    if report["summary"]["vulnerable"] > 0:
        sys.exit(1)  # Exit with error if vulnerabilities found
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

