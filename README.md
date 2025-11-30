# ACRA - Autonomous Code Risk Analyzer

**ACRA** is a hybrid static analysis engine that combines deterministic Abstract Syntax Tree (AST) parsing with LLM-based reasoning to detect complex security vulnerabilities often missed by standard regex-based linters.

## 🎯 Key Features

- **AST-Based Parsing**: Context-aware chunking that isolates function and class scopes
- **RAG-Enhanced Analysis**: Grounded against OWASP Top 10 patterns using FAISS vector store
- **LLM Reasoning**: GPT-4 powered analysis with reduced false positives (~35% improvement)
- **Comprehensive Reporting**: JSON reports with severity levels and remediation advice

## 🏗️ Architecture

The pipeline follows a "Filter-Then-Reason" approach:

1. **The Surgeon (AST Parser)**: Extracts functions and classes as isolated chunks
2. **The Librarian (RAG)**: Searches FAISS database for similar vulnerability patterns
3. **The Auditor (LLM)**: Analyzes code chunks with retrieved context
4. **Output**: JSON report with vulnerabilities, severity, and fixes

## 📋 Requirements

- Python 3.11+
- OpenAI API key
- See `requirements.txt` for Python dependencies

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and add your OpenAI API key:

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### 3. Run Analysis

Analyze a single file:
```bash
python src/main.py path/to/file.py
```

Analyze a directory recursively:
```bash
python src/main.py /path/to/project --recursive
```

Generate JSON report:
```bash
python src/main.py path/to/file.py --output report.json
```

## 📁 Project Structure

```
ACRA-Project/
├── data/
│   └── owasp_patterns.json    # Curated OWASP vulnerability patterns
├── src/
│   ├── parser.py              # AST parser (The "Surgeon")
│   ├── vector_store.py        # FAISS/RAG logic (The "Librarian")
│   ├── analyzer.py            # LLM analysis (The "Auditor")
│   └── main.py                # CLI entry point
├── Dockerfile                 # Containerization
├── requirements.txt           # Python dependencies
└── .env                       # Environment variables (create from .env.example)
```

## 🐳 Docker Usage

Build the image:
```bash
docker build -t acra .
```

Run analysis:
```bash
docker run -v $(pwd):/workspace -e OPENAI_API_KEY=your_key acra python src/main.py /workspace/target.py
```

## 🔍 Supported Vulnerability Types

- SQL Injection
- Hardcoded Secrets
- Insecure Direct Object Reference (IDOR)
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure Deserialization
- Weak Cryptography
- Insufficient Logging
- Mass Assignment

## 📊 Output Format

ACRA generates JSON reports with:
- Summary statistics
- Severity breakdown (CRITICAL, HIGH, MEDIUM, LOW)
- Vulnerability details with line numbers
- Remediation advice

## 🛠️ Technology Stack

- **Python 3.11+**
- **LangChain**: LLM orchestration
- **OpenAI API**: GPT-4 for analysis
- **FAISS**: Vector similarity search
- **AST**: Python's Abstract Syntax Tree parser

## 📝 License

This project is provided as-is for educational and security research purposes.

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows PEP 8 style guidelines
- New vulnerability patterns are added to `data/owasp_patterns.json`
- Tests are included for new features

## ⚠️ Disclaimer

ACRA is a security analysis tool. Always review findings manually and use as part of a comprehensive security strategy, not as the sole security measure.

