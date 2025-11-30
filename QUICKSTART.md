# ACRA Quick Start Guide

## Setup (5 minutes)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure OpenAI API Key
Create a `.env` file in the project root:
```bash
OPENAI_API_KEY=your_api_key_here
```

Get your API key from: https://platform.openai.com/api-keys

### 3. Test with Sample File
```bash
python src/main.py test_vuln.py
```

This will analyze the test file and generate a report showing detected vulnerabilities.

## Usage Examples

### Analyze a Single File
```bash
python src/main.py path/to/your/file.py
```

### Analyze Entire Project
```bash
python src/main.py /path/to/project --recursive
```

### Generate JSON Report
```bash
python src/main.py test_vuln.py --output my_report.json
```

### Use Custom Model
```bash
python src/main.py test_vuln.py --model gpt-4
```

## Understanding the Output

ACRA provides:
- **Summary**: Total chunks analyzed, vulnerabilities found, severity breakdown
- **Vulnerabilities**: Detailed list with:
  - File path and line numbers
  - Vulnerability type (SQL Injection, Hardcoded Secrets, etc.)
  - Severity (CRITICAL, HIGH, MEDIUM, LOW)
  - Reason and remediation advice

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected (useful for CI/CD pipelines)

## Troubleshooting

### "OPENAI_API_KEY not found"
- Ensure `.env` file exists in project root
- Check that `OPENAI_API_KEY=your_key` is set correctly

### "Patterns file not found"
- Ensure `data/owasp_patterns.json` exists
- Use `--patterns` flag to specify custom path

### Import Errors
- Run from project root directory
- Ensure all dependencies are installed: `pip install -r requirements.txt`

