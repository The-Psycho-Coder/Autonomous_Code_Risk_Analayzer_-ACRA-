# How to Run ACRA

## Prerequisites

1. **Python 3.11+** installed
2. **OpenAI API Key** (get from https://platform.openai.com/api-keys)

## Step-by-Step Setup

### 1. Install Dependencies

Open a terminal in the project directory and run:

```bash
pip install -r requirements.txt
```

### 2. Configure API Key

Edit the `.env` file and replace `your_openai_api_key_here` with your actual OpenAI API key:

```bash
OPENAI_API_KEY=sk-your-actual-key-here
```

**OR** set it as an environment variable:

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-actual-key-here"
```

**Windows (CMD):**
```cmd
set OPENAI_API_KEY=sk-your-actual-key-here
```

**Linux/Mac:**
```bash
export OPENAI_API_KEY="sk-your-actual-key-here"
```

### 3. Run ACRA

#### Option A: Run from project root (Recommended)

```bash
# Make sure you're in the project root directory
cd "E:\Raval Rocks\Projects\Autonomous Code Risk Analyzer (ACRA)"

# Run with test file
python -m src.main test_vuln.py

# Or analyze your own file
python -m src.main path/to/your/file.py

# Analyze entire directory
python -m src.main . --recursive
```

#### Option B: Run from src directory

```bash
cd src
python main.py ../test_vuln.py
```

#### Option C: Add src to PYTHONPATH (Windows PowerShell)

```powershell
$env:PYTHONPATH="$PWD\src"
python src/main.py test_vuln.py
```

## Common Usage Examples

### Analyze the test file (includes vulnerabilities)
```bash
python -m src.main test_vuln.py
```

### Analyze a specific Python file
```bash
python -m src.main path/to/your/script.py
```

### Analyze entire project recursively
```bash
python -m src.main . --recursive
```

### Generate JSON report
```bash
python -m src.main test_vuln.py --output report.json
```

### Use a different OpenAI model
```bash
python -m src.main test_vuln.py --model gpt-4
```

### Use custom patterns file
```bash
python -m src.main test_vuln.py --patterns data/custom_patterns.json
```

## Expected Output

When you run ACRA, you'll see:

1. **Initialization**: Loading knowledge base and patterns
2. **Scanning**: Processing files and extracting code chunks
3. **Analysis**: Each function/class being analyzed
4. **Report**: Summary with vulnerabilities found

Example output:
```
🚀 Initializing ACRA...
   Loading knowledge base...
✓ Knowledge Base loaded with 12 OWASP patterns.
   Initializing security auditor...

📂 Scanning: test_vuln.py
   Found 8 code chunks to analyze.

[1/8] Analyzing: test_vuln.py::get_user_vulnerable... ⚠️  HIGH - SQL Injection
[2/8] Analyzing: test_vuln.py::get_user_safe... ✓ Safe
...

======================================================================
🔍 ACRA Security Analysis Report
======================================================================
...
```

## Troubleshooting

### Error: "OPENAI_API_KEY not found"
- Make sure `.env` file exists in project root
- Or set the environment variable (see Step 2 above)
- Verify the key starts with `sk-`

### Error: "No module named 'parser'"
- Use `python -m src.main` instead of `python src/main.py`
- Or run from the `src` directory: `cd src && python main.py ../test_vuln.py`

### Error: "Patterns file not found"
- Ensure `data/owasp_patterns.json` exists
- Check you're running from the project root directory

### Import Errors
- Install all dependencies: `pip install -r requirements.txt`
- Use Python 3.11 or higher

## Quick Test

To verify everything works:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set API key (replace with your key)
$env:OPENAI_API_KEY="sk-your-key-here"

# 3. Run test
python -m src.main test_vuln.py
```

If successful, you should see vulnerabilities detected in `test_vuln.py`!

