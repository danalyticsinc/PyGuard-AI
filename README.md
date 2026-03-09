# PyGuard AI

> **Enterprise-grade Python code security and quality audit agent** — detects OWASP Top 10 vulnerabilities, code smells, and complexity issues. Powered by Claude AI for intelligent fix suggestions.

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Claude AI](https://img.shields.io/badge/Anthropic_Claude-AI_Reviews-8B5CF6)](https://anthropic.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)

---

## What It Does

PyGuard AI combines **AST-based static analysis**, **security pattern matching**, and **Claude AI** to give Python developers enterprise-grade code reviews in seconds.

| Feature | Detail |
|---|---|
| **AST Analysis** | Parses Python code structurally — cyclomatic complexity, nesting depth, function length |
| **Security Scanning** | Detects SQL injection, hardcoded secrets, eval/exec abuse, insecure deserialization, weak crypto |
| **OWASP Coverage** | CWE-mapped issues: injection, broken auth, sensitive data exposure, XXE, insecure deserialization |
| **Claude AI Reviews** | AI explains each issue and generates corrected code snippets |
| **CLI Tool** | Scan files or entire directories from the terminal |
| **REST API** | Integrate into any CI/CD pipeline via FastAPI endpoints |
| **GitHub Actions** | Auto-scan on every PR — blocks merges on critical issues |
| **JSON Reports** | Machine-readable output for dashboards and SIEM integration |

---

## Quick Start

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/apuroopy1-prog/PyGuard-AI.git
cd PyGuard-AI

export ANTHROPIC_API_KEY=sk-ant-...
docker-compose up -d

# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

### Option 2 — Local

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app.main:app --reload
```

### Option 3 — CLI

```bash
pip install -r requirements.txt

# Scan a single file
python -m cli.pyguard scan mycode.py --verbose

# Scan entire project recursively
python -m cli.pyguard scan src/ --recursive --output report.json

# Scan without AI (offline mode)
python -m cli.pyguard scan mycode.py --no-ai

# Run demo on vulnerable code sample
python -m cli.pyguard demo
```

---

## Security Detections

| Category | Examples |
|---|---|
| **SQL Injection** | String formatting in `execute()` calls |
| **Code Injection** | `eval()`, `exec()` on user input |
| **Command Injection** | `os.system()`, `subprocess` with `shell=True` |
| **Insecure Deserialization** | `pickle.loads()`, `marshal.loads()`, `yaml.load()` |
| **Secrets Exposure** | Hardcoded passwords, API keys, tokens, private keys |
| **Weak Cryptography** | `hashlib.md5()`, `hashlib.sha1()`, `random` module |
| **Insecure Transport** | `requests` with `verify=False` |
| **Insecure Temp Files** | `tempfile.mktemp()` race condition |

---

## API Reference

```bash
# Upload a Python file
curl -X POST http://localhost:8000/api/v1/review/upload \
  -F "file=@mycode.py"

# Review a code snippet
curl -X POST http://localhost:8000/api/v1/review/snippet \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(input())", "filename": "test.py"}'

# Run demo
curl http://localhost:8000/api/v1/review/demo
```

Full interactive docs: **http://localhost:8000/docs**

---

## GitHub Actions Integration

PyGuard AI automatically scans your codebase on every push and pull request:

```yaml
# .github/workflows/ci.yml — already included in this repo
- name: Self-audit with PyGuard AI
  run: python -m cli.pyguard scan app/ --recursive --no-ai
```

---

## Built By

Discovery Analytics Inc.
