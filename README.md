# Security Scanner

A CLI tool that scans a repository for security vulnerabilities — leaked API keys, hardcoded secrets, and insecure code patterns. It uses a two-stage approach: fast regex detection followed by LLM-powered false positive filtering via Claude.

---

## How It Works

```
Local repo / Git URL
        ↓
  File Walker (git.py)
        ↓
  Regex Scanner (rules.py)    ← catches all candidates
        ↓
  LLM Verifier (llm.py)       ← filters false positives, suggests fixes
        ↓
  Report (report.py)          ← terminal table + JSON + Excel
```

**Why two stages?**
Regex alone is fast but produces false positives — it flags `password = "your_password_here"` in docs the same as a real credential. The LLM understands context and filters these out, only surfacing real issues.

---

## Installation

```bash
pip install -r requirements.txt
```

Create a `.env` file at the project root:
```
ANTHROPIC_API_KEY=sk-ant-...
```

The `.env` file is automatically loaded on startup via `python-dotenv`. It is listed in `.gitignore` — never commit your API key.

---

## Usage

Scan a local repo:
```bash
python main.py scan ./my-repo
```

Scan a remote GitHub or Bitbucket repo:
```bash
python main.py scan https://github.com/org/repo
python main.py scan git@bitbucket.org:org/repo.git
```

Save reports:
```bash
python main.py scan ./my-repo --output-excel report.xlsx --output-json report.json
```

Skip LLM verification (faster, offline):
```bash
python main.py scan ./my-repo --no-llm
```

---

## Detection Rules

| Severity | Rule | What It Catches |
|---|---|---|
| Critical | AWS Access Key | Keys starting with `AKIA...` |
| Critical | AWS Secret Key | 40-char random strings near "aws" |
| Critical | Private Key | PEM private key headers |
| Critical | GitHub Token | Tokens starting with `ghp_`, `gho_`, etc. |
| High | GCP API Key | Google Cloud keys starting with `AIza...` |
| High | Generic API Key | Any `api_key = "long_value"` |
| High | Generic Secret | Any `password =`, `secret =`, `pwd =` with a value |
| High | DB Connection String | DB URLs with credentials e.g. `postgres://user:pass@host` |
| High | Bearer Token | Hardcoded `Bearer xxxxx` auth headers |
| High | Slack Token | Slack tokens starting with `xox...` |
| Medium | SSL Verification Disabled | `verify=False` in HTTP requests |
| Medium | Weak Hash | `hashlib.md5()` or `hashlib.sha1()` |
| Medium | Dynamic exec() | `exec()` calls that could allow code injection |
| Low | Hardcoded IP Address | Raw IP addresses hardcoded in source |

---

## Output

**Terminal** — colour-coded table (red = critical, orange = high, yellow = medium, blue = low)

**Excel** — `.xlsx` report with all findings, LLM verdicts, and suggested fixes

**JSON** — machine-readable report for integration with other tools

---

## Project Structure

```
security-scanner/
├── main.py              ← entry point, loads .env
├── requirements.txt
├── .env                 ← your API key (never commit this)
└── scanner/
    ├── cli.py           ← click CLI, orchestrates the pipeline
    ├── git.py           ← walks local repo or clones remote URL
    ├── rules.py         ← regex detection rules + Finding dataclass
    ├── llm.py           ← Claude verification + VerifiedFinding
    └── report.py        ← rich terminal table + JSON + Excel output
```

---

## Dependencies

- `anthropic` — Claude API SDK
- `click` — CLI framework
- `rich` — terminal formatting and progress spinner
- `pandas` + `openpyxl` — Excel report generation
- `python-dotenv` — loads API key from `.env` file