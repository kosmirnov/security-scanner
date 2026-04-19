# Security Scanner

A CLI + web tool with two pipelines, both powered by Claude.

---

## How It Works

**Scan Pipeline**
```
Local repo / Git URL
        ↓
  File Walker (git.py)
        ↓
  Regex Scanner (rules.py)    ← 6 rules, catches all candidates
        ↓
  LLM Verifier (llm.py)       ← Claude filters false positives, suggests fixes
        ↓
  Report (report.py)          ← terminal table + JSON + Excel
```

**Why two stages?**
Regex alone is fast but produces false positives — it flags `password = "your_password_here"` in docs the same as a real credential. Claude understands context and filters these out, only surfacing real issues.

**PR Review Pipeline**
```
Git Diff
        ↓
  questions_agent (Claude)    ← generates 2–3 targeted questions
        ↓
  Developer answers live
        ↓
  verdict_agent (Claude)      ← evaluates answers
        ↓
  APPROVE / REQUEST CHANGES
```

**Why the Q&A step?**
A diff alone doesn't prove understanding. The viva voce forces the developer to explain the security implications of their own changes before the PR is approved.

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
| Critical | GitHub Token | Tokens starting with `ghp_`, `gho_`, etc. |
| High | Generic Secret | Any `password =`, `secret =`, `pwd =` with a value |
| High | DB Connection String | DB URLs with credentials e.g. `postgres://user:pass@host` |
| Medium | SSL Verification Disabled | `verify=False` in HTTP requests |
| Medium | Dynamic exec() | `exec()` calls that could allow code injection |

---

## Output

**Terminal** — colour-coded table (red = critical, orange = high, yellow = medium, blue = low)

**Excel** — `.xlsx` report with all findings, LLM verdicts, and suggested fixes

**JSON** — machine-readable report for integration with other tools

---

## PR Review Agent

A viva voce code review flow — answer questions about your own diff to get it approved.

```bash
python main.py review
```

The agent reads your last commit diff, generates 2–3 targeted questions about the security implications and design decisions, and returns `APPROVE` or `REQUEST CHANGES` based on your answers.

Also available via the web UI (`PR Review Agent` tab) and API endpoints `POST /review/questions` and `POST /review/verdict`.

---

## Project Structure

```
security-scanner/
├── main.py              ← entry point, loads .env
├── api.py               ← FastAPI web server (POST /scan, POST /review/*)
├── requirements.txt
├── .env                 ← your API key (never commit this)
├── docs/
│   └── index.html       ← web UI served at /
└── scanner/
    ├── cli.py           ← click CLI, orchestrates the pipeline
    ├── git.py           ← walks local repo or clones remote URL
    ├── rules.py         ← regex detection rules + Finding model
    ├── llm.py           ← Claude verification + VerifiedFinding model
    ├── report.py        ← rich terminal table + JSON + Excel output
    └── agents/
        └── pr_review_agent.py  ← PydanticAI questions + verdict agents
```

---

## Dependencies

- `anthropic` — Claude API SDK
- `click` — CLI framework
- `rich` — terminal formatting and progress spinner
- `pandas` + `openpyxl` — Excel report generation
- `python-dotenv` — loads API key from `.env` file