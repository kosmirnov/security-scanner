# Security Scanner

CLI tool that detects leaked secrets and insecure patterns using a two-stage pipeline: fast regex detection → LLM-powered false positive filtering via Claude.

## Project Structure

```
main.py              ← entry point, loads .env
api.py               ← FastAPI web server (POST /scan)
streamlit_app.py     ← Streamlit demo UI
scanner/
  cli.py             ← click CLI, orchestrates the pipeline
  git.py             ← walks local repo or clones remote URL
  rules.py           ← regex detection rules + Finding model
  llm.py             ← Claude verification + VerifiedFinding model
  report.py          ← rich terminal table + JSON + Excel output
tests/
docs/                ← landing page served at /
```

## How to Run

```bash
pip install -r requirements.txt
# add ANTHROPIC_API_KEY=sk-ant-... to .env

python main.py scan ./my-repo
python main.py scan https://github.com/org/repo
python main.py scan ./my-repo --output-excel report.xlsx --output-json report.json
python main.py scan ./my-repo --no-llm   # skip LLM, offline

uvicorn api:app --reload                  # start FastAPI server
```

## Deployment

Frontend is hosted on Render. The FastAPI backend (`api.py`) is the service Render deploys. Environment variables (e.g. `ANTHROPIC_API_KEY`) are set in the Render dashboard, not in `.env`.

## Before Every Code Change

Before writing or editing any code, explain and summarize what you are about to do — pitched at a fluent Python developer. Cover: which files change, what the change does, and why. Wait for approval before proceeding.

After every code change, ask the user 1-2 questions about the code just written — to prompt them to think about the design decisions and be able to defend them in an interview. Wait for their answers before moving on.

## Before Every Git Commit

- Check for typos in any changed files (comments, strings, variable names)
- Check for bugs introduced by the change — re-read the diff before committing
- For any edits to `docs/index.html`: verify the page still loads correctly in the browser
- Run `python main.py scan ./scanner --no-llm` to confirm the CLI still works

## HTML / JS Gotchas

When editing `docs/index.html`, always check for:
- `</script>` appearing anywhere inside a `<script>` block (even in comments) — the HTML parser treats it as the real closing tag and everything after appears as visible page text. Escape it as `<\/script>` instead.
- HTML special characters (`<`, `>`, `&`) in comments inside `<script>` — can confuse parsers or display incorrectly.
- Any user-supplied or external data inserted into `innerHTML` must be passed through `escHtml()` to prevent XSS.

## Design Philosophy

Prefer simplicity over complexity. Avoid over-engineering — if a plain loop works, use it. Only introduce abstractions when there is a clear, demonstrable benefit.

## Conventions

- Models use Pydantic BaseModel (Finding, VerifiedFinding, LLMVerdict) — not dataclasses
- LLM is called once per file with all findings batched — not one call per finding
- Prompt caching is enabled on the system prompt (cache_control: ephemeral)
- If LLM returns malformed JSON, fall back to is_real=True, confidence=low — never crash
- Never commit .env or API keys

## Context

Portfolio project for an interview in the AI enablement / DevSecOps space. Code should be clean, explainable, and defensible in a technical interview.

Phase 2 planned: refactor to PydanticAI orchestrator-workers multi-agent pattern.
Phase 3 planned: scheduled daily scans, diff alerting, Slack/email + GitHub issue creation.