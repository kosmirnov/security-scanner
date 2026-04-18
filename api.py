# =============================================================
# WHAT IS THIS FILE?
# =============================================================
# This is the web server for the security scanner.
# It is built with FastAPI — a Python framework for creating APIs.
#
# An API (Application Programming Interface) is a way for one
# program to talk to another over the internet using HTTP requests.
# The same protocol your browser uses to load web pages.
#
# HOW IT FITS INTO THE OVERALL SYSTEM:
#
#   Browser (index.html)
#       |
#       |  HTTP POST /scan  (sends repo URL as JSON)
#       v
#   This file — api.py  (the server)
#       |
#       |-- scanner/git.py    → clones the repo, reads files
#       |-- scanner/rules.py  → runs regex rules to find candidates
#       |-- scanner/llm.py    → calls Claude to filter false positives
#       |
#       |  JSON response  (findings + summary)
#       v
#   Browser (renders the results table)
#
# To start the server locally:
#   uvicorn api:app --reload
#
# "uvicorn" is the web server that runs this file.
# "api:app" means: in the file called api.py, find the variable called app.
# "--reload" means: automatically restart when you save changes (dev mode only).
# =============================================================


# =============================================================
# IMPORTS — loading the tools we need
# =============================================================
# Python doesn't load everything automatically — you have to explicitly
# import the libraries you want to use.

import os  # access to operating system features like environment variables

# FastAPI — the web framework. Think of it like Express.js but for Python.
# FastAPI     — the main class that creates the web application
# HTTPException — lets us return error responses with a specific HTTP status code
from fastapi import FastAPI, HTTPException

# StaticFiles — serves a folder of files (HTML, CSS, JS) directly over HTTP
from fastapi.staticfiles import StaticFiles

# FileResponse — sends a specific file as the HTTP response (used for index.html)
from fastapi.responses import FileResponse

# BaseModel — Pydantic's base class for defining the shape of request/response data.
# Pydantic automatically validates that incoming data matches the types you declared.
from pydantic import BaseModel

# load_dotenv reads the .env file and loads its values as environment variables.
# This lets us store secrets like API keys outside of the code.
from dotenv import load_dotenv


# =============================================================
# LOAD ENVIRONMENT VARIABLES
# =============================================================
# .env is a plain text file that looks like:
#   ANTHROPIC_API_KEY=sk-ant-...
#
# load_dotenv() reads that file and makes the values available via os.getenv().
# We call this BEFORE importing the scanner modules so that by the time
# scanner/llm.py runs and tries to read ANTHROPIC_API_KEY, it's already loaded.
load_dotenv()


# =============================================================
# IMPORT OUR OWN SCANNER MODULES
# =============================================================
# These are the Python files we wrote inside the scanner/ folder.
# We import them after load_dotenv() so environment variables are ready.

from scanner.git import get_files       # clones a repo (or walks a local path) and yields file contents
from scanner.rules import scan_content  # runs regex rules against a file, returns a list of Findings
from scanner.llm import verify_findings # sends findings to Claude, returns VerifiedFindings
from scanner.agents.pr_review_agent import generate_questions, generate_verdict  # PR Q&A agents


# =============================================================
# CREATE THE FASTAPI APPLICATION
# =============================================================
# This one line creates the web application object.
# All our routes (URL endpoints) will be registered on this object.
app = FastAPI()


# =============================================================
# REQUEST BODY SCHEMA — ScanRequest
# =============================================================
# When the browser sends a POST request to /scan, it sends a JSON body like:
#   { "url": "https://github.com/org/repo", "use_llm": true }
#
# We define a Pydantic model to describe the expected shape of that data.
# FastAPI reads the model and automatically:
#   - parses the incoming JSON
#   - validates that "url" is a string and "use_llm" is a boolean
#   - returns a 422 error to the client if the data doesn't match
#
# "use_llm: bool = True" means use_llm is optional — if the caller doesn't
# send it, it defaults to True.
class ScanRequest(BaseModel):
    url: str
    use_llm: bool = True


# =============================================================
# ROUTE: GET /
# =============================================================
# A "route" is a URL the server knows how to handle.
# @app.get("/") registers this function to handle HTTP GET requests to "/".
#
# GET is the HTTP method for fetching something (like loading a web page).
# POST is for sending data (like submitting a form).
#
# When someone visits the root URL in their browser, this function runs
# and sends back the index.html file — the frontend UI.
@app.get("/")
def index():
    return FileResponse("docs/index.html")


# =============================================================
# ROUTE: POST /scan
# =============================================================
# This is the main endpoint. The browser calls this when the user clicks Scan.
#
# FastAPI sees that the function takes a "request: ScanRequest" parameter
# and automatically reads the JSON body, validates it against ScanRequest,
# and passes the result in as the "request" variable.
#
# Whatever this function returns (a dict) is automatically converted to JSON
# and sent back to the browser as the HTTP response.
@app.post("/scan")
def scan(request: ScanRequest):

    # We'll collect all findings from all files into this list.
    all_findings = []

    # -----------------------------------------------------------------
    # STAGE 1 — Clone the repo and run regex rules over every file
    # -----------------------------------------------------------------
    # get_files() is a generator — it yields (file_path, content) pairs
    # one at a time instead of loading the whole repo into memory at once.
    # This is important for large repos.
    #
    # scan_content() runs all our regex rules against a single file and
    # returns a list of Finding objects (defined in scanner/rules.py).
    #
    # all_findings.extend() adds all items from a list into another list
    # (like += but for lists of objects, not numbers).
    #
    # If get_files() fails (e.g. invalid URL, private repo, network error),
    # it raises an exception. We catch it and return HTTP 400 Bad Request
    # with the error message so the browser can show it to the user.
    # HTTP 400 means "the client sent bad input" — as opposed to 500
    # which means "the server itself crashed".
    try:
        for file_path, content in get_files(request.url):
            findings = scan_content(file_path, content)
            all_findings.extend(findings)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # If no rules matched anything across the whole repo, return early
    # with an empty result. No point calling the LLM with nothing to verify.
    if not all_findings:
        return {"findings": [], "summary": {"total": 0, "real": 0, "false_positives": 0}}


    # -----------------------------------------------------------------
    # STAGE 2 — LLM verification (optional)
    # -----------------------------------------------------------------
    # At this point we have a list of regex matches (candidates).
    # Some are real secrets, some are false positives (e.g. placeholder values).
    # We now ask Claude to classify each one.

    if request.use_llm:
        try:
            # verify_findings() sends all findings to Claude in one batched API call
            # and returns a list of VerifiedFinding objects — each has:
            #   .finding      — the original Finding (file, line, match, etc.)
            #   .is_real      — True if Claude thinks it's a real secret
            #   .confidence   — "high", "medium", "low"
            #   .explanation  — why Claude made this decision
            #   .fix          — suggested remediation
            verified = verify_findings(all_findings)
        except Exception:
            # The LLM call failed (API error, timeout, etc.).
            # We don't want to return nothing — that would silently hide real findings.
            # So we fall back: treat everything as real with unknown confidence.
            # The user sees all results and can review manually.
            from scanner.llm import VerifiedFinding
            verified = [
                VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                                explanation="LLM verification failed.", fix="Manual review required.")
                for f in all_findings
            ]
    else:
        # The user unchecked "Use LLM verification" — skip Claude entirely.
        # We still wrap the raw findings in VerifiedFinding objects so the
        # rest of the code doesn't need to know whether LLM ran or not.
        from scanner.llm import VerifiedFinding
        verified = [
            VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                            explanation="LLM verification skipped.", fix="")
            for f in all_findings
        ]


    # -----------------------------------------------------------------
    # STAGE 3 — Serialise results into plain dicts for the JSON response
    # -----------------------------------------------------------------
    # VerifiedFinding is a Python object with nested attributes.
    # HTTP responses must be plain JSON, not Python objects.
    # This list comprehension converts each VerifiedFinding into a flat dict.
    #
    # A list comprehension [ expression for item in list ] is a concise way
    # to build a new list by transforming each item — equivalent to a for loop
    # that appends to a list on each iteration.
    results = [
        {
            "severity":    vf.finding.severity,
            "file":        vf.finding.file_path,
            "line":        vf.finding.line_number,
            "rule":        vf.finding.rule_name,
            "match":       vf.finding.match,
            "is_real":     vf.is_real,
            "confidence":  vf.confidence,
            "explanation": vf.explanation,
            "fix":         vf.fix,
        }
        for vf in verified
    ]

    # Count how many findings Claude (or the fallback) marked as real.
    # sum() adds up numbers. We use a generator expression that yields 1 for
    # each real finding and 0 otherwise, then sum() adds them all up.
    real = sum(1 for r in results if r["is_real"])

    # Return the final JSON response.
    # FastAPI automatically converts this Python dict into a JSON string
    # and sets the Content-Type header to application/json.
    # The browser's fetch() call receives this and parses it with response.json().
    return {
        "findings": results,
        "summary": {
            "total":            len(results),        # len() returns the number of items in a list
            "real":             real,
            "false_positives":  len(results) - real,
        }
    }


# =============================================================
# REQUEST BODY SCHEMAS — PR Review endpoints
# =============================================================

class ReviewQuestionsRequest(BaseModel):
    diff: str  # raw git diff string


class ReviewVerdictRequest(BaseModel):
    diff: str           # original diff
    questions: list[str]  # questions generated in the first step
    answers: list[str]    # developer's answers, one per question


# =============================================================
# ROUTE: POST /review/questions
# =============================================================
# Step 1 of the PR review flow. Accepts a git diff and returns
# 2-3 targeted questions generated by the questions_agent.
# async def because PydanticAI's agent.run() is a coroutine —
# FastAPI runs async endpoints on the event loop natively.
@app.post("/review/questions")
async def review_questions(request: ReviewQuestionsRequest):
    try:
        questions = await generate_questions(request.diff)
        return {"questions": questions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================
# ROUTE: POST /review/verdict
# =============================================================
# Step 2 of the PR review flow. Accepts the diff, questions, and
# the developer's answers, then returns APPROVE or REQUEST CHANGES.
@app.post("/review/verdict")
async def review_verdict(request: ReviewVerdictRequest):
    try:
        verdict = await generate_verdict(request.diff, request.questions, request.answers)
        return {"decision": verdict.decision, "feedback": verdict.feedback}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================
# STATIC FILE SERVING
# =============================================================
# This mounts the docs/ folder at the /static URL path.
# Any file in docs/ can be accessed at /static/filename.
# For example, docs/style.css would be served at /static/style.css.
#
# This must be registered AFTER the routes above — FastAPI matches
# routes in the order they are defined.
app.mount("/static", StaticFiles(directory="docs"), name="static")