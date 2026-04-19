import os

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from scanner.git import get_files
from scanner.rules import scan_content
from scanner.llm import verify_findings
from scanner.agents.pr_review_agent import generate_questions, generate_verdict

app = FastAPI()


class ScanRequest(BaseModel):
    url: str
    use_llm: bool = True


class ReviewQuestionsRequest(BaseModel):
    diff: str


class ReviewVerdictRequest(BaseModel):
    diff: str
    questions: list[str]
    answers: list[str]


@app.get("/")
def index():
    return FileResponse("docs/index.html")


@app.post("/scan")
def scan(request: ScanRequest):
    all_findings = []

    try:
        for file_path, content in get_files(request.url):
            all_findings.extend(scan_content(file_path, content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not all_findings:
        return {"findings": [], "summary": {"total": 0, "real": 0, "false_positives": 0}}

    if request.use_llm:
        try:
            verified = verify_findings(all_findings)
        except Exception:
            from scanner.llm import VerifiedFinding
            verified = [
                VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                                explanation="LLM verification failed.", fix="Manual review required.")
                for f in all_findings
            ]
    else:
        from scanner.llm import VerifiedFinding
        verified = [
            VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                            explanation="LLM verification skipped.", fix="")
            for f in all_findings
        ]

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

    real = sum(1 for r in results if r["is_real"])

    return {
        "findings": results,
        "summary": {
            "total":           len(results),
            "real":            real,
            "false_positives": len(results) - real,
        }
    }


@app.post("/review/questions")
async def review_questions(request: ReviewQuestionsRequest):
    try:
        questions = await generate_questions(request.diff)
        return {"questions": questions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/review/verdict")
async def review_verdict(request: ReviewVerdictRequest):
    try:
        verdict = await generate_verdict(request.diff, request.questions, request.answers)
        return {"decision": verdict.decision, "feedback": verdict.feedback}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


app.mount("/static", StaticFiles(directory="docs"), name="static")