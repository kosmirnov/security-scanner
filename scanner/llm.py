import json
import os
from typing import List

import anthropic
from pydantic import BaseModel

from scanner.rules import Finding

SYSTEM_PROMPT = """You are a security expert reviewing code findings from a static analysis tool.

For each finding, you must determine:
1. Whether it is a REAL security issue or a FALSE POSITIVE (e.g. placeholder, example, test value, commented-out code)
2. Your confidence level: high, medium, or low
3. A brief explanation of your verdict
4. A suggested fix if it is a real issue

Respond ONLY with a raw JSON array. Do not wrap in markdown code blocks. Do not include any explanation outside the JSON. One object per finding, in this exact format:
[
  {
    "is_real": true,
    "confidence": "high",
    "explanation": "This is a hardcoded AWS access key that appears to be a real credential.",
    "fix": "Move this value to an environment variable: os.environ['AWS_ACCESS_KEY_ID']"
  }
]

Rules:
- If the value looks like a placeholder (e.g. "your_api_key_here", "xxxx", "example", "changeme"), mark as false positive
- If it appears in a test file or comment, lower your confidence
- If it looks like a real credential (correct format, random-looking value), mark as real
- Always return the same number of objects as findings provided
"""


class LLMVerdict(BaseModel):
    is_real: bool
    confidence: str
    explanation: str
    fix: str


class VerifiedFinding(BaseModel):
    finding: Finding
    is_real: bool
    confidence: str
    explanation: str
    fix: str


def verify_findings(findings: List[Finding]) -> List[VerifiedFinding]:
    if not findings:
        return []

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)

    findings_text = "\n\n".join([
        f"Finding {i + 1}:\n"
        f"  Rule: {f.rule_name}\n"
        f"  File: {f.file_path}:{f.line_number}\n"
        f"  Line: {f.line_content}\n"
        f"  Match: {f.match}"
        for i, f in enumerate(findings)
    ])
    # findins are validated at this call
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Please review these {len(findings)} security findings:\n\n{findings_text}"
            }
        ]
    )

    raw = message.content[0].text.strip()

    # strip markdown code blocks if Claude wrapped the response
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        verdicts = [LLMVerdict(**r) for r in json.loads(raw)]
    except Exception:
        # fallback: mark all as unverified
        return [
            VerifiedFinding(finding=f, is_real=True, confidence="low",
                            explanation="LLM response could not be parsed.", fix="Manual review required.")
            for f in findings
        ]

    verified = []
    for i, f in enumerate(findings):
        if i < len(verdicts):
            v = verdicts[i]
            verified.append(VerifiedFinding(
                finding=f,
                is_real=v.is_real,
                confidence=v.confidence,
                explanation=v.explanation,
                fix=v.fix,
            ))
        else:
            verified.append(VerifiedFinding(
                finding=f, is_real=True, confidence="low",
                explanation="No LLM verdict returned.", fix="Manual review required."
            ))

    return verified