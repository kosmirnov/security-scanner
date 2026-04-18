from typing import List

from scanner.git import get_files
from scanner.rules import SECRET_RULES, PATTERN_RULES, scan_content, Finding
from scanner.llm import verify_findings, VerifiedFinding


def run_scan(target: str, no_llm: bool = False) -> List[VerifiedFinding]:
    """Full scan pipeline: collect files → detect secrets → detect patterns → verify with LLM."""

    # collect all (file_path, content) pairs from local path or remote URL
    files = list(get_files(target))

    # run secrets detection and pattern detection sequentially, then merge
    secrets_findings: List[Finding] = []
    pattern_findings: List[Finding] = []

    for file_path, content in files:
        secrets_findings.extend(scan_content(file_path, content, rules=SECRET_RULES))
        pattern_findings.extend(scan_content(file_path, content, rules=PATTERN_RULES))

    all_findings = secrets_findings + pattern_findings

    if not all_findings:
        return []

    if no_llm:
        # skip LLM — mark everything as unverified
        return [
            VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                            explanation="LLM verification skipped.", fix="")
            for f in all_findings
        ]

    # single batched LLM call for all findings — cheaper than calling per category
    return verify_findings(all_findings)