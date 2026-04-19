import re
from typing import List
from pydantic import BaseModel

SECRET_RULES = [
    {"id": "aws_access_key", "name": "AWS Access Key", "severity": "critical",
     "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")},
    {"id": "generic_secret", "name": "Generic Secret", "severity": "high",
     "pattern": re.compile(r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")},
    {"id": "db_connection", "name": "DB Connection String", "severity": "high",
     "pattern": re.compile(r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@")},
    {"id": "github_token", "name": "GitHub Token", "severity": "critical",
     "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")},
]

PATTERN_RULES = [
    {"id": "insecure_ssl", "name": "SSL Verification Disabled", "severity": "medium",
     "pattern": re.compile(r"verify\s*=\s*False")},
    {"id": "exec_call", "name": "Dynamic exec() Call", "severity": "medium",
     "pattern": re.compile(r"\bexec\s*\(")},
]

# Combined list kept for backwards compatibility (api.py, tests)
RULES = SECRET_RULES + PATTERN_RULES

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
                   ".zip", ".tar", ".gz", ".bin", ".exe", ".lock"}

SKIP_DIRS = {".git", ".idea", "__pycache__", "node_modules", ".venv", "venv", ".env"}


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    match: str


def scan_content(file_path: str, content: str, rules: list = RULES) -> List[Finding]:
    findings = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        for rule in rules:
            for m in rule["pattern"].finditer(line):
                findings.append(Finding(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    match=m.group(0),
                ))
    return findings