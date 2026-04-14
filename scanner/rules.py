import re
from dataclasses import dataclass
from typing import List

RULES = [
    {"id": "aws_access_key", "name": "AWS Access Key", "severity": "critical",
     "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")},
    {"id": "aws_secret_key", "name": "AWS Secret Key", "severity": "critical",
     "pattern": re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")},
    {"id": "gcp_api_key", "name": "GCP API Key", "severity": "high",
     "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}")},
    {"id": "generic_api_key", "name": "Generic API Key", "severity": "high",
     "pattern": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?")},
    {"id": "generic_secret", "name": "Generic Secret", "severity": "high",
     "pattern": re.compile(r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")},
    {"id": "private_key", "name": "Private Key", "severity": "critical",
     "pattern": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")},
    {"id": "db_connection", "name": "DB Connection String", "severity": "high",
     "pattern": re.compile(r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@")},
    {"id": "bearer_token", "name": "Bearer Token", "severity": "high",
     "pattern": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")},
    {"id": "github_token", "name": "GitHub Token", "severity": "critical",
     "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")},
    {"id": "slack_token", "name": "Slack Token", "severity": "high",
     "pattern": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")},
    {"id": "insecure_ssl", "name": "SSL Verification Disabled", "severity": "medium",
     "pattern": re.compile(r"verify\s*=\s*False")},
    {"id": "insecure_hash", "name": "Weak Hash (MD5/SHA1)", "severity": "medium",
     "pattern": re.compile(r"(?i)hashlib\.(md5|sha1)\s*\(")},
    {"id": "exec_call", "name": "Dynamic exec() Call", "severity": "medium",
     "pattern": re.compile(r"\bexec\s*\(")},
    {"id": "hardcoded_ip", "name": "Hardcoded IP Address", "severity": "low",
     "pattern": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")},
]

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
                   ".zip", ".tar", ".gz", ".bin", ".exe", ".lock"}

SKIP_DIRS = {".git", ".idea", "__pycache__", "node_modules", ".venv", "venv", ".env"}


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    match: str


def scan_content(file_path: str, content: str) -> List[Finding]:
    findings = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        for rule in RULES:
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