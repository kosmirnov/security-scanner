import pytest
from scanner.rules import scan_content, Finding


# --- AWS ---

def test_aws_access_key_detected():
    content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_content("config.py", content)
    rule_ids = [f.rule_id for f in findings]
    assert "aws_access_key" in rule_ids


def test_aws_access_key_not_triggered_on_random_text():
    content = "this is just a normal comment with no keys"
    findings = scan_content("config.py", content)
    assert not any(f.rule_id == "aws_access_key" for f in findings)


# --- Generic Secret ---

def test_generic_secret_detected():
    content = 'password = "supersecret123"'
    findings = scan_content("config.py", content)
    assert any(f.rule_id == "generic_secret" for f in findings)


def test_generic_secret_detected_pwd():
    content = 'pwd = "mypassword"'
    findings = scan_content("config.py", content)
    assert any(f.rule_id == "generic_secret" for f in findings)


# --- DB Connection ---

def test_db_connection_detected():
    content = 'DATABASE_URL = "postgres://admin:secret123@localhost:5432/mydb"'
    findings = scan_content("config.py", content)
    assert any(f.rule_id == "db_connection" for f in findings)


def test_db_connection_mysql_detected():
    content = 'DB = "mysql://root:password@localhost/app"'
    findings = scan_content("config.py", content)
    assert any(f.rule_id == "db_connection" for f in findings)


# --- SSL ---

def test_insecure_ssl_detected():
    content = "response = requests.get(url, verify=False)"
    findings = scan_content("utils.py", content)
    assert any(f.rule_id == "insecure_ssl" for f in findings)


def test_insecure_ssl_not_triggered_on_verify_true():
    content = "response = requests.get(url, verify=True)"
    findings = scan_content("utils.py", content)
    assert not any(f.rule_id == "insecure_ssl" for f in findings)


# --- Weak Hash ---

def test_md5_detected():
    content = "hashlib.md5(password.encode()).hexdigest()"
    findings = scan_content("utils.py", content)
    assert any(f.rule_id == "insecure_hash" for f in findings)


def test_sha1_detected():
    content = "hashlib.sha1(data).hexdigest()"
    findings = scan_content("utils.py", content)
    assert any(f.rule_id == "insecure_hash" for f in findings)


# --- exec() ---

def test_exec_detected():
    content = "exec(user_input)"
    findings = scan_content("utils.py", content)
    assert any(f.rule_id == "exec_call" for f in findings)


# --- GitHub Token ---

def test_github_token_detected():
    content = 'GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"'
    findings = scan_content("auth.py", content)
    assert any(f.rule_id == "github_token" for f in findings)


# --- Slack Token ---

def test_slack_token_detected():
    content = 'SLACK_TOKEN = "xoxb-REDACTED-REDACTED-REDACTEDREDACTED"'
    findings = scan_content("auth.py", content)
    assert any(f.rule_id == "slack_token" for f in findings)


# --- Finding fields ---

def test_finding_fields_are_correct():
    content = "exec(cmd)"
    findings = scan_content("app.py", content)
    assert len(findings) > 0
    f = findings[0]
    assert f.file_path == "app.py"
    assert f.line_number == 1
    assert f.rule_id == "exec_call"
    assert "exec(" in f.line_content


# --- Multi-line ---

def test_finding_correct_line_number():
    content = "import os\nimport sys\nexec(user_input)"
    findings = scan_content("app.py", content)
    exec_findings = [f for f in findings if f.rule_id == "exec_call"]
    assert len(exec_findings) == 1
    assert exec_findings[0].line_number == 3


# --- No findings ---

def test_clean_file_returns_no_findings():
    content = "def add(a, b):\n    return a + b\n"
    findings = scan_content("math.py", content)
    assert findings == []