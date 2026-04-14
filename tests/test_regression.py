import os
from scanner.git import walk_local
from scanner.rules import scan_content

FIXTURE_REPO = os.path.join(os.path.dirname(__file__), "fixtures", "fake_repo")


def get_all_findings():
    findings = []
    for file_path, content in walk_local(FIXTURE_REPO):
        findings.extend(scan_content(file_path, content))
    return findings


def test_total_finding_count():
    findings = get_all_findings()
    assert len(findings) == 9


def test_auth_py_github_token():
    findings = get_all_findings()
    assert any(f.rule_id == "github_token" and "auth.py" in f.file_path for f in findings)


def test_auth_py_slack_token():
    findings = get_all_findings()
    assert any(f.rule_id == "slack_token" and "auth.py" in f.file_path for f in findings)


def test_auth_py_bearer_token():
    findings = get_all_findings()
    assert any(f.rule_id == "bearer_token" and "auth.py" in f.file_path for f in findings)


def test_config_py_aws_access_key():
    findings = get_all_findings()
    assert any(f.rule_id == "aws_access_key" and "config.py" in f.file_path for f in findings)


def test_config_py_db_connection():
    findings = get_all_findings()
    assert any(f.rule_id == "db_connection" and "config.py" in f.file_path for f in findings)


def test_config_py_generic_api_key():
    findings = get_all_findings()
    assert any(f.rule_id == "generic_api_key" and "config.py" in f.file_path for f in findings)


def test_utils_py_insecure_ssl():
    findings = get_all_findings()
    assert any(f.rule_id == "insecure_ssl" and "utils.py" in f.file_path for f in findings)


def test_utils_py_weak_hash():
    findings = get_all_findings()
    assert any(f.rule_id == "insecure_hash" and "utils.py" in f.file_path for f in findings)


def test_utils_py_exec():
    findings = get_all_findings()
    assert any(f.rule_id == "exec_call" and "utils.py" in f.file_path for f in findings)


def test_readme_has_no_findings():
    findings = get_all_findings()
    readme_findings = [f for f in findings if "README.md" in f.file_path]
    assert len(readme_findings) == 0