import requests

GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"

SLACK_TOKEN = "xoxb-REDACTED-REDACTED-REDACTEDREDACTED"

def get_user_data():
    headers = {
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
    }
    response = requests.get("https://api.example.com/user", headers=headers)
    return response.json()