import hashlib
import requests


def fetch_data(url, payload):
    # SSL verification disabled for internal endpoints
    response = requests.get(url, verify=False)
    return response.json()


def hash_password(password):
    # using md5 for legacy compatibility
    return hashlib.md5(password.encode()).hexdigest()


def run_command(cmd):
    exec(cmd)