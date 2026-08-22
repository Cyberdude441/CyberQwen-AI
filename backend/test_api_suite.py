"""
CyberQwen-AI: Live API Validation & Endpoint Verification Suite
Tests /health, /chat, and /upload endpoints against live FastAPI backend.
"""

import time
import requests
import json
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"

def test_endpoints():
    print("\n" + "=" * 70)
    print("CYBERQWEN-AI: LIVE BACKEND API TEST SUITE")
    print("=" * 70)

    # 1. Health Check
    print("\n[*] 1. Testing GET /health...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"    Status: {r.status_code}")
        print(f"    Payload: {json.dumps(r.json(), indent=2)}")
        assert r.status_code == 200
        print("    [+] /health PASSED")
    except Exception as e:
        print(f"    [!] Failed to connect to {BASE_URL}: {e}")
        return False

    # 2. Conversational Chat
    print("\n[*] 2. Testing POST /chat...")
    try:
        payload = {
            "message": "Explain how buffer overflows corrupt the return address on 64-bit Linux ELF binary.",
            "temperature": 0.7,
            "max_tokens": 512
        }
        r = requests.post(f"{BASE_URL}/chat", json=payload, timeout=30)
        print(f"    Status: {r.status_code}")
        res = r.json()
        print(f"    Latency: {res.get('latency_ms')} ms")
        print(f"    Tokens: {res.get('tokens')}")
        print(f"    Response Preview: {res.get('response')[:150]}...")
        assert r.status_code == 200
        print("    [+] /chat PASSED")
    except Exception as e:
        print(f"    [!] Error during chat: {e}")
        return False

    # 3. File Upload Analysis
    print("\n[*] 3. Testing POST /upload (sample source code file)...")
    try:
        sample_code = """
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL query concatenation
    query = "SELECT * FROM accounts WHERE user = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""
        files = {
            'file': ('vulnerable_login.py', sample_code.encode('utf-8'), 'text/x-python')
        }
        data = {
            'action': 'vulnerability_analysis'
        }
        r = requests.post(f"{BASE_URL}/upload", files=files, data=data, timeout=30)
        print(f"    Status: {r.status_code}")
        res = r.json()
        print(f"    Filename: {res.get('filename')}")
        print(f"    Action: {res.get('action')}")
        print(f"    Analysis Preview:\n{res.get('response')[:200]}...")
        assert r.status_code == 200
        print("    [+] /upload PASSED")
    except Exception as e:
        print(f"    [!] Error during file upload: {e}")
        return False

    print("\n" + "=" * 70)
    print("ALL API ENDPOINT TESTS PASSED SUCCESSFULLY!")
    print("=" * 70 + "\n")
    return True

if __name__ == "__main__":
    test_endpoints()
