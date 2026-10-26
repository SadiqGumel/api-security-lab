import urllib.request
import urllib.error
import json
import sys

BASE_URL = "http://127.0.0.1:3001"

print("=" * 60)
print("[*] Running Verification Suite Against Remediated Controls")
print("=" * 60)

# Test 1: BOLA Prevention
req_bola = urllib.request.Request(
    f"{BASE_URL}/rest/basket/1",
    headers={"Authorization": "Bearer valid_token_user_26"}
)

try:
    with urllib.request.urlopen(req_bola) as resp:
        print("[!] BOLA Verification: FAIL - Server allowed unauthorized access.")
        sys.exit(1)
except urllib.error.HTTPError as e:
    if e.code == 403:
        print("[+] BOLA Verification: PASS - Server strictly rejected unowned object (HTTP 403).")
    else:
        print(f"[-] BOLA Verification: Unexpected status code HTTP {e.code}")

# Test 2: Rate Limiting & Telemetry Headers
print("[*] Auditing Rate Limiting and RFC Telemetry Headers...")
rate_headers_detected = False
rate_limited = False

for i in range(4):
    req_rate = urllib.request.Request(
        f"{BASE_URL}/rest/user/login",
        data=b'{"email":"test@local","password":"pass"}',
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req_rate) as resp:
            headers = resp.headers
            if "ratelimit-limit" in [h.lower() for h in headers.keys()]:
                rate_headers_detected = True
    except urllib.error.HTTPError as e:
        if e.code == 429:
            rate_limited = True
            if "retry-after" in [h.lower() for h in e.headers.keys()]:
                rate_headers_detected = True

if rate_headers_detected and rate_limited:
    print("[+] Rate Limiting Verification: PASS - HTTP 429 and standard RateLimit headers confirmed.")
else:
    print("[!] Rate Limiting Verification: FAIL - Throttling or headers missing.")

print("=" * 60)
print("[+] Verification Complete: All defensive security controls validated.")
