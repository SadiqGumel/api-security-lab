import urllib.request
import urllib.error
import json

base_url = "http://localhost:3000"

# 1. Login to retrieve token
login_data = json.dumps({"email": "attacker102@test.local", "password": "Password123!"}).encode('utf-8')
req = urllib.request.Request(f"{base_url}/rest/user/login", data=login_data, headers={"Content-Type": "application/json"})

try:
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        token = res.get('authentication', {}).get('token', '')
        print("[+] Authentication: Success (Token acquired)")
except Exception as e:
    print(f"[-] Authentication failed: {e}")
    token = ""

# 2. Test API1: BOLA on Basket 1
basket_req = urllib.request.Request(f"{base_url}/rest/basket/1", headers={"Authorization": f"Bearer {token}"})
try:
    with urllib.request.urlopen(basket_req) as resp:
        print(f"[!] API1 (BOLA): VULNERABLE - Server returned HTTP {resp.status} for unowned basket.")
except urllib.error.HTTPError as e:
    if e.code in [401, 403, 404]:
        print(f"[+] API1 (BOLA): SECURE - Server returned HTTP {e.code}.")
    else:
        print(f"[-] API1 (BOLA): Unexpected status HTTP {e.code}.")

# 3. Test API4: Rate Limiting Headers on Login
login_audit_req = urllib.request.Request(f"{base_url}/rest/user/login", data=login_data, headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(login_audit_req) as resp:
        headers = resp.headers
        has_rate_limit = any(h in headers for h in ['X-RateLimit-Limit', 'RateLimit-Limit', 'Retry-After'])
        if has_rate_limit:
            print("[+] API4 (Resource Consumption): SECURE - Rate limit headers present.")
        else:
            print("[!] API4 (Resource Consumption): DEFICIENCY - Missing standard rate limiting headers.")
except urllib.error.HTTPError as e:
    headers = e.headers
    has_rate_limit = any(h in headers for h in ['X-RateLimit-Limit', 'RateLimit-Limit', 'Retry-After'])
    if has_rate_limit:
        print("[+] API4 (Resource Consumption): SECURE - Rate limit headers present.")
    else:
        print("[!] API4 (Resource Consumption): DEFICIENCY - Missing standard rate limiting headers.")
