import urllib.request
import urllib.error
import json
import random
import os

base_url = "http://localhost:3000"
env = {"baseUrl": base_url, "authToken": "", "currentUserId": ""}
results = []

def run_test(name, passed, detail):
    status = "PASS" if passed else "FAIL"
    results.append({"test": name, "status": status, "detail": detail})
    symbol = "[+]" if passed else "[!]"
    print(f"{symbol} {status}: {name} - {detail}")

print("="*60)
print("[*] Running Automated Security Regression Suite (Postman Engine)")
print("="*60)

# 1. Login & Token Acquisition
login_payload = json.dumps({"email": "attacker102@test.local", "password": "Password123!"}).encode()
req = urllib.request.Request(f"{base_url}/rest/user/login", data=login_payload, headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req) as resp:
        body = json.loads(resp.read().decode())
        token = body.get("authentication", {}).get("token", "")
        env["authToken"] = token
        env["currentUserId"] = body.get("authentication", {}).get("umId", "")
        run_test("01. Authentication & Token Extraction", bool(token), f"Acquired JWT (Length: {len(token)})")
except Exception as e:
    run_test("01. Authentication & Token Extraction", False, str(e))

# 2. API1 BOLA Check (Basket 1)
basket_req = urllib.request.Request(f"{base_url}/rest/basket/1", headers={"Authorization": f"Bearer {env['authToken']}"})
try:
    with urllib.request.urlopen(basket_req) as resp:
        body = json.loads(resp.read().decode())
        owner = body.get("data", {}).get("UserId")
        run_test("02. API1 BOLA Check", False, f"Server returned 200 OK for unowned resource. Exposed UserId: {owner}")
except urllib.error.HTTPError as e:
    if e.code in [401, 403, 404]:
        run_test("02. API1 BOLA Check", True, f"Server rejected unowned basket with HTTP {e.code}")
    else:
        run_test("02. API1 BOLA Check", False, f"Unexpected status {e.code}")

# 3. API3 Mass Assignment Check
rand_email = f"audit_{random.randint(1000, 99999)}@test.local"
reg_payload = json.dumps({"email": rand_email, "password": "Password123!", "role": "admin"}).encode()
reg_req = urllib.request.Request(f"{base_url}/api/Users", data=reg_payload, headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(reg_req) as resp:
        body = json.loads(resp.read().decode())
        assigned_role = body.get("data", {}).get("role") or body.get("role")
        if assigned_role == "admin":
            run_test("03. API3 Mass Assignment Check", False, "Server accepted user-controlled 'role: admin'")
        else:
            run_test("03. API3 Mass Assignment Check", True, f"Server enforced role: {assigned_role}")
except urllib.error.HTTPError as e:
    run_test("03. API3 Mass Assignment Check", True, f"Server rejected unauthorized parameters with HTTP {e.code}")

# 4. API4 Rate Limiting Headers
rate_req = urllib.request.Request(f"{base_url}/rest/user/login", data=json.dumps({"email":"test@invalid","password":"wrong"}).encode(), headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(rate_req) as resp:
        headers = resp.headers
        has_rate = any(h in headers for h in ['X-RateLimit-Limit', 'RateLimit-Limit', 'Retry-After'])
        run_test("04. API4 Rate Limiting Headers", has_rate, "Headers present" if has_rate else "Missing X-RateLimit / Retry-After headers")
except urllib.error.HTTPError as e:
    headers = e.headers
    has_rate = any(h in headers for h in ['X-RateLimit-Limit', 'RateLimit-Limit', 'Retry-After'])
    run_test("04. API4 Rate Limiting Headers", has_rate, "Headers present" if has_rate else "Missing X-RateLimit / Retry-After headers")

# Save summary report
report_path = os.path.expanduser("~/api-security-lab/reports/postman_regression_report.json")
with open(report_path, "w") as f:
    json.dump(results, f, indent=2)

print("="*60)
print(f"[+] Suite Completed. Report exported to {report_path}")
