import urllib.request
import urllib.error
import json
import time

TARGET = "http://localhost:3000"
ENDPOINTS = [
    "/",
    "/rest/user/login",
    "/rest/basket/1",
    "/api/Users",
    "/rest/admin/application-version"
]

findings = []

def record_finding(name, severity, description, uri):
    findings.append({
        "ruleId": name.lower().replace(" ", "-"),
        "level": severity,
        "message": {"text": description},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
    })

print(f"[*] Starting Local DAST Baseline Scan on {TARGET}...")

for ep in ENDPOINTS:
    url = f"{TARGET}{ep}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Security-Audit-Baseline/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # Check Security Headers
            if "strict-transport-security" not in headers:
                record_finding("Missing HSTS Header", "medium", "HTTP Strict Transport Security is not enforced.", ep)
            if "content-security-policy" not in headers:
                record_finding("Missing CSP Header", "medium", "Content Security Policy header is absent.", ep)
            if "x-content-type-options" not in headers or headers["x-content-type-options"] != "nosniff":
                record_finding("MIME Sniffing Not Blocked", "low", "X-Content-Type-Options: nosniff is missing.", ep)
                
            # Check CORS
            if headers.get("access-control-allow-origin") == "*":
                record_finding("Overly Permissive CORS", "high", "Access-Control-Allow-Origin is set to wildcard (*).", ep)
                
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
            record_finding("Overly Permissive CORS", "high", "Access-Control-Allow-Origin wildcard present on error route.", ep)
    except Exception as e:
        print(f"[-] Error querying {url}: {e}")

report = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "Local DAST Baseline Engine",
                "version": "1.0.0",
                "rules": [
                    {"id": "missing-hsts-header", "name": "Missing HSTS Header"},
                    {"id": "missing-csp-header", "name": "Missing CSP Header"},
                    {"id": "overly-permissive-cors", "name": "Overly Permissive CORS"}
                ]
            }
        },
        "results": findings,
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }]
    }]
}

output_path = "/home/abubakar/api-security-lab/zap-reports/zap_baseline_report.json"
with open(output_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"[+] Scan Complete. Generated {len(findings)} baseline findings.")
print(f"[+] SARIF/DAST report exported to: {output_path}")
