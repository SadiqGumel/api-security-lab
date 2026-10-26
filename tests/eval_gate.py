import json
import sys

report = "/home/abubakar/api-security-lab/zap-reports/zap_baseline_report.json"

try:
    with open(report) as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] Error loading SARIF report: {e}")
    sys.exit(1)

results = data.get("runs", [{}])[0].get("results", [])
high_findings = [r for r in results if r.get("level") in ["high", "error"]]
med_findings = [r for r in results if r.get("level") in ["medium", "warning"]]

print("=" * 60)
print(f"[*] Local Baseline SARIF Findings -> High: {len(high_findings)} | Medium: {len(med_findings)}")
print("=" * 60)

if high_findings:
    print("[!] CI/CD Gate Result: FAILED (High-severity findings present)")
    for h in high_findings:
        rule = h.get('ruleId', 'unknown-rule')
        msg = h.get('message', {}).get('text', '')
        print(f"    - {rule}: {msg}")
    sys.exit(1)
else:
    print("[+] CI/CD Gate Result: PASSED (No High-severity findings)")
    sys.exit(0)
