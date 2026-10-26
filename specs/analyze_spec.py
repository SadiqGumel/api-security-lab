import json
import os
import sys

spec_path = os.path.expanduser("~/api-security-lab/specs/openapi_spec.json")

if not os.path.exists(spec_path):
    print(f"[-] Spec file not found at {spec_path}")
    sys.exit(1)

with open(spec_path, "r") as f:
    try:
        spec = json.load(f)
    except Exception as e:
        print(f"[-] Failed to parse JSON: {e}")
        sys.exit(1)

print("="*60)
print(f"[*] API Title: {spec.get('info', {}).get('title', 'Unknown')}")
print(f"[*] API Version: {spec.get('info', {}).get('version', 'Unknown')}")
print(f"[*] Total Defined Endpoints: {len(spec.get('paths', {}))}")
print("="*60)

unprotected_routes = []
missing_error_handling = []

paths = spec.get("paths", {})
for route, methods in paths.items():
    for method, details in methods.items():
        if method.lower() not in ["get", "post", "put", "patch", "delete"]:
            continue
        
        has_security = "security" in details or "security" in spec
        if not has_security and not route.startswith("/rest/user/login"):
            unprotected_routes.append(f"{method.upper()} {route}")
            
        responses = details.get("responses", {})
        if "401" not in responses and "403" not in responses:
            missing_error_handling.append(f"{method.upper()} {route}")

print(f"\n[!] Endpoints with No Explicit Security Scheme: {len(unprotected_routes)}")
for r in unprotected_routes:
    print(f"    - {r}")

print(f"\n[!] Endpoints Missing 401/403 Error Contracts: {len(missing_error_handling)}")
for r in missing_error_handling:
    print(f"    - {r}")

definitions = spec.get("definitions", {}) or spec.get("components", {}).get("schemas", {})
user_model = definitions.get("User", {})
if user_model:
    properties = list(user_model.get("properties", {}).keys())
    print(f"\n[*] User Model Audit: Found {len(properties)} properties: {', '.join(properties)}")
    sensitive_props = [p for p in properties if p.lower() in ["role", "isadmin", "is_admin", "isactive", "deluxetoken"]]
    if sensitive_props:
        print(f"[!] Mass Assignment Exposure: Model exposes sensitive properties: {sensitive_props}")

print("="*60)
