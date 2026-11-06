# API Vulnerability Assessment & DAST Integration Report

## 1. Executive Summary
A comprehensive security assessment was conducted against OWASP Juice Shop API following the OWASP API Security Top 10 (2023) standard. The assessment combined dynamic penetration testing, architectural review, automated regression assertions via Postman/Newman, and CI/CD security gating with SARIF reporting.

## 2. OWASP API Top 10 Findings Summary
* **API1:2023 - Broken Object Level Authorization (BOLA):** Confirmed on `GET /rest/basket/{id}`. Authenticated user (ID: 26) successfully retrieved unauthorized basket data (ID: 1).
* **API2:2023 - Broken Authentication (JWT Security):** Examined token verification weaknesses, lack of algorithm pinning (RS256 vs HS256 confusion), and missing audience/issuer validation.
* **API3:2023 - Broken Object Property Level Authorization (Mass Assignment):** Registration endpoint binds raw object bodies without DTO allowlists, accepting arbitrary properties (`role: admin`).
* **API4:2023 - Unrestricted Resource Consumption:** Missing standard rate limiting headers (`X-RateLimit-*`, `Retry-After`) and throttling on `POST /rest/user/login`.

## 3. Technical Evidence & HTTP Telemetry
### API1:2023 (BOLA)
* **Request:** `GET /rest/basket/1` with Bearer token for User 26.
* **Response:** `HTTP/1.1 200 OK` exposing User 1's products.

### API4:2023 (Rate Limiting)
* Repeated automated calls to `POST /rest/user/login` exhibited no throttling telemetry or 429 status codes in baseline configuration.

## 4. Automated DAST & CI/CD Pipeline
* **Engine:** Headless DAST baseline scanner generating SARIF v2.1 compliance artifacts (`zap-reports/zap_baseline_report.json`).
* **Workflow:** Configured in `.github/workflows/dast-api-scan.yml`.
* **Policy Gate:** Fails builds (`exit 1`) when High-severity findings exceed policy thresholds (`MAX_HIGH = 0`).

## 5. Developer Remediation Guidelines
Refer to repository remediation middleware for:
* Object tenancy validation (`authorizeTenancy.js`)
* Asymmetric algorithm-pinned token verification (`verifyToken.js`)
* Rate limiting middleware configuration (`rateLimiter.js`)

---

## 6. Phase 6: Multi-Tenant Fuzzing & CI/CD Security Gate Enforcement

### 6.1 Multi-Tenant BOLA Authorization Matrix
Testing evaluated object-level authorization across tenant boundaries using distinct user security contexts (`Tenant A` vs. `Tenant B`).

| Test Case | Method & Endpoint | Context | Expected Defensive Status | Target Baseline Status | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cross-Tenant Read** | `GET /rest/basket/1` | Caller: User B (ID: 2) | `403 Forbidden` / `404 Not Found` | `200 OK` (User A basket exposed) | **FAIL (BOLA Confirmed)** |
| **Cross-Tenant Item Mutation** | `POST /api/BasketItems/` | Caller: User B (ID: 2) | `403 Forbidden` / `404 Not Found` | `200 OK` (Appended item to Basket 1) | **FAIL (BOLA Confirmed)** |

---

### 6.2 Asynchronous Concurrency & Rate Limiting Fuzzing
* **Method:** Asynchronous concurrent burst test (`httpx.AsyncClient` / `asyncio`) targeting `POST /rest/user/login`.
* **Traffic Volume:** 25 requests within a 1-second burst interval.
* **Findings:**
  - Status codes received: `401 Unauthorized` for all 25 requests.
  - Zero requests returned `429 Too Many Requests`.
  - Absence of standard RFC telemetry headers (`Retry-After`, `RateLimit-Limit`).
* **Verdict:** Endpoint vulnerable to credential stuffing and resource exhaustion (OWASP API4:2023).

---

### 6.3 Automated CI/CD Security Gate Enforcement Evidence

During Pull Request evaluation (`phase-6-advanced-fuzzing` into `main`), the automated pipeline (`.github/workflows/api-security-ci.yml`) executed the test suite inside an ephemeral runner.

**Pipeline Telemetry & Gating Summary:**
* **Workflow:** API Security Dynamic Fuzzing & CI/CD Gate
* **Artifact Generated:** `reports/audit-summary.json`
* **Violations Recorded:**
  - `test_tenant_boundary_basket_read`: Cross-tenant access permitted on `/rest/basket/1` (`HTTP 200`).
  - `test_tenant_boundary_basket_mutation`: Unauthorized insertion permitted into target basket.
  - `test_authentication_rate_limiting`: Missing `429` status on burst attempts.
* **Gate Status:** `BLOCKED`
* **Exit Behavior:** The enforcement script detected policy violations and executed `exit 1`.
* **CI/CD Impact:** The merge check failed automatically, successfully blocking unapproved code commits from reaching the `main` branch.

---

## 7. Phase 7: GraphQL Fuzzing, Cryptographic Token Hardening & API Gateway Guardrails

### 7.1 Architecture Overview

```text
Incoming Request -> [ API Gateway (:8000) ]
                          |
            +-------------+-------------+
            |                           |
     Path == /graphql            Default / Rest APIs
            |                           |
      HTTP 403 Forbidden          Reverse Proxy
      (Edge Policy Block)               |
                                        v
                            [ Juice Shop Core (:3000) ]
```
Phase 7 introduced centralized edge enforcement using an API Gateway reverse-proxy fronting the target application.
### 7.2 GraphQL Introspection & Depth Testing Matrix
* **Target Endpoint:** `/graphql`
* **Introspection Assertion:** Verified client schema extraction handling. The target responded with an HTML SPA fallback (`text/html`), handled gracefully by the test runner.
* **Recursion & Batching Fuzzing:** Automated recursion payloads and array-wrapped batch execution assertions passed cleanly through content-type validation.

### 7.3 Cryptographic Token Security (JWT RS256 -> HS256 Confusion)
* **Test Module:** `tests/test_jwt_confusion.py`
* **Vulnerability Target:** Asymmetric-to-symmetric key confusion (CVE algorithm downgrade pattern).
* **Execution:** Forged administrative claims (`id: 1, role: admin`) signed via HMAC-SHA256 (`HS256`) using public key reference material as the symmetric HMAC secret.
* **Result:** **PASSED**. Server rejected the tampered signature with `HTTP 401 Unauthorized`.

### 7.4 Centralized Gateway Guardrail Enforcement
* **Deployment:** Containerized reverse proxy (`api-gateway`) mounted on port 8000.
* **Traffic Proxying:** `GET /rest/admin/application-version` via port 8000 routed directly to backend (`HTTP 200 OK`).
* **Edge Route Blocking:** `POST /graphql` intercepted at the gateway boundary, returning `HTTP 403 Forbidden` (`{"error": "Forbidden: Direct GraphQL access blocked by API Gateway policy."}`).
