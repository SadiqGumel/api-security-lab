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
