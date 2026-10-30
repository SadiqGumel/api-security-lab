import pytest
import httpx
import asyncio

@pytest.mark.asyncio
async def test_authentication_rate_limiting():
    """
    OWASP API4:2023 - Unrestricted Resource Consumption Check.
    Fires rapid concurrent requests to test rate limiting and telemetry headers.
    """
    endpoint = "http://localhost:3000/rest/user/login"
    payload = {"email": "audit_rate_test@juice-sh.op", "password": "wrong_password"}
    burst_count = 25

    async with httpx.AsyncClient(timeout=10.0) as async_client:
        tasks = [
            async_client.post(endpoint, json=payload)
            for _ in range(burst_count)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    valid_responses = [r for r in responses if isinstance(r, httpx.Response)]
    status_codes = [r.status_code for r in valid_responses]
    throttled = [r for r in valid_responses if r.status_code == 429]

    # Validate whether rate limiting was triggered
    assert len(throttled) > 0, (
        f"Rate-limiting check failed: {burst_count} rapid requests were accepted without HTTP 429. "
        f"Status codes seen: {set(status_codes)}"
    )

    # Validate presence of standard rate limit telemetry headers
    sample_429 = throttled[0]
    headers_lower = {k.lower(): v for k, v in sample_429.headers.items()}
    assert any(h in headers_lower for h in ["retry-after", "ratelimit-limit", "x-ratelimit-limit"]), (
        "Rate-limiting triggered but missing standard Retry-After or RateLimit headers."
    )
