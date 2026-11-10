import pytest
import time
from api-gateway.middleware.rateLimiter import TokenBucketRateLimiter
from api-gateway.security.behavioralMonitor import BehavioralSecurityMonitor

def test_token_bucket_auth_tier_limiting():
    """Verify that authentication endpoints strictly block requests after the 5th attempt."""
    limiter = TokenBucketRateLimiter()
    client_ip = "192.168.1.100"
    
    # First 5 requests should pass
    for i in range(5):
        allowed, headers = limiter.check_rate_limit(client_ip, tier="auth")
        assert allowed is True
        assert int(headers["RateLimit-Remaining"]) == 4 - i

    # 6th request should fail with 429 / Retry-After
    allowed, headers = limiter.check_rate_limit(client_ip, tier="auth")
    assert allowed is False
    assert "Retry-After" in headers
    assert headers["RateLimit-Remaining"] == "0"

def test_behavioral_credential_stuffing_detection():
    """Verify that excessive failed logins trigger an IP quarantine."""
    monitor = BehavioralSecurityMonitor()
    attacker_ip = "203.0.113.50"

    assert monitor.is_quarantined(attacker_ip) is False

    # Simulate 10 rapid failed login attempts across different accounts
    quarantined = False
    for _ in range(10):
        quarantined = monitor.record_failed_login(attacker_ip)

    assert quarantined is True
    assert monitor.is_quarantined(attacker_ip) is True

def test_sequential_bola_scraping_detection():
    """Verify rapid-fire sequential resource ID requests trigger quarantine."""
    monitor = BehavioralSecurityMonitor()
    scraper_ip = "198.51.100.25"

    assert monitor.is_quarantined(scraper_ip) is False

    # Simulate rapid sequential scraping: IDs 1, 2, 3, 4, 5
    triggered = False
    for rid in range(1, 6):
        triggered = monitor.record_resource_access(scraper_ip, rid)

    assert triggered is True
    assert monitor.is_quarantined(scraper_ip) is True
