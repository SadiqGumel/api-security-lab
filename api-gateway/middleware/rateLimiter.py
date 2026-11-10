import time
from collections import defaultdict
from typing import Tuple

class TokenBucketRateLimiter:
    """
    Sliding-window token bucket / frequency tracking rate limiter 
    supporting tiered limits for standard vs authentication endpoints.
    """
    def __init__(self):
        # Store sliding window requests: { client_key: [timestamp1, timestamp2, ...] }
        self.request_windows = defaultdict(list)
        
        # Define tiered limits: (max_requests, window_seconds)
        self.tiers = {
            "auth": (5, 10),       # 5 requests per 10 seconds for login/sensitive routes
            "standard": (100, 60)  # 100 requests per minute for standard routes
        }

    def _get_client_key(self, identifier: str, tier: str) -> str:
        return f"{tier}:{identifier}"

    def check_rate_limit(self, identifier: str, tier: str = "standard") -> Tuple[bool, dict]:
        """
        Evaluates current request pressure against sliding window limits.
        Returns: (is_allowed, telemetry_headers)
        """
        max_requests, window_seconds = self.tiers.get(tier, self.tiers["standard"])
        now = time.time()
        key = self._get_client_key(identifier, tier)

        # Clean old timestamps outside the current sliding window
        window_start = now - window_seconds
        timestamps = self.request_windows[key]
        self.request_windows[key] = [t for t in timestamps if t > window_start]

        current_count = len(self.request_windows[key])
        remaining = max(0, max_requests - current_count - 1)
        reset_time = int(now + window_seconds)

        headers = {
            "RateLimit-Limit": str(max_requests),
            "RateLimit-Remaining": str(remaining),
            "RateLimit-Reset": str(reset_time)
        }

        if current_count >= max_requests:
            headers["Retry-After"] = str(window_seconds)
            return False, headers

        # Record current request timestamp
        self.request_windows[key].append(now)
        return True, headers
