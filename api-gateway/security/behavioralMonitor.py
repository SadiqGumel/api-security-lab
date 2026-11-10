import time
from collections import defaultdict
from typing import Dict, Tuple

class BehavioralSecurityMonitor:
    """
    Monitors request heuristics to detect credential stuffing sweeps 
    and BOLA rapid sequential ID harvesting.
    """
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.resource_access_log = defaultdict(list)
        self.quarantined_ips: Dict[str, float] = {}

    def is_quarantined(self, client_ip: str) -> bool:
        if client_ip in self.quarantined_ips:
            if time.time() < self.quarantined_ips[client_ip]:
                return True
            del self.quarantined_ips[client_ip]
        return False

    def record_failed_login(self, client_ip: str) -> bool:
        """
        Tracks failed logins. If > 10 failures occur within 60s, trigger quarantine.
        """
        now = time.time()
        window_start = now - 60
        
        # Prune old entries
        self.failed_logins[client_ip] = [t for t in self.failed_logins[client_ip] if t > window_start]
        self.failed_logins[client_ip].append(now)

        if len(self.failed_logins[client_ip]) >= 10:
            self.quarantine_ip(client_ip, duration_seconds=900)  # 15 min ban
            return True # Quarantined due to credential stuffing
        return False

    def record_resource_access(self, client_ip: str, resource_id: int) -> bool:
        """
        Detects rapid-fire sequential ID scraping (BOLA / enumeration).
        """
        now = time.time()
        window_start = now - 5  # 5-second sliding check
        
        # Prune window
        self.resource_access_log[client_ip] = [
            (t, rid) for t, rid in self.resource_access_log[client_ip] if t > window_start
        ]
        self.resource_access_log[client_ip].append((now, resource_id))

        accesses = self.resource_access_log[client_ip]
        if len(accesses) >= 5:
            # Check if IDs are strictly sequential (e.g., 1, 2, 3, 4, 5)
            ids = [rid for _, rid in accesses]
            is_sequential = all(ids[i] + 1 == ids[i+1] for i in range(len(ids)-1))
            if is_sequential:
                self.quarantine_ip(client_ip, duration_seconds=300) # 5 min quarantine
                return True
        return False

    def quarantine_ip(self, client_ip: str, duration_seconds: int):
        self.quarantined_ips[client_ip] = time.time() + duration_seconds
