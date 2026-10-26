from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time

# In-memory tracking for rate limiting simulation
rate_limit_tracker = {}

class SecureHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload, extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_POST(self):
        client_ip = self.client_address[0]
        if self.path == "/rest/user/login":
            now = time.time()
            attempts = rate_limit_tracker.get(client_ip, [])
            # Filter attempts within 60 seconds
            attempts = [t for t in attempts if now - t < 60]
            
            if len(attempts) >= 3:
                headers = {
                    "RateLimit-Limit": "3",
                    "RateLimit-Remaining": "0",
                    "Retry-After": "60"
                }
                return self._send_json(429, {"status": "error", "message": "Rate limit exceeded."}, headers)

            attempts.append(now)
            rate_limit_tracker[client_ip] = attempts

            headers = {
                "RateLimit-Limit": "3",
                "RateLimit-Remaining": str(3 - len(attempts)),
                "RateLimit-Reset": "60"
            }
            return self._send_json(200, {"status": "success", "token": "simulated_secure_jwt"}, headers)

    def do_GET(self):
        auth_header = self.headers.get("Authorization", "")
        # Simulated verified token represents user ID 26
        caller_user_id = 26 if "Bearer valid_token_user_26" in auth_header else None

        if not caller_user_id:
            return self._send_json(401, {"status": "error", "message": "Unauthorized token."})

        if self.path.startswith("/rest/basket/"):
            basket_id = int(self.path.split("/")[-1])
            # Basket 1 belongs to User 1; Basket 6 belongs to User 26
            basket_owner = 1 if basket_id == 1 else 26

            # Enforce BOLA Tenancy Check
            if basket_owner != caller_user_id:
                return self._send_json(403, {"status": "error", "message": "Forbidden: Access denied."})

            return self._send_json(200, {"status": "success", "data": {"id": basket_id, "UserId": basket_owner}})

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 3001), SecureHandler)
    server.serve_forever()
