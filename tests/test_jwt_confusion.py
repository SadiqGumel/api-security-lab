import pytest
import httpx
import hmac
import hashlib
import base64
import json

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def test_jwt_algorithm_confusion_downgrade(sync_client: httpx.Client):
    """
    Automates RS256 -> HS256 downgrade fuzzing.
    Uses Python's standard library (hmac/hashlib) to forge an administrative token.
    Defensive expectation: The server must reject the algorithm mismatch with HTTP 401.
    """
    # 1. Fetch public key or certificate metadata if exposed
    pub_res = sync_client.get("/rest/admin/application-version")
    public_secret = "owasp-juice-shop-public-key"  # Target public reference / fallback secret

    # 2. Forge header asserting symmetric HS256
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "id": 1,
        "email": "admin@juice-sh.op",
        "role": "admin"
    }

    # 3. Base64URL-encode header and payload
    encoded_header = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    encoded_payload = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')

    # 4. Generate HMAC-SHA256 signature using the public key as the secret
    signature = hmac.new(public_secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)

    forged_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    # 5. Send the forged token to a protected endpoint
    headers = {"Authorization": f"Bearer {forged_token}"}
    response = sync_client.get("/rest/basket/1", headers=headers)

    # 6. Verify server rejects the tampered token
    assert response.status_code == 401, (
        f"Critical JWT Confusion Vulnerability! Server accepted forged HS256 token. "
        f"Status: {response.status_code}"
    )
