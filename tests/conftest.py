import pytest
import httpx

BASE_URL = "http://localhost:3000"

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL

@pytest.fixture(scope="session")
def sync_client():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        yield client

def login_user(client: httpx.Client, email: str, password: str) -> str:
    response = client.post("/rest/user/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"Authentication failed for user: {email}"
    data = response.json()
    return data["authentication"]["token"]

@pytest.fixture(scope="session")
def user_a_token(sync_client):
    # Tenant A (Standard user account)
    return login_user(sync_client, "admin@juice-sh.op", "admin123")

@pytest.fixture(scope="session")
def user_b_token(sync_client):
    # Tenant B (Alternative account to test cross-tenant boundaries)
    return login_user(sync_client, "jim@juice-sh.op", "ncc-1701")
