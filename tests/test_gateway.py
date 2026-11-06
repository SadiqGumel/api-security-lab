import pytest
import httpx

GATEWAY_BASE_URL = "http://localhost:8000"

def test_gateway_reverse_proxy_forwarding():
    """
    Verifies that the API Gateway correctly routes legitimate traffic to Juice Shop.
    """
    with httpx.Client(base_url=GATEWAY_BASE_URL) as client:
        response = client.get("/rest/admin/application-version")
        assert response.status_code == 200, (
            f"Gateway failed to proxy clean traffic: {response.status_code}"
        )
        assert "version" in response.json() or "success" in response.text

def test_gateway_graphql_edge_blocking():
    """
    Verifies that the API Gateway blocks unauthenticated/unapproved GraphQL calls at the edge.
    """
    with httpx.Client(base_url=GATEWAY_BASE_URL) as client:
        response = client.post("/graphql", json={"query": "{ __schema { types { name } } }"})
        assert response.status_code == 403, (
            f"Gateway failed to enforce edge policy: {response.status_code}"
        )
        data = response.json()
        assert "error" in data and "Direct GraphQL access blocked" in data["error"]
