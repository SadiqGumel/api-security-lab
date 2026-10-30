import pytest
import httpx

def test_tenant_boundary_basket_read(sync_client: httpx.Client, user_a_token: str, user_b_token: str):
    """
    OWASP API1:2023 - Broken Object Level Authorization (BOLA) Check.
    Validates whether Tenant B can read Tenant A's private basket data.
    Expected defensive behavior: HTTP 403 Forbidden or HTTP 404 Not Found.
    """
    target_basket_id = 1
    headers = {"Authorization": f"Bearer {user_b_token}"}

    response = sync_client.get(f"/rest/basket/{target_basket_id}", headers=headers)

    assert response.status_code in [403, 404], (
        f"Security Boundary Violation! Cross-tenant access permitted on /rest/basket/{target_basket_id}. "
        f"Received status code: {response.status_code}"
    )

def test_tenant_boundary_basket_mutation(sync_client: httpx.Client, user_b_token: str):
    """
    OWASP API1:2023 - BOLA Mutation Check.
    Ensures Tenant B cannot inject items into Tenant A's basket (BasketId: 1).
    """
    headers = {"Authorization": f"Bearer {user_b_token}"}
    payload = {
        "ProductId": 1,
        "BasketId": 1,
        "quantity": 1
    }

    response = sync_client.post("/api/BasketItems/", json=payload, headers=headers)

    assert response.status_code in [403, 404], (
        f"Unauthorized Mutation Violation! Server allowed Tenant B to add items to Basket 1. "
        f"Received status code: {response.status_code}"
    )
