import pytest
import httpx

def test_graphql_introspection_exposure(sync_client: httpx.Client):
    """
    Evaluates whether a GraphQL engine is present and exposes schema introspection.
    Defensive expectation: Either disabled/404, or introspection restricted.
    """
    payload = {
        "query": """
        query IntrospectSchema {
            __schema {
                types { name }
            }
        }
        """
    }
    response = sync_client.post("/graphql", json=payload)
    
    # Check if the route returned HTML (SPA fallback / non-existent route)
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        pytest.skip("GraphQL endpoint not implemented on /graphql (SPA fallback returned).")

    assert response.status_code == 200, f"Unexpected status: {response.status_code}"
    body = response.json()
    
    schema_exposed = "data" in body and "__schema" in body.get("data", {})
    assert not schema_exposed, "GraphQL Introspection Vulnerability: Schema metadata exposed."

def test_graphql_deeply_nested_query_dos(sync_client: httpx.Client):
    """
    Evaluates recursion and depth limiting on GraphQL queries.
    """
    nested_query = {"query": "{ " + "cards { id user { " * 5 + "id" + " } }" * 5 + " }"}
    response = sync_client.post("/graphql", json=nested_query, timeout=5.0)

    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        pytest.skip("GraphQL endpoint not implemented on /graphql.")

    assert response.status_code == 400 or "errors" in response.json(), (
        f"Server processed deep nested query without cost analysis (Status: {response.status_code})"
    )

def test_graphql_batching_abuse(sync_client: httpx.Client):
    """
    Evaluates whether array-wrapped batch queries are accepted.
    """
    batched_payload = [{"query": "{ __typename }"}] * 10
    response = sync_client.post("/graphql", json=batched_payload)

    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        pytest.skip("GraphQL endpoint not implemented on /graphql.")

    assert response.status_code != 200 or not isinstance(response.json(), list), (
        "Server accepted array-wrapped batch execution."
    )
