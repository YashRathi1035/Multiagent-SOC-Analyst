"""Unit and integration tests for FastAPI REST API endpoints (Phase 7).

Verifies:
1. System health check endpoint
2. Headless log ingestion and multi-agent investigation execution
3. Persistent case listing, retrieval, status update, and deletion
4. Threat intelligence indicator lookup with RFC 1918 guard
5. RAG knowledge search across ATT&CK and NIST playbooks
"""

import pytest
from fastapi.testclient import TestClient

from api.routes import app
from data.test_cases.scenarios import SYNTHETIC_BRUTE_FORCE_LOG
from models.schemas import ReviewStatus, SeverityLevel


@pytest.fixture
def client():
    """Create FastAPI test client."""
    return TestClient(app)


class TestAPIEndpoints:
    """Test suite for FastAPI REST API."""

    def test_health_check(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "llm_runtime" in data
        assert "database_cases" in data

    def test_root_redirects_or_returns_health(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_investigate_empty_payload(self, client):
        response = client.post(
            "/api/v1/investigate",
            json={"log_content": "   ", "log_format": "auth_openssh"},
        )
        assert response.status_code == 400
        assert "cannot be empty" in response.json()["detail"]

    def test_investigate_brute_force_success(self, client):
        response = client.post(
            "/api/v1/investigate",
            json={
                "log_content": SYNTHETIC_BRUTE_FORCE_LOG,
                "log_format": "auth_openssh",
                "raw_filename": "test_brute_force.log",
                "enable_ml": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["case_id"].startswith("CASE-")
        assert data["alerts_detected"] >= 1
        assert data["events_normalized"] == 6
        assert data["report"] is not None
        assert data["report"]["severity"] in ("HIGH", "CRITICAL")
        assert len(data["agent_trace"]) >= 5

    def test_case_management_lifecycle(self, client):
        # 1. Trigger an investigation to create a case
        inv_res = client.post(
            "/api/v1/investigate",
            json={
                "log_content": SYNTHETIC_BRUTE_FORCE_LOG,
                "log_format": "auth_openssh",
            },
        )
        case_id = inv_res.json()["case_id"]

        # 2. List cases
        list_res = client.get("/api/v1/cases?limit=10")
        assert list_res.status_code == 200
        list_data = list_res.json()
        assert list_data["total"] >= 1
        assert any(c["case_id"] == case_id for c in list_data["cases"])

        # 3. Retrieve specific case
        get_res = client.get(f"/api/v1/cases/{case_id}")
        assert get_res.status_code == 200
        case_detail = get_res.json()
        assert case_detail["metadata"]["case_id"] == case_id
        assert case_detail["report"]["case_id"] == case_id

        # 4. Update status and notes
        patch_res = client.patch(
            f"/api/v1/cases/{case_id}/status",
            json={
                "status": "APPROVED",
                "notes": "Analyst reviewed: confirmed malicious external IP.",
            },
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["case"]["status"] == "APPROVED"

        # 5. Delete case
        del_res = client.delete(f"/api/v1/cases/{case_id}")
        assert del_res.status_code == 200

        # Verify 404 after deletion
        assert client.get(f"/api/v1/cases/{case_id}").status_code == 404

    def test_indicator_lookup_external_and_private(self, client):
        # External IP lookup
        ext_res = client.post(
            "/api/v1/indicators/lookup",
            json={"indicator": "187.141.143.180"},
        )
        assert ext_res.status_code == 200
        data = ext_res.json()
        assert data["indicator"] == "187.141.143.180"
        assert "reputation_score" in data

        # Private RFC 1918 IP lookup
        priv_res = client.post(
            "/api/v1/indicators/lookup",
            json={"indicator": "10.0.5.22"},
        )
        assert priv_res.status_code == 200
        priv_data = priv_res.json()
        assert "Private" in priv_data["threat_category"]
        assert priv_data["reputation_score"] == 0.0
        assert priv_data["is_malicious"] is False

    def test_knowledge_search(self, client):
        response = client.post(
            "/api/v1/knowledge/search",
            json={"query": "SSH brute force authentication", "top_k": 3},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] >= 1
        assert "results" in data
        assert any("T1110" in r["id"] for r in data["results"])
