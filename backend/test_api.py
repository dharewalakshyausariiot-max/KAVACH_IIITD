"""Integration tests for the HerGuard FastAPI endpoints.

Covers /api/health, /api/scan, and /api/notice with USE_MOCK=true
without requiring a live Supabase connection.
"""

from __future__ import annotations

import os
import uuid
import pytest
from fastapi.testclient import TestClient

# Ensure mock mode is enabled before importing app
os.environ["USE_MOCK"] = "true"

from main import app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a FastAPI TestClient."""
    return TestClient(app)


@pytest.fixture
def fake_png_bytes() -> bytes:
    """Tiny valid-header PNG image bytes for mock scanning."""
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def test_health_check_returns_ok_and_mock_mode(client: TestClient) -> None:
    """GET /api/health returns ok status and mock_mode indicator."""
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert data.get("status") == "ok"
    assert data.get("mock_mode") is True


def test_scan_with_fake_png_returns_hash_deepfake_and_matches(
    client: TestClient, fake_png_bytes: bytes
) -> None:
    """POST /api/scan returns a 64-char SHA-256 hash, deepfake result, and mock matches."""
    response = client.post(
        "/api/scan",
        files={"file": ("sample.png", fake_png_bytes, "image/png")},
    )
    assert response.status_code == 200

    data = response.json()

    # Valid UUID case_id
    assert "case_id" in data
    uuid.UUID(data["case_id"])

    # 64-character SHA-256 hex digest
    image_hash = data.get("image_hash")
    assert isinstance(image_hash, str)
    assert len(image_hash) == 64
    assert all(c in "0123456789abcdef" for c in image_hash.lower())

    # Deepfake result schema
    deepfake = data.get("deepfake")
    assert isinstance(deepfake, dict)
    assert "is_deepfake" in deepfake
    assert "confidence" in deepfake
    assert 0.0 <= deepfake["confidence"] <= 1.0
    assert deepfake.get("simulated") is True

    # Exposure matches
    matches = data.get("matches")
    assert isinstance(matches, list)
    assert len(matches) >= 3
    for match in matches:
        assert "url" in match
        assert "similarity_score" in match
        assert "host_details" in match
        assert match["host_details"]["abuse_email"] is not None


def test_repeated_scan_returns_identical_hash(
    client: TestClient, fake_png_bytes: bytes
) -> None:
    """POST /api/scan with the same image data produces the exact same SHA-256 hash."""
    res1 = client.post(
        "/api/scan",
        files={"file": ("sample1.png", fake_png_bytes, "image/png")},
    )
    res2 = client.post(
        "/api/scan",
        files={"file": ("sample2.png", fake_png_bytes, "image/png")},
    )

    assert res1.status_code == 200
    assert res2.status_code == 200

    hash1 = res1.json().get("image_hash")
    hash2 = res2.json().get("image_hash")

    assert hash1 == hash2


def test_notice_creation_dmca_and_cybercrime(client: TestClient) -> None:
    """POST /api/notice with valid JSON returns HTTP 200 containing the infringing URL."""
    target_url = "https://mirror-1.example/images/leak_test_target"

    # 1. DMCA Notice
    dmca_payload = {
        "case_id": str(uuid.uuid4()),
        "matched_url": target_url,
        "requester_name": "Pooja Malhotra",
        "requester_email": "pooja@example.com",
        "notice_type": "dmca",
    }
    res_dmca = client.post("/api/notice", json=dmca_payload)
    assert res_dmca.status_code == 200
    dmca_json = res_dmca.json()
    assert dmca_json["matched_url"] == target_url
    assert target_url in dmca_json["body"]
    assert dmca_json["status"] == "draft"
    assert "17 U.S.C. 512(c)" in dmca_json["body"] or "17 U.S.C. § 512(c)" in dmca_json["body"]

    # 2. Cybercrime Complaint
    cyber_payload = {
        "case_id": str(uuid.uuid4()),
        "matched_url": target_url,
        "requester_name": "Pooja Malhotra",
        "requester_email": "pooja@example.com",
        "notice_type": "cybercrime",
    }
    res_cyber = client.post("/api/notice", json=cyber_payload)
    assert res_cyber.status_code == 200
    cyber_json = res_cyber.json()
    assert cyber_json["matched_url"] == target_url
    assert target_url in cyber_json["body"]
    assert cyber_json["status"] == "draft"
    assert "66E" in cyber_json["body"]
    assert "67A" in cyber_json["body"]


def test_scan_with_unsupported_media_type_returns_415(client: TestClient) -> None:
    """POST /api/scan with text/plain returns HTTP 415 (Unsupported Media Type)."""
    text_content = b"This is plain text, not an image."
    response = client.post(
        "/api/scan",
        files={"file": ("notes.txt", text_content, "text/plain")},
    )
    assert response.status_code == 415
