"""Unit tests for the HerGuard legal notices module.

Tests generate_notice directly for DMCA and cybercrime notice types,
validating statutory citations, recipient fallback, missing fields,
disclaimer inclusion, and cryptographic SHA-256 fingerprint preservation.
"""

from __future__ import annotations

import hashlib
import uuid
import pytest

from notices import LEGAL_DISCLAIMER, generate_notice
from schemas import HostDetails, NoticeRequest, NoticeResponse


@pytest.fixture
def base_request() -> NoticeRequest:
    """Fixture providing a standard valid NoticeRequest."""
    return NoticeRequest(
        case_id=uuid.uuid4(),
        matched_url="https://mirror.leakplatform.example/uploads/leak123.png",
        requester_name="Ananya Verma",
        requester_email="ananya@example.com",
    )


def test_dmca_notice_citations_and_structure(base_request: NoticeRequest) -> None:
    """Verify DMCA notice citations, 24-hour requirement, good faith, and log preservation."""
    sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    host = HostDetails(
        domain="mirror.leakplatform.example",
        ip_address="198.51.100.12",
        hosting_provider="Example Cloud Hosting",
        abuse_email="abuse@leakplatform.example",
    )

    response = generate_notice(
        req=base_request,
        notice_type="dmca",
        host=host,
        image_hash=sample_hash,
    )

    assert isinstance(response, NoticeResponse)
    assert response.status == "draft"
    assert response.case_id == base_request.case_id
    assert response.matched_url == base_request.matched_url
    assert response.recipient_email == "abuse@leakplatform.example"

    # Core statutory & policy citations
    assert "17 U.S.C. 512(c)" in response.body or "17 U.S.C. § 512(c)" in response.body
    assert "platform non-consensual imagery policies" in response.body
    assert "Rule 3(2)(b)" in response.body
    assert "24-hour" in response.body
    assert "preserve logs" in response.body
    assert "good-faith" in response.body

    # SHA-256 fingerprint check
    assert sample_hash in response.body
    assert "Evidence SHA-256 Fingerprint:" in response.body

    # Disclaimer check
    assert LEGAL_DISCLAIMER in response.body
    assert "cybercrime.gov.in" in response.body
    assert "1930" in response.body
    assert "never auto-send" in response.body


def test_cybercrime_complaint_citations_and_structure(base_request: NoticeRequest) -> None:
    """Verify cybercrime complaint citations, host details, and FIR request."""
    sample_hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    host = HostDetails(
        domain="mirror.leakplatform.example",
        ip_address="203.0.113.55",
        hosting_provider="Offshore Hosting Ltd",
        abuse_email="report@offshore.example",
    )

    response = generate_notice(
        req=base_request,
        notice_type="cybercrime",
        host=host,
        image_hash=sample_hash,
    )

    assert isinstance(response, NoticeResponse)
    assert response.status == "draft"
    assert response.recipient_email == "report@offshore.example"

    # Penal provisions
    assert "66E" in response.body
    assert "67A" in response.body
    assert "IT Act 2000" in response.body

    # Technical host & infrastructure details
    assert "mirror.leakplatform.example" in response.body
    assert "203.0.113.55" in response.body
    assert "Offshore Hosting Ltd" in response.body

    # Remedies sought
    assert "FIR" in response.body
    assert "Acknowledgement" in response.body

    # Fingerprint matching in body
    assert sample_hash in response.body

    # Mandatory disclaimer
    assert LEGAL_DISCLAIMER in response.body
    assert "cybercrime.gov.in" in response.body
    assert "1930" in response.body


def test_recipient_fallback_rules(base_request: NoticeRequest) -> None:
    """Verify fallback hierarchy: host.abuse_email -> abuse_form_url -> None."""
    # Case 1: host.abuse_email takes priority
    host_with_email = HostDetails(
        domain="example.com",
        abuse_email="abuse@primary.example",
    )
    res1 = generate_notice(
        req=base_request,
        notice_type="dmca",
        host=host_with_email,
        abuse_form_url="https://example.com/abuse-form",
    )
    assert res1.recipient_email == "abuse@primary.example"

    # Case 2: host.abuse_email is None/empty -> falls back to abuse_form_url
    host_without_email = HostDetails(
        domain="example.com",
        abuse_email=None,
    )
    res2 = generate_notice(
        req=base_request,
        notice_type="dmca",
        host=host_without_email,
        abuse_form_url="https://example.com/abuse-form",
    )
    assert res2.recipient_email == "https://example.com/abuse-form"

    # Case 3: Neither provided -> None
    res3 = generate_notice(
        req=base_request,
        notice_type="dmca",
        host=host_without_email,
        abuse_form_url=None,
    )
    assert res3.recipient_email is None


def test_missing_fields_and_defaults(base_request: NoticeRequest) -> None:
    """Verify clean fallback behavior when optional fields are omitted."""
    # Calling generate_notice with only req: defaults to dmca, derives domain from URL
    response = generate_notice(base_request)
    assert response.status == "draft"
    assert response.recipient_email is None

    # Domain was parsed from matched_url
    assert "mirror.leakplatform.example" in response.body

    # Cryptographic hash fallback: SHA-256 of f"{case_id}:{matched_url}"
    expected_fallback_hash = hashlib.sha256(
        f"{base_request.case_id}:{base_request.matched_url}".encode("utf-8")
    ).hexdigest()
    assert expected_fallback_hash in response.body
    assert len(expected_fallback_hash) == 64


def test_unsupported_notice_type_raises_value_error(base_request: NoticeRequest) -> None:
    """Verify ValueError is raised for unrecognized notice_type strings."""
    with pytest.raises(ValueError, match="Unsupported notice_type"):
        generate_notice(base_request, notice_type="cease_and_desist")
