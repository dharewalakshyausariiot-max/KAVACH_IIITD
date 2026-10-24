"""Legal notice and complaint draft generator for HerGuard.

Produces pre-formatted takedown notices and cybercrime complaint drafts
incorporating DMCA 17 U.S.C. 512(c), India's IT Rules 2021 Rule 3(2)(b), and
IT Act 2000 Sections 66E and 67A. All outputs are strictly drafts and are
never automatically sent.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any
from urllib.parse import urlparse

if __package__:
    from .schemas import HostDetails, NoticeRequest, NoticeResponse
else:
    from schemas import HostDetails, NoticeRequest, NoticeResponse


LEGAL_DISCLAIMER: str = (
    "LEGAL DISCLAIMER: This document is an auto-generated draft and does not constitute "
    "legal advice or attorney representation. Drafts only, never auto-send. Requesters "
    "must review and verify all details before submitting. If you are located in India, "
    "you can report cyber offences and non-consensual imagery directly to the National "
    "Cyber Crime Reporting Portal at https://cybercrime.gov.in or by calling 1930."
)


def _resolve_evidence_hash(
    req: NoticeRequest,
    image_hash: str | None = None,
) -> str:
    """Return the explicit image hash or derive a deterministic SHA-256 fingerprint."""
    if image_hash and str(image_hash).strip():
        return str(image_hash).strip()
    for attr in ("image_hash", "evidence_hash", "sha256", "image_sha256"):
        val = getattr(req, attr, None)
        if val and str(val).strip():
            return str(val).strip()
    raw = f"{req.case_id}:{req.matched_url}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _extract_host_info(
    host: HostDetails | dict[str, Any] | None,
    req: NoticeRequest,
) -> tuple[str, str, str, str]:
    """Extract (domain, ip_address, hosting_provider, abuse_email)."""
    domain: str | None = None
    ip_address: str | None = None
    hosting_provider: str | None = None
    abuse_email: str | None = None

    if host is not None:
        if isinstance(host, dict):
            domain = host.get("domain")
            ip_address = host.get("ip_address")
            hosting_provider = host.get("hosting_provider")
            abuse_email = host.get("abuse_email")
        else:
            domain = getattr(host, "domain", None)
            ip_address = getattr(host, "ip_address", None)
            hosting_provider = getattr(host, "hosting_provider", None)
            abuse_email = getattr(host, "abuse_email", None)

    if not domain and getattr(req, "matched_url", None):
        parsed = urlparse(req.matched_url)
        domain = parsed.netloc or parsed.path.split("/")[0]

    return (
        domain or "Unknown Domain",
        ip_address or "Not Available / Dynamic",
        hosting_provider or "Unknown Hosting Provider",
        abuse_email or "None Listed",
    )


def _extract_recipient(
    host: HostDetails | dict[str, Any] | None,
    abuse_form_url: str | None,
    req: NoticeRequest,
) -> str | None:
    """Determine notice recipient: host.abuse_email or abuse_form_url."""
    abuse_email: str | None = None
    if host is not None:
        if isinstance(host, dict):
            abuse_email = host.get("abuse_email")
        else:
            abuse_email = getattr(host, "abuse_email", None)

    if abuse_email and str(abuse_email).strip():
        return str(abuse_email).strip()
    if abuse_form_url and str(abuse_form_url).strip():
        return str(abuse_form_url).strip()

    for attr in ("abuse_email", "abuse_form_url", "recipient_email"):
        val = getattr(req, attr, None)
        if val and str(val).strip():
            return str(val).strip()

    return None


def _format_dmca_notice(
    req: NoticeRequest,
    evidence_hash: str,
    domain: str,
    recipient: str | None,
) -> tuple[str, str]:
    """Build subject and body for a DMCA / IT Rules 2021 takedown notice."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    recipient_display = recipient or f"Abuse Department / Legal Agent for {domain}"

    subject = (
        f"URGENT: Content Removal Notice (DMCA 17 U.S.C. 512(c) / IT Rules 2021) "
        f"- Case {req.case_id}"
    )

    body = f"""TAKEDOWN NOTICE PURSUANT TO DMCA (17 U.S.C. § 512(c)) AND IT RULES 2021 RULE 3(2)(b)

Date: {date_str}
Case Reference: {req.case_id}
To: Designated Abuse / Copyright Agent ({recipient_display})
Platform / Domain: {domain}
From: {req.requester_name} ({req.requester_email})

Subject: {subject}

Dear Abuse / Legal Team,

I am writing to formally demand the immediate removal of and disabling of access to unauthorized and unlawful material hosted on your network or service, pursuant to:
1. The Digital Millennium Copyright Act (DMCA 17 U.S.C. 512(c));
2. Your platform non-consensual imagery policies, Terms of Service, and community safety standards; and
3. Rule 3(2)(b) of India's Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021 (IT Rules 2021).

1. IDENTIFICATION OF UNLAWFUL / INFRINGING MATERIAL
- Offending URL: {req.matched_url}
- Evidence SHA-256 Fingerprint: {evidence_hash}
- Case Identifier: {req.case_id}
- Hosting Domain: {domain}

The material accessible at the offending URL depicts or contains non-consensual imagery and/or unauthorized personal content of the undersigned, circulated without knowledge, license, or consent, in clear breach of platform non-consensual imagery policies.

2. STATUTORY BASIS & 24-HOUR REMOVAL EXPECTATION
- DMCA 17 U.S.C. 512(c): This notification satisfies the statutory requirements for takedown notices under 17 U.S.C. § 512(c)(3). You are obligated to act expeditiously to remove or disable access to the infringing material.
- Platform Non-Consensual Imagery Policies: The specified content constitutes non-consensual intimate imagery (NCII) / non-consensual sexual content, warranting immediate platform-wide cessation and removal.
- India's IT Rules 2021 Rule 3(2)(b): Under Rule 3(2)(b) of the IT Rules 2021, an intermediary is required to remove or disable access to content that exposes the private area of any person or depicts non-consensual imagery within twenty-four (24) hours of receipt of notice. Immediate compliance with this 24-hour removal expectation is formally requested.

3. FORMAL REQUEST TO PRESERVE LOGS AND ELECTRONIC EVIDENCE
Pursuant to anticipated civil and criminal proceedings, you are hereby requested to preserve logs, including all server access logs, timestamps, source IP addresses, account profile data, upload records, and transmission metadata connected with the offending URL and the account(s) responsible for uploading it. Do not destroy, purge, or alter this evidence.

4. GOOD-FAITH STATEMENT & STATUTORY DECLARATION
- I have a good-faith belief that the use and distribution of the identified material is not authorized by the copyright owner, the depicted individual, its agent, or the law.
- I declare, under penalty of perjury, that the information in this notification is accurate and that I am the individual depicted, the copyright owner, or authorized to act on behalf of the owner of an exclusive right that is allegedly infringed.

Please confirm receipt and verify when the material has been removed or disabled.

Sincerely,
{req.requester_name}
Contact: {req.requester_email}

================================================================================
{LEGAL_DISCLAIMER}
================================================================================
"""
    return subject, body.strip()


def _format_cybercrime_complaint(
    req: NoticeRequest,
    evidence_hash: str,
    domain: str,
    ip_address: str,
    hosting_provider: str,
    abuse_email: str,
) -> tuple[str, str]:
    """Build subject and body for a cybercrime complaint draft."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = (
        f"Formal Cybercrime Complaint Draft: Violation of IT Act 2000 (Sections 66E & 67A) "
        f"- Case {req.case_id}"
    )

    body = f"""COMPLAINT DRAFT FOR CYBER OFFENCES
(Under Sections 66E and 67A of the Information Technology Act, 2000)

Date: {date_str}
Case Reference: {req.case_id}
To: The Officer-in-Charge / Cyber Crime Investigation Cell / Grievance Officer
Platform / Intermediary: {domain}
Complainant: {req.requester_name}
Email: {req.requester_email}

Subject: {subject}

Respected Authorities / Grievance Officer,

I am submitting this formal complaint regarding the unauthorized, non-consensual publication, transmission, and hosting of intimate/private imagery on electronic networks, causing severe invasion of privacy and ongoing harm.

1. STATUTORY PROVISIONS CITED
The reported conduct constitutes cognizable criminal offences under the Information Technology Act, 2000 (IT Act 2000):
- IT Act 2000 Section 66E: Punishment for violation of bodily privacy (capturing, publishing, or transmitting the image of a private area of any person without consent).
- IT Act 2000 Section 67A: Punishment for publishing or transmitting material containing sexually explicit act, etc., in electronic form.

2. EVIDENCE DETAILS & DIGITAL SIGNATURE
- Offending URL: {req.matched_url}
- Evidence Hash (SHA-256 Digest): {evidence_hash}
- Case Identifier: {req.case_id}

3. HOST AND REGISTRAR DETAILS
The technical infrastructure, host/registrar details, and service records identified for the offending URL are:
- Domain / Platform: {domain}
- Host IP Address: {ip_address}
- Hosting Provider: {hosting_provider}
- Abuse Contact: {abuse_email}

4. PRAYER FOR RELIEF (REQUEST FOR FIR / ACKNOWLEDGEMENT)
In light of the criminal offences established under IT Act 2000 Sections 66E and 67A, the complainant respectfully requests:
1. FIR Registration: Immediate registration of a First Information Report (FIR) under Sections 66E and 67A of the IT Act 2000 and all other relevant legal provisions.
2. Formal Acknowledgement: Immediate issuance of a written acknowledgement and formal complaint diary/reference number for this submission.
3. Content Removal and Preservation: Issuance of directives to the host/intermediary to immediately block/take down the offending URL and preserve all associated access logs, source IP logs, and uploader account data.
4. Investigation: Prompt investigation to identify, trace, and prosecute the individuals responsible for creating, uploading, and circulating this content.

I verify that the facts stated in this complaint draft are true to the best of my knowledge and belief.

Complainant:
{req.requester_name}
Email: {req.requester_email}

================================================================================
{LEGAL_DISCLAIMER}
================================================================================
"""
    return subject, body.strip()


def generate_notice(
    req: NoticeRequest,
    notice_type: str | None = None,
    host: HostDetails | dict[str, Any] | None = None,
    abuse_form_url: str | None = None,
    image_hash: str | None = None,
    **kwargs: Any,
) -> NoticeResponse:
    """Generate a legal takedown notice or cybercrime complaint draft.

    Args:
        req: The NoticeRequest containing case_id, matched_url, requester details.
        notice_type: "dmca" for DMCA/IT Rules takedown or "cybercrime" for an
            IT Act complaint draft. Defaults to "dmca" if unspecified.
        host: HostDetails or dict containing domain, ip_address, hosting_provider,
            abuse_email.
        abuse_form_url: Web submission URL for host abuse reporting.
        image_hash: SHA-256 fingerprint of the offending media.
        **kwargs: Additional metadata accepted for forward compatibility.

    Returns:
        NoticeResponse with status="draft", pre-formatted subject, body, and recipient.
    """
    if host is None:
        host = getattr(req, "host", None) or getattr(req, "host_details", None)
    if abuse_form_url is None:
        abuse_form_url = getattr(req, "abuse_form_url", None)

    resolved_hash = _resolve_evidence_hash(req, image_hash=image_hash)
    domain, ip_address, hosting_provider, host_abuse_email = _extract_host_info(host, req)
    recipient = _extract_recipient(host, abuse_form_url, req)

    effective_type = notice_type or getattr(req, "notice_type", None) or "dmca"
    normalized_type = str(effective_type).strip().lower()

    if normalized_type in {"dmca", "dmca_takedown", "takedown"}:
        subject, body = _format_dmca_notice(
            req=req,
            evidence_hash=resolved_hash,
            domain=domain,
            recipient=recipient,
        )
    elif normalized_type in {"cybercrime", "cyber_crime", "fir", "complaint"}:
        subject, body = _format_cybercrime_complaint(
            req=req,
            evidence_hash=resolved_hash,
            domain=domain,
            ip_address=ip_address,
            hosting_provider=hosting_provider,
            abuse_email=host_abuse_email,
        )
    else:
        raise ValueError(
            f"Unsupported notice_type: {effective_type!r}. Supported types: 'dmca', 'cybercrime'."
        )

    return NoticeResponse(
        case_id=req.case_id,
        matched_url=req.matched_url,
        subject=subject,
        body=body,
        recipient_email=recipient,
        status="draft",
    )
