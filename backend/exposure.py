"""Deterministic demo exposures and strict TinyFish/RDAP integration.

Real searches look for publicly indexed SHA-256 references. A hash alone cannot
perform perceptual reverse-image search or establish visual similarity.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import TYPE_CHECKING, List, cast
from urllib.parse import quote, urlsplit

import httpx

if TYPE_CHECKING:
    from backend.schemas import ExposureMatch, HostDetails
elif __package__:
    from .schemas import ExposureMatch, HostDetails
else:
    from schemas import ExposureMatch, HostDetails


_MAX_MATCHES = 20
_MAX_RESPONSE_BYTES = 1024 * 1024
_HASH_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def _mock_enabled() -> bool:
    """Parse the environment strictly so a typo cannot enable demo results."""
    value = os.getenv("USE_MOCK", "true").strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise ValueError("USE_MOCK must be a boolean (true/false, 1/0, yes/no, on/off).")


def _object(value: object, context: str) -> dict[str, object]:
    """Narrow decoded JSON to an object with string keys."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{context}: expected a JSON object.")
    return cast(dict[str, object], value)


def _domain(url: str) -> str:
    """Extract a DNS hostname from a credential-free absolute HTTP(S) URL."""
    if not url or len(url) > 2048 or any(char.isspace() or ord(char) < 32 for char in url):
        raise ValueError("Discovered URL is empty, oversized, or contains whitespace.")
    try:
        parts = urlsplit(url)
        hostname = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        port = parts.port
        if (
            parts.scheme not in {"http", "https"}
            or parts.username is not None
            or parts.password is not None
            or "\\" in url
            or not _DOMAIN_PATTERN.fullmatch(hostname)
            or port == 0
        ):
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Discovered URL must be an absolute HTTP(S) URL with a DNS domain.") from exc
    return hostname


async def _request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    service: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    follow_redirects: bool = False,
    timeout: float = 15.0,
) -> dict[str, object]:
    """Read bounded JSON and translate upstream failures without leaking bodies."""
    try:
        async with client.stream(
            method, url, headers=headers, json=payload,
            follow_redirects=follow_redirects,
            timeout=httpx.Timeout(timeout, connect=10.0, pool=10.0),
        ) as response:
            response.raise_for_status()
            chunks = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                chunks.extend(chunk)
                if len(chunks) > _MAX_RESPONSE_BYTES:
                    raise ValueError(f"{service}: response exceeded the 1 MiB limit.")
            decoded: object = json.loads(chunks)
            return _object(decoded, service)
    except httpx.TimeoutException as exc:
        raise ValueError(f"{service}: upstream request timed out.") from exc
    except httpx.HTTPStatusError as exc:
        raise ValueError(f"{service}: upstream returned HTTP {exc.response.status_code}.") from exc
    except httpx.RequestError as exc:
        raise ValueError(f"{service}: upstream connection or protocol failure.") from exc
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"{service}: invalid or oversized JSON response.") from exc


def _parse_matches(payload: dict[str, object]) -> list[tuple[str, float]]:
    """Require a successful synchronous run and validate every returned match."""
    if payload.get("status") != "COMPLETED" or payload.get("error") is not None:
        raise ValueError("TinyFish: run failed or did not complete successfully.")
    result = _object(payload.get("result"), "TinyFish result")
    if result.get("error") is not None:
        raise ValueError("TinyFish: result reports an upstream error.")
    matches = result.get("matches")
    if not isinstance(matches, list) or len(matches) > _MAX_MATCHES:
        raise ValueError("TinyFish: result.matches must be an array of at most 20 matches.")
    unique: dict[str, float] = {}
    for item in matches:
        match = _object(item, "TinyFish match")
        url, score = match.get("url"), match.get("similarity_score")
        if not isinstance(url, str):
            raise ValueError("TinyFish: each match must include a URL string.")
        domain = _domain(url)
        if domain.endswith((".example", ".invalid", ".localhost", ".test")):
            raise ValueError("TinyFish: reserved demonstration domains are not real exposures.")
        if (
            isinstance(score, bool) or not isinstance(score, (int, float))
            or not 0 <= score <= 1
        ):
            raise ValueError("TinyFish: similarity_score must be a finite number between 0 and 1.")
        unique[url] = max(unique.get(url, 0.0), float(score))
    return list(unique.items())


def _contact_values(entity: dict[str, object], field: str) -> list[str]:
    """Read string properties from an RDAP entity's RFC 7095 jCard."""
    card = entity.get("vcardArray")
    if card is None:
        return []
    if not isinstance(card, list) or len(card) != 2 or card[0] != "vcard" or not isinstance(card[1], list):
        raise ValueError("RDAP: malformed vcardArray.")
    values: list[str] = []
    for prop in card[1]:
        if not isinstance(prop, list) or len(prop) != 4:
            raise ValueError("RDAP: malformed contact property.")
        if prop[0] == field and isinstance(prop[3], str) and prop[3].strip():
            values.append(prop[3].strip())
    return values


def _rdap_contacts(payload: dict[str, object], domain: str) -> HostDetails:
    """Extract registrar and abuse contacts, including nested registrar entities.

    HostDetails has no registrar field. Its hosting_provider field therefore
    carries a labeled registrar name; this does not identify the web host.
    Missing/redacted contact fields remain None instead of being fabricated.
    """
    if "errorCode" in payload or payload.get("error") is not None:
        raise ValueError(f"RDAP for {domain}: service returned an error object.")
    if payload.get("objectClassName") != "domain":
        raise ValueError(f"RDAP for {domain}: expected a domain registration object.")
    entities = payload.get("entities", [])
    if not isinstance(entities, list):
        raise ValueError(f"RDAP for {domain}: entities must be an array.")
    queue: list[object] = list(entities)
    registrar: str | None = None
    abuse_email: str | None = None
    visited = 0
    while queue:
        visited += 1
        if visited > 1000:
            raise ValueError(f"RDAP for {domain}: excessive entity nesting or count.")
        entity = _object(queue.pop(), "RDAP entity")
        roles = entity.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise ValueError(f"RDAP for {domain}: malformed entity roles.")
        if "registrar" in roles and registrar is None:
            names = _contact_values(entity, "fn") or _contact_values(entity, "org")
            registrar = names[0] if names else None
        if "abuse" in roles and abuse_email is None:
            emails = _contact_values(entity, "email")
            for email in emails:
                if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", email):
                    raise ValueError(f"RDAP for {domain}: malformed abuse email.")
                abuse_email = email
                break
        children = entity.get("entities", [])
        if not isinstance(children, list):
            raise ValueError(f"RDAP for {domain}: malformed child entities.")
        queue.extend(children)
    return HostDetails(
        domain=domain,
        hosting_provider=f"Registrar: {registrar}" if registrar else None,
        abuse_email=abuse_email,
    )


async def _real_exposures(image_hash: str) -> list[ExposureMatch]:
    """Query TinyFish once and enrich distinct hostnames with bounded RDAP work."""
    endpoint = os.getenv("TINYFISH_URL", "").strip()
    api_key = os.getenv("TINYFISH_API_KEY", "").strip()
    if not endpoint or not api_key:
        raise ValueError("Real exposure mode requires TINYFISH_URL and TINYFISH_API_KEY.")
    _domain(endpoint)
    if urlsplit(endpoint).scheme != "https":
        raise ValueError("TINYFISH_URL must use HTTPS to protect the API key.")
    payload: dict[str, object] = {
        "url": f"https://www.google.com/search?q=%22{image_hash}%22",
        "goal": (
            f"Find publicly indexed pages referencing the exact SHA-256 {image_hash}. "
            "Return at most 20 verified page URLs in matches, each with url and "
            "similarity_score. Use 1.0 only for an explicit exact hash reference; "
            "do not infer visual similarity from a hash. Do not invent URLs or "
            "scores. Return an empty matches array only after a successful search "
            "with no results and error=null. For blocked searches or tool failures, "
            "set error to a descriptive message and return matches=[]."
        ),
        "output_schema": {
            "type": "object",
            "properties": {"error": {"type": "string", "nullable": True}, "matches": {
                "type": "array", "maxItems": _MAX_MATCHES,
                "items": {"type": "object", "properties": {
                    "url": {"type": "string"},
                    "similarity_score": {"type": "number", "minimum": 0, "maximum": 1},
                }, "required": ["url", "similarity_score"]},
            }},
            "required": ["matches", "error"],
        },
        "agent_config": {"max_duration_seconds": 90},
    }
    async with httpx.AsyncClient(
        follow_redirects=False, max_redirects=5,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=5),
    ) as client:
        response = await _request_json(
            client, "POST", endpoint, "TinyFish", payload=payload,
            headers={"X-API-Key": api_key}, timeout=100.0,
        )
        matches = _parse_matches(response)
        domains = list(dict.fromkeys(_domain(url) for url, _ in matches))
        semaphore = asyncio.Semaphore(5)

        async def lookup(domain: str) -> HostDetails:
            """Perform one RDAP lookup without forwarding TinyFish credentials."""
            async with semaphore:
                result = await _request_json(
                    client, "GET", f"https://rdap.org/domain/{quote(domain, safe='')}",
                    f"RDAP for {domain}", follow_redirects=True,
                    headers={"Accept": "application/rdap+json"},
                )
                return _rdap_contacts(result, domain)

        tasks = [asyncio.create_task(lookup(domain)) for domain in domains]
        try:
            hosts = dict(zip(domains, await asyncio.gather(*tasks)))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return [
            ExposureMatch(url=url, similarity_score=score, host_details=hosts[_domain(url)])
            for url, score in matches
        ]


async def find_exposures(image_hash: str) -> List[ExposureMatch]:
    """Return 3–5 deterministic demo matches, or actual results in real mode.

    USE_MOCK defaults to true and is read for each call. Real mode requires the
    synchronous TinyFish /v1/automation/run endpoint in TINYFISH_URL. Invalid
    configuration, failed requests, and malformed responses raise ValueError;
    no real-mode failure is converted into mock results or an empty success.
    RDAP queries use the discovered hostname verbatim, including subdomains;
    an unregistered hostname's RDAP error is propagated rather than concealed.
    """
    if not isinstance(image_hash, str) or not _HASH_PATTERN.fullmatch(image_hash):
        raise ValueError("image_hash must be a 64-character SHA-256 hexadecimal digest.")
    image_hash = image_hash.lower()
    if _mock_enabled():
        count = 3 + int(image_hash[:2], 16) % 3
        return [
            ExposureMatch(
                url=f"https://mirror-{index + 1}.example/images/{image_hash[:16]}",
                similarity_score=round(0.80 + int(image_hash[index * 2:index * 2 + 2], 16) / 2550, 4),
                host_details=HostDetails(
                    domain=f"mirror-{index + 1}.example",
                    ip_address=f"192.0.2.{index + 1}",
                    hosting_provider=f"Simulated registrar {index + 1}",
                    abuse_email=f"abuse@mirror-{index + 1}.example",
                ),
            )
            for index in range(count)
        ]
    try:
        return await asyncio.wait_for(_real_exposures(image_hash), timeout=180.0)
    except asyncio.TimeoutError as exc:
        raise ValueError("Exposure search exceeded its 180-second overall deadline.") from exc
