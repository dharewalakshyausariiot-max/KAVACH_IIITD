"""Persist evidence metadata to Supabase, with a durable local JSONL fallback.

Only the evidence_vault columns and defined exposure/host metadata are accepted.
Validation precedes all I/O, so neither storage destination receives image bytes,
data URLs, or arbitrary payload fields. Local files contain sensitive metadata
and inherit directory ACLs on Windows; deployments must restrict those ACLs.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Tuple, cast
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid4

import httpx


LOCAL_VAULT_PATH = Path(__file__).resolve().parent / "data" / "vault_local.jsonl"
_APPEND_LOCK = threading.Lock()
_COLUMNS = frozenset({"id", "case_id", "image_hash", "timestamp", "matched_urls", "status"})
_HOST_FIELDS = frozenset({"domain", "ip_address", "hosting_provider", "abuse_email"})
_MATCH_FIELDS = frozenset({"url", "similarity_score", "host_details"})
_IMAGE_ENCODING = re.compile(
    r"data\s*:\s*image/|^(?:/9j/|iVBORw0KGgo|UklGR|R0lGOD|SUkqA|TU0AK)",
    re.IGNORECASE,
)


def _text(value: object, field: str, limit: int = 256) -> str:
    """Accept bounded text metadata, rejecting binary and encoded image input."""
    if (
        not isinstance(value, str) or not value or len(value) > limit
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or _IMAGE_ENCODING.search(unquote(value).lstrip())
    ):
        raise ValueError(f"{field} must contain bounded text metadata, never image data.")
    return value


def _metadata_url(value: object) -> str:
    """Validate an ordinary web URL; embedded credentials and data URLs are refused."""
    url = _text(value, "matched URL", 2048)
    try:
        parts = urlsplit(url)
        if (
            parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.port == 0 or "\\" in url or any(char.isspace() for char in url)
        ):
            raise ValueError
    except ValueError as exc:
        raise ValueError("Matched URLs must be absolute HTTP(S) URLs without credentials.") from exc
    return url


def _mapping(value: object, allowed: frozenset[str], field: str) -> dict[str, object]:
    """Enforce explicit metadata fields instead of serializing arbitrary objects."""
    if not isinstance(value, dict) or any(key not in allowed for key in value):
        raise ValueError(f"{field} contains unsupported fields or is not an object.")
    return cast(dict[str, object], value)


def _host_metadata(value: object) -> dict[str, object] | None:
    """Validate host metadata without allowing binary data in nested fields."""
    if value is None:
        return None
    host = _mapping(value, _HOST_FIELDS, "host_details")
    domain = _text(host.get("domain"), "host_details.domain", 253)
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("host_details.domain is not a valid DNS domain.") from exc
    if not re.fullmatch(
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", ascii_domain,
    ):
        raise ValueError("host_details.domain is not a valid DNS domain.")
    result: dict[str, object] = {"domain": domain}
    for key in ("ip_address", "hosting_provider", "abuse_email"):
        if key not in host:
            continue
        item = host[key]
        if item is None:
            result[key] = None
            continue
        text = _text(item, f"host_details.{key}")
        if key == "ip_address":
            try:
                ipaddress.ip_address(text)
            except ValueError as exc:
                raise ValueError("host_details.ip_address is invalid.") from exc
        if key == "abuse_email" and not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", text):
            raise ValueError("host_details.abuse_email is invalid.")
        result[key] = text
    return result


def _matched_urls(value: object) -> list[object]:
    """Accept URL strings or schema-shaped ExposureMatch dictionaries only."""
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("matched_urls must be an array with at most 100 entries.")
    matches: list[object] = []
    for item in value:
        if isinstance(item, str):
            matches.append(_metadata_url(item))
            continue
        match = _mapping(item, _MATCH_FIELDS, "matched_urls entry")
        score = match.get("similarity_score")
        if (
            isinstance(score, bool) or not isinstance(score, (int, float))
            or not 0 <= score <= 1
        ):
            raise ValueError("similarity_score must be a finite number between 0 and 1.")
        normalized: dict[str, object] = {
            "url": _metadata_url(match.get("url")), "similarity_score": float(score),
        }
        if "host_details" in match:
            normalized["host_details"] = _host_metadata(match["host_details"])
        matches.append(normalized)
    return matches


def _uuid(value: object, field: str) -> str:
    """Normalize a UUID without accepting its binary representation."""
    if isinstance(value, UUID):
        return str(value)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUID or UUID string.")
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid UUID.") from exc


def _prepare_record(record: dict[str, object]) -> dict[str, object]:
    """Copy, normalize, and validate the exact evidence_vault table contract."""
    source = _mapping(record, _COLUMNS, "record")
    image_hash = source.get("image_hash")
    if not isinstance(image_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", image_hash):
        raise ValueError("image_hash must be a 64-character SHA-256 hexadecimal digest.")
    timestamp = source.get("timestamp", datetime.now(timezone.utc))
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO 8601 timestamp with a timezone.") from exc
    if not isinstance(timestamp, datetime) or timestamp.utcoffset() is None:
        raise ValueError("timestamp must be a timezone-aware datetime or ISO 8601 string.")
    status = _text(source.get("status", "pending"), "status", 64)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", status):
        raise ValueError("status must be a short alphanumeric status label.")
    return {
        "id": _uuid(source.get("id", uuid4()), "id"),
        "case_id": _uuid(source.get("case_id"), "case_id"),
        "image_hash": image_hash.lower(),
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "matched_urls": _matched_urls(source.get("matched_urls", [])),
        "status": status,
    }


def _insert_supabase(record: dict[str, object], url: str, key: str) -> None:
    """Insert through Supabase's REST API and require a confirmed created row.

    Secret API keys use apikey alone; legacy JWT service-role keys also use
    Authorization. No redirects or automatic POST retries are permitted.
    """
    parts = urlsplit(url)
    if (
        parts.scheme != "https" or not parts.hostname
        or parts.username is not None or parts.password is not None
        or parts.query or parts.fragment or parts.path not in {"", "/"}
    ):
        raise ValueError("SUPABASE_URL must be an HTTPS project origin.")
    headers = {"apikey": key, "Prefer": "return=representation"}
    if key.count(".") == 2:
        headers["Authorization"] = f"Bearer {key}"
    with httpx.Client(
        timeout=httpx.Timeout(10.0, connect=5.0, pool=5.0), follow_redirects=False,
    ) as client:
        response = client.post(
            f"{url.rstrip('/')}/rest/v1/evidence_vault", json=record, headers=headers,
        )
        response.raise_for_status()
        if response.status_code != 201:
            raise ValueError("Supabase did not confirm creation of the evidence row.")
        returned: object = response.json()
        if (
            not isinstance(returned, list) or len(returned) != 1
            or not isinstance(returned[0], dict)
            or returned[0].get("id") != record["id"]
            or returned[0].get("case_id") != record["case_id"]
            or returned[0].get("image_hash") != record["image_hash"]
        ):
            raise ValueError("Supabase returned an invalid insertion acknowledgement.")


@contextmanager
def _file_lock(file: BinaryIO) -> Iterator[None]:
    """Hold a cross-process lock, with a bounded wait on Windows and POSIX."""
    deadline = time.monotonic() + 10.0
    while True:
        try:
            file.seek(0)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            if time.monotonic() >= deadline:
                raise OSError("Timed out acquiring the local evidence vault lock.") from exc
            time.sleep(0.05)
    try:
        yield
    finally:
        file.seek(0)
        if sys.platform == "win32":
            msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def _append_local(record: dict[str, object]) -> None:
    """Append one flushed JSON line under thread/process locks or raise OSError."""
    line = (json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        LOCAL_VAULT_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _APPEND_LOCK:
            flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(LOCAL_VAULT_PATH, flags, 0o600)
            with os.fdopen(descriptor, "a+b", buffering=0) as file:
                with _file_lock(file):
                    file.seek(0, os.SEEK_END)
                    start = file.tell()
                    if start:
                        file.seek(-1, os.SEEK_END)
                        if file.read(1) != b"\n":
                            raise OSError("Local evidence vault has an incomplete final line; repair is required.")
                    try:
                        written = 0
                        while written < len(line):
                            count = file.write(line[written:])
                            if not count:
                                raise OSError("Local evidence vault append made no progress.")
                            written += count
                        file.flush()
                        os.fsync(file.fileno())
                    except OSError:
                        file.truncate(start)
                        os.fsync(file.fileno())
                        raise
    except OSError as exc:
        raise OSError("Unable to persist evidence to the local JSONL fallback.") from exc


def insert_case(record: dict[str, object]) -> Tuple[bool, str]:
    """Persist metadata, returning (True, destination) only after confirmed storage.

    Missing credentials and any Supabase insertion exception silently select the
    local JSONL fallback. Invalid input raises ValueError before any I/O. If the
    fallback itself fails, OSError propagates rather than reporting false success.
    The same row ID is used for both attempts so uncertain remote writes after a
    timeout can be reconciled. This function performs blocking I/O; async callers
    should run it in a worker thread.
    """
    prepared = _prepare_record(record)
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip()
    if url and key:
        try:
            _insert_supabase(prepared, url, key)
        except Exception:
            # Every remote-storage failure must preserve validated evidence locally.
            _append_local(prepared)
            return True, "local_jsonl_fallback"
        return True, "supabase"
    _append_local(prepared)
    return True, "local_jsonl_fallback"
