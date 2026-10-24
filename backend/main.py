"""HerGuard Backend FastAPI Application.

Exposes REST APIs for health checking, privacy-preserving media scanning,
and statutory legal takedown/cybercrime notice drafting.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware

if __package__:
    from .exposure import _mock_enabled, find_exposures
    from .forensics import (
        ALLOWED_TYPES,
        MAX_BYTES,
        detect_deepfake,
        looks_like_image,
        sha256_hex,
    )
    from .notices import generate_notice
    from .schemas import HostDetails, NoticeRequest, NoticeResponse, ScanResponse
    from .vault import insert_case
else:
    from exposure import _mock_enabled, find_exposures
    from forensics import (
        ALLOWED_TYPES,
        MAX_BYTES,
        detect_deepfake,
        looks_like_image,
        sha256_hex,
    )
    from notices import generate_notice
    from schemas import HostDetails, NoticeRequest, NoticeResponse, ScanResponse
    from vault import insert_case


app = FastAPI(
    title="HerGuard API",
    description="Privacy-first deepfake detection and legal exposure mitigation backend.",
    version="1.0.0",
)

# CORS configuration
raw_cors = os.getenv("CORS_ORIGINS", "*").strip()
cors_origins = [origin.strip() for origin in raw_cors.split(",") if origin.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if "*" not in cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class NoticeApiRequest(NoticeRequest):
    """Notice request schema supporting optional notice_type and host metadata."""

    notice_type: Literal["dmca", "cybercrime"] = "dmca"
    host: HostDetails | None = None
    abuse_form_url: str | None = None
    image_hash: str | None = None


@app.get("/api/health")
async def health_check() -> dict[str, Any]:
    """Health check endpoint indicating service health and mock status."""
    return {
        "status": "ok",
        "mock_mode": _mock_enabled(),
    }


@app.post("/api/scan", response_model=ScanResponse)
async def scan_media(file: UploadFile = File(...)) -> ScanResponse:
    """Analyze an uploaded image for forensic integrity, deepfake signals, and exposures."""
    # Validate content-type header
    content_type = (file.content_type or "").lower().split(";")[0].strip()
    if content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported Media Type '{content_type}'. Must be one of: {sorted(ALLOWED_TYPES)}",
        )

    # Read binary content
    data = await file.read()
    if not data or len(data) > MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File must contain between 1 byte and 10 MiB.",
        )

    # Validate image magic bytes
    if not looks_like_image(data):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File signature does not match JPEG, PNG, or WebP.",
        )

    image_hash = sha256_hex(data)
    deepfake_res = detect_deepfake(data, image_hash)
    matches = await find_exposures(image_hash)

    case_id = uuid4()
    now = datetime.now(timezone.utc)

    # Persist evidence metadata to vault (blocking I/O offloaded to worker thread)
    vault_record: dict[str, object] = {
        "case_id": str(case_id),
        "image_hash": image_hash,
        "timestamp": now.isoformat(),
        "matched_urls": [m.model_dump() for m in matches],
        "status": "completed",
    }
    await asyncio.to_thread(insert_case, vault_record)

    return ScanResponse(
        case_id=case_id,
        image_hash=image_hash,
        timestamp=now,
        deepfake=deepfake_res,
        matches=matches,
        status="completed",
    )


@app.post("/api/notice", response_model=NoticeResponse)
async def create_notice(payload: NoticeApiRequest) -> NoticeResponse:
    """Generate a legal takedown notice or cybercrime complaint draft."""
    return generate_notice(
        req=payload,
        notice_type=payload.notice_type,
        host=payload.host,
        abuse_form_url=payload.abuse_form_url,
        image_hash=payload.image_hash,
    )
