"""Shared request and response models for the HerGuard backend."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class HostDetails(BaseModel):
    """Public hosting details associated with an exposure URL."""

    domain: str
    ip_address: str | None = None
    hosting_provider: str | None = None
    abuse_email: str | None = None


class ExposureMatch(BaseModel):
    """A potential public match for the submitted image."""

    url: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    host_details: HostDetails | None = None


class DeepfakeResult(BaseModel):
    """Detector output; simulated results are not forensic evidence."""

    is_deepfake: bool
    confidence: float = Field(ge=0.0, le=1.0)
    model: str
    simulated: bool = True


class ScanResponse(BaseModel):
    """Analysis and exposure results stored under an evidence case."""

    case_id: UUID
    image_hash: str
    timestamp: datetime
    deepfake: DeepfakeResult
    matches: list[ExposureMatch] = Field(default_factory=list)
    status: str = "completed"


class NoticeRequest(BaseModel):
    """Details needed to prepare a removal notice for one exposure."""

    case_id: UUID
    matched_url: str
    requester_name: str = Field(min_length=1)
    requester_email: str = Field(min_length=1)


class NoticeResponse(BaseModel):
    """A prepared removal notice and its intended recipient."""

    case_id: UUID
    matched_url: str
    subject: str
    body: str
    recipient_email: str | None = None
    status: Literal["draft", "sent", "failed"] = "draft"
