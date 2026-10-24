"""Image validation helpers and an explicitly simulated deepfake detector."""

import hashlib

if __package__:
    from .schemas import DeepfakeResult
else:
    from schemas import DeepfakeResult


ALLOWED_TYPES: frozenset[str] = frozenset(
    {"image/jpeg", "image/png", "image/webp"}
)
MAX_BYTES: int = 10 * 1024 * 1024


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of the supplied bytes as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def looks_like_image(data: bytes) -> bool:
    """Check JPEG, PNG, or WebP signatures without claiming full validation."""
    return (
        data.startswith(b"\xff\xd8\xff")
        or data.startswith(b"\x89PNG\r\n\x1a\n")
        or (
            len(data) >= 12
            and data[:4] == b"RIFF"
            and data[8:12] == b"WEBP"
        )
    )


def detect_deepfake(data: bytes, image_hash: str) -> DeepfakeResult:
    """Return a reproducible demo result, not an actual deepfake assessment.

    Reject inconsistent hashes so the result always corresponds to the supplied
    image. The digest drives synthetic scores only; it carries no authenticity
    signal and must not be used for real-world forensic decisions.
    """
    if not data or len(data) > MAX_BYTES:
        raise ValueError("Image must contain between 1 byte and 10 MiB.")
    if not looks_like_image(data):
        raise ValueError("Image must have a JPEG, PNG, or WebP signature.")
    actual_hash = sha256_hex(data)
    if image_hash != actual_hash:
        raise ValueError("image_hash must match the SHA-256 digest of data.")

    synthetic_score = int(actual_hash[:8], 16) / 0xFFFFFFFF
    is_deepfake = synthetic_score >= 0.5
    confidence = synthetic_score if is_deepfake else 1.0 - synthetic_score
    return DeepfakeResult(
        is_deepfake=is_deepfake,
        confidence=round(confidence, 6),
        model="herguard-simulated-v1",
        simulated=True,
    )
