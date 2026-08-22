from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Iterable, Literal
from urllib.parse import quote


MarkerProfile = Literal[
    "official_document",
    "personal_identity",
    "database_credential",
    "internal_endpoint",
    "ops_token",
]
MarkerTransform = Literal[
    "exact",
    "base64",
    "hex",
    "url_encoded",
    "chunked_exact",
    "chunked_base64",
    "chunked_hex",
    "chunked_url_encoded",
]

SUPPORTED_MARKER_PROFILES: tuple[str, ...] = (
    "official_document",
    "personal_identity",
    "database_credential",
    "internal_endpoint",
    "ops_token",
)
SUPPORTED_MARKER_TRANSFORMS: tuple[str, ...] = (
    "exact",
    "base64",
    "hex",
    "url_encoded",
)
MAX_MARKER_CHUNKS = 64
MAX_MARKER_CHUNK_BYTES = 16 * 1024
MAX_MARKER_STREAM_BYTES = 128 * 1024


class MarkerEvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class MarkerSpec:
    marker_id: str
    profile: MarkerProfile
    source_kind: str
    source_ref: str
    token_sha256: str
    token: str

    def public_identity(self) -> dict[str, str]:
        return {
            "marker_id": self.marker_id,
            "profile": self.profile,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "token_sha256": self.token_sha256,
        }


@dataclass(frozen=True)
class MarkerWitness:
    marker_id: str
    profile: MarkerProfile
    source_kind: str
    source_ref: str
    source_sha256: str
    sink_kind: str
    sink_ref: str
    sink_evidence_sha256: str
    transform: MarkerTransform
    chunk_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "marker_id": self.marker_id,
            "profile": self.profile,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "source_sha256": self.source_sha256,
            "sink_kind": self.sink_kind,
            "sink_ref": self.sink_ref,
            "sink_evidence_sha256": self.sink_evidence_sha256,
            "transform": self.transform,
            "chunk_count": self.chunk_count,
            "raw_marker_retained": False,
        }


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def create_marker(
    profile: str,
    *,
    seed: str,
    source_ref: str,
    source_kind: str = "decoy_file",
) -> MarkerSpec:
    if profile not in SUPPORTED_MARKER_PROFILES:
        raise MarkerEvidenceError(f"Unsupported marker profile: {profile}")
    if not seed or len(seed) > 256 or any(character in seed for character in "\r\n\x00"):
        raise MarkerEvidenceError("seed must be a non-empty bounded single-line string")
    if (
        not source_ref
        or len(source_ref) > 512
        or source_ref.startswith(("/", "\\"))
        or ".." in source_ref.replace("\\", "/").split("/")
        or any(character in source_ref for character in "\r\n\x00")
    ):
        raise MarkerEvidenceError("source_ref must be a bounded relative path")
    if not source_kind or len(source_kind) > 64:
        raise MarkerEvidenceError("source_kind must be a non-empty bounded value")

    identity_material = f"{seed}\0{profile}\0{source_kind}\0{source_ref}".encode("utf-8")
    identity_digest = _sha256(identity_material)
    token = f"AEGIS-CANARY:{profile.upper()}:{identity_digest[:24]}"
    return MarkerSpec(
        marker_id=f"marker-{profile}-{identity_digest[:12]}",
        profile=profile,  # type: ignore[arg-type]
        source_kind=source_kind,
        source_ref=source_ref.replace("\\", "/"),
        token_sha256=_sha256(token.encode("utf-8")),
        token=token,
    )


def encode_marker(marker: MarkerSpec, transform: str) -> bytes:
    payload = marker.token.encode("utf-8")
    if transform == "exact":
        return payload
    if transform == "base64":
        return base64.b64encode(payload)
    if transform == "hex":
        return payload.hex().encode("ascii")
    if transform == "url_encoded":
        return quote(marker.token, safe="").encode("ascii")
    raise MarkerEvidenceError(f"Unsupported marker transform: {transform}")


def _bounded_chunks(chunks: Iterable[bytes | str]) -> list[bytes]:
    normalized: list[bytes] = []
    total = 0
    for index, chunk in enumerate(chunks):
        if index >= MAX_MARKER_CHUNKS:
            raise MarkerEvidenceError("marker stream exceeds chunk limit")
        encoded = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        if len(encoded) > MAX_MARKER_CHUNK_BYTES:
            raise MarkerEvidenceError("marker chunk exceeds byte limit")
        total += len(encoded)
        if total > MAX_MARKER_STREAM_BYTES:
            raise MarkerEvidenceError("marker stream exceeds total byte limit")
        normalized.append(encoded)
    if not normalized:
        raise MarkerEvidenceError("marker stream must contain at least one chunk")
    return normalized


def find_marker_witnesses(
    chunks: Iterable[bytes | str],
    markers: Iterable[MarkerSpec],
    *,
    sink_kind: str,
    sink_ref: str,
) -> list[MarkerWitness]:
    if not sink_kind or len(sink_kind) > 64:
        raise MarkerEvidenceError("sink_kind must be a non-empty bounded value")
    if not sink_ref or len(sink_ref) > 512 or any(
        character in sink_ref for character in "\r\n\x00"
    ):
        raise MarkerEvidenceError("sink_ref must be a bounded single-line value")

    normalized_chunks = _bounded_chunks(chunks)
    joined = b"".join(normalized_chunks)
    sink_digest = _sha256(joined)
    witnesses: list[MarkerWitness] = []
    for marker in markers:
        for transform in SUPPORTED_MARKER_TRANSFORMS:
            rendered = encode_marker(marker, transform)
            if rendered not in joined:
                continue
            found_in_single_chunk = any(rendered in chunk for chunk in normalized_chunks)
            recorded_transform = (
                transform if found_in_single_chunk else f"chunked_{transform}"
            )
            witnesses.append(MarkerWitness(
                marker_id=marker.marker_id,
                profile=marker.profile,
                source_kind=marker.source_kind,
                source_ref=marker.source_ref,
                source_sha256=marker.token_sha256,
                sink_kind=sink_kind,
                sink_ref=sink_ref,
                sink_evidence_sha256=sink_digest,
                transform=recorded_transform,  # type: ignore[arg-type]
                chunk_count=len(normalized_chunks),
            ))
    return witnesses
