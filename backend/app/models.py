from typing import Any

from pydantic import BaseModel


class ScoreCard(BaseModel):
    authenticity_score: int
    deepfake_probability: int
    risk_level: str
    confidence_score: int


class MetadataReport(BaseModel):
    file_size_mb: float
    creation_date: str
    codec: str
    duration_seconds: float | None
    tampering_indicators: list[str]


class EvidenceItem(BaseModel):
    label: str
    detail: str
    severity: str


class SuspiciousFrame(BaseModel):
    timestamp_seconds: float
    frame_url: str
    reason: str
    score: int


class AnalysisReport(BaseModel):
    id: str
    filename: str
    media_type: str
    uploaded_at: str
    scores: ScoreCard
    metadata: MetadataReport
    face_analysis: dict[str, Any]
    lip_sync_analysis: dict[str, Any]
    audio_clone_detection: dict[str, Any]
    suspicious_frames: list[SuspiciousFrame]
    evidence: list[EvidenceItem]
    awareness_message: str = "Do not forward unverified media"
