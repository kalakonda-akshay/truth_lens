from typing import Any

from pydantic import BaseModel, Field


class ScoreCard(BaseModel):
    authenticity_score: int
    deepfake_probability: int
    risk_level: str
    confidence_score: int
    threat_score: int = 0


class MetadataReport(BaseModel):
    file_size_mb: float
    creation_date: str
    codec: str
    duration_seconds: float | None
    tampering_indicators: list[str]
    camera_information: str = "Not available"
    editing_software: str = "Not detected"
    exif_data: dict[str, str] = Field(default_factory=dict)


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
    image_forensics: dict[str, Any] = Field(default_factory=dict)
    url_analysis: dict[str, Any] = Field(default_factory=dict)
    email_analysis: dict[str, Any] = Field(default_factory=dict)
    suspicious_frames: list[SuspiciousFrame]
    evidence: list[EvidenceItem]
    verdict: str = "Needs Review"
    analysis_summary: str = "Automated TruthLens forensic analysis completed."
    key_findings: list[str] = Field(default_factory=list)
    conclusion: str = "Results are probabilistic and should be reviewed before high-impact decisions."
    reasons_for_decision: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=lambda: [
            "Verify the media source before sharing.",
            "Request the original file when making high-impact decisions.",
        ]
    )
    awareness_message: str = "Do not forward unverified media"
