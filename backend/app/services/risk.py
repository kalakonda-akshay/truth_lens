from app.models import EvidenceItem, ScoreCard


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def calculate_scores(
    tampering_count: int,
    suspicious_frame_score: int,
    lip_sync_score: int,
    audio_clone_confidence: int,
) -> tuple[ScoreCard, list[EvidenceItem]]:
    active_signals = [
        min(35, tampering_count * 12),
        suspicious_frame_score,
        lip_sync_score,
        audio_clone_confidence,
    ]
    weighted_risk = round(
        active_signals[0] * 0.22
        + active_signals[1] * 0.34
        + active_signals[2] * 0.18
        + active_signals[3] * 0.26
    )
    probability = max(0, min(100, weighted_risk))
    level = risk_level(probability)
    evidence: list[EvidenceItem] = []
    if tampering_count:
        evidence.append(EvidenceItem(label="Metadata Indicators", detail=f"{tampering_count} metadata warning(s) detected.", severity=level))
    if suspicious_frame_score >= 35:
        evidence.append(EvidenceItem(label="Visual Frame Indicators", detail=f"Highest suspicious frame score: {suspicious_frame_score}%.", severity=level))
    if lip_sync_score >= 35:
        evidence.append(EvidenceItem(label="Lip-Sync Indicator", detail=f"Lip-sync risk score: {lip_sync_score}%.", severity=level))
    if audio_clone_confidence >= 35:
        evidence.append(EvidenceItem(label="Synthetic Voice Indicator", detail=f"Audio synthetic confidence: {audio_clone_confidence}%.", severity=level))

    return (
        ScoreCard(
            authenticity_score=max(0, 100 - probability),
            deepfake_probability=probability,
            risk_level=level,
            confidence_score=min(96, 55 + 8 * len(evidence) + max(active_signals) // 5),
            threat_score=probability,
        ),
        evidence,
    )
