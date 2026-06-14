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
    metadata_score = min(35, tampering_count * 12)
    visual_score = max(0, min(100, suspicious_frame_score))
    lip_score = max(0, min(100, lip_sync_score))
    audio_score = max(0, min(100, audio_clone_confidence))
    active_signals = [metadata_score, visual_score, lip_score, audio_score]

    weighted_risk = round(
        metadata_score * 0.12
        + visual_score * 0.56
        + lip_score * 0.12
        + audio_score * 0.20
    )
    strongest_signal_floor = max(active_signals)
    probability = max(0, min(100, max(weighted_risk, strongest_signal_floor)))
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
