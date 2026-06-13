from app.models import EvidenceItem, ScoreCard


def calculate_scores(
    tampering_count: int,
    suspicious_frame_score: int,
    lip_sync_score: int,
    audio_clone_confidence: int,
) -> tuple[ScoreCard, list[EvidenceItem]]:
    weighted_risk = round(
        (tampering_count * 8)
        + (suspicious_frame_score * 0.32)
        + (lip_sync_score * 0.24)
        + (audio_clone_confidence * 0.28)
    )
    deepfake_probability = max(4, min(96, weighted_risk))
    authenticity_score = max(1, 100 - deepfake_probability)

    if deepfake_probability >= 70:
        risk_level = "High"
    elif deepfake_probability >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    confidence_score = min(98, max(55, 62 + tampering_count * 5 + suspicious_frame_score // 6))

    evidence = [
        EvidenceItem(
            label="Risk Scoring Engine",
            detail=f"Combined forensic signals produced a {deepfake_probability}% deepfake probability.",
            severity=risk_level,
        )
    ]

    return (
        ScoreCard(
            authenticity_score=authenticity_score,
            deepfake_probability=deepfake_probability,
            risk_level=risk_level,
            confidence_score=confidence_score,
        ),
        evidence,
    )
