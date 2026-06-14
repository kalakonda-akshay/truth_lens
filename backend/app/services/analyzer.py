import mimetypes
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse

import cv2
import librosa
import numpy as np
from PIL import ExifTags, Image

from app.config import get_settings
from app.models import AnalysisReport, EvidenceItem, MetadataReport, ScoreCard, SuspiciousFrame
from app.services.risk import calculate_scores, risk_level


VIDEO_EXTENSIONS = {".mp4", ".mov", ".avi", ".mkv", ".webm"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".flac", ".aac"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
DISCLAIMER_RECOMMENDATIONS = [
    "Do not forward the content until its original source is verified.",
    "Compare against an original camera, platform, or sender source when available.",
    "Escalate high-risk findings to a qualified digital forensics or security analyst.",
]


def ai_classification(probability: int) -> str:
    if probability > 75:
        return "AI Generated"
    if probability >= 50:
        return "Likely AI Generated"
    if probability >= 25:
        return "Manipulated"
    if probability >= 0:
        return "Authentic"
    return "Unable To Determine"


def _media_type(path: Path, content_type: str | None) -> str:
    if path.suffix.lower() in IMAGE_EXTENSIONS or (content_type or "").startswith("image/"):
        return "image"
    if path.suffix.lower() in VIDEO_EXTENSIONS or (content_type or "").startswith("video/"):
        return "video"
    if path.suffix.lower() in AUDIO_EXTENSIONS or (content_type or "").startswith("audio/"):
        return "audio"
    return "unknown"


def _codec_and_duration(path: Path, media_type: str) -> tuple[str, float | None]:
    if media_type == "image":
        try:
            with Image.open(path) as image:
                return f"{image.format or path.suffix.replace('.', '').upper()} {image.width}x{image.height}", None
        except Exception:
            return "Unreadable image", None
    if media_type == "video":
        capture = cv2.VideoCapture(str(path))
        if not capture.isOpened():
            return "Unreadable video container", None
        fourcc = int(capture.get(cv2.CAP_PROP_FOURCC))
        codec = "".join(chr((fourcc >> 8 * i) & 0xFF) for i in range(4)).strip() or "Unknown"
        fps = capture.get(cv2.CAP_PROP_FPS) or 0
        frames = capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0
        capture.release()
        return codec, round(frames / fps, 2) if fps else None
    if media_type == "audio":
        try:
            return f"{path.suffix.lower().replace('.', '').upper()} audio stream", round(librosa.get_duration(path=str(path)), 2)
        except Exception:
            return "Audio metadata unavailable", None
    return mimetypes.guess_type(path.name)[0] or "Unknown", None


def _image_exif(path: Path) -> tuple[dict[str, str], str, str, str | None]:
    exif_data: dict[str, str] = {}
    try:
        with Image.open(path) as image:
            for tag_id, value in image.getexif().items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                if not isinstance(value, bytes):
                    exif_data[tag] = str(value)[:180]
    except Exception:
        return {}, "Not available", "Not detected", None
    make = exif_data.get("Make", "").strip()
    model = exif_data.get("Model", "").strip()
    camera = " ".join(part for part in [make, model] if part) or "Not available"
    software = exif_data.get("Software", "Not detected")
    created = exif_data.get("DateTimeOriginal") or exif_data.get("DateTime")
    return exif_data, camera, software, created


def scan_metadata(path: Path, media_type: str) -> MetadataReport:
    stat = path.stat()
    codec, duration = _codec_and_duration(path, media_type)
    indicators: list[str] = []
    exif_data: dict[str, str] = {}
    camera = "Not available"
    editing_software = "Not detected"
    image_creation_date = None
    if media_type == "image":
        exif_data, camera, editing_software, image_creation_date = _image_exif(path)
        if not exif_data:
            indicators.append("Missing EXIF metadata; source camera cannot be verified.")
        if editing_software != "Not detected":
            indicators.append(f"Editing software tag detected: {editing_software}.")
    if media_type == "unknown":
        indicators.append("Unsupported media container; forensic confidence reduced.")
    if stat.st_size < 20_000 and media_type != "url":
        indicators.append("File is unusually small for forensic media analysis.")
    if "Unreadable" in codec or "unavailable" in codec.lower():
        indicators.append("Codec/container could not be fully parsed.")
    if duration is not None and duration < 1:
        indicators.append("Media duration is extremely short.")
    if not indicators:
        indicators.append("No metadata risk indicators detected.")
    return MetadataReport(
        file_size_mb=round(stat.st_size / (1024 * 1024), 3),
        creation_date=image_creation_date or datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        codec=codec,
        duration_seconds=duration,
        tampering_indicators=indicators,
        camera_information=camera,
        editing_software=editing_software,
        exif_data=exif_data,
    )


def _score_from_range(value: float, low: float, high: float) -> int:
    if low <= value <= high:
        return 0
    distance = min(abs(value - low), abs(value - high))
    return int(np.clip(distance * 100 / max(high - low, 1), 0, 100))


def analyze_image(path: Path, report_id: str, metadata: MetadataReport) -> tuple[dict, list[SuspiciousFrame], int, list[EvidenceItem], list[str]]:
    settings = get_settings()
    image = cv2.imread(str(path))
    if image is None:
        return {"summary": "Image could not be decoded for visual forensics."}, [], 45, [
            EvidenceItem(label="Decode Failure", detail="Image could not be decoded by OpenCV.", severity="Medium")
        ], ["Image decode failed"]

    original = image.copy()
    height, width = image.shape[:2]
    scale = min(1.0, 1200 / max(width, height))
    if scale < 1:
        image = cv2.resize(image, (int(width * scale), int(height * scale)))
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    edges = cv2.Canny(gray, 80, 180)
    texture_variance = float(np.var(laplacian))
    edge_density = float(np.count_nonzero(edges)) / edges.size
    brightness = float(np.mean(gray))
    contrast = float(np.std(gray))
    tile_size = max(32, min(gray.shape) // 8)
    tile_means = [float(np.mean(gray[y : y + tile_size, x : x + tile_size])) for y in range(0, gray.shape[0], tile_size) for x in range(0, gray.shape[1], tile_size) if gray[y : y + tile_size, x : x + tile_size].size]
    lighting_variance = float(np.std(tile_means)) if tile_means else 0
    block = 8
    h, w = gray.shape
    vertical = float(np.mean(np.abs(gray[:, block:w:block].astype(np.float32) - gray[:, block - 1 : w - 1 : block].astype(np.float32)))) if w > block else 0
    horizontal = float(np.mean(np.abs(gray[block:h:block, :].astype(np.float32) - gray[block - 1 : h - 1 : block, :].astype(np.float32)))) if h > block else 0
    compression_seams = vertical + horizontal
    noise_residual = gray.astype(np.float32) - cv2.GaussianBlur(gray, (0, 0), 1.4).astype(np.float32)
    noise_std = float(np.std(noise_residual))

    metrics = {
        "texture_inconsistency": _score_from_range(texture_variance, 120, 4200),
        "lighting_inconsistency": _score_from_range(lighting_variance, 8, 48),
        "edge_anomaly": _score_from_range(edge_density, 0.025, 0.22),
        "compression_artifacts": int(np.clip(compression_seams * 2.6, 0, 100)),
        "noise_pattern_anomaly": _score_from_range(noise_std, 2.5, 28),
        "brightness_anomaly": _score_from_range(brightness, 35, 220),
        "contrast_anomaly": _score_from_range(contrast, 18, 95),
    }

    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.12, minNeighbors=5)
    face_irregularity = 0
    for (x, y, fw, fh) in faces:
        roi = gray[y : y + fh, x : x + fw]
        if roi.size:
            face_irregularity = max(face_irregularity, _score_from_range(float(np.var(cv2.Laplacian(roi, cv2.CV_64F))), 100, 3600))
    metrics["face_anomaly"] = face_irregularity
    metrics["faces_detected"] = int(len(faces))
    metrics["diffusion_artifacts"] = int(np.clip((metrics["texture_inconsistency"] + metrics["noise_pattern_anomaly"]) / 2, 0, 100))
    metrics["gan_artifacts"] = int(np.clip((metrics["edge_anomaly"] + metrics["face_anomaly"]) / 2, 0, 100))
    metadata_score = 0
    if not metadata.exif_data:
        metadata_score += 18
    if metadata.editing_software != "Not detected":
        metadata_score += 16
    visual_score = int(np.clip(np.mean([value for key, value in metrics.items() if key != "faces_detected"]), 0, 100))
    ai_probability = int(np.clip(visual_score * 0.72 + metadata_score, 0, 100))

    evidence: list[EvidenceItem] = []
    findings: list[str] = []
    thresholds = {
        "texture_inconsistency": ("Texture inconsistency detected", 45),
        "lighting_inconsistency": ("Lighting mismatch detected", 45),
        "edge_anomaly": ("Edge/outline anomaly detected", 45),
        "compression_artifacts": ("Compression artifact inconsistency detected", 55),
        "noise_pattern_anomaly": ("Noise pattern anomaly detected", 45),
        "face_anomaly": ("Face-region anomaly detected", 55),
        "diffusion_artifacts": ("Diffusion-like artifact pattern detected", 55),
        "gan_artifacts": ("GAN-like artifact pattern detected", 55),
    }
    for key, (label, threshold) in thresholds.items():
        score = int(metrics[key])
        if score >= threshold:
            severity = risk_level(score)
            evidence.append(EvidenceItem(label=label, detail=f"{label} with measured score {score}%.", severity=severity))
            findings.append(label)
    if not metadata.exif_data:
        evidence.append(EvidenceItem(label="Missing Camera Metadata", detail="No EXIF camera metadata was present in the uploaded image.", severity="Medium"))
        findings.append("Missing camera metadata")
    if metadata.editing_software != "Not detected":
        evidence.append(EvidenceItem(label="Editing Software Trace", detail=f"EXIF software field reports: {metadata.editing_software}.", severity="Medium"))
        findings.append("Editing software trace present")

    suspicious: list[SuspiciousFrame] = []
    if evidence and visual_score >= 35:
        anomaly = cv2.normalize(np.abs(laplacian).astype(np.float32), None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
        _, mask = cv2.threshold(anomaly, int(np.percentile(anomaly, 92)), 255, cv2.THRESH_BINARY)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        overlay = cv2.addWeighted(image, 0.68, cv2.applyColorMap(anomaly, cv2.COLORMAP_TURBO), 0.32, 0)
        boxes = 0
        for contour in sorted(contours, key=cv2.contourArea, reverse=True):
            if boxes >= 4 or cv2.contourArea(contour) < max(80, image.shape[0] * image.shape[1] * 0.002):
                continue
            x, y, bw, bh = cv2.boundingRect(contour)
            cv2.rectangle(overlay, (x, y), (x + bw, y + bh), (0, 255, 255), 3)
            boxes += 1
        if boxes:
            frame_name = f"{report_id}-image-evidence.jpg"
            cv2.imwrite(str(settings.storage_dir / "frames" / frame_name), overlay)
            suspicious.append(SuspiciousFrame(timestamp_seconds=0, frame_url=f"/frames/{frame_name}", reason="Heatmap is derived from measured local edge/noise residual anomalies.", score=visual_score))

    metrics.update({
        "summary": "OpenCV measured texture variance, lighting variance, edge density, compression seams, residual noise, and face-region anomalies.",
        "heatmap_generated": bool(suspicious),
        "resolution": f"{original.shape[1]}x{original.shape[0]}",
    })
    return metrics, suspicious, ai_probability, evidence, findings


def analyze_faces(path: Path, report_id: str, media_type: str) -> tuple[dict, list[SuspiciousFrame]]:
    if media_type != "video":
        return {"frames_analyzed": 0, "suspicious_frames": 0, "summary": "Video frame analysis not applicable."}, []
    settings = get_settings()
    capture = cv2.VideoCapture(str(path))
    fps = capture.get(cv2.CAP_PROP_FPS) or 24
    frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    interval = max(1, frame_count // 12) if frame_count else 24
    suspicious: list[SuspiciousFrame] = []
    analyzed = 0
    for index in range(0, max(frame_count, 1), interval):
        if analyzed >= 12:
            break
        capture.set(cv2.CAP_PROP_POS_FRAMES, index)
        ok, frame = capture.read()
        if not ok:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        blur = cv2.Laplacian(gray, cv2.CV_64F).var()
        brightness = float(np.mean(gray))
        edge_density = float(np.count_nonzero(cv2.Canny(gray, 80, 180))) / gray.size
        score = int(np.clip(_score_from_range(blur, 80, 4200) * 0.4 + _score_from_range(brightness, 35, 220) * 0.25 + _score_from_range(edge_density, 0.025, 0.22) * 0.35, 0, 100))
        if score >= 45:
            frame_name = f"{report_id}-frame-{analyzed}.jpg"
            annotated = frame.copy()
            cv2.rectangle(annotated, (20, 20), (annotated.shape[1] - 20, annotated.shape[0] - 20), (0, 255, 255), 4)
            cv2.imwrite(str(settings.storage_dir / "frames" / frame_name), annotated)
            suspicious.append(SuspiciousFrame(timestamp_seconds=round(index / fps, 2), frame_url=f"/frames/{frame_name}", reason="Frame anomaly score exceeded threshold from blur, brightness, and edge-density metrics.", score=score))
        analyzed += 1
    capture.release()
    return {"frames_analyzed": analyzed, "suspicious_frames": len(suspicious), "summary": "OpenCV sampled frames and retained only frames with measured anomaly scores above threshold."}, suspicious[:4]


def analyze_lip_sync(path: Path, media_type: str) -> dict:
    if media_type != "video":
        return {"forensic_score": 0, "summary": "Not applicable."}
    return {"forensic_score": 0, "summary": "Lip-sync mismatch is not claimed because no speech-to-mouth model is available in this prototype."}


def _write_audio_spectrogram(path: Path, report_id: str, y: np.ndarray, sr: int) -> SuspiciousFrame:
    settings = get_settings()
    spectrogram = np.abs(librosa.stft(y, n_fft=1024, hop_length=256))
    db = librosa.amplitude_to_db(spectrogram, ref=np.max)
    normalized = cv2.normalize(db, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    color = cv2.applyColorMap(normalized, cv2.COLORMAP_TURBO)
    color = cv2.flip(color, 0)
    frame_name = f"{report_id}-audio-spectrogram.jpg"
    cv2.imwrite(str(settings.storage_dir / "frames" / frame_name), color)
    return SuspiciousFrame(timestamp_seconds=0, frame_url=f"/frames/{frame_name}", reason="Spectrogram generated from decoded audio samples.", score=0)


def analyze_audio_clone(path: Path, media_type: str, report_id: str | None = None) -> tuple[dict, list[SuspiciousFrame]]:
    if media_type not in {"audio", "video"}:
        return {"synthetic_voice_confidence": 0, "summary": "Audio stream unavailable for this media type."}, []
    try:
        y, sr = librosa.load(str(path), sr=16000, mono=True, duration=45)
        if len(y) == 0:
            raise ValueError("empty audio")
        flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))
        zcr = float(np.mean(librosa.feature.zero_crossing_rate(y)))
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
        mfcc_variance = float(np.mean(np.var(mfcc, axis=1)))
        rms = float(np.mean(librosa.feature.rms(y=y)))
        confidence = int(np.clip(flatness * 180 + zcr * 220 + _score_from_range(mfcc_variance, 20, 180) * 0.45 + _score_from_range(rms, 0.01, 0.22) * 0.18, 0, 100))
        frames = [_write_audio_spectrogram(path, report_id, y, sr)] if report_id else []
        return {
            "synthetic_voice_confidence": confidence,
            "spectral_flatness": round(flatness, 4),
            "zero_crossing_rate": round(zcr, 4),
            "mfcc_variance": round(mfcc_variance, 3),
            "rms_energy": round(rms, 4),
            "summary": "Librosa decoded the audio and measured spectral flatness, zero-crossing rate, MFCC variance, and RMS energy.",
        }, frames
    except Exception as exc:
        return {"synthetic_voice_confidence": 0, "summary": f"Audio could not be decoded; no synthetic voice finding was generated. {exc}"}, []


def _text_metadata(label: str, indicators: list[str], size: int = 0) -> MetadataReport:
    return MetadataReport(file_size_mb=round(size / (1024 * 1024), 4), creation_date=datetime.now(timezone.utc).isoformat(), codec=label, duration_seconds=None, tampering_indicators=indicators)


def analyze_url_text(raw_url: str) -> AnalysisReport:
    parsed = urlparse(raw_url if re.match(r"^https?://", raw_url, re.I) else f"https://{raw_url}")
    domain = parsed.netloc.lower()
    indicators: list[str] = []
    score = 0
    if parsed.scheme != "https":
        indicators.append("URL does not use HTTPS.")
        score += 18
    if "@" in raw_url:
        indicators.append("URL contains @ redirection syntax.")
        score += 25
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        indicators.append("Domain uses a raw IP address.")
        score += 25
    if len([part for part in domain.split(".") if part]) > 3:
        indicators.append("Excessive subdomain depth detected.")
        score += 12
    if re.search(r"(login|verify|secure|account|update|wallet|reset)", raw_url, re.I):
        indicators.append("Credential or account-verification keyword detected.")
        score += 18
    if re.search(r"(paypa1|g00gle|micros0ft|amaz0n|appleid|secure-bank)", domain, re.I):
        indicators.append("Potential typosquatting or brand impersonation detected.")
        score += 28
    if "-" in domain:
        indicators.append("Hyphenated domain structure detected.")
        score += 8
    if not indicators:
        indicators.append("No phishing URL indicators detected.")
    score = int(np.clip(score, 0, 100))
    level = risk_level(score)
    report_id = str(uuid.uuid4())
    return AnalysisReport(
        id=report_id,
        filename=raw_url,
        media_type="url",
        uploaded_at=datetime.now(timezone.utc).isoformat(),
        scores=ScoreCard(authenticity_score=100 - score, deepfake_probability=0, risk_level=level, confidence_score=88, threat_score=score),
        metadata=_text_metadata("URL indicator", indicators),
        face_analysis={},
        lip_sync_analysis={},
        audio_clone_detection={},
        url_analysis={"domain": domain, "scheme": parsed.scheme, "path": parsed.path, "indicators": indicators},
        suspicious_frames=[],
        evidence=[EvidenceItem(label="URL Indicator", detail=item, severity=level) for item in indicators if not item.startswith("No ")],
        verdict="Likely Phishing" if score >= 65 else "Suspicious URL" if score >= 35 else "No URL Threat Detected",
        ai_classification=ai_classification(0),
        analysis_summary=f"URL analysis measured {len([i for i in indicators if not i.startswith('No ')])} phishing indicator(s).",
        key_findings=[i for i in indicators if not i.startswith("No ")],
        conclusion="Treat this URL as unsafe until verified." if score >= 35 else "No high-risk URL indicators were detected.",
        reasons_for_decision=indicators,
        recommendations=["Use official domains typed manually.", "Do not enter credentials on suspicious URLs.", "Report suspicious links to security staff."],
    )


def analyze_email_text(raw_email: str) -> AnalysisReport:
    lowered = raw_email.lower()
    checks = [
        ("Credential theft language detected.", ["password", "verify your account", "login immediately", "reset your account"], 22),
        ("Urgency or threat pressure detected.", ["urgent", "suspended", "24 hours", "immediately", "final notice"], 22),
        ("Payment or reward lure detected.", ["prize", "refund", "invoice", "wire transfer", "gift card", "crypto"], 22),
        ("Attachment or link risk detected.", [".exe", ".scr", "bit.ly", "tinyurl", "http://"], 22),
    ]
    indicators: list[str] = []
    score = 0
    for label, needles, points in checks:
        if any(needle in lowered for needle in needles):
            indicators.append(label)
            score += points
    if re.search(r"from:.*(support|security|admin).*@(gmail|outlook|yahoo)\.", lowered):
        indicators.append("Impersonation from consumer email domain detected.")
        score += 22
    if "dear customer" in lowered or "dear user" in lowered:
        indicators.append("Generic greeting often used in phishing.")
        score += 10
    if not indicators:
        indicators.append("No scam or phishing indicators detected.")
    score = int(np.clip(score, 0, 100))
    level = risk_level(score)
    report_id = str(uuid.uuid4())
    return AnalysisReport(
        id=report_id,
        filename="Pasted email / EML content",
        media_type="email",
        uploaded_at=datetime.now(timezone.utc).isoformat(),
        scores=ScoreCard(authenticity_score=100 - score, deepfake_probability=0, risk_level=level, confidence_score=86, threat_score=score),
        metadata=_text_metadata("Email text / EML", indicators, len(raw_email.encode("utf-8"))),
        face_analysis={},
        lip_sync_analysis={},
        audio_clone_detection={},
        email_analysis={"indicators": indicators, "highlight_terms": ["password", "urgent", "verify", "suspended", "invoice", "gift card"]},
        suspicious_frames=[],
        evidence=[EvidenceItem(label="Email Indicator", detail=item, severity=level) for item in indicators if not item.startswith("No ")],
        verdict="Likely Email Scam" if score >= 65 else "Suspicious Email" if score >= 35 else "No Email Threat Detected",
        ai_classification=ai_classification(0),
        analysis_summary=f"Email analysis measured {len([i for i in indicators if not i.startswith('No ')])} scam/phishing indicator(s).",
        key_findings=[i for i in indicators if not i.startswith("No ")],
        conclusion="Treat this email as phishing until verified through another channel." if score >= 35 else "No high-risk email scam indicators were detected.",
        reasons_for_decision=indicators,
        recommendations=["Do not click links or open attachments in suspicious email.", "Verify the sender through a known trusted channel.", "Report suspected phishing to the security team."],
    )


def analyze_upload(file_name: str, content_type: str | None, source: BinaryIO) -> AnalysisReport:
    settings = get_settings()
    report_id = str(uuid.uuid4())
    suffix = Path(file_name).suffix.lower() or ".bin"
    destination = settings.storage_dir / "uploads" / f"{report_id}{suffix}"
    with destination.open("wb") as output:
        shutil.copyfileobj(source, output)

    media_type = _media_type(destination, content_type)
    metadata = scan_metadata(destination, media_type)
    image_forensics: dict = {}
    if media_type == "image":
        image_forensics, suspicious_frames, probability, evidence, findings = analyze_image(destination, report_id, metadata)
        level = risk_level(probability)
        scores = ScoreCard(authenticity_score=100 - probability, deepfake_probability=probability, risk_level=level, confidence_score=min(96, 62 + len(evidence) * 8), threat_score=probability)
        face_analysis = {"frames_analyzed": 1, "suspicious_frames": len(suspicious_frames), "summary": "Still-image analysis completed using measured image statistics."}
        lip_sync = {"forensic_score": 0, "summary": "Not applicable."}
        audio_clone = {"synthetic_voice_confidence": 0, "summary": "Not applicable."}
        verdict = "Likely AI Generated or Manipulated" if probability >= 65 else "Review Recommended" if probability >= 35 else "No Strong Image Manipulation Detected"
        key_findings = findings
    else:
        face_analysis, suspicious_frames = analyze_faces(destination, report_id, media_type)
        lip_sync = analyze_lip_sync(destination, media_type)
        audio_clone, audio_frames = analyze_audio_clone(destination, media_type, report_id)
        suspicious_frames = suspicious_frames + audio_frames
        scores, evidence = calculate_scores(
            tampering_count=len([i for i in metadata.tampering_indicators if not i.startswith("No ")]),
            suspicious_frame_score=max([frame.score for frame in suspicious_frames], default=0),
            lip_sync_score=lip_sync["forensic_score"],
            audio_clone_confidence=audio_clone["synthetic_voice_confidence"],
        )
        if not evidence and any(not item.startswith("No ") for item in metadata.tampering_indicators):
            evidence.append(EvidenceItem(label="Metadata Indicator", detail=", ".join(metadata.tampering_indicators), severity=scores.risk_level))
        verdict = "Likely Synthetic or Manipulated" if scores.threat_score >= 65 else "Review Recommended" if scores.threat_score >= 35 else "No Strong Synthetic Indicators Detected"
        key_findings = [item.detail for item in evidence]

    if not key_findings:
        key_findings = ["No high-risk forensic indicators were detected by the available analysis modules."]
    return AnalysisReport(
        id=report_id,
        filename=file_name,
        media_type=media_type,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
        scores=scores,
        metadata=metadata,
        face_analysis=face_analysis,
        lip_sync_analysis=lip_sync,
        audio_clone_detection=audio_clone,
        image_forensics=image_forensics,
        suspicious_frames=suspicious_frames,
        evidence=evidence,
        verdict=verdict,
        ai_classification=ai_classification(scores.deepfake_probability),
        analysis_summary=f"{media_type.title()} analysis completed using measured forensic indicators only.",
        key_findings=key_findings,
        conclusion="High-risk indicators were detected; human verification is recommended before trust or sharing." if scores.threat_score >= 35 else "No high-risk indicators were detected; normal source verification is still recommended.",
        reasons_for_decision=key_findings,
        recommendations=DISCLAIMER_RECOMMENDATIONS,
    )
