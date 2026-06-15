import mimetypes
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse

import cv2
import numpy as np
import soundfile as sf
from PIL import ExifTags, Image

from app.config import get_settings
from app.models import AnalysisReport, EvidenceItem, MetadataReport, ScoreCard, SuspiciousFrame
from app.services.content_models import infer_audio_ai_probability, infer_image_ai_probability, infer_video_ai_probability
from app.services.pretrained_models import infer_pretrained_audio, infer_pretrained_images
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


def threat_classification(score: int, media_type: str = "media") -> str:
    if score >= 85:
        return "Critical Threat"
    if score >= 65:
        return "High Threat"
    if score >= 35:
        return "Medium Threat"
    return "Low Threat"


def _model_confidence(probability: int, evidence_count: int, model_available: bool = True) -> int:
    certainty = abs(probability - 50)
    availability_bonus = 12 if model_available else 0
    return int(np.clip(48 + certainty * 0.65 + min(evidence_count, 6) * 5 + availability_bonus, 45, 98))


def _fused_probability(*signals: int) -> int:
    valid = [int(np.clip(signal, 0, 100)) for signal in signals if signal is not None]
    if not valid:
        return 0
    strongest = max(valid)
    mean_signal = int(round(float(np.mean(valid))))
    return int(np.clip(max(strongest, round(strongest * 0.76 + mean_signal * 0.24)), 0, 100))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        key = item.split(":", 1)[0].strip().lower()
        if key and key not in seen:
            seen.add(key)
            output.append(item)
    return output


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
            info = sf.info(str(path))
            return f"{path.suffix.lower().replace('.', '').upper()} audio stream", round(info.frames / max(info.samplerate, 1), 2)
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
    has_camera_exif = bool(metadata.exif_data and metadata.camera_information != "Not available")
    content_model = infer_image_ai_probability(image, has_camera_exif)
    pretrained_model = infer_pretrained_images([Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))])
    visual_score = int(np.clip(np.mean([value for key, value in metrics.items() if key != "faces_detected"]), 0, 100))
    ai_probability = _fused_probability(
        pretrained_model.probability if pretrained_model.available else 0,
        content_model.probability,
        visual_score,
    )

    evidence: list[EvidenceItem] = []
    findings: list[str] = []
    evidence.append(EvidenceItem(
        label="Pretrained AI Image Detector",
        detail=(
            f"{pretrained_model.model_name} output: {pretrained_model.probability}% AI, label {pretrained_model.label}."
            if pretrained_model.available
            else f"{pretrained_model.model_name} unavailable; forensic content model used. {pretrained_model.error}"
        ),
        severity=risk_level(ai_probability),
    ))
    evidence.append(EvidenceItem(
        label="Image Forensic Content Model",
        detail=f"{content_model.label} probability: {content_model.probability}%.",
        severity=risk_level(content_model.probability),
    ))
    if pretrained_model.available:
        findings.append(f"Pretrained image detector probability: {pretrained_model.probability}% ({pretrained_model.label})")
    findings.extend(content_model.evidence)
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
    if evidence and max(visual_score, ai_probability) >= 35:
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
        "summary": "Image content model evaluated pixel texture, residual noise, frequency spectrum, compression seams, camera metadata support, and OpenCV visual anomalies.",
        "heatmap_generated": bool(suspicious),
        "resolution": f"{original.shape[1]}x{original.shape[0]}",
        "ai_model": content_model.label,
        "ai_model_probability": ai_probability,
        "pretrained_model": pretrained_model.model_name,
        "pretrained_model_available": pretrained_model.available,
        "pretrained_model_probability": pretrained_model.probability,
        "forensic_model_probability": content_model.probability,
        **{f"model_{key}": value for key, value in content_model.features.items()},
    })
    return metrics, suspicious, ai_probability, evidence, _dedupe(findings)


def _compression_seam_score(gray: np.ndarray) -> int:
    block = 8
    h, w = gray.shape
    if h <= block or w <= block:
        return 0
    vertical = float(np.mean(np.abs(gray[:, block:w:block].astype(np.float32) - gray[:, block - 1 : w - 1 : block].astype(np.float32))))
    horizontal = float(np.mean(np.abs(gray[block:h:block, :].astype(np.float32) - gray[block - 1 : h - 1 : block, :].astype(np.float32))))
    return int(np.clip((vertical + horizontal) * 2.3, 0, 100))


def _video_frame_metrics(frame: np.ndarray) -> tuple[dict[str, int | float], np.ndarray]:
    height, width = frame.shape[:2]
    scale = min(1.0, 720 / max(width, height))
    if scale < 1:
        frame = cv2.resize(frame, (int(width * scale), int(height * scale)))
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    edges = cv2.Canny(gray, 80, 180)
    texture_variance = float(np.var(laplacian))
    edge_density = float(np.count_nonzero(edges)) / edges.size
    brightness = float(np.mean(gray))
    contrast = float(np.std(gray))
    residual = gray.astype(np.float32) - cv2.GaussianBlur(gray, (0, 0), 1.2).astype(np.float32)
    noise_std = float(np.std(residual))

    face_score = 0
    face_regions = 0
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    for (x, y, fw, fh) in face_cascade.detectMultiScale(gray, scaleFactor=1.12, minNeighbors=5):
        roi = gray[y : y + fh, x : x + fw]
        if roi.size:
            face_regions += 1
            roi_edges = float(np.count_nonzero(cv2.Canny(roi, 60, 160))) / roi.size
            roi_texture = float(np.var(cv2.Laplacian(roi, cv2.CV_64F)))
            face_score = max(face_score, int(np.clip(_score_from_range(roi_texture, 90, 3600) * 0.6 + _score_from_range(roi_edges, 0.03, 0.24) * 0.4, 0, 100)))

    metrics = {
        "texture_anomaly": _score_from_range(texture_variance, 100, 4400),
        "edge_anomaly": _score_from_range(edge_density, 0.02, 0.24),
        "brightness_anomaly": _score_from_range(brightness, 32, 224),
        "contrast_anomaly": _score_from_range(contrast, 16, 98),
        "compression_artifacts": _compression_seam_score(gray),
        "noise_pattern_anomaly": _score_from_range(noise_std, 2.0, 32),
        "face_region_anomaly": face_score,
        "face_regions": face_regions,
        "brightness": round(brightness, 2),
        "edge_density": round(edge_density, 4),
    }
    metric_peak = max(
        int(metrics["texture_anomaly"]),
        int(metrics["edge_anomaly"]),
        int(metrics["compression_artifacts"]),
        int(metrics["noise_pattern_anomaly"]),
        int(metrics["face_region_anomaly"]),
    )
    frame_score = int(np.clip(max(
        metrics["texture_anomaly"] * 0.20
        + metrics["edge_anomaly"] * 0.18
        + metrics["compression_artifacts"] * 0.18
        + metrics["noise_pattern_anomaly"] * 0.16
        + metrics["face_region_anomaly"] * 0.18
        + max(metrics["brightness_anomaly"], metrics["contrast_anomaly"]) * 0.10,
        metric_peak * 0.82,
    ),
        0,
        100,
    ))
    metrics["frame_anomaly"] = frame_score
    return metrics, frame


def analyze_video(path: Path, report_id: str, media_type: str) -> tuple[dict, list[SuspiciousFrame], int, list[EvidenceItem], list[str]]:
    if media_type != "video":
        return {"frames_analyzed": 0, "suspicious_frames": 0, "summary": "Video frame analysis not applicable."}, [], 0, [], []
    settings = get_settings()
    capture = cv2.VideoCapture(str(path))
    fps = capture.get(cv2.CAP_PROP_FPS) or 24
    frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    if not capture.isOpened():
        return {"frames_analyzed": 0, "suspicious_frames": 0, "summary": "Video container could not be decoded by OpenCV."}, [], 45, [
            EvidenceItem(label="Video Decode Failure", detail="OpenCV could not decode frames from this video container.", severity="Medium")
        ], ["Video decode failed"]

    sample_count = 16
    if frame_count > 0:
        targets = np.linspace(0, max(0, frame_count - 1), min(sample_count, frame_count), dtype=int).tolist()
    else:
        targets = list(range(0, sample_count * int(fps), int(max(1, fps))))
    suspicious: list[SuspiciousFrame] = []
    evidence: list[EvidenceItem] = []
    findings: list[str] = []
    frame_scores: list[int] = []
    temporal_diffs: list[float] = []
    model_frames: list[Image.Image] = []
    metric_max = {
        "texture_anomaly": 0,
        "edge_anomaly": 0,
        "compression_artifacts": 0,
        "noise_pattern_anomaly": 0,
        "face_region_anomaly": 0,
    }
    previous_gray: np.ndarray | None = None
    analyzed = 0
    for index in targets:
        capture.set(cv2.CAP_PROP_POS_FRAMES, index)
        ok, frame = capture.read()
        if not ok:
            continue
        metrics, normalized_frame = _video_frame_metrics(frame)
        if len(model_frames) < 8:
            model_frames.append(Image.fromarray(cv2.cvtColor(normalized_frame, cv2.COLOR_BGR2RGB)))
        score = int(metrics["frame_anomaly"])
        frame_scores.append(score)
        for key in metric_max:
            metric_max[key] = max(metric_max[key], int(metrics[key]))

        gray_small = cv2.resize(cv2.cvtColor(normalized_frame, cv2.COLOR_BGR2GRAY), (160, 90))
        if previous_gray is not None:
            temporal_diffs.append(float(np.mean(cv2.absdiff(gray_small, previous_gray))))
        previous_gray = gray_small

        if score >= 45:
            frame_name = f"{report_id}-frame-{analyzed}.jpg"
            annotated = normalized_frame.copy()
            heat = cv2.normalize(np.abs(cv2.Laplacian(cv2.cvtColor(annotated, cv2.COLOR_BGR2GRAY), cv2.CV_64F)).astype(np.float32), None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
            annotated = cv2.addWeighted(annotated, 0.7, cv2.applyColorMap(heat, cv2.COLORMAP_TURBO), 0.3, 0)
            cv2.rectangle(annotated, (20, 20), (annotated.shape[1] - 20, annotated.shape[0] - 20), (0, 255, 255), 4)
            cv2.imwrite(str(settings.storage_dir / "frames" / frame_name), annotated)
            reasons = []
            if int(metrics["face_region_anomaly"]) >= 45:
                reasons.append("face-region inconsistency")
            if int(metrics["edge_anomaly"]) >= 45:
                reasons.append("edge anomaly")
            if int(metrics["compression_artifacts"]) >= 45:
                reasons.append("compression artifact inconsistency")
            if int(metrics["noise_pattern_anomaly"]) >= 45:
                reasons.append("noise residual anomaly")
            reason = ", ".join(reasons) or "combined frame artifact score"
            suspicious.append(SuspiciousFrame(timestamp_seconds=round(index / fps, 2), frame_url=f"/frames/{frame_name}", reason=f"Frame retained from measured {reason}.", score=score))
        analyzed += 1
    capture.release()

    temporal_score = 0
    if temporal_diffs:
        mean_diff = float(np.mean(temporal_diffs))
        diff_std = float(np.std(temporal_diffs))
        frozen_or_looped = _score_from_range(mean_diff, 2.5, 42)
        jumpiness = _score_from_range(diff_std, 0.8, 24)
        temporal_score = int(np.clip(frozen_or_looped * 0.55 + jumpiness * 0.45, 0, 100))
    max_frame_score = max(frame_scores, default=0)
    average_top_score = int(np.mean(sorted(frame_scores, reverse=True)[:4])) if frame_scores else 0
    classical_video_score = int(np.clip(max(max_frame_score * 0.72 + temporal_score * 0.28, average_top_score * 0.82), 0, 100))
    content_model = infer_video_ai_probability(frame_scores, temporal_score, metric_max)
    pretrained_model = infer_pretrained_images(model_frames)
    video_score = _fused_probability(
        pretrained_model.probability if pretrained_model.available else 0,
        content_model.probability,
        classical_video_score,
        max_frame_score,
    )
    evidence.append(EvidenceItem(
        label="Pretrained AI Video-Frame Detector",
        detail=(
            f"{pretrained_model.model_name} frame inference: {pretrained_model.probability}% AI, top label {pretrained_model.label}."
            if pretrained_model.available
            else f"{pretrained_model.model_name} unavailable; video forensic content model used. {pretrained_model.error}"
        ),
        severity=risk_level(video_score),
    ))
    evidence.append(EvidenceItem(
        label="Video Forensic Content Model",
        detail=f"{content_model.label} probability: {content_model.probability}%.",
        severity=risk_level(content_model.probability),
    ))
    if pretrained_model.available:
        findings.append(f"Pretrained video-frame detector probability: {pretrained_model.probability}% ({pretrained_model.label})")
    findings.extend(content_model.evidence)

    checks = [
        ("Face-region inconsistency detected", metric_max["face_region_anomaly"], 45),
        ("Edge anomaly detected across sampled video frames", metric_max["edge_anomaly"], 45),
        ("Compression artifact inconsistency detected", metric_max["compression_artifacts"], 55),
        ("Noise residual anomaly detected", metric_max["noise_pattern_anomaly"], 45),
        ("Texture inconsistency detected across frames", metric_max["texture_anomaly"], 45),
        ("Temporal inconsistency detected", temporal_score, 45),
    ]
    for label, score, threshold in checks:
        if score >= threshold:
            severity = risk_level(int(score))
            evidence.append(EvidenceItem(label=label, detail=f"{label} with measured score {int(score)}%.", severity=severity))
            findings.append(label)

    summary = {
        "frames_analyzed": analyzed,
        "suspicious_frames": len(suspicious),
        "max_frame_anomaly": max_frame_score,
        "average_top_frame_anomaly": average_top_score,
        "temporal_inconsistency": temporal_score,
        "video_forensic_score": video_score,
        "deepfake_probability": video_score,
        "deepfake_detected": "YES" if video_score >= 65 else "NO",
        "classical_video_forensic_score": classical_video_score,
        "ai_model": content_model.label,
        "ai_model_probability": video_score,
        "pretrained_model": pretrained_model.model_name,
        "pretrained_model_available": pretrained_model.available,
        "pretrained_model_probability": pretrained_model.probability,
        "forensic_model_probability": content_model.probability,
        "summary": "Video content model evaluated extracted frame anomaly clusters, face-region consistency, compression seams, residual noise, and temporal consistency.",
    }
    return summary, suspicious[:4], video_score, evidence, _dedupe(findings)


def analyze_faces(path: Path, report_id: str, media_type: str) -> tuple[dict, list[SuspiciousFrame]]:
    analysis, frames, _score, _evidence, _findings = analyze_video(path, report_id, media_type)
    return analysis, frames


def analyze_lip_sync(path: Path, media_type: str) -> dict:
    if media_type != "video":
        return {"forensic_score": 0, "summary": "Not applicable."}
    return {"forensic_score": 0, "summary": "Lip-sync mismatch is not claimed because no speech-to-mouth model is available in this prototype."}


def _write_audio_spectrogram(path: Path, report_id: str, y: np.ndarray, sr: int) -> SuspiciousFrame:
    settings = get_settings()
    n_fft = 1024
    hop = 256
    if y.size < n_fft:
        y = np.pad(y, (0, n_fft - y.size))
    frames = np.lib.stride_tricks.sliding_window_view(y, n_fft)[::hop][:1200]
    spectrogram = np.abs(np.fft.rfft(frames * np.hanning(n_fft), axis=1)).T
    db = 20 * np.log10(spectrogram / max(float(np.max(spectrogram)), 1e-8) + 1e-8)
    normalized = cv2.normalize(db, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    color = cv2.applyColorMap(normalized, cv2.COLORMAP_TURBO)
    color = cv2.flip(color, 0)
    frame_name = f"{report_id}-audio-spectrogram.jpg"
    cv2.imwrite(str(settings.storage_dir / "frames" / frame_name), color)
    return SuspiciousFrame(timestamp_seconds=0, frame_url=f"/frames/{frame_name}", reason="Spectrogram generated from decoded audio samples.", score=0)


def analyze_audio_clone(path: Path, media_type: str, report_id: str | None = None) -> tuple[dict, list[SuspiciousFrame]]:
    if media_type == "video":
        return {"synthetic_voice_confidence": 0, "summary": "Audio clone analysis is skipped for video containers; video verdict is based on decoded frame and temporal forensics."}, []
    if media_type != "audio":
        return {"synthetic_voice_confidence": 0, "summary": "Audio stream unavailable for this media type."}, []
    try:
        y, sr = sf.read(str(path), dtype="float32", always_2d=False, frames=45 * 48000)
        if y.ndim > 1:
            y = np.mean(y, axis=1)
        if sr != 16000 and y.size:
            target_length = max(1, int(len(y) * 16000 / sr))
            y = np.interp(np.linspace(0, len(y) - 1, target_length), np.arange(len(y)), y).astype(np.float32)
            sr = 16000
        if y.size > sr * 45:
            y = y[: sr * 45]
        if len(y) == 0:
            raise ValueError("empty audio")
        content_model = infer_audio_ai_probability(y, sr)
        pretrained_model = infer_pretrained_audio(y, sr)
        confidence = _fused_probability(
            pretrained_model.probability if pretrained_model.available else 0,
            content_model.probability,
        )
        frames = [_write_audio_spectrogram(path, report_id, y, sr)] if report_id else []
        features = content_model.features
        return {
            "synthetic_voice_confidence": confidence,
            "voice_clone_probability": confidence,
            "voice_clone_detected": "YES" if confidence >= 65 else "NO",
            "ai_model": pretrained_model.model_name if pretrained_model.available else content_model.label,
            "ai_model_probability": confidence,
            "pretrained_model": pretrained_model.model_name,
            "pretrained_model_available": pretrained_model.available,
            "pretrained_model_probability": pretrained_model.probability,
            "pretrained_model_label": pretrained_model.label,
            "pretrained_model_error": pretrained_model.error or "",
            "forensic_model_probability": content_model.probability,
            "model_evidence": (
                [f"Pretrained voice detector probability: {pretrained_model.probability}% ({pretrained_model.label})"]
                if pretrained_model.available
                else [f"Pretrained voice detector unavailable: {pretrained_model.error}"]
            ) + content_model.evidence,
            "spectral_flatness": round(float(features.get("spectral_flatness", 0)), 4),
            "zero_crossing_rate": round(float(features.get("zero_crossing_rate", 0)), 4),
            "mfcc_variance": round(float(features.get("mfcc_variance", 0)), 3),
            "rms_energy": round(float(features.get("rms_mean", 0)), 4),
            **{f"model_{key}": round(value, 4) if isinstance(value, float) else value for key, value in content_model.features.items()},
            "summary": "Audio content model evaluated spectrogram, MFCC variance, spectral flatness, frequency distribution, RMS dynamics, and pitch contour.",
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
    if re.search(r"(login|verify|secure|account|update|wallet|reset|signin|auth|otp|kyc)", raw_url, re.I):
        indicators.append("Credential or account-verification keyword detected.")
        score += 18
    if re.search(r"(paypa1|g00gle|micros0ft|amaz0n|appleid|secure-bank|faceb00k|whatsapp-login)", domain, re.I):
        indicators.append("Potential typosquatting or brand impersonation detected.")
        score += 32
    if re.search(r"(free|bonus|claim|airdrop|wallet|crypto|bank|loan)", raw_url, re.I):
        indicators.append("Financial lure or credential-harvesting theme detected.")
        score += 18
    if parsed.query and re.search(r"(redirect|url|next|return|continue)=", parsed.query, re.I):
        indicators.append("Redirect parameter detected in query string.")
        score += 18
    if len(domain) > 45:
        indicators.append("Unusually long domain detected.")
        score += 12
    if re.search(r"[a-z]{12,}\\.", domain):
        indicators.append("High-entropy domain label detected.")
        score += 16
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
        scores=ScoreCard(authenticity_score=100 - score, deepfake_probability=0, risk_level=level, confidence_score=_model_confidence(score, len(indicators)), threat_score=score),
        metadata=_text_metadata("URL indicator", indicators),
        face_analysis={},
        lip_sync_analysis={},
        audio_clone_detection={},
        url_analysis={"domain": domain, "scheme": parsed.scheme, "path": parsed.path, "indicators": indicators},
        suspicious_frames=[],
        evidence=[EvidenceItem(label="URL Indicator", detail=item, severity=level) for item in indicators if not item.startswith("No ")],
        verdict="Likely Phishing" if score >= 65 else "Suspicious URL" if score >= 35 else "No URL Threat Detected",
        ai_classification=ai_classification(0),
        threat_classification=threat_classification(score, "url"),
        model_confidence=_model_confidence(score, len(indicators)),
        evidence_summary="; ".join([i for i in indicators if not i.startswith("No ")]) or "No URL threat evidence crossed threshold.",
        analysis_summary=f"URL analysis measured {len([i for i in indicators if not i.startswith('No ')])} phishing indicator(s).",
        key_findings=[i for i in indicators if not i.startswith("No ")],
        conclusion="Treat this URL as unsafe until verified." if score >= 35 else "No high-risk URL indicators were detected.",
        reasons_for_decision=indicators,
        recommendations=["Use official domains typed manually.", "Do not enter credentials on suspicious URLs.", "Report suspicious links to security staff."],
    )


def analyze_email_text(raw_email: str) -> AnalysisReport:
    lowered = raw_email.lower()
    checks = [
        ("Credential theft language detected.", ["password", "verify your account", "login immediately", "reset your account", "confirm your identity", "otp", "kyc"], 24),
        ("Urgency or threat pressure detected.", ["urgent", "suspended", "24 hours", "immediately", "final notice", "limited time", "act now"], 22),
        ("Payment or reward lure detected.", ["prize", "refund", "invoice", "wire transfer", "gift card", "crypto", "tax", "loan", "payment failed"], 24),
        ("Attachment or link risk detected.", [".exe", ".scr", ".zip", ".html", "bit.ly", "tinyurl", "http://"], 22),
    ]
    indicators: list[str] = []
    score = 0
    for label, needles, points in checks:
        if any(needle in lowered for needle in needles):
            indicators.append(label)
            score += points
    if re.search(r"from:.*(support|security|admin).*@(gmail|outlook|yahoo)\.", lowered):
        indicators.append("Impersonation from consumer email domain detected.")
        score += 26
    if re.search(r"(reply-to|return-path):.*@(gmail|outlook|yahoo|proton)\.", lowered) and re.search(r"from:.*@(?!gmail|outlook|yahoo|proton)", lowered):
        indicators.append("Sender and reply-to domain mismatch detected.")
        score += 20
    if re.search(r"(bank|paypal|microsoft|google|apple|meta|instagram|whatsapp|income tax|rbi|sbi|hdfc)", lowered) and re.search(r"(verify|login|suspended|blocked|password|otp)", lowered):
        indicators.append("Brand impersonation with credential request detected.")
        score += 28
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
        scores=ScoreCard(authenticity_score=100 - score, deepfake_probability=0, risk_level=level, confidence_score=_model_confidence(score, len(indicators)), threat_score=score),
        metadata=_text_metadata("Email text / EML", indicators, len(raw_email.encode("utf-8"))),
        face_analysis={},
        lip_sync_analysis={},
        audio_clone_detection={},
        email_analysis={"indicators": indicators, "highlight_terms": ["password", "urgent", "verify", "suspended", "invoice", "gift card"]},
        suspicious_frames=[],
        evidence=[EvidenceItem(label="Email Indicator", detail=item, severity=level) for item in indicators if not item.startswith("No ")],
        verdict="Likely Email Scam" if score >= 65 else "Suspicious Email" if score >= 35 else "No Email Threat Detected",
        ai_classification=ai_classification(0),
        threat_classification=threat_classification(score, "email"),
        model_confidence=_model_confidence(score, len(indicators)),
        evidence_summary="; ".join([i for i in indicators if not i.startswith("No ")]) or "No email threat evidence crossed threshold.",
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
        scores = ScoreCard(authenticity_score=100 - probability, deepfake_probability=probability, risk_level=level, confidence_score=_model_confidence(probability, len(evidence), bool(image_forensics.get("pretrained_model_available"))), threat_score=probability)
        face_analysis = {"frames_analyzed": 1, "suspicious_frames": len(suspicious_frames), "summary": "Still-image analysis completed using measured image statistics."}
        lip_sync = {"forensic_score": 0, "summary": "Not applicable."}
        audio_clone = {"synthetic_voice_confidence": 0, "voice_clone_probability": 0, "voice_clone_detected": "NO", "summary": "Not applicable."}
        verdict = "Likely AI Generated or Manipulated" if probability >= 65 else "Review Recommended" if probability >= 35 else "No Strong Image Manipulation Detected"
        key_findings = findings
    else:
        if media_type == "video":
            face_analysis, suspicious_frames, visual_score, video_evidence, video_findings = analyze_video(destination, report_id, media_type)
        elif media_type == "audio":
            face_analysis, suspicious_frames, visual_score, video_evidence, video_findings = (
                {"frames_analyzed": 0, "suspicious_frames": 0, "summary": "Video frame analysis not applicable."},
                [],
                0,
                [],
                [],
            )
        else:
            face_analysis, suspicious_frames, visual_score, video_evidence, video_findings = (
                {"frames_analyzed": 0, "suspicious_frames": 0, "summary": "Video frame analysis not applicable."},
                [],
                0,
                [],
                [],
            )
        lip_sync = analyze_lip_sync(destination, media_type)
        audio_clone, audio_frames = analyze_audio_clone(destination, media_type, report_id)
        suspicious_frames = suspicious_frames + audio_frames
        audio_evidence = []
        audio_findings = []
        if media_type == "audio" and audio_clone.get("synthetic_voice_confidence", 0) >= 0:
            audio_score = int(audio_clone["synthetic_voice_confidence"])
            audio_evidence.append(EvidenceItem(
                label="Audio AI Content Model",
                detail=f"{audio_clone.get('ai_model', 'audio_content_model')} probability: {audio_score}%.",
                severity=risk_level(audio_score),
            ))
            audio_findings.extend(str(item) for item in audio_clone.get("model_evidence", []))
        scores, evidence = calculate_scores(
            tampering_count=len([i for i in metadata.tampering_indicators if not i.startswith("No ")]),
            suspicious_frame_score=visual_score,
            lip_sync_score=lip_sync["forensic_score"],
            audio_clone_confidence=audio_clone["synthetic_voice_confidence"],
        )
        scores.confidence_score = _model_confidence(scores.deepfake_probability, len(video_evidence) + len(audio_evidence), True)
        primary_evidence = video_evidence + audio_evidence
        evidence = primary_evidence + [item for item in evidence if item.detail not in {existing.detail for existing in primary_evidence}]
        if not evidence and any(not item.startswith("No ") for item in metadata.tampering_indicators):
            evidence.append(EvidenceItem(label="Metadata Indicator", detail=", ".join(metadata.tampering_indicators), severity=scores.risk_level))
        verdict = "Likely Synthetic or Manipulated" if scores.threat_score >= 65 else "Review Recommended" if scores.threat_score >= 35 else "No Strong Synthetic Indicators Detected"
        key_findings = []
        seen_findings: set[str] = set()
        for finding in video_findings + audio_findings + [item.detail for item in evidence]:
            signature = finding.split(" with measured", 1)[0].split(":", 1)[0].strip().lower()
            if signature and signature not in seen_findings:
                seen_findings.add(signature)
                key_findings.append(finding)

    if not key_findings:
        key_findings = ["No high-risk forensic indicators were detected by the available analysis modules."]
    evidence_summary = "; ".join([item.detail for item in evidence[:5]]) if evidence else "No evidence item crossed the reporting threshold."
    voice_clone_detected = str(audio_clone.get("voice_clone_detected", "NO"))
    deepfake_detected = "YES" if media_type == "video" and scores.deepfake_probability >= 65 else "NO"
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
        threat_classification=threat_classification(scores.threat_score, media_type),
        model_confidence=scores.confidence_score,
        evidence_summary=evidence_summary,
        voice_clone_detected=voice_clone_detected,
        deepfake_detected=deepfake_detected,
        analysis_summary=f"{media_type.title()} analysis completed using measured forensic indicators only.",
        key_findings=key_findings,
        conclusion="High-risk indicators were detected; human verification is recommended before trust or sharing." if scores.threat_score >= 35 else "No high-risk indicators were detected; normal source verification is still recommended.",
        reasons_for_decision=key_findings,
        recommendations=DISCLAIMER_RECOMMENDATIONS,
    )
