from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np


def _clamp(value: float, low: float = 0, high: float = 100) -> int:
    return int(np.clip(round(value), low, high))


def _range_anomaly(value: float, low: float, high: float) -> float:
    if low <= value <= high:
        return 0.0
    distance = min(abs(value - low), abs(value - high))
    return float(np.clip(distance * 100 / max(high - low, 1e-6), 0, 100))


def _sigmoid_score(value: float) -> int:
    return _clamp(100 / (1 + np.exp(-value)))


@dataclass(frozen=True)
class ModelSignal:
    probability: int
    label: str
    features: dict[str, float | int | str]
    evidence: list[str]


def _gray_features(gray: np.ndarray) -> dict[str, float]:
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    edges = cv2.Canny(gray, 80, 180)
    residual = gray.astype(np.float32) - cv2.GaussianBlur(gray, (0, 0), 1.4).astype(np.float32)
    h, w = gray.shape
    block = 8
    seams = 0.0
    if h > block and w > block:
        vertical = float(np.mean(np.abs(gray[:, block:w:block].astype(np.float32) - gray[:, block - 1 : w - 1 : block].astype(np.float32))))
        horizontal = float(np.mean(np.abs(gray[block:h:block, :].astype(np.float32) - gray[block - 1 : h - 1 : block, :].astype(np.float32))))
        seams = vertical + horizontal
    spectrum = np.fft.fftshift(np.fft.fft2(gray.astype(np.float32)))
    magnitude = np.log1p(np.abs(spectrum))
    cy, cx = h // 2, w // 2
    yy, xx = np.ogrid[:h, :w]
    radius = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2)
    high_mask = radius > min(h, w) * 0.32
    mid_mask = (radius > min(h, w) * 0.12) & (radius <= min(h, w) * 0.32)
    high_freq_ratio = float(np.mean(magnitude[high_mask]) / max(np.mean(magnitude[mid_mask]), 1e-6)) if np.any(high_mask) and np.any(mid_mask) else 0.0
    return {
        "texture_variance": float(np.var(laplacian)),
        "edge_density": float(np.count_nonzero(edges)) / edges.size,
        "noise_residual_std": float(np.std(residual)),
        "compression_seams": seams,
        "brightness": float(np.mean(gray)),
        "contrast": float(np.std(gray)),
        "high_frequency_ratio": high_freq_ratio,
    }


def infer_image_ai_probability(image: np.ndarray, has_camera_exif: bool) -> ModelSignal:
    height, width = image.shape[:2]
    scale = min(1.0, 960 / max(width, height))
    if scale < 1:
        image = cv2.resize(image, (int(width * scale), int(height * scale)))
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    features = _gray_features(gray)
    texture_anomaly = _range_anomaly(features["texture_variance"], 140, 5200)
    edge_anomaly = _range_anomaly(features["edge_density"], 0.025, 0.24)
    noise_anomaly = _range_anomaly(features["noise_residual_std"], 3.2, 30)
    frequency_anomaly = _range_anomaly(features["high_frequency_ratio"], 0.55, 1.42)
    seam_score = np.clip(features["compression_seams"] * 2.8, 0, 100)
    metadata_signal = 0 if has_camera_exif else 10
    logit = (
        -2.8
        + metadata_signal * 0.028
        + texture_anomaly * 0.020
        + edge_anomaly * 0.018
        + noise_anomaly * 0.026
        + frequency_anomaly * 0.030
        + seam_score * 0.035
    )
    probability = _sigmoid_score(logit)
    evidence: list[str] = []
    checks = [
        ("Texture distribution outside camera-photo range", texture_anomaly, 42),
        ("Edge density inconsistent with natural capture", edge_anomaly, 42),
        ("Residual noise pattern inconsistent with camera sensor noise", noise_anomaly, 42),
        ("Frequency spectrum resembles synthetic rendering/compositing", frequency_anomaly, 42),
        ("Compression seam artifacts detected", seam_score, 55),
    ]
    for label, score, threshold in checks:
        if score >= threshold:
            evidence.append(f"{label}: {int(score)}%")
    if not has_camera_exif:
        evidence.append("Camera EXIF absent; model weighted this as a weak supporting signal.")
    return ModelSignal(probability, "image_content_model_v1", {**features, "metadata_signal": metadata_signal}, evidence)


def infer_audio_ai_probability(y: np.ndarray, sr: int) -> ModelSignal:
    if y.size == 0:
        return ModelSignal(0, "audio_content_model_v1", {"error": "empty audio"}, [])
    y = y.astype(np.float32)
    y = y / max(float(np.max(np.abs(y))), 1e-8)
    frame_length = max(256, int(sr * 0.025))
    hop = max(128, int(sr * 0.010))
    if y.size < frame_length:
        y = np.pad(y, (0, frame_length - y.size))
    frames = np.lib.stride_tricks.sliding_window_view(y, frame_length)[::hop]
    frames = frames[:800]
    windowed = frames * np.hanning(frame_length)
    spectrum = np.abs(np.fft.rfft(windowed, axis=1)) + 1e-8
    power = spectrum**2
    freqs = np.fft.rfftfreq(frame_length, 1 / sr)
    flatness = float(np.mean(np.exp(np.mean(np.log(spectrum), axis=1)) / np.maximum(np.mean(spectrum, axis=1), 1e-8)))
    zcr = float(np.mean(np.mean(np.abs(np.diff(np.signbit(frames), axis=1)), axis=1)))
    rms_series = np.sqrt(np.mean(frames**2, axis=1))
    rms_mean = float(np.mean(rms_series))
    rms_std = float(np.std(rms_series))
    bands = np.array_split(np.log(power + 1e-8), 24, axis=1)
    log_bands = np.stack([np.mean(band, axis=1) for band in bands], axis=1)
    cepstral = np.abs(np.fft.rfft(log_bands - np.mean(log_bands, axis=1, keepdims=True), axis=1))[:, :13]
    mfcc_variance = float(np.mean(np.var(cepstral, axis=0)))
    energy = np.maximum(np.sum(power, axis=1), 1e-8)
    centroid_series = np.sum(power * freqs[None, :], axis=1) / energy
    centroid = float(np.mean(centroid_series))
    bandwidth_series = np.sqrt(np.sum(power * (freqs[None, :] - centroid_series[:, None]) ** 2, axis=1) / energy)
    bandwidth = float(np.mean(bandwidth_series))
    cumulative = np.cumsum(power, axis=1)
    rolloff_indices = np.argmax(cumulative >= 0.85 * energy[:, None], axis=1)
    rolloff = float(np.mean(freqs[rolloff_indices]))
    contrast = float(np.mean(np.percentile(10 * np.log10(power + 1e-8), 90, axis=1) - np.percentile(10 * np.log10(power + 1e-8), 10, axis=1)))
    pitch_variation = float(np.std(centroid_series) / max(np.mean(centroid_series), 1e-6)) if centroid_series.size else 0.0
    high_flatness_score = np.clip((flatness - 0.62) * 260, 0, 100)
    spectral_purity_score = np.clip((0.025 - flatness) * 4000, 0, 100)
    zcr_score = _range_anomaly(zcr, 0.018, 0.14)
    mfcc_score = _range_anomaly(mfcc_variance, 18, 165)
    dynamics_ratio = rms_std / max(rms_mean, 1e-6)
    bandwidth_ratio = bandwidth / max(centroid, 1e-6)
    dynamics_score = np.clip((0.22 - dynamics_ratio) * 520, 0, 100)
    pitch_score = np.clip((0.055 - pitch_variation) * 1800, 0, 100)
    bandwidth_score = np.clip((0.72 - bandwidth_ratio) * 220, 0, 100)
    logit = (
        -3.0
        + high_flatness_score * 0.008
        + spectral_purity_score * 0.018
        + zcr_score * 0.010
        + mfcc_score * 0.010
        + dynamics_score * 0.026
        + pitch_score * 0.024
        + bandwidth_score * 0.018
    )
    probability = _sigmoid_score(logit)
    evidence: list[str] = []
    checks = [
        ("High spectral flatness anomaly", high_flatness_score, 45),
        ("Overly pure harmonic spectrum", spectral_purity_score, 45),
        ("Zero-crossing pattern anomaly", zcr_score, 45),
        ("MFCC variance outside natural speech range", mfcc_score, 45),
        ("RMS dynamics too uniform or unstable", dynamics_score, 45),
        ("Pitch contour anomaly", pitch_score, 45),
        ("Frequency bandwidth anomaly", bandwidth_score, 45),
    ]
    for label, score, threshold in checks:
        if score >= threshold:
            evidence.append(f"{label}: {int(score)}%")
    return ModelSignal(
        probability,
        "audio_content_model_v1",
        {
            "spectral_flatness": flatness,
            "zero_crossing_rate": zcr,
            "rms_mean": rms_mean,
            "rms_dynamics": dynamics_ratio,
            "mfcc_variance": mfcc_variance,
            "spectral_centroid": centroid,
            "spectral_bandwidth": bandwidth,
            "spectral_rolloff": rolloff,
            "spectral_contrast": contrast,
            "pitch_variation": pitch_variation,
            "bandwidth_ratio": bandwidth_ratio,
        },
        evidence,
    )


def infer_video_ai_probability(frame_scores: list[int], temporal_score: int, frame_feature_peaks: dict[str, int]) -> ModelSignal:
    if not frame_scores:
        return ModelSignal(0, "video_content_model_v1", {"error": "no decoded frames"}, [])
    top_average = float(np.mean(sorted(frame_scores, reverse=True)[: max(1, min(5, len(frame_scores)))]))
    max_frame = max(frame_scores)
    face_score = frame_feature_peaks.get("face_region_anomaly", 0)
    edge_score = frame_feature_peaks.get("edge_anomaly", 0)
    texture_score = frame_feature_peaks.get("texture_anomaly", 0)
    compression_score = frame_feature_peaks.get("compression_artifacts", 0)
    noise_score = frame_feature_peaks.get("noise_pattern_anomaly", 0)
    logit = (
        -2.2
        + top_average * 0.034
        + max_frame * 0.012
        + temporal_score * 0.024
        + face_score * 0.018
        + edge_score * 0.014
        + texture_score * 0.014
        + compression_score * 0.018
        + noise_score * 0.014
    )
    probability = _sigmoid_score(logit)
    evidence: list[str] = []
    checks = [
        ("Suspicious frame anomaly cluster", top_average, 42),
        ("Temporal consistency anomaly", temporal_score, 42),
        ("Face-region anomaly", face_score, 45),
        ("Edge anomaly", edge_score, 45),
        ("Texture anomaly", texture_score, 45),
        ("Compression artifact anomaly", compression_score, 55),
        ("Noise residual anomaly", noise_score, 45),
    ]
    for label, score, threshold in checks:
        if score >= threshold:
            evidence.append(f"{label}: {int(score)}%")
    return ModelSignal(probability, "video_content_model_v1", {"top_frame_average": top_average, "max_frame": max_frame, "temporal_score": temporal_score, **frame_feature_peaks}, evidence)
