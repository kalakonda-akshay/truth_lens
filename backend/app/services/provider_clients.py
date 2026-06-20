from __future__ import annotations

import base64
import io
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cv2
import numpy as np
import requests

from app.config import get_settings


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    available: bool
    probability: int = 0
    label: str = "unavailable"
    evidence: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass(frozen=True)
class SightengineMediaResult:
    provider: str
    available: bool
    ai_probability: int = 0
    deepfake_probability: int = 0
    evidence: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass(frozen=True)
class VirusTotalResult:
    provider: str
    available: bool
    threat_score: int = 0
    phishing_probability: int = 0
    domain_risk_score: int = 0
    classification: str = "SAFE"
    evidence: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""


def _percent(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 1:
        number *= 100
    return int(np.clip(round(number), 0, 100))


def _settings_ready(*values: str) -> bool:
    return all(bool(value and value.strip()) for value in values)


def _top_generator(type_block: dict[str, Any]) -> str | None:
    generators = type_block.get("ai_generators")
    if not isinstance(generators, dict) or not generators:
        return None
    name, score = max(generators.items(), key=lambda item: float(item[1] or 0))
    percent = _percent(score)
    return f"{name.replace('_', ' ').title()} signal {percent}%"


def sightengine_image(path: Path, models: str = "genai,deepfake") -> SightengineMediaResult:
    settings = get_settings()
    if not _settings_ready(settings.sightengine_api_user, settings.sightengine_api_secret):
        return SightengineMediaResult("Sightengine", False, error="Sightengine credentials are not configured.")
    try:
        with path.open("rb") as handle:
            response = requests.post(
                "https://api.sightengine.com/1.0/check.json",
                data={
                    "models": models,
                    "api_user": settings.sightengine_api_user,
                    "api_secret": settings.sightengine_api_secret,
                },
                files={"media": (path.name, handle)},
                timeout=35,
            )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            return SightengineMediaResult("Sightengine", False, raw=payload, error=str(payload.get("error") or payload))
        type_block = payload.get("type") or {}
        ai_probability = _percent(type_block.get("ai_generated"))
        deepfake_probability = _percent(type_block.get("deepfake"))
        evidence = [f"Sightengine AI-generated score: {ai_probability}%."]
        if "deepfake" in type_block:
            evidence.append(f"Sightengine deepfake score: {deepfake_probability}%.")
        top_generator = _top_generator(type_block)
        if top_generator:
            evidence.append(f"Top generator fingerprint: {top_generator}.")
        return SightengineMediaResult("Sightengine", True, ai_probability, deepfake_probability, evidence, payload)
    except Exception as exc:
        return SightengineMediaResult("Sightengine", False, error=str(exc))


def sightengine_frames(frames: list[np.ndarray], models: str = "genai,deepfake") -> SightengineMediaResult:
    settings = get_settings()
    if not _settings_ready(settings.sightengine_api_user, settings.sightengine_api_secret):
        return SightengineMediaResult("Sightengine", False, error="Sightengine credentials are not configured.")
    ai_scores: list[int] = []
    deepfake_scores: list[int] = []
    evidence: list[str] = []
    raw_results: list[dict[str, Any]] = []
    try:
        for index, frame in enumerate(frames[:8]):
            ok, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 92])
            if not ok:
                continue
            response = requests.post(
                "https://api.sightengine.com/1.0/check.json",
                data={
                    "models": models,
                    "api_user": settings.sightengine_api_user,
                    "api_secret": settings.sightengine_api_secret,
                },
                files={"media": (f"frame-{index}.jpg", io.BytesIO(buffer.tobytes()), "image/jpeg")},
                timeout=35,
            )
            response.raise_for_status()
            payload = response.json()
            raw_results.append(payload)
            if payload.get("status") != "success":
                evidence.append(f"Sightengine frame {index} failed: {payload.get('error') or payload}.")
                continue
            type_block = payload.get("type") or {}
            ai = _percent(type_block.get("ai_generated"))
            deepfake = _percent(type_block.get("deepfake"))
            ai_scores.append(ai)
            deepfake_scores.append(deepfake)
            if ai >= 35 or deepfake >= 35:
                evidence.append(f"Frame {index}: Sightengine AI {ai}%, deepfake {deepfake}%.")
        if not ai_scores and not deepfake_scores:
            return SightengineMediaResult("Sightengine", False, raw={"frames": raw_results}, error="No Sightengine frame scores were returned.")
        ai_probability = int(np.clip(round(max(ai_scores or [0]) * 0.7 + np.mean(ai_scores or [0]) * 0.3), 0, 100))
        deepfake_probability = int(np.clip(round(max(deepfake_scores or [0]) * 0.75 + np.mean(deepfake_scores or [0]) * 0.25), 0, 100))
        if not evidence:
            evidence.append(f"Sightengine frame analysis returned low-risk scores across {len(ai_scores)} sampled frame(s).")
        return SightengineMediaResult("Sightengine", True, ai_probability, deepfake_probability, evidence, {"frames": raw_results})
    except Exception as exc:
        return SightengineMediaResult("Sightengine", False, raw={"frames": raw_results}, error=str(exc))


def resemble_detect_audio(path: Path) -> ProviderResult:
    settings = get_settings()
    if not _settings_ready(settings.resemble_api_key, settings.resemble_detect_url):
        return ProviderResult("Resemble Detect", False, error="Resemble Detect credentials are not configured.")
    try:
        with path.open("rb") as handle:
            response = requests.post(
                settings.resemble_detect_url,
                headers={"Authorization": f"Bearer {settings.resemble_api_key}", "Prefer": "wait"},
                data={"visualize": "true", "audio_source_tracing": "true", "zero_retention_mode": "true"},
                files={"file": (path.name, handle)},
                timeout=60,
            )
        response.raise_for_status()
        payload = response.json()
        probability = _resemble_detection_probability(payload)
        if probability == 0:
            probability = _first_probability(payload, [
            "voice_clone_probability",
            "fake_probability",
            "deepfake_probability",
            "probability",
            "score",
            "item.metrics.aggregated_score",
            "data.score",
            "data.probability",
            "result.score",
            "result.probability",
            ])
        label = str(_nested_get(payload, "item.metrics.label") or _nested_get(payload, "label") or _nested_get(payload, "result.label") or _nested_get(payload, "data.label") or "Resemble Detect")
        evidence = [f"Resemble Detect voice-clone probability: {probability}%."]
        if label:
            evidence.append(f"Resemble Detect label: {label}.")
        return ProviderResult("Resemble Detect", True, probability, label, evidence, payload)
    except Exception as exc:
        return ProviderResult("Resemble Detect", False, error=str(exc))


def virustotal_url(raw_url: str) -> VirusTotalResult:
    settings = get_settings()
    if not _settings_ready(settings.virustotal_api_key):
        return VirusTotalResult("VirusTotal", False, error="VirusTotal API key is not configured.")
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        normalized = raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}"
        analysis_payload: dict[str, Any] | None = None
        post = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": normalized}, timeout=25)
        if post.status_code < 400:
            analysis_id = ((post.json().get("data") or {}).get("id") or "").strip()
            for _ in range(4):
                if not analysis_id:
                    break
                analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=25)
                if analysis.status_code < 400:
                    analysis_payload = analysis.json()
                    status = (((analysis_payload.get("data") or {}).get("attributes") or {}).get("status") or "").lower()
                    if status == "completed":
                        break
                time.sleep(1.5)
        url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").strip("=")
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=25)
        report_payload = report.json() if report.status_code < 400 else {}
        attrs = ((report_payload.get("data") or {}).get("attributes") or {})
        stats = attrs.get("last_analysis_stats") or (((analysis_payload or {}).get("data") or {}).get("attributes") or {}).get("stats") or {}
        results = attrs.get("last_analysis_results") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = max(malicious + suspicious + harmless + undetected, 1)
        threat_score = int(np.clip(round(((malicious * 1.0 + suspicious * 0.55) / total) * 100), 0, 100))
        if malicious >= 5:
            threat_score = max(threat_score, 90)
        elif malicious >= 2 or suspicious >= 4:
            threat_score = max(threat_score, 70)
        elif malicious == 1 or suspicious >= 1:
            threat_score = max(threat_score, 42)
        categories = [
            str(item.get("category", "")).lower()
            for item in results.values()
            if isinstance(item, dict) and str(item.get("category", "")).lower() in {"malicious", "suspicious"}
        ]
        evidence = [f"VirusTotal engines: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected."]
        engine_names = [
            name for name, item in results.items()
            if isinstance(item, dict) and str(item.get("category", "")).lower() in {"malicious", "suspicious"}
        ][:6]
        if engine_names:
            evidence.append("Flagging engines: " + ", ".join(engine_names) + ".")
        if attrs.get("reputation") is not None:
            evidence.append(f"VirusTotal reputation score: {attrs.get('reputation')}.")
        phishing_probability = int(np.clip(max(threat_score, 75 if "phishing" in " ".join(categories) else 0), 0, 100))
        classification = _url_classification(threat_score)
        domain_risk_score = int(np.clip(round((malicious + suspicious) * 100 / total), 0, 100))
        return VirusTotalResult("VirusTotal", True, threat_score, phishing_probability, domain_risk_score, classification, evidence, {"analysis": analysis_payload, "url": report_payload})
    except Exception as exc:
        return VirusTotalResult("VirusTotal", False, error=str(exc))


def _url_classification(score: int) -> str:
    if score >= 85:
        return "MALICIOUS"
    if score >= 65:
        return "LIKELY PHISHING"
    if score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


def _nested_get(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first_probability(payload: dict[str, Any], paths: list[str]) -> int:
    for path in paths:
        value = _nested_get(payload, path)
        if value is not None:
            return _percent(value)
    return 0


def _resemble_detection_probability(payload: dict[str, Any]) -> int:
    metrics = _nested_get(payload, "item.metrics")
    if not isinstance(metrics, dict):
        return 0
    score = metrics.get("aggregated_score")
    if score is None:
        scores = metrics.get("score")
        if isinstance(scores, list) and scores:
            try:
                score = max(float(item) for item in scores)
            except (TypeError, ValueError):
                score = None
    probability = _percent(score)
    label = str(metrics.get("label") or "").lower()
    if label in {"real", "authentic", "bonafide", "bona-fide", "human"}:
        return int(np.clip(100 - probability, 0, 100))
    return probability
