from __future__ import annotations

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


def reality_defender_audio(path: Path) -> ProviderResult:
    settings = get_settings()
    if not _settings_ready(settings.reality_defender_api_key):
        return ProviderResult("Reality Defender", False, error="Reality Defender API key is not configured.")
    headers = {"X-API-KEY": settings.reality_defender_api_key}
    try:
        presign = requests.post(
            "https://api.prd.realitydefender.xyz/api/files/aws-presigned",
            headers={**headers, "Content-Type": "application/json"},
            json={"fileName": path.name},
            timeout=30,
        )
        presign.raise_for_status()
        presign_payload = presign.json()
        upload_url = _find_first(
            presign_payload,
            [
                "signedUrl",
                "presignedUrl",
                "uploadUrl",
                "url",
                "response.signedUrl",
                "response.presignedUrl",
                "response.uploadUrl",
                "data.signedUrl",
                "data.presignedUrl",
                "data.uploadUrl",
            ],
        )
        request_id = _find_first(presign_payload, ["requestId", "request_id", "id", "data.requestId", "data.request_id", "media.requestId"])
        if not upload_url or not request_id:
            return ProviderResult("Reality Defender", False, raw=presign_payload, error=f"Reality Defender presign response missing upload URL or request id: {presign_payload}")
        with path.open("rb") as handle:
            upload = requests.put(str(upload_url), data=handle, timeout=90)
        upload.raise_for_status()
        detail_payload: dict[str, Any] = {}
        for _ in range(18):
            detail = requests.get(
                f"https://api.prd.realitydefender.xyz/api/media/users/{request_id}",
                headers=headers,
                timeout=30,
            )
            detail.raise_for_status()
            detail_payload = detail.json()
            status = str(_nested_get(detail_payload, "resultsSummary.status") or "").upper()
            if status in {"AUTHENTIC", "FAKE", "SUSPICIOUS", "NOT_APPLICABLE", "UNABLE_TO_EVALUATE"}:
                break
            time.sleep(5)
        summary = _nested_get(detail_payload, "resultsSummary") or {}
        status = str(summary.get("status") or "").upper()
        if status in {"NOT_APPLICABLE", "UNABLE_TO_EVALUATE", ""}:
            reasons = summary.get("metadata", {}).get("reasons") if isinstance(summary, dict) else None
            error = summary.get("error") if isinstance(summary, dict) else None
            return ProviderResult("Reality Defender", False, raw=detail_payload, error=f"Reality Defender could not evaluate audio. Status: {status or 'UNKNOWN'}. Reasons: {reasons or error or 'No details returned.'}")
        final_score = _percent(_nested_get(detail_payload, "resultsSummary.metadata.finalScore"))
        probability = final_score if status in {"FAKE", "SUSPICIOUS"} else int(np.clip(100 - final_score, 0, 100))
        evidence = [
            f"Reality Defender status: {status}.",
            f"Reality Defender ensemble final score: {final_score}%.",
        ]
        languages = _nested_get(detail_payload, "resultsSummary.metadata.languages")
        if languages:
            evidence.append(f"Detected language(s): {languages}.")
        return ProviderResult("Reality Defender", True, probability, status, evidence, detail_payload)
    except requests.HTTPError as exc:
        response = exc.response
        detail = str(exc)
        if response is not None:
            body = response.text.strip()
            if body:
                detail = f"{detail}: {body[:500]}"
        return ProviderResult("Reality Defender", False, error=detail)
    except Exception as exc:
        return ProviderResult("Reality Defender", False, error=str(exc))


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


def _find_first(payload: dict[str, Any], paths: list[str]) -> Any:
    for path in paths:
        value = _nested_get(payload, path)
        if value:
            return value
    return None
