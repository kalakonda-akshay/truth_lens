from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np
from PIL import Image

from app.config import get_settings


IMAGE_MODEL_NAME = "dima806/ai_vs_real_image_detection"
AUDIO_MODEL_NAME = "garystafford/wav2vec2-deepfake-voice-detector"


@dataclass(frozen=True)
class PretrainedPrediction:
    available: bool
    probability: int
    model_name: str
    label: str
    error: str | None = None


def _cache_dir() -> Path:
    path = get_settings().storage_dir / "models"
    path.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("HF_HOME", str(path))
    os.environ.setdefault("HF_HUB_CACHE", str(path))
    os.environ.setdefault("HF_HUB_ETAG_TIMEOUT", "5")
    os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "30")
    return path


@lru_cache(maxsize=1)
def _image_pipeline():
    _cache_dir()
    from transformers import pipeline

    return pipeline("image-classification", model=IMAGE_MODEL_NAME, device=-1)


@lru_cache(maxsize=1)
def _audio_components():
    _cache_dir()
    import torch
    from transformers import AutoFeatureExtractor, AutoModelForAudioClassification

    extractor = AutoFeatureExtractor.from_pretrained(AUDIO_MODEL_NAME)
    model = AutoModelForAudioClassification.from_pretrained(AUDIO_MODEL_NAME)
    model.eval()
    return extractor, model, torch


def _fake_probability(outputs: list[dict]) -> tuple[int, str]:
    if not outputs:
        return 0, "unknown"
    fake_terms = ("fake", "ai", "artificial", "synthetic", "generated")
    fake_scores = [float(item["score"]) for item in outputs if any(term in str(item["label"]).lower() for term in fake_terms)]
    if fake_scores:
        top_fake = max(fake_scores)
        top_label = max(outputs, key=lambda item: float(item["score"]))["label"]
        return int(np.clip(round(top_fake * 100), 0, 100)), str(top_label)
    top = max(outputs, key=lambda item: float(item["score"]))
    label = str(top["label"])
    if "real" in label.lower() or "human" in label.lower():
        return int(np.clip(round((1 - float(top["score"])) * 100), 0, 100)), label
    return int(np.clip(round(float(top["score"]) * 100), 0, 100)), label


def infer_pretrained_images(images: list[Image.Image]) -> PretrainedPrediction:
    if not images:
        return PretrainedPrediction(False, 0, IMAGE_MODEL_NAME, "no frames", "No images supplied.")
    try:
        detector = _image_pipeline()
        raw = detector([image.convert("RGB") for image in images])
        batches = raw if raw and isinstance(raw[0], list) else [raw]
        probabilities = []
        labels = []
        for batch in batches:
            probability, label = _fake_probability(batch)
            probabilities.append(probability)
            labels.append(label)
        aggregate = int(np.clip(round(max(probabilities) * 0.65 + np.mean(probabilities) * 0.35), 0, 100))
        return PretrainedPrediction(True, aggregate, IMAGE_MODEL_NAME, labels[int(np.argmax(probabilities))])
    except Exception as exc:
        return PretrainedPrediction(False, 0, IMAGE_MODEL_NAME, "model unavailable", str(exc))


def infer_pretrained_audio(y: np.ndarray, sr: int) -> PretrainedPrediction:
    try:
        extractor, model, torch = _audio_components()
        samples = y.astype(np.float32)
        inputs = extractor(samples, sampling_rate=sr, return_tensors="pt", padding=True)
        with torch.no_grad():
            probabilities = torch.nn.functional.softmax(model(**inputs).logits, dim=-1)[0].cpu().numpy()
        labels = model.config.id2label
        outputs = [{"label": labels.get(index, str(index)), "score": float(score)} for index, score in enumerate(probabilities)]
        probability, label = _fake_probability(outputs)
        return PretrainedPrediction(True, probability, AUDIO_MODEL_NAME, label)
    except Exception as exc:
        return PretrainedPrediction(False, 0, AUDIO_MODEL_NAME, "model unavailable", str(exc))
