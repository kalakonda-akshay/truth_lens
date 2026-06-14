import unittest

import cv2
import numpy as np

from app.services.content_models import (
    infer_audio_ai_probability,
    infer_image_ai_probability,
    infer_video_ai_probability,
)


class ContentModelTests(unittest.TestCase):
    def test_image_scores_separate_camera_like_and_synthetic_patterns(self):
        rng = np.random.default_rng(4)
        camera_like = np.zeros((256, 256, 3), dtype=np.uint8)
        camera_like[:] = np.linspace(45, 205, 256, dtype=np.uint8)[None, :, None]
        camera_like = np.clip(camera_like.astype(np.int16) + rng.normal(0, 9, camera_like.shape), 0, 255).astype(np.uint8)

        synthetic = cv2.GaussianBlur(np.full((256, 256, 3), 160, dtype=np.uint8), (9, 9), 0)
        for x in range(0, 256, 8):
            synthetic[:, x : x + 1] = 245

        real_score = infer_image_ai_probability(camera_like, has_camera_exif=True).probability
        synthetic_score = infer_image_ai_probability(synthetic, has_camera_exif=False).probability

        self.assertLess(real_score, 25)
        self.assertGreater(synthetic_score, 75)
        self.assertGreater(synthetic_score - real_score, 50)

    def test_audio_scores_separate_dynamic_and_uniform_voice_patterns(self):
        sr = 16000
        t = np.linspace(0, 1.5, int(sr * 1.5), endpoint=False)
        rng = np.random.default_rng(3)
        real_like = (
            0.18 * np.sin(2 * np.pi * (140 + 35 * np.sin(2 * np.pi * 2.3 * t)) * t)
            + 0.06 * np.sin(2 * np.pi * 310 * t)
            + 0.03 * rng.normal(size=t.shape)
        ).astype(np.float32)
        real_like *= (0.5 + 0.5 * np.sin(2 * np.pi * 1.1 * t) ** 2).astype(np.float32)
        clone_like = (
            0.22 * np.sin(2 * np.pi * 190 * t)
            + 0.08 * np.sin(2 * np.pi * 380 * t)
            + 0.03 * np.sin(2 * np.pi * 570 * t)
        ).astype(np.float32)

        real_score = infer_audio_ai_probability(real_like, sr).probability
        clone_score = infer_audio_ai_probability(clone_like, sr).probability

        self.assertLess(real_score, 25)
        self.assertGreater(clone_score, 75)
        self.assertGreater(clone_score - real_score, 50)

    def test_video_scores_separate_clean_and_artifact_clusters(self):
        real = infer_video_ai_probability(
            [4, 7, 8, 6, 5, 9],
            temporal_score=5,
            frame_feature_peaks={
                "face_region_anomaly": 4,
                "edge_anomaly": 8,
                "texture_anomaly": 7,
                "compression_artifacts": 10,
                "noise_pattern_anomaly": 6,
            },
        ).probability
        synthetic = infer_video_ai_probability(
            [72, 78, 84, 76, 81, 70],
            temporal_score=68,
            frame_feature_peaks={
                "face_region_anomaly": 65,
                "edge_anomaly": 72,
                "texture_anomaly": 70,
                "compression_artifacts": 82,
                "noise_pattern_anomaly": 66,
            },
        ).probability

        self.assertLess(real, 25)
        self.assertGreater(synthetic, 75)
        self.assertGreater(synthetic - real, 50)


if __name__ == "__main__":
    unittest.main()
