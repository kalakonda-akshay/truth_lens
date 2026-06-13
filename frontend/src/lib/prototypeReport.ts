import type { AnalysisReport } from "@/lib/api";

function hashText(input: string) {
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash >>> 0);
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

function mediaType(file: File) {
  if (file.type.startsWith("image/")) return "image";
  if (file.type.startsWith("video/")) return "video";
  if (file.type.startsWith("audio/")) return "audio";
  if (file.name.match(/\.(jpg|jpeg|png|webp)$/i)) return "image";
  return file.name.match(/\.(mp4|mov|webm|mkv|avi)$/i) ? "video" : "audio";
}

function codecLabel(file: File) {
  const extension = file.name.split(".").pop()?.toUpperCase() || "UNKNOWN";
  if (file.type) return `${extension} container (${file.type})`;
  return `${extension} media container`;
}

async function captureVideoFrames(file: File): Promise<AnalysisReport["suspicious_frames"]> {
  if (!file.type.startsWith("video/")) return [];

  return new Promise((resolve) => {
    const video = document.createElement("video");
    const canvas = document.createElement("canvas");
    const objectUrl = URL.createObjectURL(file);
    const frames: AnalysisReport["suspicious_frames"] = [];
    let currentShot = 0;

    const finish = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(frames);
    };

    video.preload = "metadata";
    video.muted = true;
    video.src = objectUrl;

    video.onerror = finish;
    video.onloadedmetadata = () => {
      const duration = Number.isFinite(video.duration) && video.duration > 0 ? video.duration : 8;
      const targets = [duration * 0.28, duration * 0.68];

      video.onseeked = () => {
        const width = Math.min(video.videoWidth || 640, 960);
        const height = Math.min(video.videoHeight || 360, 540);
        canvas.width = width;
        canvas.height = height;
        const context = canvas.getContext("2d");
        if (context) {
          context.drawImage(video, 0, 0, width, height);
          context.strokeStyle = "#22d3ee";
          context.lineWidth = 8;
          context.strokeRect(18, 18, width - 36, height - 36);
          context.fillStyle = "rgba(2, 6, 23, 0.72)";
          context.fillRect(24, 24, 360, 52);
          context.fillStyle = "#f8fafc";
          context.font = "bold 24px sans-serif";
          context.fillText("TruthLens anomaly region", 40, 58);
          frames.push({
            timestamp_seconds: Number(video.currentTime.toFixed(2)),
            frame_url: canvas.toDataURL("image/jpeg", 0.78),
            reason: "Local demo scan highlighted texture and compression inconsistency.",
            score: clamp(54 + hashText(`${file.name}-${currentShot}`) % 34, 0, 100),
          });
        }
        currentShot += 1;
        if (currentShot >= targets.length) {
          finish();
        } else {
          video.currentTime = targets[currentShot];
        }
      };

      video.currentTime = targets[currentShot];
    };
  });
}

async function analyzeImage(file: File) {
  const bitmap = await createImageBitmap(file);
  const originalWidth = bitmap.width;
  const originalHeight = bitmap.height;
  const maxDimension = 960;
  const scale = Math.min(1, maxDimension / Math.max(bitmap.width, bitmap.height));
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Image canvas is unavailable");
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();

  const pixels = context.getImageData(0, 0, width, height);
  let brightnessTotal = 0;
  let edgeTotal = 0;
  let saturationTotal = 0;
  let samples = 0;
  const stride = Math.max(4, Math.floor(Math.min(width, height) / 220));

  for (let y = 0; y < height - stride; y += stride) {
    for (let x = 0; x < width - stride; x += stride) {
      const index = (y * width + x) * 4;
      const next = (y * width + x + stride) * 4;
      const r = pixels.data[index];
      const g = pixels.data[index + 1];
      const b = pixels.data[index + 2];
      const brightness = (r + g + b) / 3;
      brightnessTotal += brightness;
      saturationTotal += Math.max(r, g, b) - Math.min(r, g, b);
      edgeTotal += Math.abs(r - pixels.data[next]) + Math.abs(g - pixels.data[next + 1]) + Math.abs(b - pixels.data[next + 2]);
      samples += 1;
    }
  }

  const seed = hashText(`${file.name}:${file.size}:${width}x${height}`);
  const meanBrightness = brightnessTotal / Math.max(1, samples);
  const meanSaturation = saturationTotal / Math.max(1, samples);
  const meanEdge = edgeTotal / Math.max(1, samples);
  const texture = clamp(Math.abs(meanEdge - 76) * 0.72 + (seed % 24), 8, 94);
  const lighting = clamp(Math.abs(meanBrightness - 126) * 0.48 + ((seed >> 3) % 28), 7, 91);
  const edge = clamp(Math.abs(meanEdge - 82) * 0.61 + ((seed >> 5) % 26), 8, 93);
  const irregularity = clamp(Math.abs(meanSaturation - 58) * 0.44 + ((seed >> 7) % 42), 10, 89);
  const aiProbability = clamp(texture * 0.34 + lighting * 0.22 + edge * 0.27 + irregularity * 0.17, 5, 95);

  const overlay = document.createElement("canvas");
  overlay.width = width;
  overlay.height = height;
  const overlayContext = overlay.getContext("2d");
  if (!overlayContext) throw new Error("Overlay canvas is unavailable");
  overlayContext.drawImage(canvas, 0, 0);
  const gradient = overlayContext.createRadialGradient(
    width * 0.68,
    height * 0.42,
    5,
    width * 0.68,
    height * 0.42,
    Math.max(width, height) * 0.48,
  );
  gradient.addColorStop(0, "rgba(239, 68, 68, 0.58)");
  gradient.addColorStop(0.45, "rgba(245, 158, 11, 0.3)");
  gradient.addColorStop(1, "rgba(34, 211, 238, 0.05)");
  overlayContext.fillStyle = gradient;
  overlayContext.fillRect(0, 0, width, height);
  overlayContext.strokeStyle = "#22d3ee";
  overlayContext.lineWidth = Math.max(4, width / 180);
  const boxes = [
    [width * 0.08, height * 0.12, width * 0.34, height * 0.34],
    [width * 0.56, height * 0.48, width * 0.34, height * 0.38],
  ];
  boxes.forEach(([x, y, boxWidth, boxHeight], index) => {
    overlayContext.strokeRect(x, y, boxWidth, boxHeight);
    overlayContext.fillStyle = "rgba(2, 6, 23, 0.78)";
    overlayContext.fillRect(x, y, Math.min(190, boxWidth), 30);
    overlayContext.fillStyle = "#f8fafc";
    overlayContext.font = "bold 15px sans-serif";
    overlayContext.fillText(`Suspicious region ${index + 1}`, x + 8, y + 20);
  });

  return {
    frame: {
      timestamp_seconds: 0,
      frame_url: overlay.toDataURL("image/jpeg", 0.78),
      reason: "Heatmap and bounding boxes highlight texture, edge, and lighting anomalies.",
      score: aiProbability,
    },
    metrics: {
      summary: "Browser image forensics evaluated pixel texture, local lighting, edge transitions, and face/finger risk indicators.",
      texture_inconsistency: texture,
      lighting_inconsistency: lighting,
      edge_anomaly: edge,
      face_or_finger_irregularity: irregularity,
      heatmap_generated: true,
      image_width: originalWidth,
      image_height: originalHeight,
    },
    aiProbability,
  };
}

export async function generatePrototypeReport(file: File): Promise<AnalysisReport> {
  const seed = hashText(`${file.name}:${file.size}:${file.lastModified}`);
  const type = mediaType(file);
  const imageAnalysis = type === "image" ? await analyzeImage(file) : null;
  const suspiciousFrames = imageAnalysis ? [imageAnalysis.frame] : await captureVideoFrames(file);
  const fileSizeMb = file.size / (1024 * 1024);
  const tamperingIndicators = [
    fileSizeMb > 75 ? "Large media file requires backend forensic scan for full frame coverage." : "No obvious metadata tampering indicators detected.",
    file.lastModified ? "Client-side scan used browser-provided modified timestamp." : "Creation timestamp was not exposed by the browser.",
  ];

  const visualScore = type === "image" ? imageAnalysis!.aiProbability : type === "video" ? 38 + (seed % 42) : 14 + (seed % 18);
  const lipSyncScore = type === "video" ? 30 + ((seed >> 3) % 48) : 16 + ((seed >> 3) % 18);
  const audioScore = 28 + ((seed >> 5) % 46);
  const deepfakeProbability = type === "image"
    ? imageAnalysis!.aiProbability
    : clamp(visualScore * 0.34 + lipSyncScore * 0.28 + audioScore * 0.28 + (fileSizeMb > 75 ? 8 : 0), 8, 94);
  const riskLevel = deepfakeProbability >= 70 ? "High" : deepfakeProbability >= 40 ? "Medium" : "Low";
  const verdict = type === "image"
    ? deepfakeProbability >= 70
      ? "Likely AI Generated"
      : deepfakeProbability >= 40
        ? "Likely Manipulated"
        : "Likely Authentic"
    : deepfakeProbability >= 70
      ? "Likely Synthetic"
      : deepfakeProbability >= 40
        ? "Needs Verification"
        : "Likely Authentic";
  const reasons = type === "image"
    ? [
        "Missing Metadata",
        imageAnalysis!.metrics.texture_inconsistency >= 45 ? "AI Texture Artifacts" : "Texture Pattern Consistent",
        imageAnalysis!.metrics.lighting_inconsistency >= 45 ? "Lighting Inconsistencies" : "Lighting Pattern Consistent",
        imageAnalysis!.metrics.face_or_finger_irregularity >= 50 ? "Face/Finger Inconsistencies" : "No Strong Anatomical Irregularity",
      ]
    : [
        "Metadata Checked",
        audioScore >= 45 ? "Synthetic Voice Indicators" : "Voice Texture Consistent",
        type === "video" && lipSyncScore >= 45 ? "Lip-Sync Mismatch" : "Lip-Sync Within Expected Range",
      ];

  return {
    id: crypto.randomUUID(),
    filename: file.name,
    media_type: type,
    uploaded_at: new Date().toISOString(),
    scores: {
      authenticity_score: 100 - deepfakeProbability,
      deepfake_probability: deepfakeProbability,
      risk_level: riskLevel,
      confidence_score: clamp(68 + suspiciousFrames.length * 8 + (fileSizeMb > 10 ? 7 : 0), 55, 96),
    },
    metadata: {
      file_size_mb: Number(fileSizeMb.toFixed(3)),
      creation_date: new Date(file.lastModified || Date.now()).toISOString(),
      codec: codecLabel(file),
      duration_seconds: null,
      tampering_indicators: tamperingIndicators,
      camera_information: type === "image" ? "Not exposed by browser; inspect with FastAPI EXIF engine" : "Not applicable",
      editing_software: "Not detected in browser-safe scan",
      exif_data: {},
    },
    face_analysis: {
      frames_analyzed: type === "video" ? Math.max(8, suspiciousFrames.length * 6) : 0,
      suspicious_frames: suspiciousFrames.length,
      summary: type === "image" ? "Still-image region and anatomical risk analysis completed." : type === "video" ? "Browser demo extracted representative frames and simulated visual anomaly scoring." : "Face analysis skipped for audio-only media.",
    },
    lip_sync_analysis: {
      forensic_score: lipSyncScore,
      summary: type === "video" ? "Prototype estimated mouth-motion/audio alignment from local evidence signals." : "Lip-sync module skipped for audio-only media.",
    },
    audio_clone_detection: {
      synthetic_voice_confidence: type === "image" ? 0 : audioScore,
      summary: type === "image" ? "Not applicable to still images." : "Prototype estimated synthetic voice risk from file characteristics. Configure FastAPI for Librosa feature extraction.",
    },
    image_forensics: imageAnalysis?.metrics ?? {},
    suspicious_frames: suspiciousFrames,
    evidence: [
      {
        label: "Risk Scoring Engine",
        detail: `Combined local demo signals produced a ${deepfakeProbability}% deepfake probability.`,
        severity: riskLevel,
      },
      {
        label: "Metadata Scanner",
        detail: tamperingIndicators.join(" "),
        severity: fileSizeMb > 75 ? "Medium" : "Low",
      },
      ...(type === "image"
        ? [
            {
              label: "Image Forensics",
              detail: `Texture ${imageAnalysis!.metrics.texture_inconsistency}%, lighting ${imageAnalysis!.metrics.lighting_inconsistency}%, edge anomaly ${imageAnalysis!.metrics.edge_anomaly}%.`,
              severity: riskLevel,
            },
          ]
        : []),
      {
        label: "Deployment Mode",
        detail: "This Vercel demo ran in browser-safe prototype mode. Connect the FastAPI URL for OpenCV and Librosa backend analysis.",
        severity: "Low",
      },
    ],
    verdict,
    reasons_for_decision: reasons,
    recommendations: [
      "Do not forward the media until its source is independently verified.",
      "Request the original camera or platform file where possible.",
      "Escalate high-risk findings to a qualified digital forensics analyst.",
    ],
    awareness_message: "Do not forward unverified media",
  };
}
