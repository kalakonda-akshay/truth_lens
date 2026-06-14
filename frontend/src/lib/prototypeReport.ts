import type { AnalysisReport } from "@/lib/api";

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

function riskLevel(score: number) {
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

function scoreOutsideRange(value: number, low: number, high: number) {
  if (value >= low && value <= high) return 0;
  return clamp((Math.min(Math.abs(value - low), Math.abs(value - high)) * 100) / Math.max(1, high - low), 0, 100);
}

function detectMediaType(file: File) {
  if (file.type.startsWith("image/") || /\.(jpg|jpeg|png|webp)$/i.test(file.name)) return "image";
  if (file.type.startsWith("video/") || /\.(mp4|mov|webm|mkv|avi)$/i.test(file.name)) return "video";
  return "audio";
}

function codecLabel(file: File) {
  const extension = file.name.split(".").pop()?.toUpperCase() || "UNKNOWN";
  return file.type ? `${extension} container (${file.type})` : `${extension} media container`;
}

function baseReport(file: File, mediaType: string, probability: number, findings: string[], evidence: AnalysisReport["evidence"], frames: AnalysisReport["suspicious_frames"], extras: Partial<AnalysisReport>): AnalysisReport {
  const risk = riskLevel(probability);
  const keyFindings = findings.length ? findings : ["No high-risk forensic indicators were detected by the available browser analysis modules."];
  return {
    id: crypto.randomUUID(),
    filename: file.name,
    media_type: mediaType,
    uploaded_at: new Date().toISOString(),
    scores: {
      authenticity_score: 100 - probability,
      deepfake_probability: mediaType === "url" || mediaType === "email" ? 0 : probability,
      risk_level: risk,
      confidence_score: clamp(58 + evidence.length * 8 + frames.length * 5, 50, 94),
      threat_score: probability,
    },
    metadata: {
      file_size_mb: Number((file.size / (1024 * 1024)).toFixed(3)),
      creation_date: new Date(file.lastModified || Date.now()).toISOString(),
      codec: codecLabel(file),
      duration_seconds: null,
      tampering_indicators: mediaType === "image"
        ? ["Browser uploads do not expose full EXIF metadata; use the FastAPI backend for camera/software EXIF extraction."]
        : ["No metadata risk indicators detected in browser-safe mode."],
      camera_information: mediaType === "image" ? "Not exposed by browser" : "Not applicable",
      editing_software: "Not exposed by browser",
      exif_data: {},
    },
    face_analysis: {},
    lip_sync_analysis: {},
    audio_clone_detection: {},
    image_forensics: {},
    url_analysis: {},
    email_analysis: {},
    suspicious_frames: frames,
    evidence,
    verdict: probability >= 65 ? "High-Risk Evidence Detected" : probability >= 35 ? "Review Recommended" : "No Strong Threat Indicators Detected",
    analysis_summary: `${mediaType.toUpperCase()} analysis completed using measured browser-accessible forensic indicators only.`,
    key_findings: keyFindings,
    conclusion: probability >= 35 ? "Risk indicators were detected; human verification is recommended before trust or sharing." : "No high-risk indicators were detected; normal source verification is still recommended.",
    reasons_for_decision: keyFindings,
    recommendations: [
      "Do not forward the content until its source is independently verified.",
      "Use backend EXIF/OpenCV/Librosa analysis for final forensic review where possible.",
      "Escalate high-risk findings to a qualified digital forensics or security analyst.",
    ],
    awareness_message: "Do not forward unverified media",
    ...extras,
  };
}

async function analyzeImage(file: File): Promise<AnalysisReport> {
  const bitmap = await createImageBitmap(file);
  const originalWidth = bitmap.width;
  const originalHeight = bitmap.height;
  const scale = Math.min(1, 960 / Math.max(bitmap.width, bitmap.height));
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Canvas unavailable");
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();

  const data = context.getImageData(0, 0, width, height);
  const gray = new Float32Array(width * height);
  for (let i = 0, pixel = 0; i < data.data.length; i += 4, pixel += 1) {
    gray[pixel] = data.data[i] * 0.299 + data.data[i + 1] * 0.587 + data.data[i + 2] * 0.114;
  }

  let edgeTotal = 0;
  let brightnessTotal = 0;
  let contrastTotal = 0;
  let samples = 0;
  const anomaly = new Float32Array(width * height);
  const step = Math.max(1, Math.floor(Math.min(width, height) / 240));
  for (let y = step; y < height - step; y += step) {
    for (let x = step; x < width - step; x += step) {
      const index = y * width + x;
      const gx = Math.abs(gray[index + step] - gray[index - step]);
      const gy = Math.abs(gray[index + step * width] - gray[index - step * width]);
      const edge = gx + gy;
      edgeTotal += edge;
      brightnessTotal += gray[index];
      anomaly[index] = edge;
      samples += 1;
    }
  }
  const meanEdge = edgeTotal / Math.max(1, samples);
  const meanBrightness = brightnessTotal / Math.max(1, samples);
  for (let i = 0; i < gray.length; i += Math.max(1, step * 5)) {
    contrastTotal += Math.abs(gray[i] - meanBrightness);
  }
  const contrast = contrastTotal / Math.max(1, Math.floor(gray.length / Math.max(1, step * 5)));
  const textureScore = scoreOutsideRange(meanEdge, 18, 92);
  const lightingScore = scoreOutsideRange(meanBrightness, 35, 220);
  const edgeScore = scoreOutsideRange(meanEdge / 255, 0.035, 0.26);
  const contrastScore = scoreOutsideRange(contrast, 12, 72);
  const metadataScore = 18;
  const visualScores = [textureScore, lightingScore, edgeScore, contrastScore];
  const visualScore = clamp(visualScores.reduce((sum, value) => sum + value, 0) / visualScores.length, 0, 100);
  const probability = clamp(visualScore * 0.78 + metadataScore, 0, 100);

  const metrics = {
    summary: "Browser image analysis measured brightness, contrast, local edge energy, and texture consistency from uploaded pixels.",
    texture_inconsistency: textureScore,
    lighting_inconsistency: lightingScore,
    edge_anomaly: edgeScore,
    contrast_anomaly: contrastScore,
    heatmap_generated: false,
    image_width: originalWidth,
    image_height: originalHeight,
  };
  const evidence: AnalysisReport["evidence"] = [];
  const findings: string[] = [];
  [
    ["Texture inconsistency detected", textureScore, 45],
    ["Lighting mismatch detected", lightingScore, 45],
    ["Edge anomaly detected", edgeScore, 45],
    ["Contrast anomaly detected", contrastScore, 45],
  ].forEach(([label, score, threshold]) => {
    if (Number(score) >= Number(threshold)) {
      evidence.push({ label: String(label), detail: `${label} with measured browser score ${score}%.`, severity: riskLevel(Number(score)) });
      findings.push(String(label));
    }
  });

  const frames: AnalysisReport["suspicious_frames"] = [];
  if (evidence.length && visualScore >= 35) {
    const overlay = document.createElement("canvas");
    overlay.width = width;
    overlay.height = height;
    const overlayContext = overlay.getContext("2d");
    if (overlayContext) {
      overlayContext.drawImage(canvas, 0, 0);
      const imageData = overlayContext.getImageData(0, 0, width, height);
      const threshold = meanEdge * 1.85;
      let minX = width;
      let minY = height;
      let maxX = 0;
      let maxY = 0;
      let count = 0;
      for (let i = 0; i < anomaly.length; i += 1) {
        if (anomaly[i] > threshold) {
          const x = i % width;
          const y = Math.floor(i / width);
          minX = Math.min(minX, x);
          minY = Math.min(minY, y);
          maxX = Math.max(maxX, x);
          maxY = Math.max(maxY, y);
          const p = i * 4;
          imageData.data[p] = 255;
          imageData.data[p + 1] = Math.max(imageData.data[p + 1], 120);
          imageData.data[p + 2] = 0;
          count += 1;
        }
      }
      if (count > width * height * 0.002) {
        overlayContext.putImageData(imageData, 0, 0);
        overlayContext.strokeStyle = "#22d3ee";
        overlayContext.lineWidth = 4;
        overlayContext.strokeRect(minX, minY, Math.max(8, maxX - minX), Math.max(8, maxY - minY));
        metrics.heatmap_generated = true;
        frames.push({
          timestamp_seconds: 0,
          frame_url: overlay.toDataURL("image/jpeg", 0.82),
          reason: "Heatmap generated from measured local edge-energy outliers.",
          score: visualScore,
        });
      }
    }
  }
  return baseReport(file, "image", probability, findings, evidence, frames, {
    image_forensics: metrics,
    face_analysis: { frames_analyzed: 1, suspicious_frames: frames.length, summary: "Still-image browser analysis completed." },
  });
}

async function captureVideoFrames(file: File): Promise<{ frames: AnalysisReport["suspicious_frames"]; score: number; findings: string[]; evidence: AnalysisReport["evidence"] }> {
  const video = document.createElement("video");
  const canvas = document.createElement("canvas");
  const url = URL.createObjectURL(file);
  const frames: AnalysisReport["suspicious_frames"] = [];
  const findings: string[] = [];
  const evidence: AnalysisReport["evidence"] = [];
  return new Promise((resolve) => {
    let current = 0;
    let maxScore = 0;
    const finish = () => {
      URL.revokeObjectURL(url);
      resolve({ frames, score: maxScore, findings, evidence });
    };
    video.preload = "metadata";
    video.muted = true;
    video.onerror = finish;
    video.onloadedmetadata = () => {
      const duration = Number.isFinite(video.duration) && video.duration > 0 ? video.duration : 1;
      const targets = [0.2, 0.45, 0.7].map((ratio) => duration * ratio);
      video.onseeked = () => {
        const width = Math.min(video.videoWidth || 640, 800);
        const height = Math.min(video.videoHeight || 360, 450);
        canvas.width = width;
        canvas.height = height;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        if (context) {
          context.drawImage(video, 0, 0, width, height);
          const pixels = context.getImageData(0, 0, width, height).data;
          let brightness = 0;
          let edge = 0;
          let samples = 0;
          for (let y = 2; y < height - 2; y += 6) {
            for (let x = 2; x < width - 2; x += 6) {
              const i = (y * width + x) * 4;
              const j = (y * width + x + 2) * 4;
              const currentBrightness = (pixels[i] + pixels[i + 1] + pixels[i + 2]) / 3;
              brightness += currentBrightness;
              edge += Math.abs(currentBrightness - (pixels[j] + pixels[j + 1] + pixels[j + 2]) / 3);
              samples += 1;
            }
          }
          const score = clamp(scoreOutsideRange(brightness / Math.max(1, samples), 35, 220) * 0.35 + scoreOutsideRange(edge / Math.max(1, samples), 5, 55) * 0.65, 0, 100);
          maxScore = Math.max(maxScore, score);
          if (score >= 45) {
            context.strokeStyle = "#22d3ee";
            context.lineWidth = 5;
            context.strokeRect(20, 20, width - 40, height - 40);
            frames.push({ timestamp_seconds: Number(video.currentTime.toFixed(2)), frame_url: canvas.toDataURL("image/jpeg", 0.82), reason: "Frame retained because measured brightness/edge anomaly exceeded threshold.", score });
          }
        }
        current += 1;
        if (current >= targets.length) {
          if (maxScore >= 45) {
            findings.push("Video frame anomaly detected");
            evidence.push({ label: "Video Frame Anomaly", detail: `Highest measured frame anomaly score: ${maxScore}%.`, severity: riskLevel(maxScore) });
          }
          finish();
        } else {
          video.currentTime = targets[current];
        }
      };
      video.currentTime = targets[current];
    };
    video.src = url;
  });
}

async function analyzeAudio(file: File): Promise<{ frames: AnalysisReport["suspicious_frames"]; score: number; findings: string[]; evidence: AnalysisReport["evidence"]; metrics: Record<string, number | string> }> {
  try {
    const buffer = await file.arrayBuffer();
    const audioContext = new AudioContext();
    const decoded = await audioContext.decodeAudioData(buffer.slice(0));
    const data = decoded.getChannelData(0);
    let zeroCrossings = 0;
    let energy = 0;
    for (let i = 1; i < data.length; i += 1) {
      if ((data[i - 1] < 0 && data[i] >= 0) || (data[i - 1] >= 0 && data[i] < 0)) zeroCrossings += 1;
      energy += data[i] * data[i];
    }
    const zcr = zeroCrossings / Math.max(1, data.length);
    const rms = Math.sqrt(energy / Math.max(1, data.length));
    const score = clamp(scoreOutsideRange(zcr, 0.015, 0.18) * 0.55 + scoreOutsideRange(rms, 0.01, 0.28) * 0.45, 0, 100);
    const canvas = document.createElement("canvas");
    canvas.width = 960;
    canvas.height = 420;
    const context = canvas.getContext("2d");
    const frames: AnalysisReport["suspicious_frames"] = [];
    if (context) {
      context.fillStyle = "#020617";
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.strokeStyle = "#22d3ee";
      context.lineWidth = 2;
      const step = Math.max(1, Math.floor(data.length / canvas.width));
      for (let x = 0; x < canvas.width; x += 1) {
        let min = 1;
        let max = -1;
        for (let i = 0; i < step && x * step + i < data.length; i += 1) {
          const value = data[x * step + i];
          min = Math.min(min, value);
          max = Math.max(max, value);
        }
        context.beginPath();
        context.moveTo(x, (1 + min) * 0.5 * canvas.height);
        context.lineTo(x, (1 + max) * 0.5 * canvas.height);
        context.stroke();
      }
      frames.push({ timestamp_seconds: 0, frame_url: canvas.toDataURL("image/jpeg", 0.82), reason: "Waveform generated from decoded audio samples.", score });
    }
    await audioContext.close();
    const findings = score >= 45 ? ["Audio signal anomaly detected"] : [];
    const evidence = score >= 45 ? [{ label: "Audio Signal Anomaly", detail: `Measured zero-crossing/RMS anomaly score: ${score}%.`, severity: riskLevel(score) }] : [];
    return { frames, score, findings, evidence, metrics: { zero_crossing_rate: Number(zcr.toFixed(4)), rms_energy: Number(rms.toFixed(4)), summary: "Browser decoded audio and measured zero-crossing rate and RMS energy." } };
  } catch {
    return { frames: [], score: 0, findings: ["Audio could not be decoded in browser"], evidence: [], metrics: { summary: "Browser could not decode this audio format." } };
  }
}

export async function generatePrototypeReport(file: File): Promise<AnalysisReport> {
  const type = detectMediaType(file);
  if (type === "image") return analyzeImage(file);
  if (type === "video") {
    const result = await captureVideoFrames(file);
    return baseReport(file, "video", result.score, result.findings, result.evidence, result.frames, {
      face_analysis: { frames_analyzed: 3, suspicious_frames: result.frames.length, summary: "Browser sampled video frames and retained only threshold-exceeding frames." },
      lip_sync_analysis: { forensic_score: 0, summary: "No lip-sync mismatch is claimed without a speech-to-mouth model." },
    });
  }
  const audio = await analyzeAudio(file);
  return baseReport(file, "audio", audio.score, audio.findings, audio.evidence, audio.frames, {
    audio_clone_detection: { synthetic_voice_confidence: audio.score, ...audio.metrics },
  });
}

function baseTextReport(input: string, kind: "url" | "email", score: number, indicators: string[], verdict: string): AnalysisReport {
  const evidence = indicators.filter((indicator) => !indicator.startsWith("No ")).map((indicator) => ({ label: kind === "url" ? "URL Indicator" : "Email Indicator", detail: indicator, severity: riskLevel(score) }));
  return {
    id: crypto.randomUUID(),
    filename: kind === "url" ? input : "Pasted email / EML content",
    media_type: kind,
    uploaded_at: new Date().toISOString(),
    scores: { authenticity_score: 100 - score, deepfake_probability: 0, risk_level: riskLevel(score), confidence_score: 86, threat_score: score },
    metadata: { file_size_mb: kind === "email" ? Number((new Blob([input]).size / (1024 * 1024)).toFixed(4)) : 0, creation_date: new Date().toISOString(), codec: kind === "url" ? "URL indicator" : "Email text / EML", duration_seconds: null, tampering_indicators: indicators, camera_information: "Not applicable", editing_software: "Not applicable", exif_data: {} },
    face_analysis: {},
    lip_sync_analysis: {},
    audio_clone_detection: {},
    image_forensics: {},
    url_analysis: kind === "url" ? { indicators } : {},
    email_analysis: kind === "email" ? { indicators, highlight_terms: ["password", "urgent", "verify", "suspended", "invoice", "gift card"] } : {},
    suspicious_frames: [],
    evidence,
    verdict,
    analysis_summary: `${kind.toUpperCase()} analysis completed using matched threat indicators.`,
    key_findings: evidence.length ? evidence.map((item) => item.detail) : ["No high-risk text indicators were detected."],
    conclusion: score >= 35 ? "Threat indicators were detected; verify through an independent channel." : "No high-risk indicators were detected.",
    reasons_for_decision: indicators,
    recommendations: kind === "url" ? ["Use official domains typed manually.", "Do not enter credentials on suspicious URLs.", "Report suspicious links."] : ["Do not click suspicious links or attachments.", "Verify the sender through a trusted channel.", "Report suspected phishing."],
    awareness_message: "Do not forward unverified media",
  };
}

export function analyzeUrlInput(rawUrl: string): AnalysisReport {
  const url = rawUrl.trim();
  const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return baseTextReport(url, "url", 90, ["Malformed URL structure detected."], "Likely Phishing");
  }
  const domain = parsed.hostname.toLowerCase();
  const indicators: string[] = [];
  let score = 0;
  if (parsed.protocol !== "https:") { indicators.push("URL does not use HTTPS."); score += 18; }
  if (url.includes("@")) { indicators.push("URL contains @ redirection syntax."); score += 25; }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) { indicators.push("Domain uses a raw IP address."); score += 25; }
  if (domain.split(".").filter(Boolean).length > 3) { indicators.push("Excessive subdomain depth detected."); score += 12; }
  if (/(login|verify|secure|account|update|wallet|reset)/i.test(url)) { indicators.push("Credential or account-verification keyword detected."); score += 18; }
  if (/(paypa1|g00gle|micros0ft|amaz0n|appleid|secure-bank)/i.test(domain)) { indicators.push("Potential typosquatting or brand impersonation detected."); score += 28; }
  if (domain.includes("-")) { indicators.push("Hyphenated domain structure detected."); score += 8; }
  if (!indicators.length) indicators.push("No phishing URL indicators detected.");
  const finalScore = clamp(score, 0, 100);
  return baseTextReport(url, "url", finalScore, indicators, finalScore >= 65 ? "Likely Phishing" : finalScore >= 35 ? "Suspicious URL" : "No URL Threat Detected");
}

export function analyzeEmailInput(rawEmail: string): AnalysisReport {
  const lowered = rawEmail.toLowerCase();
  const indicators: string[] = [];
  let score = 0;
  [
    ["Credential theft language detected.", /(password|verify your account|login immediately|reset your account)/i, 22],
    ["Urgency or threat pressure detected.", /(urgent|suspended|24 hours|immediately|final notice)/i, 22],
    ["Payment or reward lure detected.", /(prize|refund|invoice|wire transfer|gift card|crypto)/i, 22],
    ["Attachment or link risk detected.", /(\.exe|\.scr|bit\.ly|tinyurl|http:\/\/)/i, 22],
    ["Impersonation from consumer email domain detected.", /from:.*(support|security|admin).*@(gmail|outlook|yahoo)\./i, 22],
    ["Generic greeting often used in phishing.", /(dear customer|dear user)/i, 10],
  ].forEach(([label, regex, points]) => {
    if ((regex as RegExp).test(lowered)) {
      indicators.push(String(label));
      score += Number(points);
    }
  });
  if (!indicators.length) indicators.push("No scam or phishing indicators detected.");
  const finalScore = clamp(score, 0, 100);
  return baseTextReport(rawEmail, "email", finalScore, indicators, finalScore >= 65 ? "Likely Email Scam" : finalScore >= 35 ? "Suspicious Email" : "No Email Threat Detected");
}
