import type { AnalysisReport } from "@/lib/api";

export type DemoSample = {
  id: string;
  title: string;
  mediaType: "image" | "video" | "audio" | "url" | "email";
  risk: "Low" | "High";
  description: string;
};

export const demoSamples: DemoSample[] = [
  { id: "real-image", title: "Real Image", mediaType: "image", risk: "Low", description: "Camera-style metadata and consistent visual texture." },
  { id: "ai-image", title: "AI Generated Image", mediaType: "image", risk: "High", description: "Synthetic texture, lighting, and anatomical indicators." },
  { id: "real-video", title: "Real Video", mediaType: "video", risk: "Low", description: "Consistent frames, audio texture, and lip synchronization." },
  { id: "deepfake-video", title: "Deepfake Video", mediaType: "video", risk: "High", description: "Facial boundary artifacts and lip-sync mismatch." },
  { id: "real-audio", title: "Real Audio", mediaType: "audio", risk: "Low", description: "Natural acoustic variation and voice texture." },
  { id: "voice-clone", title: "Voice Clone Audio", mediaType: "audio", risk: "High", description: "Over-stable spectral texture and clone indicators." },
  { id: "phishing-url", title: "Phishing URL", mediaType: "url", risk: "High", description: "Typosquatting, credential keywords, and suspicious URL structure." },
  { id: "scam-email", title: "Scam Email", mediaType: "email", risk: "High", description: "Impersonation, urgency pressure, and credential-theft language." },
];

function demoVisual(sample: DemoSample) {
  const high = sample.risk === "High";
  const label = sample.title;
  const detail = high ? "ANOMALY REGIONS HIGHLIGHTED" : "CONSISTENT FORENSIC SIGNALS";
  return `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="960" height="540">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop stop-color="#07111f"/>
          <stop offset="1" stop-color="${high ? "#3b1022" : "#07352d"}"/>
        </linearGradient>
        <radialGradient id="heat">
          <stop stop-color="${high ? "#ef4444" : "#34d399"}" stop-opacity=".85"/>
          <stop offset=".55" stop-color="#f59e0b" stop-opacity=".25"/>
          <stop offset="1" stop-color="#22d3ee" stop-opacity=".02"/>
        </radialGradient>
      </defs>
      <rect width="960" height="540" fill="url(#bg)"/>
      <circle cx="650" cy="240" r="240" fill="url(#heat)"/>
      <path d="M0 440 L240 270 L430 380 L650 170 L960 410 V540 H0Z" fill="#22d3ee" opacity=".12"/>
      <rect x="70" y="90" width="340" height="260" rx="18" fill="none" stroke="#22d3ee" stroke-width="7"/>
      <rect x="560" y="170" width="270" height="220" rx="18" fill="none" stroke="${high ? "#fbbf24" : "#34d399"}" stroke-width="7"/>
      <text x="70" y="55" fill="#f8fafc" font-family="Arial" font-size="30" font-weight="700">${label}</text>
      <text x="70" y="500" fill="#cbd5e1" font-family="Arial" font-size="22">${detail}</text>
    </svg>
  `)}`;
}

export function createDemoReport(sample: DemoSample): AnalysisReport {
  const high = sample.risk === "High";
  const probability = high ? (sample.mediaType === "image" ? 87 : 82) : 13;
  const imageMetrics: AnalysisReport["image_forensics"] = sample.mediaType === "image"
    ? {
        summary: high ? "AI texture and anatomical irregularities detected." : "Texture, edges, and lighting are internally consistent.",
        texture_inconsistency: high ? 88 : 14,
        lighting_inconsistency: high ? 74 : 16,
        edge_anomaly: high ? 81 : 12,
        face_or_finger_irregularity: high ? 79 : 9,
        heatmap_generated: true,
      }
    : {};
  const suspicious = (high || sample.mediaType === "image") && !["url", "email"].includes(sample.mediaType)
    ? [{
        timestamp_seconds: sample.mediaType === "video" ? 4.8 : 0,
        frame_url: demoVisual(sample),
        reason: high ? "Highlighted regions contain synthetic or manipulated forensic patterns." : "Reference visualization shows consistent regions.",
        score: probability,
      }]
    : [];

  const reasons = sample.mediaType === "url"
    ? ["Potential Typosquatting", "Credential Harvesting Keywords", "Suspicious Domain Structure", "Redirect Risk Indicators"]
    : sample.mediaType === "email"
      ? ["Impersonation Detected", "Urgency Pressure", "Credential Theft Language", "Suspicious Link Pattern"]
      : sample.mediaType === "image"
    ? high
      ? ["Missing Metadata", "AI Texture Artifacts", "Lighting Inconsistencies", "Face/Finger Inconsistencies"]
      : ["Camera Metadata Present", "Texture Pattern Consistent", "Lighting Pattern Consistent", "No Face Irregularity"]
    : sample.mediaType === "video"
      ? high
        ? ["Facial Boundary Artifacts", "Lip-Sync Mismatch", "Frame Texture Inconsistency"]
        : ["Metadata Checked", "Lip-Sync Within Expected Range", "Frame Texture Consistent"]
      : high
        ? ["Synthetic Voice Indicators", "Over-Stable Spectral Pattern", "Missing Recorder Metadata"]
        : ["Natural Voice Variation", "Acoustic Texture Consistent", "Recorder Metadata Present"];

  return {
    id: crypto.randomUUID(),
    filename: `${sample.id}.${sample.mediaType === "image" ? "jpg" : sample.mediaType === "video" ? "mp4" : sample.mediaType === "audio" ? "wav" : "txt"}`,
    media_type: sample.mediaType,
    uploaded_at: new Date().toISOString(),
    scores: {
      authenticity_score: 100 - probability,
      deepfake_probability: probability,
      risk_level: sample.risk,
      confidence_score: high ? 94 : 91,
      threat_score: probability,
    },
    metadata: {
      file_size_mb: sample.mediaType === "image" ? 2.48 : sample.mediaType === "video" ? 18.72 : 4.2,
      creation_date: new Date().toISOString(),
      codec: sample.mediaType === "image" ? "JPEG 1920x1080" : sample.mediaType === "video" ? "H.264 / AAC" : "WAV PCM",
      duration_seconds: sample.mediaType === "image" || sample.mediaType === "url" || sample.mediaType === "email" ? null : sample.mediaType === "video" ? 12.4 : 8.8,
      tampering_indicators: high ? ["Metadata chain is incomplete.", "Forensic signature differs across regions."] : ["No obvious metadata tampering indicators detected."],
      camera_information: sample.mediaType === "image" && !high ? "TruthLens Demo Camera X1" : "Not available",
      editing_software: high ? "Possible generative/editing pipeline" : "Not detected",
      exif_data: sample.mediaType === "image" && !high ? { Make: "TruthLens", Model: "Demo Camera X1", ISO: "100" } : {},
    },
    face_analysis: {
      frames_analyzed: sample.mediaType === "video" ? 12 : sample.mediaType === "image" ? 1 : 0,
      suspicious_frames: suspicious.length,
      summary: reasons.join(", "),
    },
    lip_sync_analysis: {
      forensic_score: sample.mediaType === "video" ? (high ? 84 : 12) : 0,
      summary: sample.mediaType === "video" ? (high ? "Mouth motion diverges from phoneme timing." : "Mouth motion aligns with speech.") : "Not applicable.",
    },
    audio_clone_detection: {
      synthetic_voice_confidence: sample.mediaType === "audio" || sample.mediaType === "video" ? probability : 0,
      summary: sample.mediaType === "image" ? "Not applicable." : high ? "Synthetic voice indicators detected." : "Natural voice variation detected.",
    },
    image_forensics: imageMetrics,
    url_analysis: sample.mediaType === "url" ? { indicators: reasons, domain: "secure-bank-login.example" } : {},
    email_analysis: sample.mediaType === "email" ? { indicators: reasons, highlight_terms: ["verify", "password", "urgent"] } : {},
    suspicious_frames: suspicious,
    evidence: reasons.map((reason, index) => ({
      label: reason,
      detail: high ? `TruthLens identified ${reason.toLowerCase()} as a material risk signal.` : `${reason} supports an authentic classification.`,
      severity: high && index < 3 ? "High" : "Low",
    })),
    verdict: sample.mediaType === "image"
      ? high ? "Likely AI Generated" : "Likely Authentic"
      : sample.mediaType === "url" ? "Likely Phishing"
      : sample.mediaType === "email" ? "Likely Email Scam"
      : high ? "Likely Synthetic" : "Likely Authentic",
    analysis_summary: `Judge sample ${sample.title} produced a ${probability}% threat score.`,
    key_findings: reasons,
    conclusion: high ? "TruthLens recommends treating this evidence as unsafe until independently verified." : "TruthLens found low-risk signals in this sample.",
    reasons_for_decision: reasons,
    recommendations: high
      ? ["Do not forward this media.", "Verify against the original source.", "Escalate to a digital forensics specialist."]
      : ["Retain the original file and provenance.", "Continue normal source verification before publication."],
    awareness_message: "Do not forward unverified media",
  };
}
