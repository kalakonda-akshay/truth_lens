export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");
export const API_PROXY_URL = "/api";

export function backendCandidates(path: string) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return [
    ...(API_URL ? [`${API_URL}${normalizedPath}`] : []),
    `${API_PROXY_URL}${normalizedPath}`,
  ];
}

export type AnalysisReport = {
  id: string;
  filename: string;
  media_type: string;
  uploaded_at: string;
  scores: {
    authenticity_score: number;
    deepfake_probability: number;
    risk_level: "Low" | "Medium" | "High" | string;
    confidence_score: number;
    threat_score: number;
  };
  metadata: {
    file_size_mb: number;
    creation_date: string;
    codec: string;
    duration_seconds: number | null;
    tampering_indicators: string[];
    camera_information: string;
    editing_software: string;
    exif_data: Record<string, string>;
  };
  face_analysis: Record<string, string | number>;
  lip_sync_analysis: Record<string, string | number>;
  audio_clone_detection: Record<string, string | number>;
  image_forensics: Record<string, string | number | boolean>;
  url_analysis: Record<string, string | number | boolean | string[]>;
  email_analysis: Record<string, string | number | boolean | string[]>;
  suspicious_frames: Array<{
    timestamp_seconds: number;
    frame_url: string;
    reason: string;
    score: number;
  }>;
  evidence: Array<{
    label: string;
    detail: string;
    severity: string;
  }>;
  verdict: string;
  ai_classification: "AI Generated" | "Likely AI Generated" | "Manipulated" | "Authentic" | "Unable To Determine" | string;
  analysis_summary: string;
  key_findings: string[];
  conclusion: string;
  reasons_for_decision: string[];
  recommendations: string[];
  awareness_message: string;
};

export function normalizeReport(report: AnalysisReport): AnalysisReport {
  return {
    ...report,
    scores: {
      ...report.scores,
      threat_score: report.scores.threat_score ?? report.scores.deepfake_probability ?? 0,
    },
    metadata: {
      ...report.metadata,
      camera_information: report.metadata.camera_information ?? "Not available",
      editing_software: report.metadata.editing_software ?? "Not detected",
      exif_data: report.metadata.exif_data ?? {},
    },
    image_forensics: report.image_forensics ?? {},
    url_analysis: report.url_analysis ?? {},
    email_analysis: report.email_analysis ?? {},
    verdict: report.verdict ?? (report.scores.deepfake_probability >= 70 ? "Likely Synthetic" : "Needs Verification"),
    ai_classification: report.ai_classification ?? classifyAiProbability(report.scores.deepfake_probability),
    analysis_summary: report.analysis_summary ?? "Automated TruthLens forensic analysis completed.",
    key_findings: report.key_findings ?? report.evidence.map((item) => item.detail),
    conclusion: report.conclusion ?? "Results are probabilistic and should be reviewed before high-impact decisions.",
    reasons_for_decision: report.reasons_for_decision ?? report.evidence.map((item) => item.label),
    recommendations: report.recommendations ?? [
      "Verify the media source before sharing.",
      "Request the original file when making high-impact decisions.",
    ],
  };
}

export function classifyAiProbability(probability: number) {
  if (probability > 75) return "AI Generated";
  if (probability >= 50) return "Likely AI Generated";
  if (probability >= 25) return "Manipulated";
  if (probability >= 0) return "Authentic";
  return "Unable To Determine";
}

export async function fetchTextAnalysis(kind: "url" | "email", content: string): Promise<AnalysisReport> {
  for (const endpoint of backendCandidates(`/analyze/${kind}`)) {
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      });
      if (response.ok) {
        return normalizeReport(await response.json());
      }
    } catch {
      // Try the next endpoint. Production prefers Railway directly and falls back to the Vercel proxy.
    }
  }
  throw new Error("Unable to analyze text input");
}

export async function fetchReport(id: string): Promise<AnalysisReport> {
  for (const endpoint of backendCandidates(`/reports/${id}`)) {
    try {
      const response = await fetch(endpoint, { cache: "no-store" });
      if (response.ok) {
        return normalizeReport(await response.json());
      }
    } catch {
      // Try the next endpoint.
    }
  }
  throw new Error("Unable to load report");
}
