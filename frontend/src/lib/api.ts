export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");

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
  reasons_for_decision: string[];
  recommendations: string[];
  awareness_message: string;
};

export function normalizeReport(report: AnalysisReport): AnalysisReport {
  return {
    ...report,
    metadata: {
      ...report.metadata,
      camera_information: report.metadata.camera_information ?? "Not available",
      editing_software: report.metadata.editing_software ?? "Not detected",
      exif_data: report.metadata.exif_data ?? {},
    },
    image_forensics: report.image_forensics ?? {},
    verdict: report.verdict ?? (report.scores.deepfake_probability >= 70 ? "Likely Synthetic" : "Needs Verification"),
    reasons_for_decision: report.reasons_for_decision ?? report.evidence.map((item) => item.label),
    recommendations: report.recommendations ?? [
      "Verify the media source before sharing.",
      "Request the original file when making high-impact decisions.",
    ],
  };
}

export async function fetchReport(id: string): Promise<AnalysisReport> {
  if (!API_URL) {
    throw new Error("No external API configured");
  }
  const response = await fetch(`${API_URL}/reports/${id}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Unable to load report");
  }
  return normalizeReport(await response.json());
}
