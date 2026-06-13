export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

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
  };
  face_analysis: Record<string, string | number>;
  lip_sync_analysis: Record<string, string | number>;
  audio_clone_detection: Record<string, string | number>;
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
  awareness_message: string;
};

export async function fetchReport(id: string): Promise<AnalysisReport> {
  const response = await fetch(`${API_URL}/reports/${id}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Unable to load report");
  }
  return response.json();
}
