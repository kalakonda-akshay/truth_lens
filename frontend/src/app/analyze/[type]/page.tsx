import { notFound } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { UploadPanel } from "@/components/UploadPanel";

const modes = {
  image: ["Image Analysis", "Upload JPG, JPEG, PNG or WEBP evidence for AI-generation and manipulation analysis."],
  video: ["Video Analysis", "Upload MP4, MOV, AVI, MKV or WEBM evidence for frame and temporal forensics."],
  audio: ["Audio Analysis", "Upload MP3, WAV, M4A, AAC or FLAC evidence for synthetic voice detection."],
  url: ["URL Analysis", "Submit a URL for typosquatting, credential harvesting and phishing-risk analysis."],
  email: ["Email Analysis", "Upload EML/TXT evidence or paste message content for phishing and impersonation analysis."],
} as const;

export default async function AnalyzePage({ params }: { params: Promise<{ type: string }> }) {
  const { type } = await params;
  if (!(type in modes)) notFound();
  const mode = type as keyof typeof modes;
  return <AppShell title={modes[mode][0]} subtitle={modes[mode][1]}><UploadPanel initialMode={mode} showModeSelector={false} /></AppShell>;
}
