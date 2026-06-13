"use client";

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { CloudUpload, FileAudio, FileImage, FileVideo, ShieldCheck } from "lucide-react";
import { API_URL, normalizeReport } from "@/lib/api";
import { generatePrototypeReport } from "@/lib/prototypeReport";
import { recordScan } from "@/lib/scanStats";

function detectMediaType(file: File) {
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (file.type.startsWith("image/") || ["jpg", "jpeg", "png", "webp"].includes(extension ?? "")) return "Image";
  if (file.type.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg", "flac", "aac"].includes(extension ?? "")) return "Audio";
  if (file.type.startsWith("video/") || ["mp4", "mov", "webm", "mkv", "avi"].includes(extension ?? "")) return "Video";
  return "";
}

export function UploadPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const detectedType = file ? detectMediaType(file) : "";

  const selectFile = useCallback((nextFile?: File) => {
    if (!nextFile) return;
    if (!detectMediaType(nextFile)) {
      setFile(null);
      setProgress(0);
      setError("Unsupported file. Upload JPG, JPEG, PNG, WEBP, common video, or common audio formats.");
      return;
    }
    setError("");
    setFile(nextFile);
    setProgress(12);
  }, []);

  async function upload() {
    if (!file) {
      setError("Choose an image, video, or audio file first.");
      return;
    }

    const form = new FormData();
    form.append("file", file);
    setProgress(32);
    setError("");
    setIsAnalyzing(true);
    let timer: number | undefined;

    try {
      timer = window.setInterval(() => {
        setProgress((value) => Math.min(value + 9, 88));
      }, 420);

      let report;
      if (API_URL) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 120000);
        const response = await fetch(`${API_URL}/analyze`, {
          method: "POST",
          body: form,
          signal: controller.signal,
        });
        window.clearTimeout(timeout);
        if (!response.ok) throw new Error("Analysis failed");
        report = normalizeReport(await response.json());
      } else {
        report = await generatePrototypeReport(file);
      }

      window.clearInterval(timer);
      sessionStorage.setItem(`truthlens:report:${report.id}`, JSON.stringify(report));
      recordScan(report.media_type, report.scores.risk_level);
      setProgress(100);
      router.push(`/results/${report.id}`);
    } catch {
      setError(API_URL ? "Analysis service timed out or is unavailable. Check the FastAPI backend URL." : "Local prototype analysis failed for this file. Try a JPG, PNG, shorter MP4, MP3, or WAV sample.");
      setProgress(0);
    } finally {
      if (timer) window.clearInterval(timer);
      setIsAnalyzing(false);
    }
  }

  return (
    <section id="upload" className="mx-auto mt-16 max-w-5xl px-6">
      <div className="glass rounded-[2rem] p-6 shadow-glow md:p-8">
        <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyber-cyan">Upload dashboard</p>
            <h2 className="mt-3 text-3xl font-black text-white md:text-4xl">Verify suspicious media</h2>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-cyber-green/30 bg-cyber-green/10 px-4 py-2 text-sm text-cyber-green">
            <ShieldCheck className="h-4 w-4" />
            Explainable AI report
          </div>
        </div>

        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            selectFile(event.dataTransfer.files[0]);
          }}
          className={`flex w-full flex-col items-center justify-center rounded-3xl border border-dashed p-10 text-center transition ${
            dragging ? "border-cyber-cyan bg-cyber-cyan/10" : "border-slate-600 bg-slate-950/50 hover:border-cyber-cyan/70"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept="image/jpeg,image/png,image/webp,video/*,audio/*"
            className="hidden"
            onChange={(event) => selectFile(event.target.files?.[0])}
          />
          <CloudUpload className="h-14 w-14 text-cyber-cyan" />
          <p className="mt-4 text-xl font-bold text-white">Drag and drop image, video, or audio evidence</p>
          <p className="mt-2 max-w-xl text-sm text-slate-400">JPG, PNG, WEBP, MP4, MOV, WEBM, MP3, WAV, M4A and other common formats are supported.</p>
        </button>

        {file && (
          <div className="mt-6 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
            <div className="flex items-center gap-3">
              {detectedType === "Image" ? (
                <FileImage className="h-5 w-5 text-cyber-cyan" />
              ) : detectedType === "Audio" ? (
                <FileAudio className="h-5 w-5 text-cyber-cyan" />
              ) : (
                <FileVideo className="h-5 w-5 text-cyber-cyan" />
              )}
              <div>
                <p className="font-semibold text-white">{file.name}</p>
                <p className="text-sm text-slate-400">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB · Detected Media Type: {detectedType}
                </p>
              </div>
            </div>
            <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-800">
              <div className="h-full rounded-full bg-gradient-to-r from-cyber-cyan to-cyber-green transition-all" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {error && <p className="mt-4 text-sm text-cyber-red">{error}</p>}

        <button
          type="button"
          onClick={upload}
          disabled={isAnalyzing}
          className="mt-6 w-full rounded-2xl bg-cyber-cyan px-6 py-4 text-base font-black text-slate-950 transition hover:-translate-y-0.5 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isAnalyzing ? "Analyzing evidence..." : "Run TruthLens Analysis"}
        </button>
      </div>
    </section>
  );
}
