"use client";

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { CloudUpload, FileAudio, FileImage, FileText, FileVideo, Link as LinkIcon, ShieldCheck } from "lucide-react";
import { API_PROXY_URL, fetchTextAnalysis, normalizeReport } from "@/lib/api";
import { recordScan } from "@/lib/scanStats";

const analysisModes = [
  { key: "image", label: "Images", Icon: FileImage },
  { key: "video", label: "Videos", Icon: FileVideo },
  { key: "audio", label: "Audio", Icon: FileAudio },
  { key: "url", label: "URLs", Icon: LinkIcon },
  { key: "email", label: "Emails", Icon: FileText },
] as const;

function detectMediaType(file: File) {
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (file.type.startsWith("image/") || ["jpg", "jpeg", "png", "webp"].includes(extension ?? "")) return "Image";
  if (file.type.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg", "flac", "aac"].includes(extension ?? "")) return "Audio";
  if (file.type.startsWith("video/") || ["mp4", "mov", "webm", "mkv", "avi"].includes(extension ?? "")) return "Video";
  return "";
}

export function UploadPanel() {
  const [mode, setMode] = useState<"image" | "video" | "audio" | "url" | "email">("image");
  const [file, setFile] = useState<File | null>(null);
  const [textInput, setTextInput] = useState("");
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const detectedType = file ? detectMediaType(file) : "";
  const accepts = {
    image: "image/jpeg,image/png,image/webp",
    video: "video/mp4,video/quicktime,video/x-msvideo,video/*",
    audio: "audio/mpeg,audio/wav,audio/mp4,audio/*",
    url: "",
    email: ".eml,text/plain",
  };

  const selectFile = useCallback((nextFile?: File) => {
    if (!nextFile) return;
    if (mode === "email") {
      nextFile.text().then((text) => {
        setTextInput(text);
        setError("");
        setProgress(12);
      }).catch(() => setError("Unable to read this EML/text file."));
      return;
    }
    const nextType = detectMediaType(nextFile);
    if (!nextType) {
      setFile(null);
      setProgress(0);
      setError("Unsupported file. Upload JPG, JPEG, PNG, WEBP, common video, or common audio formats.");
      return;
    }
    if ((mode === "image" && nextType !== "Image") || (mode === "video" && nextType !== "Video") || (mode === "audio" && nextType !== "Audio")) {
      setError(`This dashboard tab expects ${mode} evidence. Switch tabs or choose a matching file.`);
      return;
    }
    setError("");
    setFile(nextFile);
    setProgress(12);
  }, [mode]);

  async function runTextAnalysis() {
    if (!textInput.trim()) {
      setError(mode === "url" ? "Paste a URL to analyze." : "Paste email text or upload an EML file.");
      return;
    }
    setError("");
    setProgress(35);
    setIsAnalyzing(true);
    try {
      const textMode = mode === "url" ? "url" : "email";
      const report = await fetchTextAnalysis(textMode, textInput);
      sessionStorage.setItem(`truthlens:report:${report.id}`, JSON.stringify(report));
      recordScan(report.media_type, report.scores.risk_level);
      setProgress(100);
      router.push(`/results/${report.id}`);
    } catch {
      setError("Text analysis failed. Check the input and try again.");
      setProgress(0);
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function upload() {
    if (mode === "url" || mode === "email") {
      await runTextAnalysis();
      return;
    }
    if (!file) {
      setError(`Choose a ${mode} file first.`);
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

      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 120000);
      const response = await fetch(`${API_PROXY_URL}/analyze`, {
        method: "POST",
        body: form,
        signal: controller.signal,
      });
      window.clearTimeout(timeout);
      if (!response.ok) throw new Error("Analysis failed");
      const report = normalizeReport(await response.json());

      window.clearInterval(timer);
      sessionStorage.setItem(`truthlens:report:${report.id}`, JSON.stringify(report));
      recordScan(report.media_type, report.scores.risk_level);
      setProgress(100);
      router.push(`/results/${report.id}`);
    } catch {
      setError("Analysis service timed out or is unavailable. Check the FastAPI backend URL.");
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
            <h2 className="mt-3 text-3xl font-black text-white md:text-4xl">Unified cyber verification</h2>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-cyber-green/30 bg-cyber-green/10 px-4 py-2 text-sm text-cyber-green">
            <ShieldCheck className="h-4 w-4" />
            Explainable AI report
          </div>
        </div>

        <div className="mb-6 grid gap-2 sm:grid-cols-5">
          {analysisModes.map(({ key, label, Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                setMode(key);
                setFile(null);
                setError("");
                setProgress(0);
              }}
              className={`rounded-2xl border px-4 py-3 text-sm font-black transition ${
                mode === key ? "border-cyber-cyan bg-cyber-cyan text-slate-950" : "border-slate-700 bg-slate-950/50 text-slate-300 hover:border-cyber-cyan"
              }`}
            >
              <Icon className="mx-auto mb-2 h-5 w-5" />
              {label}
            </button>
          ))}
        </div>

        {mode === "url" || mode === "email" ? (
          <div className="rounded-3xl border border-slate-700 bg-slate-950/50 p-5">
            <label className="text-sm font-black uppercase tracking-[0.25em] text-cyber-cyan">
              {mode === "url" ? "URL analysis" : "Email scam analysis"}
            </label>
            <textarea
              value={textInput}
              onChange={(event) => setTextInput(event.target.value)}
              rows={mode === "url" ? 3 : 9}
              placeholder={mode === "url" ? "https://secure-bank-login.example.com/verify" : "Paste email headers/body or suspicious message text here..."}
              className="mt-4 w-full rounded-2xl border border-slate-700 bg-slate-950 p-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyber-cyan"
            />
            {mode === "email" && (
              <div className="mt-4">
                <input
                  ref={inputRef}
                  type="file"
                  accept=".eml,text/plain"
                  className="hidden"
                  onChange={(event) => selectFile(event.target.files?.[0])}
                />
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="rounded-xl border border-cyber-cyan/40 px-4 py-2 text-sm font-bold text-cyber-cyan hover:bg-cyber-cyan hover:text-slate-950"
                >
                  Upload EML/Text File
                </button>
              </div>
            )}
            <p className="mt-3 text-sm text-slate-400">
              {mode === "url" ? "Checks phishing indicators, typosquatting, suspicious domains, and redirect syntax." : "Checks phishing language, impersonation, credential theft, scam pressure, and risky links."}
            </p>
          </div>
        ) : (
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
              accept={accepts[mode]}
              className="hidden"
              onChange={(event) => selectFile(event.target.files?.[0])}
            />
            <CloudUpload className="h-14 w-14 text-cyber-cyan" />
            <p className="mt-4 text-xl font-bold text-white">Drag and drop {mode} evidence</p>
            <p className="mt-2 max-w-xl text-sm text-slate-400">Images: JPG/PNG/WEBP · Video: MP4/MOV/AVI · Audio: MP3/WAV/M4A</p>
          </button>
        )}

        {file && mode !== "url" && mode !== "email" && (
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
