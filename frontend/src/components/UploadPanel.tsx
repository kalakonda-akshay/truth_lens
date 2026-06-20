"use client";

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { CloudUpload, FileAudio, FileImage, FileText, FileVideo, Link as LinkIcon, ShieldCheck } from "lucide-react";
import { backendCandidates, fetchTextAnalysis, normalizeReport, storedAuthToken } from "@/lib/api";
import { recordScan } from "@/lib/scanStats";

const analysisModes = [
  { key: "image", label: "Images", detail: "JPG, PNG, WEBP", Icon: FileImage },
  { key: "video", label: "Videos", detail: "MP4, MOV, AVI", Icon: FileVideo },
  { key: "audio", label: "Audio", detail: "MP3, WAV, M4A", Icon: FileAudio },
  { key: "url", label: "URLs", detail: "Paste Link", Icon: LinkIcon },
  { key: "email", label: "Emails", detail: "EML, TXT, Paste", Icon: FileText },
] as const;

function detectMediaType(file: File) {
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (file.type.startsWith("image/") || ["jpg", "jpeg", "png", "webp"].includes(extension ?? "")) return "Image";
  if (file.type.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg", "flac", "aac"].includes(extension ?? "")) return "Audio";
  if (file.type.startsWith("video/") || ["mp4", "mov", "webm", "mkv", "avi"].includes(extension ?? "")) return "Video";
  return "";
}

type AnalysisMode = "image" | "video" | "audio" | "url" | "email";

export function UploadPanel({ initialMode = "image", showModeSelector = true }: { initialMode?: AnalysisMode; showModeSelector?: boolean }) {
  const [mode, setMode] = useState<AnalysisMode>(initialMode);
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
    video: ".mp4,.mov,.avi,.mkv,.webm,video/mp4,video/quicktime,video/x-msvideo,video/webm",
    audio: ".mp3,.wav,.m4a,.aac,.flac,audio/mpeg,audio/wav,audio/mp4,audio/aac,audio/flac",
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
      setError(`This investigation type expects ${mode} evidence. Switch type or choose a matching file.`);
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
      const storageKey = `truthlens:report:${report.id}`;
      const serializedReport = JSON.stringify(report);
      sessionStorage.setItem(storageKey, serializedReport);
      localStorage.setItem(storageKey, serializedReport);
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

      let report = null;
      for (const endpoint of backendCandidates("/analyze")) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 300000);
        try {
          const response = await fetch(endpoint, {
            method: "POST",
            body: form,
            headers: storedAuthToken() ? { Authorization: `Bearer ${storedAuthToken()}` } : {},
            signal: controller.signal,
          });
          if (response.ok) {
            report = normalizeReport(await response.json());
            break;
          }
        } catch {
          // Try the next endpoint. Railway direct avoids Vercel function timeouts for larger media.
        } finally {
          window.clearTimeout(timeout);
        }
      }
      if (!report) throw new Error("Analysis failed");

      window.clearInterval(timer);
      const storageKey = `truthlens:report:${report.id}`;
      const serializedReport = JSON.stringify(report);
      sessionStorage.setItem(storageKey, serializedReport);
      localStorage.setItem(storageKey, serializedReport);
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
    <section id="upload" className="w-full">
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm md:p-6">
        <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="text-base font-black text-slate-950">Start New Investigation</h2>
            <p className="mt-1 text-xs text-slate-500">Upload or submit suspicious content to begin analysis</p>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-semibold text-emerald-700">
            <ShieldCheck className="h-4 w-4" />
            Evidence-backed report
          </div>
        </div>

        {showModeSelector && <div className="mb-5 grid gap-3 sm:grid-cols-5">
          {analysisModes.map(({ key, label, detail, Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                setMode(key);
                setFile(null);
                setError("");
                setProgress(0);
              }}
              className={`rounded-xl border px-4 py-4 text-center transition hover:-translate-y-0.5 ${
                mode === key ? "border-blue-600 bg-blue-50 text-blue-700 shadow-sm" : "border-slate-200 bg-white text-slate-700 hover:border-blue-300 hover:bg-slate-50"
              }`}
            >
              <Icon className="mx-auto mb-2 h-7 w-7" />
              <p className="text-sm font-black">{label}</p>
              <p className="mt-1 text-[11px] font-medium text-slate-500">{detail}</p>
            </button>
          ))}
        </div>}

        {mode === "url" || mode === "email" ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">
            <label className="text-xs font-black uppercase tracking-[0.16em] text-blue-700">
              {mode === "url" ? "URL analysis" : "Email scam analysis"}
            </label>
            <textarea
              value={textInput}
              onChange={(event) => setTextInput(event.target.value)}
              rows={mode === "url" ? 3 : 9}
              placeholder={mode === "url" ? "https://secure-bank-login.example.com/verify" : "Paste email headers/body or suspicious message text here..."}
              className="mt-4 w-full rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
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
                  className="rounded-xl border border-blue-200 bg-white px-4 py-2 text-sm font-bold text-blue-700 hover:bg-blue-600 hover:text-white"
                >
                  Upload EML/Text File
                </button>
              </div>
            )}
            <p className="mt-3 text-sm text-slate-500">
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
            className={`flex w-full flex-col items-center justify-center rounded-xl border border-dashed p-8 text-center transition ${
              dragging ? "border-blue-500 bg-blue-50" : "border-slate-300 bg-slate-50 hover:border-blue-400 hover:bg-blue-50/50"
            }`}
          >
            <input
              ref={inputRef}
              type="file"
              accept={accepts[mode]}
              className="hidden"
              onChange={(event) => selectFile(event.target.files?.[0])}
            />
            <CloudUpload className="h-10 w-10 text-blue-600" />
            <p className="mt-4 text-base font-black text-slate-900">Drag & drop files here or click to upload</p>
            <p className="mt-1 max-w-xl text-sm text-slate-500">Your files are secure and only used for analysis.</p>
          </button>
        )}

        {file && mode !== "url" && mode !== "email" && (
          <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center gap-3">
              {detectedType === "Image" ? (
                <FileImage className="h-5 w-5 text-blue-600" />
              ) : detectedType === "Audio" ? (
                <FileAudio className="h-5 w-5 text-blue-600" />
              ) : (
                <FileVideo className="h-5 w-5 text-blue-600" />
              )}
              <div>
                <p className="font-semibold text-slate-900">{file.name}</p>
                <p className="text-sm text-slate-500">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB · Detected Media Type: {detectedType}
                </p>
              </div>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-200">
              <div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-emerald-500 transition-all" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {error && <p className="mt-4 text-sm font-semibold text-red-600">{error}</p>}

        <button
          type="button"
          onClick={upload}
          disabled={isAnalyzing}
          className="mt-6 w-full rounded-xl bg-blue-600 px-6 py-4 text-base font-black text-white transition hover:-translate-y-0.5 hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isAnalyzing ? "Analyzing evidence..." : "Run TruthLens Analysis"}
        </button>
      </div>
    </section>
  );
}
