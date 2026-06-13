import Link from "next/link";
import { AlertTriangle, ArrowLeft, Download, Eye, ShieldAlert } from "lucide-react";
import { API_URL, fetchReport } from "@/lib/api";
import { MetricCard } from "@/components/MetricCard";

function riskTone(risk: string): "green" | "amber" | "red" {
  if (risk === "High") return "red";
  if (risk === "Medium") return "amber";
  return "green";
}

const riskClasses = {
  green: "text-cyber-green",
  amber: "text-cyber-amber",
  red: "text-cyber-red",
};

export default async function ResultsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const report = await fetchReport(id);
  const tone = riskTone(report.scores.risk_level);

  return (
    <main className="cyber-grid min-h-screen px-6 py-8">
      <div className="mx-auto max-w-7xl">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <Link href="/" className="inline-flex items-center gap-2 text-sm font-bold text-cyber-cyan">
            <ArrowLeft className="h-4 w-4" />
            New analysis
          </Link>
          <a href={`${API_URL}/reports/${report.id}/pdf`} className="inline-flex items-center justify-center gap-2 rounded-2xl bg-cyber-cyan px-5 py-3 font-black text-slate-950">
            <Download className="h-4 w-4" />
            Download PDF report
          </a>
        </div>

        <section className="mt-8 grid gap-6 lg:grid-cols-[1fr_0.8fr]">
          <div className="glass rounded-[2rem] p-7">
            <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyber-cyan">TruthLens report</p>
            <h1 className="mt-4 break-words text-4xl font-black text-white md:text-5xl">{report.filename}</h1>
            <p className="mt-4 text-slate-300">
              This explainable prototype report combines metadata, OpenCV visual signals, lip-sync scoring, and Librosa audio features.
            </p>
            <div className="mt-6 rounded-2xl border border-cyber-amber/30 bg-cyber-amber/10 p-4 text-cyber-amber">
              <div className="flex items-center gap-3 font-black">
                <AlertTriangle className="h-5 w-5" />
                {report.awareness_message}
              </div>
            </div>
          </div>

          <div className="glass rounded-[2rem] p-7">
            <div className="flex items-center gap-3">
              <ShieldAlert className={`h-9 w-9 ${riskClasses[tone]}`} />
              <div>
                <p className="text-sm uppercase tracking-[0.25em] text-slate-400">Risk level</p>
                <p className={`text-4xl font-black ${riskClasses[tone]}`}>{report.scores.risk_level}</p>
              </div>
            </div>
            <p className="mt-5 text-sm leading-6 text-slate-300">
              Use this result as a triage signal. High-impact public safety, financial, or reputation decisions should involve expert review.
            </p>
          </div>
        </section>

        <section className="mt-6 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
          <MetricCard label="Authenticity" value={`${report.scores.authenticity_score}%`} tone="green" />
          <MetricCard label="Deepfake probability" value={`${report.scores.deepfake_probability}%`} tone={tone} />
          <MetricCard label="Confidence" value={`${report.scores.confidence_score}%`} tone="cyan" />
          <MetricCard label="Media type" value={report.media_type.toUpperCase()} tone="cyan" />
        </section>

        <section className="mt-6 grid gap-6 lg:grid-cols-2">
          <div className="glass rounded-[2rem] p-7">
            <h2 className="text-2xl font-black text-white">Metadata report</h2>
            <div className="mt-5 grid gap-3 text-sm text-slate-300">
              <p><span className="text-slate-500">File size:</span> {report.metadata.file_size_mb} MB</p>
              <p><span className="text-slate-500">Creation date:</span> {new Date(report.metadata.creation_date).toLocaleString()}</p>
              <p><span className="text-slate-500">Codec:</span> {report.metadata.codec}</p>
              <p><span className="text-slate-500">Duration:</span> {report.metadata.duration_seconds ?? "N/A"} seconds</p>
            </div>
            <div className="mt-5 space-y-3">
              {report.metadata.tampering_indicators.map((indicator) => (
                <div key={indicator} className="rounded-2xl border border-slate-700 bg-slate-950/50 p-3 text-sm text-slate-300">
                  {indicator}
                </div>
              ))}
            </div>
          </div>

          <div className="glass rounded-[2rem] p-7">
            <h2 className="text-2xl font-black text-white">Highlighted evidence</h2>
            <div className="mt-5 space-y-4">
              {report.evidence.map((item) => (
                <div key={`${item.label}-${item.detail}`} className="rounded-2xl border border-slate-700 bg-slate-950/60 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <h3 className="font-black text-white">{item.label}</h3>
                    <span className="rounded-full border border-cyber-cyan/30 px-3 py-1 text-xs font-bold text-cyber-cyan">{item.severity}</span>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-400">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mt-6 glass rounded-[2rem] p-7">
          <div className="flex items-center gap-3">
            <Eye className="h-6 w-6 text-cyber-cyan" />
            <h2 className="text-2xl font-black text-white">Suspicious frames</h2>
          </div>
          {report.suspicious_frames.length === 0 ? (
            <p className="mt-5 text-slate-400">No suspicious video frames were extracted for this media file.</p>
          ) : (
            <div className="mt-6 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
              {report.suspicious_frames.map((frame) => (
                <div key={`${frame.timestamp_seconds}-${frame.score}`} className="overflow-hidden rounded-2xl border border-slate-700 bg-slate-950/70">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={`${API_URL}${frame.frame_url}`} alt={frame.reason} className="h-44 w-full object-cover" />
                  <div className="p-4">
                    <p className="font-black text-white">{frame.score}% anomaly</p>
                    <p className="mt-1 text-xs text-slate-400">{frame.timestamp_seconds}s - {frame.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
