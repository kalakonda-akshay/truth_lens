import {
  AlertTriangle,
  CheckCircle2,
  Gauge,
  LockKeyhole,
} from "lucide-react";
import { UploadPanel } from "@/components/UploadPanel";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";

const statuses = [
  ["Sightengine API", "Operational"],
  ["Reality Defender", "Operational"],
  ["Local URL Engine", "Operational"],
  ["Local Email Engine", "Operational"],
];

const statCards = [
  { label: "Total Analyses", value: "128", delta: "+18 this week", color: "text-blue-600", spark: "M2 26 C12 8 20 36 30 18 S48 20 58 8" },
  { label: "Threats Detected", value: "37", delta: "+6 this week", color: "text-red-600", spark: "M2 30 C10 10 18 34 26 18 S42 6 58 16" },
  { label: "Cases Closed", value: "91", delta: "+14 this week", color: "text-emerald-600", spark: "M2 28 C14 18 22 30 32 18 S48 20 58 4" },
  { label: "Accuracy", value: "94.7%", delta: "Overall Detection Accuracy", color: "text-violet-600", spark: "M2 30 C12 16 20 24 30 10 S44 30 58 18" },
];

const recentAnalyses = [
  ["CASE-2026-0145", "Image", "chatgpt_image.png", "AI GENERATED", "HIGH", "May 31, 2026 11:45 AM"],
  ["CASE-2026-0144", "Audio", "ai_modi_song.mp3", "SYNTHETIC AUDIO", "HIGH", "May 31, 2026 11:20 AM"],
  ["CASE-2026-0143", "Video", "ai_video_sample.mp4", "AI GENERATED", "HIGH", "May 31, 2026 10:58 AM"],
  ["CASE-2026-0142", "URL", "http://freerewards.win", "MALICIOUS", "CRITICAL", "May 31, 2026 10:32 AM"],
  ["CASE-2026-0141", "Email", "scam_offer.eml", "LIKELY PHISHING", "HIGH", "May 31, 2026 10:05 AM"],
];

const alerts = [
  ["Malicious URL Detected", "http://freerewards.win", "10:32 AM"],
  ["Phishing Email Detected", "scam_offer.eml", "10:05 AM"],
  ["AI Generated Content", "ai_video_sample.mp4", "10:58 AM"],
];

function StatusPanel() {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-base font-black text-slate-950">System Status</h2>
      <div className="mt-5 space-y-5">
        {statuses.map(([name, status]) => (
          <div key={name} className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <LockKeyhole className="h-4 w-4 text-slate-500" />
              <span className="text-sm font-semibold text-slate-700">{name}</span>
            </div>
            <span className="flex items-center gap-2 text-xs font-black text-emerald-600">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              {status}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function StatCard({ card }: { card: (typeof statCards)[number] }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-semibold text-slate-600">{card.label}</p>
      <div className="mt-2 flex items-end justify-between">
        <div>
          <p className="text-3xl font-black text-slate-950">{card.value}</p>
          <p className={`mt-1 text-xs font-black ${card.color}`}>{card.delta}</p>
        </div>
        <svg viewBox="0 0 60 40" className={`h-11 w-20 ${card.color}`} fill="none">
          <path d={card.spark} stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
        </svg>
      </div>
    </div>
  );
}

function resultTone(result: string) {
  if (result.includes("MALICIOUS") || result.includes("AI GENERATED")) return "border-red-200 bg-red-50 text-red-700";
  if (result.includes("SYNTHETIC")) return "border-violet-200 bg-violet-50 text-violet-700";
  return "border-orange-200 bg-orange-50 text-orange-700";
}

function riskTone(risk: string) {
  if (risk === "CRITICAL") return "border-red-300 bg-red-600 text-white";
  if (risk === "HIGH") return "border-red-200 bg-red-50 text-red-700";
  return "border-orange-200 bg-orange-50 text-orange-700";
}

function RecentAnalyses() {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
        <h2 className="text-base font-black text-slate-950">Recent Analyses</h2>
        <Link href="/reports" className="text-xs font-black text-blue-600">View All</Link>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[820px] text-left text-sm">
          <thead className="bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              {["Case ID", "Type", "File / Input", "Result", "Risk Level", "Date"].map((header) => (
                <th key={header} className="px-5 py-3 font-black">{header}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {recentAnalyses.map(([caseId, type, file, result, risk, date]) => (
              <tr key={caseId} className="hover:bg-slate-50">
                <td className="px-5 py-4 font-semibold text-slate-700">{caseId}</td>
                <td className="px-5 py-4 text-slate-600">{type}</td>
                <td className="px-5 py-4 font-medium text-slate-800">{file}</td>
                <td className="px-5 py-4">
                  <span className={`rounded border px-2 py-1 text-[11px] font-black ${resultTone(result)}`}>{result}</span>
                </td>
                <td className="px-5 py-4">
                  <span className={`rounded border px-2 py-1 text-[11px] font-black ${riskTone(risk)}`}>{risk}</span>
                </td>
                <td className="px-5 py-4 text-xs text-slate-500">{date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function RightRail() {
  return (
    <aside className="space-y-5">
      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-black text-slate-950">Recent Alerts</h2>
          <Link href="/alerts" className="text-xs font-black text-blue-600">View All</Link>
        </div>
        <div className="mt-4 divide-y divide-slate-100">
          {alerts.map(([title, body, time]) => (
            <div key={title} className="flex gap-3 py-4 first:pt-0 last:pb-0">
              <AlertTriangle className="mt-0.5 h-4 w-4 text-red-600" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-black text-slate-900">{title}</p>
                <p className="mt-1 truncate text-xs text-slate-500">{body}</p>
              </div>
              <span className="text-[11px] font-semibold text-slate-500">{time}</span>
            </div>
          ))}
        </div>
      </section>
      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-base font-black text-slate-950">Threat Overview</h2>
        <div className="mt-5 grid grid-cols-[120px_1fr] items-center gap-4">
          <div className="grid h-28 w-28 place-items-center rounded-full" style={{ background: "conic-gradient(#ef4444 0 49%, #f59e0b 49% 78%, #22c55e 78% 100%)" }}>
            <div className="grid h-16 w-16 place-items-center rounded-full bg-white text-center">
              <p className="text-lg font-black text-slate-950">37</p>
              <p className="text-[10px] font-bold text-slate-500">Total Threats</p>
            </div>
          </div>
          <div className="space-y-3 text-xs font-semibold text-slate-600">
            <p><span className="mr-2 inline-block h-2 w-2 rounded-full bg-red-500" />High Risk 18 (48.6%)</p>
            <p><span className="mr-2 inline-block h-2 w-2 rounded-full bg-amber-500" />Medium Risk 11 (29.7%)</p>
            <p><span className="mr-2 inline-block h-2 w-2 rounded-full bg-emerald-500" />Low Risk 8 (21.6%)</p>
          </div>
        </div>
      </section>
    </aside>
  );
}

export default function Home() {
  return (
    <AppShell title="Investigation Dashboard" subtitle="Analyze suspicious content using external intelligence, forensic evidence, and threat scoring.">
          <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
            <UploadPanel />
            <StatusPanel />
          </div>

          <section className="mt-5 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            {statCards.map((card) => <StatCard key={card.label} card={card} />)}
          </section>

          <div className="mt-5 grid gap-5 xl:grid-cols-[1fr_320px]">
            <RecentAnalyses />
            <RightRail />
          </div>

          <section className="mt-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-black text-slate-950">Investigation Readiness</h2>
              <Gauge className="h-5 w-5 text-blue-600" />
            </div>
            <div className="grid gap-4 md:grid-cols-4">
              {[
                ["Audio Analysis", "Voice clone checks and spectrogram evidence"],
                ["Video Analysis", "Frame extraction, suspicious timeline, AI frame scoring"],
                ["URL Analysis", "Local phishing intelligence and indicator evidence"],
                ["Email Analysis", "Phishing highlights and embedded URL checks"],
              ].map(([title, body]) => (
                <div key={title} className="rounded-xl bg-[#07122B] p-5 text-white">
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  <p className="mt-3 text-sm font-black">{title}</p>
                  <p className="mt-2 text-xs leading-5 text-slate-300">{body}</p>
                </div>
              ))}
            </div>
          </section>
    </AppShell>
  );
}
