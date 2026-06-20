"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Download, Eye, Filter, Search } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { AnalysisReport } from "@/lib/api";
import { authRequest, BASE_PATH } from "@/lib/auth";

type View = "cases" | "evidence" | "reports" | "alerts" | "timeline";

const copy = {
  cases: ["My Cases", "User-linked investigations created by completed TruthLens analyses."],
  evidence: ["Evidence Library", "Search submitted files, suspicious frames and explainable forensic findings."],
  reports: ["Forensic Reports", "Review and download professional TruthLens investigation reports."],
  alerts: ["Security Alerts", "High-priority findings generated from your completed analyses."],
  timeline: ["Investigation Timeline", "Chronological audit trail of uploaded evidence and generated verdicts."],
} as const;

function riskClass(risk: string) {
  const value = risk.toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "bg-red-50 text-red-700 border-red-200";
  if (value.includes("medium")) return "bg-amber-50 text-amber-700 border-amber-200";
  return "bg-emerald-50 text-emerald-700 border-emerald-200";
}

export function InvestigationWorkspace({ view }: { view: View }) {
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [query, setQuery] = useState("");
  const [media, setMedia] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    authRequest("/user/reports", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load user investigations.");
        setReports(await response.json());
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load investigations."))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => reports.filter((report) => {
    const text = `${report.id} ${report.filename} ${report.media_type} ${report.verdict} ${report.threat_classification}`.toLowerCase();
    const matchesQuery = text.includes(query.toLowerCase());
    const matchesMedia = media === "all" || report.media_type === media;
    const matchesView = view !== "alerts" || ["high", "critical"].some((risk) => report.scores.risk_level.toLowerCase().includes(risk));
    return matchesQuery && matchesMedia && matchesView;
  }), [media, query, reports, view]);

  return (
    <AppShell title={copy[view][0]} subtitle={copy[view][1]}>
      <section className="rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-col gap-3 border-b border-slate-100 p-5 md:flex-row">
          <div className="relative flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search case ID, file, verdict..." className="w-full rounded-xl border border-slate-200 py-3 pl-10 pr-4 text-sm outline-none focus:border-blue-500" /></div>
          <div className="flex items-center gap-2"><Filter className="h-4 w-4 text-slate-500" /><select value={media} onChange={(e) => setMedia(e.target.value)} className="rounded-xl border border-slate-200 px-4 py-3 text-sm font-bold"><option value="all">All evidence</option>{["image", "video", "audio", "url", "email"].map((type) => <option key={type} value={type}>{type.toUpperCase()}</option>)}</select></div>
        </div>
        {loading ? <p className="p-8 text-sm text-slate-500">Loading secure case records...</p> : error ? <p className="p-8 text-sm font-semibold text-red-600">{error}</p> : filtered.length === 0 ? (
          <div className="p-10 text-center"><p className="font-black text-slate-900">No matching records</p><p className="mt-2 text-sm text-slate-500">Run an analysis to create a user-linked investigation.</p><Link href="/analyze/image" className="mt-5 inline-block rounded-xl bg-blue-600 px-5 py-3 text-sm font-black text-white">Start Investigation</Link></div>
        ) : view === "timeline" ? (
          <div className="divide-y divide-slate-100 p-5">
            {filtered.map((report) => <div key={report.id} className="relative ml-3 border-l-2 border-blue-200 py-5 pl-7 before:absolute before:-left-[7px] before:top-7 before:h-3 before:w-3 before:rounded-full before:bg-blue-600"><p className="text-xs font-black uppercase tracking-wide text-blue-600">{new Date(report.uploaded_at).toLocaleString()}</p><p className="mt-1 font-black">{report.media_type.toUpperCase()} evidence analyzed: {report.filename}</p><p className="mt-1 text-sm text-slate-600">{report.verdict} · {report.model_used}</p></div>)}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr>{["Case ID", "Type", "File / Input", view === "evidence" ? "Evidence" : "Result", "Risk", "Date", "Actions"].map((item) => <th key={item} className="px-5 py-3 font-black">{item}</th>)}</tr></thead>
              <tbody className="divide-y divide-slate-100">{filtered.map((report) => (
                <tr key={report.id} className="hover:bg-slate-50">
                  <td className="px-5 py-4 font-bold">TL-{report.id.slice(0, 8).toUpperCase()}</td><td className="px-5 py-4 uppercase text-slate-600">{report.media_type}</td><td className="max-w-xs truncate px-5 py-4 font-semibold">{report.filename}</td>
                  <td className="px-5 py-4">{view === "evidence" ? `${report.evidence.length} finding(s)` : report.media_type === "url" || report.media_type === "email" ? report.threat_classification : report.ai_classification}</td>
                  <td className="px-5 py-4"><span className={`rounded border px-2 py-1 text-xs font-black ${riskClass(report.scores.risk_level)}`}>{report.scores.risk_level}</span></td>
                  <td className="px-5 py-4 text-xs text-slate-500">{new Date(report.uploaded_at).toLocaleString()}</td>
                  <td className="px-5 py-4"><div className="flex gap-2"><Link href={`/results/${report.id}`} aria-label="View report" className="rounded-lg border border-slate-200 p-2 text-blue-600 hover:bg-blue-50"><Eye className="h-4 w-4" /></Link>{view === "reports" && <a href={`${BASE_PATH}/api/reports/${report.id}/pdf`} aria-label="Download PDF" className="rounded-lg border border-slate-200 p-2 text-emerald-600 hover:bg-emerald-50"><Download className="h-4 w-4" /></a>}</div></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
      {view === "alerts" && <div className="mt-5 rounded-2xl border border-amber-200 bg-amber-50 p-5 text-sm text-amber-900"><AlertTriangle className="mr-2 inline h-5 w-5" />Alerts are generated only from completed analyses with High or Critical risk.</div>}
    </AppShell>
  );
}
