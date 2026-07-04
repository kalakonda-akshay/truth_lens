"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { CheckCircle2, ShieldCheck, XCircle } from "lucide-react";
import { fetchVerification, type VerificationRecord } from "@/lib/api";

export default function VerifyReportPage() {
  const params = useParams<{ id: string }>();
  const [record, setRecord] = useState<VerificationRecord | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchVerification(params.id)
      .then(setRecord)
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to verify report."));
  }, [params.id]);

  return (
    <main className="min-h-screen bg-[#07122B] px-5 py-12 text-white">
      <section className="mx-auto max-w-3xl rounded-3xl border border-white/10 bg-white p-8 text-slate-950 shadow-2xl">
        <div className="flex items-center gap-4">
          <div className="grid h-14 w-14 place-items-center rounded-2xl bg-blue-50 text-blue-700"><ShieldCheck /></div>
          <div>
            <p className="text-3xl font-black">TruthLens Report Verification</p>
            <p className="text-sm text-slate-500">Validate report integrity using stored hash and signature.</p>
          </div>
        </div>

        {error ? (
          <div className="mt-8 rounded-2xl border border-red-200 bg-red-50 p-5 text-red-800">
            <XCircle className="mb-2 h-6 w-6" />
            <p className="font-black">Verification failed</p>
            <p className="mt-1 text-sm font-semibold">{error}</p>
          </div>
        ) : !record ? (
          <p className="mt-8 rounded-2xl bg-slate-50 p-5 text-sm font-bold text-slate-600">Checking report signature...</p>
        ) : (
          <div className="mt-8 space-y-5">
            <div className={`rounded-2xl border p-5 ${record.valid ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-red-200 bg-red-50 text-red-900"}`}>
              {record.valid ? <CheckCircle2 className="mb-2 h-7 w-7" /> : <XCircle className="mb-2 h-7 w-7" />}
              <p className="text-xl font-black">{record.valid ? "Report Verified" : "Report Integrity Mismatch"}</p>
              <p className="mt-1 text-sm font-semibold">Status: {record.status.toUpperCase()}</p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {[
                ["Report ID", record.report_id],
                ["Media Type", record.media_type],
                ["File/Input", record.filename],
                ["Risk Level", record.risk_level],
                ["Threat Classification", record.threat_classification],
                ["Authenticity Verdict", record.authenticity_verdict],
              ].map(([label, value]) => (
                <div key={label} className="rounded-2xl bg-slate-50 p-4">
                  <p className="text-xs font-black uppercase tracking-widest text-slate-500">{label}</p>
                  <p className="mt-2 break-all font-bold">{value}</p>
                </div>
              ))}
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs font-black uppercase tracking-widest text-slate-500">SHA-256 Report Hash</p>
              <p className="mt-2 break-all font-mono text-sm">{record.report_hash}</p>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs font-black uppercase tracking-widest text-slate-500">TruthLens Signature</p>
              <p className="mt-2 break-all font-mono text-sm">{record.signature}</p>
            </div>
          </div>
        )}

        <div className="mt-8 flex flex-wrap gap-3">
          <Link href="/dashboard" className="rounded-xl bg-blue-600 px-5 py-3 text-sm font-black text-white hover:bg-blue-700">Open Dashboard</Link>
          <Link href={`/results/${params.id}`} className="rounded-xl border border-slate-200 px-5 py-3 text-sm font-black text-slate-700 hover:bg-slate-50">View Report</Link>
        </div>
      </section>
    </main>
  );
}
