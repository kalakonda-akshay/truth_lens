"use client";

import Link from "next/link";
import type { ComponentType } from "react";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileImage, FileText, KeyRound, ShieldCheck, Users } from "lucide-react";
import type { LucideProps } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { authRequest, useAuth } from "@/lib/auth";

type AdminUser = {
  id: string;
  email: string;
  name: string;
  provider: string;
  role: string;
  password_reset_required: number | boolean;
  created_at: string;
  total_analyses: number;
  image_analyses: number;
  last_activity: string | null;
};

type AdminAnalysis = {
  id: string;
  filename: string;
  media_type: string;
  uploaded_at: string;
  user_email: string;
  user_name: string;
  risk_level: string;
  authenticity_score: number;
  ai_probability: number;
  threat_score: number;
  analysis_status: string;
  ai_classification: string;
  authenticity_verdict: string;
  evidence_count: number;
};

type Summary = {
  total_users: number;
  total_analyses: number;
  image_uploads: number;
  high_risk_reports: number;
  latest_image_reports: AdminAnalysis[];
};

type StatCard = [string, number, ComponentType<LucideProps>, string];

function formatDate(value?: string | null) {
  if (!value) return "No activity";
  return new Date(value).toLocaleString();
}

function badgeClass(value: string) {
  const lowered = value.toLowerCase();
  if (lowered.includes("critical") || lowered.includes("high") || lowered.includes("generated") || lowered.includes("failed")) return "bg-red-50 text-red-700 ring-red-200";
  if (lowered.includes("medium") || lowered.includes("suspicious") || lowered.includes("review")) return "bg-amber-50 text-amber-700 ring-amber-200";
  return "bg-emerald-50 text-emerald-700 ring-emerald-200";
}

export default function AdminPage() {
  const { user } = useAuth();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [analyses, setAnalyses] = useState<AdminAnalysis[]>([]);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");
  const [resetNotice, setResetNotice] = useState<{ email: string; temporary_password: string; message: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadAdminData() {
      setLoading(true);
      setError("");
      try {
        const [summaryResponse, usersResponse, analysesResponse] = await Promise.all([
          authRequest("/admin/summary"),
          authRequest("/admin/users"),
          authRequest("/admin/analyses"),
        ]);
        const summaryData = await summaryResponse.json();
        const usersData = await usersResponse.json();
        const analysesData = await analysesResponse.json();
        if (!summaryResponse.ok) throw new Error(summaryData.detail ?? "Admin summary failed.");
        if (!usersResponse.ok) throw new Error(usersData.detail ?? "Admin users failed.");
        if (!analysesResponse.ok) throw new Error(analysesData.detail ?? "Admin analyses failed.");
        setSummary(summaryData);
        setUsers(usersData.users ?? []);
        setAnalyses(analysesData.analyses ?? []);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Unable to load admin data.");
      } finally {
        setLoading(false);
      }
    }
    if (user?.role === "founder_admin") void loadAdminData();
  }, [user?.role]);

  const visibleAnalyses = useMemo(() => {
    if (filter === "all") return analyses;
    return analyses.filter((item) => item.media_type === filter);
  }, [analyses, filter]);
  const statCards: StatCard[] = [
    ["Total Users", summary?.total_users ?? 0, Users, "Registered analysts and admins"],
    ["Total Analyses", summary?.total_analyses ?? 0, ShieldCheck, "All stored investigations"],
    ["Image Uploads", summary?.image_uploads ?? 0, FileImage, "Every image submitted"],
    ["High Risk Reports", summary?.high_risk_reports ?? 0, AlertTriangle, "High/Critical findings"],
  ];

  async function resetPassword(target: AdminUser) {
    if (!confirm(`Generate a temporary password for ${target.email}? Their active sessions will be signed out.`)) return;
    setError("");
    setResetNotice(null);
    try {
      const response = await authRequest(`/admin/users/${target.id}/reset-password`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Password reset failed.");
      setResetNotice(data);
      setUsers((current) => current.map((item) => item.id === target.id ? { ...item, password_reset_required: true, provider: "email" } : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Password reset failed.");
    }
  }

  if (user?.role !== "founder_admin") {
    return (
      <AppShell title="Admin Panel" subtitle="Founder administrator monitoring for TruthLens AI.">
        <section className="rounded-2xl border border-amber-200 bg-amber-50 p-6 text-amber-900">
          <AlertTriangle className="mb-3 h-7 w-7" />
          <h2 className="text-xl font-black">Admin access required</h2>
          <p className="mt-2 text-sm font-semibold">Only the configured founder administrator can view users, uploads, images, and reports.</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell title="Admin Panel" subtitle="Monitor users, uploads, image submissions, and TruthLens forensic reports.">
      {error && <div className="mb-5 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm font-bold text-red-700">{error}</div>}
      {resetNotice && (
        <section className="mb-5 rounded-2xl border border-blue-200 bg-blue-50 p-5 text-blue-950">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="font-black">Temporary password generated</h2>
              <p className="mt-1 text-sm font-semibold">{resetNotice.email} must log in with this temporary password, complete OTP, then set a new password.</p>
              <p className="mt-2 text-xs font-bold text-blue-700">Old password was not shown or exposed.</p>
            </div>
            <code className="rounded-xl bg-white px-4 py-3 text-lg font-black tracking-wide text-slate-950">{resetNotice.temporary_password}</code>
          </div>
        </section>
      )}
      {loading ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center font-black text-slate-600">Loading admin intelligence...</div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statCards.map(([label, value, Icon, detail]) => (
              <section key={String(label)} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-black uppercase tracking-widest text-slate-500">{label}</p>
                    <p className="mt-2 text-3xl font-black">{value}</p>
                    <p className="mt-1 text-xs font-semibold text-slate-500">{detail}</p>
                  </div>
                  <div className="grid h-12 w-12 place-items-center rounded-xl bg-blue-50 text-blue-700"><Icon className="h-6 w-6" /></div>
                </div>
              </section>
            ))}
          </div>

          <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
              <div>
                <h2 className="text-xl font-black">All App Users</h2>
                <p className="text-sm text-slate-500">Shows who is using TruthLens and how many reports they generated.</p>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-[900px] w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-widest text-slate-500">
                  <tr><th className="p-3">User</th><th className="p-3">Role</th><th className="p-3">Provider</th><th className="p-3">Password</th><th className="p-3">Total Scans</th><th className="p-3">Image Scans</th><th className="p-3">Joined</th><th className="p-3">Last Activity</th><th className="p-3">Action</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {users.map((item) => (
                    <tr key={item.id} className="align-top">
                      <td className="p-3"><p className="font-black">{item.name}</p><p className="text-xs text-slate-500">{item.email}</p></td>
                      <td className="p-3"><span className={`rounded-full px-2.5 py-1 text-xs font-black ring-1 ${item.role === "founder_admin" ? "bg-blue-50 text-blue-700 ring-blue-200" : "bg-slate-50 text-slate-700 ring-slate-200"}`}>{item.role}</span></td>
                      <td className="p-3 font-semibold">{item.provider}</td>
                      <td className="p-3"><span className={`rounded-full px-2.5 py-1 text-xs font-black ring-1 ${item.password_reset_required ? "bg-amber-50 text-amber-700 ring-amber-200" : "bg-emerald-50 text-emerald-700 ring-emerald-200"}`}>{item.password_reset_required ? "Change Required" : "OK"}</span></td>
                      <td className="p-3 font-black">{item.total_analyses}</td>
                      <td className="p-3 font-black">{item.image_analyses}</td>
                      <td className="p-3 text-xs">{formatDate(item.created_at)}</td>
                      <td className="p-3 text-xs">{formatDate(item.last_activity)}</td>
                      <td className="p-3"><button onClick={() => void resetPassword(item)} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-black text-slate-700 hover:border-blue-300 hover:bg-blue-50 hover:text-blue-700"><KeyRound className="h-4 w-4" />Reset</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-4 flex flex-col justify-between gap-3 lg:flex-row lg:items-center">
              <div>
                <h2 className="text-xl font-black">Every Upload And Report</h2>
                <p className="text-sm text-slate-500">Real stored analyses from the backend, including image files and report links.</p>
              </div>
              <select value={filter} onChange={(event) => setFilter(event.target.value)} className="rounded-xl border border-slate-200 px-4 py-2 text-sm font-bold">
                <option value="all">All media</option>
                <option value="image">Images only</option>
                <option value="video">Videos only</option>
                <option value="audio">Audio only</option>
                <option value="url">URLs only</option>
                <option value="email">Emails only</option>
              </select>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-[1050px] w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-widest text-slate-500">
                  <tr><th className="p-3">Report</th><th className="p-3">User</th><th className="p-3">Type</th><th className="p-3">File/Input</th><th className="p-3">Classification</th><th className="p-3">Risk</th><th className="p-3">AI/Threat</th><th className="p-3">Evidence</th><th className="p-3">Date</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {visibleAnalyses.map((item) => (
                    <tr key={item.id} className="align-top">
                      <td className="p-3"><Link href={`/results/${item.id}`} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-black text-white hover:bg-blue-700"><FileText className="h-4 w-4" />Open</Link></td>
                      <td className="p-3"><p className="font-black">{item.user_name}</p><p className="text-xs text-slate-500">{item.user_email}</p></td>
                      <td className="p-3 font-black capitalize">{item.media_type}</td>
                      <td className="max-w-[220px] p-3 font-semibold"><span className="line-clamp-2 break-all">{item.filename}</span><p className="mt-1 text-xs text-slate-400">{item.id}</p></td>
                      <td className="p-3"><span className={`rounded-full px-2.5 py-1 text-xs font-black ring-1 ${badgeClass(item.ai_classification)}`}>{item.ai_classification}</span><p className="mt-1 text-xs text-slate-500">{item.authenticity_verdict}</p></td>
                      <td className="p-3"><span className={`rounded-full px-2.5 py-1 text-xs font-black ring-1 ${badgeClass(item.risk_level)}`}>{item.risk_level}</span></td>
                      <td className="p-3 text-xs font-black">AI {item.ai_probability}%<br />Threat {item.threat_score}</td>
                      <td className="p-3 font-black">{item.evidence_count}</td>
                      <td className="p-3 text-xs">{formatDate(item.uploaded_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-xl font-black">Image Submissions And Reports</h2>
            <p className="mt-1 text-sm text-slate-500">A quick view of every image users gave to TruthLens, with direct report access.</p>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {(summary?.latest_image_reports ?? []).map((item) => (
                <article key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="break-all font-black">{item.filename}</p>
                      <p className="mt-1 text-xs text-slate-500">{item.user_email}</p>
                    </div>
                    <FileImage className="h-6 w-6 shrink-0 text-blue-600" />
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div className="rounded-xl bg-white p-3"><p className="font-black text-slate-500">AI Probability</p><p className="mt-1 text-lg font-black">{item.ai_probability}%</p></div>
                    <div className="rounded-xl bg-white p-3"><p className="font-black text-slate-500">Authenticity</p><p className="mt-1 text-lg font-black">{item.authenticity_score}%</p></div>
                  </div>
                  <div className="mt-4 flex items-center justify-between gap-3">
                    <span className={`rounded-full px-2.5 py-1 text-xs font-black ring-1 ${badgeClass(item.risk_level)}`}>{item.risk_level}</span>
                    <Link href={`/results/${item.id}`} className="text-sm font-black text-blue-700 hover:text-blue-900">View report</Link>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}
    </AppShell>
  );
}
