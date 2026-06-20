import {
  AlertTriangle,
  Bell,
  BriefcaseBusiness,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  FileAudio,
  FileImage,
  FileText,
  FileVideo,
  FolderOpen,
  Gauge,
  Home as HomeIcon,
  Link as LinkIcon,
  LockKeyhole,
  Search,
  Settings,
  ShieldCheck,
  UserCircle,
  Zap,
} from "lucide-react";
import { UploadPanel } from "@/components/UploadPanel";

const navGroups = [
  {
    label: "",
    items: [{ label: "Dashboard", Icon: HomeIcon, active: true }],
  },
  {
    label: "Analyze",
    items: [
      { label: "Image Analysis", Icon: FileImage },
      { label: "Video Analysis", Icon: FileVideo },
      { label: "Audio Analysis", Icon: FileAudio },
      { label: "URL Analysis", Icon: LinkIcon },
      { label: "Email Analysis", Icon: FileText },
    ],
  },
  {
    label: "Case Management",
    items: [
      { label: "My Cases", Icon: BriefcaseBusiness },
      { label: "Evidence Library", Icon: FolderOpen },
      { label: "Reports", Icon: FileText },
      { label: "Alerts", Icon: Bell },
    ],
  },
  {
    label: "Settings",
    items: [
      { label: "Profile", Icon: UserCircle },
      { label: "API Integrations", Icon: Zap },
      { label: "Settings", Icon: Settings },
    ],
  },
];

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

function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 hidden w-[285px] flex-col bg-[#07122B] text-white shadow-2xl xl:flex">
      <div className="flex items-center gap-4 px-6 py-6">
        <div className="grid h-11 w-11 place-items-center rounded-xl border border-white/20 bg-white/5">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <div>
          <h1 className="text-2xl font-black tracking-tight">TruthLens AI</h1>
          <p className="text-[11px] font-semibold text-slate-300">Digital Forensics & Cyber Verification Platform</p>
        </div>
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto px-5 pb-6">
        {navGroups.map((group) => (
          <div key={group.label || "main"}>
            {group.label && <p className="mb-3 px-2 text-[11px] font-bold uppercase tracking-widest text-slate-400">{group.label}</p>}
            <div className="space-y-1">
              {group.items.map((item) => {
                const { label, Icon } = item;
                const active = "active" in item && item.active;
                return (
                <a
                  key={label}
                  href={label === "Dashboard" ? "#" : "#upload"}
                  className={`flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-bold transition ${
                    active ? "bg-blue-600 text-white shadow-lg shadow-blue-950/30" : "text-slate-300 hover:bg-white/8 hover:text-white"
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  {label}
                </a>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="m-5 rounded-xl border border-white/10 bg-white/5 p-5">
        <p className="text-sm font-black">TRUTHLENS PRO</p>
        <p className="mt-3 text-xs leading-5 text-slate-300">Advanced Forensics. AI Powered. Trusted Results.</p>
        <button className="mt-5 w-full rounded-lg bg-blue-600 px-4 py-3 text-sm font-black text-white hover:bg-blue-500">
          Upgrade Now
        </button>
      </div>
    </aside>
  );
}

function TopHeader() {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-[#07122B] px-5 py-4 text-white xl:ml-[285px]">
      <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-5">
        <div className="flex items-center gap-3 xl:hidden">
          <ShieldCheck className="h-7 w-7" />
          <span className="text-xl font-black">TruthLens AI</span>
        </div>
        <div className="hidden flex-1 justify-end md:flex">
          <div className="relative w-full max-w-md">
            <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
            <input
              className="w-full rounded-lg border border-white/15 bg-white/5 py-3 pl-12 pr-4 text-sm text-white outline-none placeholder:text-slate-400 focus:border-blue-400"
              placeholder="Search cases, reports, etc."
            />
          </div>
        </div>
        <div className="flex items-center gap-5">
          <Bell className="h-5 w-5" />
          <CircleHelp className="h-5 w-5" />
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-full bg-white text-[#07122B]">
              <UserCircle className="h-7 w-7" />
            </div>
            <button className="hidden items-center gap-1 text-sm font-black md:flex">
              Analyst <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}

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
        <a href="#upload" className="text-xs font-black text-blue-600">View All</a>
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
          <a href="#upload" className="text-xs font-black text-blue-600">View All</a>
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
    <main className="min-h-screen bg-[#f8fafc] text-slate-950">
      <Sidebar />
      <TopHeader />
      <div className="xl:ml-[285px]">
        <div className="mx-auto max-w-[1500px] px-5 py-7">
          <section className="mb-6">
            <h1 className="text-3xl font-black tracking-tight text-slate-950">Welcome back, Analyst</h1>
            <p className="mt-2 text-sm text-slate-600">Analyze suspicious content using external intelligence, forensic evidence, and threat scoring.</p>
          </section>

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
        </div>
      </div>
    </main>
  );
}
