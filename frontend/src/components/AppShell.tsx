"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Bell, BriefcaseBusiness, FileAudio, FileImage, FileText, FileVideo, FolderOpen,
  Home, Link as LinkIcon, LogOut, Search, Settings, ShieldCheck, UserCircle,
} from "lucide-react";
import { AuthGate, useAuth } from "@/lib/auth";

const navigation = [
  ["Dashboard", "/dashboard", Home],
  ["Image Analysis", "/analyze/image", FileImage],
  ["Video Analysis", "/analyze/video", FileVideo],
  ["Audio Analysis", "/analyze/audio", FileAudio],
  ["URL Analysis", "/analyze/url", LinkIcon],
  ["Email Analysis", "/analyze/email", FileText],
  ["My Cases", "/cases", BriefcaseBusiness],
  ["Evidence Library", "/evidence", FolderOpen],
  ["Reports", "/reports", FileText],
  ["Alerts", "/alerts", Bell],
  ["Investigation Timeline", "/timeline", BriefcaseBusiness],
  ["Profile", "/profile", UserCircle],
  ["Settings", "/settings", Settings],
] as const;

export function AppShell({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, signOut } = useAuth();

  return (
    <AuthGate>
      <main className="min-h-screen bg-[#f8fafc] text-slate-950">
        <aside className="fixed inset-y-0 left-0 z-40 hidden w-[285px] flex-col bg-[#07122B] text-white xl:flex">
          <Link href="/dashboard" className="flex items-center gap-4 px-6 py-6">
            <div className="grid h-11 w-11 place-items-center rounded-xl border border-white/20 bg-white/5"><ShieldCheck className="h-7 w-7" /></div>
            <div><p className="text-2xl font-black">TruthLens AI</p><p className="text-[11px] text-slate-300">Digital Forensics Platform</p></div>
          </Link>
          <nav className="flex-1 space-y-1 overflow-y-auto px-5 pb-5">
            {navigation.map(([label, href, Icon], index) => (
              <div key={href}>
                {[1, 6, 11].includes(index) && <p className="mb-2 mt-5 px-3 text-[10px] font-black uppercase tracking-widest text-slate-500">{index === 1 ? "Analyze" : index === 6 ? "Case Management" : "Account"}</p>}
                <Link href={href} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-bold transition ${pathname === href ? "bg-blue-600 text-white" : "text-slate-300 hover:bg-white/10 hover:text-white"}`}>
                  <Icon className="h-5 w-5" />{label}
                </Link>
              </div>
            ))}
          </nav>
          <div className="m-5 rounded-xl border border-white/10 bg-white/5 p-5">
            <p className="text-sm font-black">TruthLens AI</p><p className="mt-1 text-xs font-bold text-blue-300">Version 2.0</p>
            <p className="mt-3 text-xs leading-5 text-slate-300">Deepfake Detection<br />Voice Clone Detection<br />Phishing Detection</p>
          </div>
        </aside>
        <header className="sticky top-0 z-30 border-b border-slate-200 bg-[#07122B] px-5 py-4 text-white xl:ml-[285px]">
          <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4">
            <Link href="/dashboard" className="flex items-center gap-2 xl:hidden"><ShieldCheck className="h-7 w-7" /><span className="font-black">TruthLens AI</span></Link>
            <div className="relative hidden max-w-md flex-1 md:block"><Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><input className="w-full rounded-lg border border-white/15 bg-white/5 py-2.5 pl-11 pr-4 text-sm outline-none" placeholder="Search cases and reports" /></div>
            <div className="flex items-center gap-3">
              {user?.avatar_url ? <div role="img" aria-label={`${user.name} avatar`} className="h-9 w-9 rounded-full bg-cover bg-center" style={{ backgroundImage: `url("${user.avatar_url}")` }} /> : <UserCircle className="h-8 w-8" />}
              <span className="hidden text-sm font-bold sm:block">{user?.name}</span>
              <button onClick={() => { signOut(); router.push("/login"); }} className="rounded-lg p-2 hover:bg-white/10" aria-label="Sign out"><LogOut className="h-5 w-5" /></button>
            </div>
          </div>
          <div className="mx-auto mt-3 max-w-[1500px] xl:hidden">
            <select value={pathname} onChange={(event) => router.push(event.target.value)} aria-label="Navigate TruthLens" className="w-full rounded-lg border border-white/15 bg-[#10214D] px-4 py-2.5 text-sm font-bold text-white">
              {navigation.map(([label, href]) => <option key={href} value={href}>{label}</option>)}
            </select>
          </div>
        </header>
        <div className="xl:ml-[285px]">
          <div className="mx-auto max-w-[1500px] px-5 py-7">
            <div className="mb-6"><h1 className="text-3xl font-black">{title}</h1><p className="mt-2 text-sm text-slate-600">{subtitle}</p></div>
            {children}
          </div>
        </div>
      </main>
    </AuthGate>
  );
}
