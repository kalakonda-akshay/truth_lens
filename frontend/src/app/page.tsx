import Link from "next/link";
import { ArrowRight, ShieldCheck } from "lucide-react";

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-[#07122B] text-white">
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl border border-white/20 bg-white/5">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div>
            <p className="text-xl font-black">TruthLens AI</p>
            <p className="text-[11px] text-slate-300">Cybersecurity Verification Platform</p>
          </div>
        </div>
        <div className="flex gap-3">
          <Link href="/login" className="rounded-lg border border-white/20 px-5 py-2.5 text-sm font-bold hover:bg-white/10">Login</Link>
          <Link href="/signup" className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-bold hover:bg-blue-500">Sign Up</Link>
        </div>
      </nav>
      <section className="mx-auto grid min-h-[78vh] max-w-7xl items-center gap-12 px-6 py-16 lg:grid-cols-2">
        <div>
          <p className="text-sm font-black uppercase tracking-[0.25em] text-blue-400">TruthLens AI 2.0</p>
          <h1 className="mt-5 text-5xl font-black leading-tight md:text-7xl">Verify digital evidence before deception spreads.</h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
            A unified investigation platform for deepfake detection, synthetic voice analysis, phishing detection, and explainable forensic reports.
          </p>
          <div className="mt-9 flex flex-wrap gap-4">
            <Link href="/signup" className="flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-4 font-black hover:bg-blue-500">
              Create Analyst Account <ArrowRight className="h-5 w-5" />
            </Link>
            <Link href="/login" className="rounded-xl border border-white/20 px-6 py-4 font-black hover:bg-white/10">Open Command Center</Link>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          {["Image & Video Forensics", "Voice Clone Detection", "URL Threat Intelligence", "Email Scam Analysis"].map((feature) => (
            <div key={feature} className="rounded-2xl border border-white/10 bg-white/5 p-6">
              <ShieldCheck className="h-7 w-7 text-blue-400" />
              <p className="mt-5 text-lg font-black">{feature}</p>
              <p className="mt-2 text-sm leading-6 text-slate-400">Evidence-backed analysis with transparent scores and professional reporting.</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
