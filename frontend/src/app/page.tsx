import { Activity, AudioWaveform, BrainCircuit, Fingerprint, LockKeyhole, Radar } from "lucide-react";
import { UploadPanel } from "@/components/UploadPanel";

const features = [
  {
    icon: Fingerprint,
    title: "Metadata Scanner",
    body: "Reads file size, timestamps, codec details, and container anomalies to surface tampering indicators.",
  },
  {
    icon: Radar,
    title: "Face Analysis",
    body: "Uses OpenCV frame extraction and anomaly highlighting for suspicious visual evidence.",
  },
  {
    icon: Activity,
    title: "Lip Sync Analysis",
    body: "Simulates forensic mouth-motion alignment scores for a compelling prototype workflow.",
  },
  {
    icon: AudioWaveform,
    title: "Audio Clone Detection",
    body: "Uses Librosa acoustic features to estimate synthetic voice confidence.",
  },
];

export default function Home() {
  return (
    <main className="cyber-grid min-h-screen overflow-hidden">
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl border border-cyber-cyan/40 bg-cyber-cyan/10 p-2">
            <LockKeyhole className="h-6 w-6 text-cyber-cyan" />
          </div>
          <span className="text-xl font-black tracking-tight">TruthLens</span>
        </div>
        <a href="#upload" className="rounded-full border border-cyber-cyan/40 px-5 py-2 text-sm font-bold text-cyber-cyan transition hover:bg-cyber-cyan hover:text-slate-950">
          Upload media
        </a>
      </nav>

      <section className="mx-auto grid max-w-7xl gap-10 px-6 pb-10 pt-12 lg:grid-cols-[1.08fr_0.92fr] lg:items-center">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.45em] text-cyber-green">Cyberathon 2026 prototype</p>
          <h1 className="mt-6 max-w-4xl text-5xl font-black leading-tight text-white md:text-7xl">
            Verify deepfakes before they become cyber incidents.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
            TruthLens combines metadata scanning, visual anomaly checks, lip-sync scoring, and audio clone detection into one explainable media risk report.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <a href="#upload" className="rounded-2xl bg-cyber-cyan px-7 py-4 text-center font-black text-slate-950 transition hover:-translate-y-0.5 hover:bg-cyan-300">
              Analyze media now
            </a>
            <a href="#features" className="rounded-2xl border border-slate-600 px-7 py-4 text-center font-black text-white transition hover:border-cyber-green hover:text-cyber-green">
              Explore platform
            </a>
          </div>
        </div>

        <div className="glass relative overflow-hidden rounded-[2rem] p-6 shadow-glow">
          <div className="absolute inset-x-10 top-0 h-32 animate-scan bg-gradient-to-b from-cyber-cyan/30 to-transparent blur-xl" />
          <div className="relative rounded-3xl border border-slate-700 bg-slate-950/70 p-6">
            <div className="mb-8 flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Live forensic console</p>
                <p className="text-2xl font-black text-white">Risk Level: Medium</p>
              </div>
              <BrainCircuit className="h-10 w-10 text-cyber-cyan" />
            </div>
            {["Metadata integrity", "Visual anomaly scan", "Lip-sync coherence", "Voice clone texture"].map((label, index) => (
              <div key={label} className="mb-5">
                <div className="mb-2 flex justify-between text-sm">
                  <span className="text-slate-300">{label}</span>
                  <span className="text-cyber-cyan">{82 - index * 11}%</span>
                </div>
                <div className="h-2 rounded-full bg-slate-800">
                  <div className="h-2 rounded-full bg-gradient-to-r from-cyber-cyan to-cyber-green" style={{ width: `${82 - index * 11}%` }} />
                </div>
              </div>
            ))}
            <div className="mt-8 rounded-2xl border border-cyber-amber/30 bg-cyber-amber/10 p-4 text-sm font-semibold text-cyber-amber">
              Do not forward unverified media
            </div>
          </div>
        </div>
      </section>

      <UploadPanel />

      <section id="features" className="mx-auto max-w-7xl px-6 py-20">
        <div className="max-w-3xl">
          <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyber-cyan">Analysis engine</p>
          <h2 className="mt-3 text-4xl font-black text-white">Explainable AI modules for high-trust demos</h2>
          <p className="mt-4 text-slate-300">
            Designed for security teams, educators, and incident responders who need a fast first-pass signal before sharing sensitive media.
          </p>
        </div>
        <div className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-4">
          {features.map((feature) => (
            <div key={feature.title} className="glass rounded-3xl p-6 transition hover:-translate-y-1 hover:border-cyber-cyan/50">
              <feature.icon className="h-8 w-8 text-cyber-cyan" />
              <h3 className="mt-5 text-xl font-black text-white">{feature.title}</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">{feature.body}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
