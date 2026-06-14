"use client";

import { useEffect, useState } from "react";
import { AudioWaveform, FileImage, FileText, Film, Gauge, Link as LinkIcon, ShieldAlert, Sparkles } from "lucide-react";
import { defaultStats, readStats, type ScanStats } from "@/lib/scanStats";

export function DemoCenter() {
  const [stats, setStats] = useState<ScanStats>(defaultStats);

  useEffect(() => {
    setStats(readStats());
    const update = (event: Event) => setStats((event as CustomEvent<ScanStats>).detail);
    window.addEventListener("truthlens:stats", update);
    return () => window.removeEventListener("truthlens:stats", update);
  }, []);

  const dashboard = [
    ["Total Scans", stats.total, Gauge],
    ["Image Scans", stats.image, FileImage],
    ["Video Scans", stats.video, Film],
    ["Audio Scans", stats.audio, AudioWaveform],
    ["High Risk", stats.highRisk, ShieldAlert],
  ] as const;

  const capabilities = [
    ["Image Forensics", FileImage, "Upload JPG/PNG/WEBP files for measured EXIF, texture, lighting, edge, compression, and residual-noise analysis."],
    ["Video Timeline", Film, "Upload MP4/MOV/AVI files to sample frames and retain only frames whose measured anomaly score crosses threshold."],
    ["Audio Spectrogram", AudioWaveform, "Upload MP3/WAV/M4A files to decode waveform evidence and measure audio signal risk indicators."],
    ["URL Threats", LinkIcon, "Paste URLs to evaluate HTTPS, redirects, IP hosts, typosquatting, subdomains, and credential keywords."],
    ["Email Scams", FileText, "Paste email text or upload EML files to detect impersonation, urgency, credential theft, and attachment/link risk."],
  ] as const;

  return (
    <>
      <section className="mx-auto mt-16 max-w-7xl px-6">
        <div className="glass rounded-[2rem] p-6 md:p-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyber-green">Forensic dashboard</p>
              <h2 className="mt-3 text-3xl font-black text-white">Live session intelligence</h2>
            </div>
            <p className="max-w-xl text-sm leading-6 text-slate-400">Counters update only after real uploaded or pasted evidence is analyzed.</p>
          </div>
          <div className="mt-7 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {dashboard.map(([label, value, Icon]) => (
              <div key={label} className="rounded-2xl border border-slate-700 bg-slate-950/60 p-5">
                <Icon className="h-5 w-5 text-cyber-cyan" />
                <p className="mt-4 text-3xl font-black text-white">{value}</p>
                <p className="mt-1 text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="judge-mode" className="mx-auto max-w-7xl px-6 py-20">
        <div className="overflow-hidden rounded-[2rem] border border-cyber-cyan/25 bg-gradient-to-br from-cyan-950/70 via-slate-950 to-emerald-950/60 p-6 shadow-glow md:p-9">
          <div className="max-w-3xl">
            <div className="flex items-center gap-2 text-cyber-cyan">
              <Sparkles className="h-5 w-5" />
              <p className="text-sm font-black uppercase tracking-[0.35em]">Cyberathon Judge Mode</p>
            </div>
            <h2 className="mt-4 text-4xl font-black text-white">Evidence-first forensic workflow</h2>
            <p className="mt-4 leading-7 text-slate-300">Use the dashboard above with real files, URLs, or email text to produce dynamic findings and PDF reports from measured indicators.</p>
          </div>

          <div className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {capabilities.map(([title, Icon, description]) => (
              <div key={title} className="rounded-3xl border border-slate-700 bg-slate-950/70 p-5">
                <div className="rounded-xl bg-cyber-cyan/10 p-2 text-cyber-cyan w-fit"><Icon className="h-6 w-6" /></div>
                <h3 className="mt-5 text-xl font-black text-white">{title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
