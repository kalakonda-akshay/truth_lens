"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AudioWaveform, FileImage, FileText, Film, Gauge, Link as LinkIcon, Play, ShieldAlert, Sparkles } from "lucide-react";
import { createDemoReport, demoSamples, type DemoSample } from "@/lib/demoReports";
import { defaultStats, readStats, recordScan, type ScanStats } from "@/lib/scanStats";

const sampleIcons = {
  image: FileImage,
  video: Film,
  audio: AudioWaveform,
  url: LinkIcon,
  email: FileText,
};

export function DemoCenter() {
  const router = useRouter();
  const [stats, setStats] = useState<ScanStats>(defaultStats);

  useEffect(() => {
    setStats(readStats());
    const update = (event: Event) => setStats((event as CustomEvent<ScanStats>).detail);
    window.addEventListener("truthlens:stats", update);
    return () => window.removeEventListener("truthlens:stats", update);
  }, []);

  function runSample(sample: DemoSample) {
    const report = createDemoReport(sample);
    sessionStorage.setItem(`truthlens:report:${report.id}`, JSON.stringify(report));
    recordScan(report.media_type, report.scores.risk_level);
    router.push(`/results/${report.id}?judge=1`);
  }

  const dashboard = [
    ["Total Scans", stats.total, Gauge],
    ["Image Scans", stats.image, FileImage],
    ["Video Scans", stats.video, Film],
    ["Audio Scans", stats.audio, AudioWaveform],
    ["High Risk", stats.highRisk, ShieldAlert],
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
            <p className="max-w-xl text-sm leading-6 text-slate-400">Counters update after uploaded media and one-click judge demonstrations.</p>
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
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-3xl">
              <div className="flex items-center gap-2 text-cyber-cyan">
                <Sparkles className="h-5 w-5" />
                <p className="text-sm font-black uppercase tracking-[0.35em]">Cyberathon Judge Mode</p>
              </div>
              <h2 className="mt-4 text-4xl font-black text-white">One click. Full forensic story.</h2>
              <p className="mt-4 leading-7 text-slate-300">Launch a high-risk AI image report with highlighted evidence, explainable scoring, and recommendations.</p>
            </div>
            <button
              type="button"
              onClick={() => runSample(demoSamples[1])}
              className="inline-flex items-center justify-center gap-3 rounded-2xl bg-cyber-cyan px-7 py-4 font-black text-slate-950 transition hover:-translate-y-1"
            >
              <Play className="h-5 w-5 fill-current" />
              Run Judge Demo
            </button>
          </div>

          <div className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {demoSamples.map((sample) => {
              const Icon = sampleIcons[sample.mediaType];
              return (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => runSample(sample)}
                  className="group rounded-3xl border border-slate-700 bg-slate-950/70 p-5 text-left transition hover:-translate-y-1 hover:border-cyber-cyan/60"
                >
                  <div className="flex items-center justify-between">
                    <div className="rounded-xl bg-cyber-cyan/10 p-2 text-cyber-cyan"><Icon className="h-6 w-6" /></div>
                    <span className={`rounded-full px-3 py-1 text-xs font-black ${sample.risk === "High" ? "bg-cyber-red/15 text-cyber-red" : "bg-cyber-green/15 text-cyber-green"}`}>
                      {sample.risk} Risk
                    </span>
                  </div>
                  <h3 className="mt-5 text-xl font-black text-white">{sample.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-400">{sample.description}</p>
                  <p className="mt-5 text-sm font-bold text-cyber-cyan group-hover:text-cyan-200">Open sample report →</p>
                </button>
              );
            })}
          </div>
        </div>
      </section>
    </>
  );
}
