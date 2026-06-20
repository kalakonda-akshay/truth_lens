"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, Download } from "lucide-react";
import { API_URL, fetchReport, normalizeReport, type AnalysisReport } from "@/lib/api";

const disclaimer =
  "This report has been generated using automated forensic analysis techniques. Results are probabilistic assessments and should be considered advisory in nature. TruthLens AI does not guarantee absolute authenticity or inauthenticity. Additional human verification is recommended for critical decisions.";

function frameSource(frameUrl: string) {
  if (frameUrl.startsWith("data:") || frameUrl.startsWith("http")) return frameUrl;
  return `${API_URL}${frameUrl}`;
}

function classificationTone(classification: string) {
  if (classification === "ANALYSIS FAILED") return "bg-red-700 text-white border-red-500";
  if (classification === "AI Generated") return "bg-red-600 text-white border-red-400";
  if (classification === "AI GENERATED") return "bg-red-600 text-white border-red-400";
  if (classification === "LIKELY AI GENERATED") return "bg-orange-500 text-white border-orange-300";
  if (classification === "SUSPICIOUS") return "bg-yellow-400 text-slate-950 border-yellow-200";
  if (classification === "AUTHENTIC" || classification === "LIKELY AUTHENTIC") return "bg-emerald-500 text-white border-emerald-300";
  if (classification === "Likely AI Generated") return "bg-orange-500 text-white border-orange-300";
  if (classification === "Manipulated") return "bg-yellow-400 text-slate-950 border-yellow-200";
  if (classification === "Authentic") return "bg-emerald-500 text-white border-emerald-300";
  return "bg-slate-300 text-slate-950 border-slate-100";
}

function riskTone(risk: string) {
  if (risk === "Critical" || risk === "High") return "bg-red-600 text-white";
  if (risk === "Medium") return "bg-orange-500 text-white";
  return "bg-emerald-500 text-white";
}

function urlThreatTone(classification: string) {
  if (classification === "MALICIOUS" || classification.includes("CRITICAL")) return "bg-red-700 text-white";
  if (classification === "LIKELY PHISHING" || classification.includes("HIGH")) return "bg-red-600 text-white";
  if (classification === "SUSPICIOUS" || classification.includes("MEDIUM")) return "bg-orange-500 text-white";
  return "bg-emerald-500 text-white";
}

function reportDate(value: string) {
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function Section({ title, index, children }: { title: string; index: number; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-300 bg-white p-4 shadow-sm">
      <h3 className="mb-4 flex items-center gap-2 text-[15px] font-black uppercase text-[#0b1b4f]">
        <span className="grid h-6 w-6 place-items-center rounded border border-cyan-500 text-xs text-cyan-600">{index}</span>
        {title}
      </h3>
      {children}
    </section>
  );
}

function DetailRows({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div className="space-y-2 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[125px_10px_1fr] gap-2">
          <span className="font-bold text-slate-800">{label}</span>
          <span className="text-slate-500">:</span>
          <span className="text-slate-700">{value}</span>
        </div>
      ))}
    </div>
  );
}

function ScoreCircle({ title, value, caption, color }: { title: string; value: number; caption: string; color: string }) {
  return (
    <div className="flex flex-col items-center border-r border-slate-200 px-4 last:border-r-0">
      <h3 className="mb-4 text-center text-base font-black uppercase text-[#0b1b4f]">{title}</h3>
      <div
        className="grid h-36 w-36 place-items-center rounded-full"
        style={{ background: `conic-gradient(${color} ${value * 3.6}deg, #d1d5db 0deg)` }}
      >
        <div className="grid h-24 w-24 place-items-center rounded-full bg-white text-center">
          <div>
            <p className="text-3xl font-black" style={{ color }}>{value}%</p>
            <p className="text-xs font-bold leading-tight text-slate-900">{caption}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function TruthLensReport({ report }: { report: AnalysisReport }) {
  const isUrl = report.media_type === "url";
  const isThreatText = report.media_type === "url" || report.media_type === "email";
  const urlThreatScore = Number(report.url_analysis.threat_score ?? report.scores.threat_score ?? 0);
  const phishingProbability = Number(report.url_analysis.phishing_probability ?? report.scores.deepfake_probability ?? report.scores.threat_score ?? 0);
  const domainRiskScore = Number(report.url_analysis.domain_risk_score ?? 0);
  const urlThreatClassification = String(report.url_analysis.threat_classification ?? report.threat_classification ?? "SAFE").toUpperCase();
  const textThreatScore = isUrl ? urlThreatScore : Number(report.scores.threat_score ?? 0);
  const textPhishingProbability = isUrl ? phishingProbability : Number(report.scores.threat_score ?? 0);
  const textRiskScore = isUrl ? domainRiskScore : Number(report.scores.threat_score ?? 0);
  const textThreatClassification = isUrl ? urlThreatClassification : String(report.threat_classification ?? "LOW THREAT").toUpperCase();
  const visualRows = report.media_type === "image"
    ? [
        ["Texture Consistency", String(report.image_forensics.texture_inconsistency ?? "Not triggered")],
        ["Lighting Analysis", String(report.image_forensics.lighting_inconsistency ?? "Not triggered")],
        ["Edge & Outline Analysis", String(report.image_forensics.edge_anomaly ?? "Not triggered")],
        ["Compression Analysis", String(report.image_forensics.compression_artifacts ?? "Not triggered")],
      ]
    : report.media_type === "audio"
      ? [
          ["Zero Crossing Rate", String(report.audio_clone_detection.zero_crossing_rate ?? "Not available")],
          ["RMS Energy", String(report.audio_clone_detection.rms_energy ?? "Not available")],
          ["Detection Engine", String(report.audio_clone_detection.detection_engine ?? "Reality Defender")],
          ["Voice Clone Probability", `${report.audio_clone_detection.voice_clone_probability ?? 0}%`],
          ["Synthetic Audio Probability", `${report.audio_clone_detection.synthetic_audio_probability ?? 0}%`],
        ]
      : report.media_type === "url"
        ? [
            ["Domain", String(report.url_analysis.domain ?? "Not available")],
            ["Scheme", String(report.url_analysis.scheme ?? "Not available")],
            ["Credential Harvesting", report.url_analysis.credential_harvesting ? "Detected" : "Not detected"],
            ["Redirect Risk", report.url_analysis.redirect_risk ? "Detected" : "Not detected"],
            ["Typosquatting", report.url_analysis.typosquatting ? "Detected" : "Not detected"],
          ]
      : report.media_type === "email"
        ? [
            ["Embedded URLs", String((report.email_analysis.embedded_urls as string[] | undefined)?.length ?? 0)],
            ["URL Checks", String(report.email_analysis.url_engine_urls_checked ?? 0)],
            ["Heuristic Score", `${report.email_analysis.heuristic_threat_score ?? 0}%`],
            ["Indicators", String((report.email_analysis.indicators as string[] | undefined)?.length ?? 0)],
          ]
      : [
          ["Frames Analyzed", String(report.face_analysis.frames_analyzed ?? 0)],
          ["Suspicious Frames", String(report.face_analysis.suspicious_frames ?? 0)],
          ["Module Summary", String(report.face_analysis.summary ?? "Not available")],
        ];

  const artifactRows = report.media_type === "image"
    ? [
        ["Diffusion Artifacts", Number(report.image_forensics.diffusion_artifacts ?? 0) >= 55 ? "Detected" : "Not detected"],
        ["GAN Artifacts", Number(report.image_forensics.gan_artifacts ?? 0) >= 55 ? "Detected" : "Not detected"],
        ["Noise Pattern Analysis", Number(report.image_forensics.noise_pattern_anomaly ?? 0) >= 45 ? "Abnormal" : "Within range"],
        ["Compression Inconsistencies", Number(report.image_forensics.compression_artifacts ?? 0) >= 55 ? "Detected" : "Not detected"],
      ]
    : report.evidence.map((item) => [item.label, item.detail]);

  const evidenceFrame = report.suspicious_frames[0];

  return (
    <article id="truthlens-report-template" className="mx-auto w-full max-w-[1120px] overflow-hidden bg-white text-slate-950 shadow-2xl">
      <header className="grid grid-cols-[1fr_1.35fr_1fr] items-center gap-6 bg-[#031225] px-9 py-7 text-white">
        <div className="flex items-center gap-5">
          <div className="grid h-24 w-24 place-items-center rounded-full border-4 border-cyan-400 bg-cyan-400/10">
            <div className="h-12 w-12 rounded-full border-4 border-white bg-cyan-300" />
          </div>
          <div>
            <p className="text-4xl font-black">Truth<span className="text-cyan-300">Lens</span></p>
            <p className="text-2xl font-black text-cyan-300">AI</p>
            <p className="mt-2 text-sm font-bold">See Truth. Stop Deception.</p>
          </div>
        </div>
        <div className="border-x border-cyan-400/50 px-8 text-center">
          <h1 className="text-4xl font-black uppercase tracking-tight">Forensic Analysis Report</h1>
          <p className="mt-3 text-xl font-bold text-cyan-100">Synthetic Media Verification</p>
        </div>
        <DetailRows
          rows={[
            ["Report ID", report.id.slice(0, 18)],
            ["Analysis Date", reportDate(report.uploaded_at)],
            ["Version", "2.0.0"],
            ["Analyzed By", "TruthLens AI Engine"],
          ]}
        />
      </header>

      <div className="space-y-3 bg-slate-50 p-8">
        <div className="grid grid-cols-[1fr_0.9fr_1.05fr] gap-5">
          <Section title="Submitted File Details" index={1}>
            <DetailRows
              rows={[
                ["File Name", report.filename],
                ["File Type", report.media_type.toUpperCase()],
                ["File Size", `${report.metadata.file_size_mb} MB`],
                ["Resolution", String(report.image_forensics.resolution ?? report.image_forensics.image_width ? `${report.image_forensics.image_width} x ${report.image_forensics.image_height}` : "N/A")],
                ["Source", report.media_type === "url" || report.media_type === "email" ? "Submitted Text" : "Direct Upload"],
              ]}
            />
          </Section>

          <div className="overflow-hidden rounded-xl border border-slate-300 bg-slate-900">
            {evidenceFrame ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={frameSource(evidenceFrame.frame_url)} alt={evidenceFrame.reason} className="h-56 w-full object-cover" />
            ) : (
              <div className="grid h-56 place-items-center bg-gradient-to-br from-slate-900 to-cyan-950 text-center text-sm font-bold text-cyan-100">
                {isUrl ? "URL evidence is listed in findings" : "No visual evidence generated"}
              </div>
            )}
            <p className="bg-[#061d38] py-2 text-center text-sm font-black uppercase text-white">Evidence Preview</p>
          </div>

          <Section title="Analysis Summary" index={2}>
            <DetailRows
              rows={[
                ["Media Type Detected", report.media_type.toUpperCase()],
                ["Analysis Performed", report.analysis_summary],
                ["Authenticity Verdict", report.authenticity_verdict],
                ["Analysis Status", report.analysis_status.toUpperCase()],
                ["Model Used", report.model_used],
                ...(report.error_details ? [["Error Details", report.error_details] as [string, string]] : []),
                ...(isThreatText
                  ? [
                      ["Threat Score", `${textThreatScore}%`] as [string, string],
                      ["Phishing Probability", `${textPhishingProbability}%`] as [string, string],
                      [isUrl ? "Domain Risk Score" : "Email Risk Score", `${textRiskScore}%`] as [string, string],
                      ["Threat Classification", textThreatClassification] as [string, string],
                    ]
                  : [
                      ["Overall Authenticity", `${report.scores.authenticity_score}%`] as [string, string],
                      ["AI Probability", `${report.scores.deepfake_probability}%`] as [string, string],
                      ["Risk Level", report.scores.risk_level.toUpperCase()] as [string, string],
                      ["Threat Classification", report.threat_classification.toUpperCase()] as [string, string],
                    ]),
                ["Model Confidence", `${report.model_confidence}%`],
                ...(report.media_type === "audio" ? [["Voice Clone Detected", report.voice_clone_detected.toUpperCase()] as [string, string]] : []),
                ...(report.media_type === "video" ? [["Deepfake Detection", report.deepfake_detected.toUpperCase()] as [string, string]] : []),
              ]}
            />
            <div className={`mt-4 rounded-lg border px-4 py-3 text-center text-lg font-black ${isThreatText ? urlThreatTone(textThreatClassification) : classificationTone(report.authenticity_verdict)}`}>
              AUTHENTICITY VERDICT: {report.authenticity_verdict.toUpperCase()}
            </div>
            <div className={`mt-3 rounded-lg border px-4 py-3 text-center text-sm font-black ${isThreatText ? urlThreatTone(textThreatClassification) : classificationTone(report.ai_classification)}`}>
              {isThreatText ? `THREAT CLASSIFICATION: ${textThreatClassification}` : `AI CLASSIFICATION: ${report.ai_classification.toUpperCase()}`}
            </div>
          </Section>
        </div>

        <section className="grid grid-cols-3 rounded-xl border border-slate-300 bg-white p-4">
          {isThreatText ? (
            <>
              <ScoreCircle title="Threat Score" value={textThreatScore} caption={textThreatClassification} color="#dc2626" />
              <ScoreCircle title={isUrl ? "Phishing Probability" : "Scam Probability"} value={textPhishingProbability} caption={isUrl ? "URL Threat" : "Email Threat"} color="#f97316" />
              <ScoreCircle title={isUrl ? "Domain Risk Score" : "Email Risk Score"} value={textRiskScore} caption={isUrl ? String(report.url_analysis.domain ?? "Domain") : "Message"} color="#0ea5e9" />
            </>
          ) : (
            <>
              <ScoreCircle title="Authenticity Score" value={report.scores.authenticity_score} caption={report.ai_classification === "Authentic" ? "Likely Authentic" : "Review Required"} color="#2f9b68" />
              <ScoreCircle title="AI Generated Probability" value={report.scores.deepfake_probability} caption={report.ai_classification} color="#dc2626" />
            </>
          )}
          {!isThreatText && <div className="flex flex-col items-center justify-center px-4">
            <h3 className="mb-6 text-center text-base font-black uppercase text-[#0b1b4f]">Risk Level</h3>
            <div className={`w-full rounded-xl p-8 text-center ${riskTone(report.scores.risk_level)}`}>
              <p className="text-4xl font-black">{report.scores.risk_level.toUpperCase()}</p>
              <p className="mt-3 text-sm font-bold">{report.conclusion}</p>
            </div>
          </div>}
        </section>

        <div className="grid grid-cols-3 gap-3">
          <Section title="Metadata Analysis" index={3}>
            <DetailRows
              rows={[
                ["Camera Information", report.metadata.camera_information],
                ["Creation Date", new Date(report.metadata.creation_date).toLocaleString()],
                ["Editing Software", report.metadata.editing_software],
                ["EXIF Data", Object.keys(report.metadata.exif_data).length ? "Present" : "Not found"],
                ["File Origin", report.media_type === "url" || report.media_type === "email" ? "Submitted Text" : "Upload"],
              ]}
            />
          </Section>
          <Section title={isThreatText ? (isUrl ? "URL Threat Analysis" : "Email Threat Analysis") : "Visual Analysis"} index={4}>
            <DetailRows rows={visualRows.slice(0, 5) as Array<[string, string]>} />
          </Section>
          <Section title={isThreatText ? "Threat Evidence Detected" : "AI Artifact Detection"} index={5}>
            <DetailRows rows={(artifactRows.length ? artifactRows.slice(0, 5) : [["Indicators", "No high-risk artifact indicators detected"]]) as Array<[string, string]>} />
          </Section>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Section title="Evidence Visualization" index={6}>
            {evidenceFrame ? (
              <div>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={frameSource(evidenceFrame.frame_url)} alt={evidenceFrame.reason} className="h-48 w-full rounded-lg object-cover" />
                <p className="mt-3 text-center text-xs text-slate-600">{evidenceFrame.reason}</p>
                <div className="mt-4 h-3 rounded-full bg-gradient-to-r from-emerald-400 via-yellow-300 to-red-500" />
                <div className="mt-1 flex justify-between text-[11px] font-bold text-slate-700"><span>Low Suspicion</span><span>High Suspicion</span></div>
              </div>
            ) : (
              <p className="text-sm text-slate-600">{isThreatText ? "Threat evidence is shown through indicators and key findings." : "No heatmap, bounding box, suspicious region, spectrogram, or frame evidence crossed reporting threshold."}</p>
            )}
          </Section>
          <Section title="Key Findings" index={7}>
            <ul className="space-y-3 text-sm text-slate-800">
              {report.key_findings.map((finding) => (
                <li key={finding} className="flex gap-2">
                  <span className="font-black text-red-600">!</span>
                  <span>{finding}</span>
                </li>
              ))}
            </ul>
          </Section>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Section title="Conclusion" index={8}>
            <p className="text-lg font-black text-red-600">{report.verdict}</p>
            <p className="mt-3 text-sm leading-6 text-slate-700">{report.conclusion}</p>
          </Section>
          <Section title="Recommendation" index={9}>
            <ul className="space-y-2 text-sm font-semibold text-slate-700">
              {report.recommendations.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </Section>
        </div>

        <section className="rounded-xl border border-slate-300 bg-white p-5">
          <h3 className="font-black uppercase text-[#0b1b4f]">Disclaimer</h3>
          <p className="mt-3 text-xs leading-5 text-slate-600">{disclaimer}</p>
        </section>
      </div>

      <footer className="bg-[#031225] px-8 py-5 text-center text-white">
        <p className="mb-2 text-xs font-semibold text-cyan-100">Evidence Summary: {report.evidence_summary}</p>
        <p className="text-sm font-bold text-cyan-300">Generated by TruthLens AI Engine</p>
        <p className="mt-1 text-2xl font-black tracking-[0.45em]">TEAM TRUTHLENS</p>
        <p className="mt-1 text-sm font-bold text-cyan-300">See Truth. Stop Deception.</p>
      </footer>
    </article>
  );
}

async function downloadPdf(report: AnalysisReport) {
  const html2canvas = (await import("html2canvas")).default;
  const { jsPDF } = await import("jspdf");
  const element = document.getElementById("truthlens-report-template");
  if (!element) return;
  const canvas = await html2canvas(element, {
    backgroundColor: "#ffffff",
    scale: 2,
    useCORS: true,
  });
  const pdf = new jsPDF("p", "mm", "a4");
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const imgWidth = pageWidth;
  const imgHeight = (canvas.height * imgWidth) / canvas.width;
  let remaining = imgHeight;
  let position = 0;
  const image = canvas.toDataURL("image/jpeg", 0.92);
  pdf.addImage(image, "JPEG", 0, position, imgWidth, imgHeight);
  remaining -= pageHeight;
  while (remaining > 0) {
    position -= pageHeight;
    pdf.addPage();
    pdf.addImage(image, "JPEG", 0, position, imgWidth, imgHeight);
    remaining -= pageHeight;
  }
  pdf.save(`truthlens-${report.id}.pdf`);
}

export default function ResultsPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const storageKey = `truthlens:report:${id}`;
    const stored = sessionStorage.getItem(storageKey) ?? localStorage.getItem(storageKey);
    if (stored) {
      setReport(normalizeReport(JSON.parse(stored)));
      return;
    }
    fetchReport(id)
      .then((nextReport) => {
        const serializedReport = JSON.stringify(nextReport);
        sessionStorage.setItem(`truthlens:report:${nextReport.id}`, serializedReport);
        localStorage.setItem(`truthlens:report:${nextReport.id}`, serializedReport);
        setReport(nextReport);
      })
      .catch(() => setError("Report not found in this browser session. Run a new TruthLens analysis."));
  }, [id]);

  if (error) {
    return (
      <main className="cyber-grid flex min-h-screen items-center justify-center px-6">
        <div className="glass max-w-xl rounded-[2rem] p-8 text-center">
          <h1 className="text-3xl font-black text-white">Report unavailable</h1>
          <p className="mt-4 text-slate-300">{error}</p>
          <Link href="/" className="mt-6 inline-flex rounded-2xl bg-cyber-cyan px-6 py-3 font-black text-slate-950">Run new analysis</Link>
        </div>
      </main>
    );
  }

  if (!report) {
    return (
      <main className="cyber-grid flex min-h-screen items-center justify-center px-6">
        <div className="glass rounded-[2rem] p-8 text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyber-cyan">Loading report</p>
          <h1 className="mt-3 text-3xl font-black text-white">Preparing TruthLens evidence...</h1>
        </div>
      </main>
    );
  }

  return (
    <main className="cyber-grid min-h-screen px-4 py-8">
      <div className="mx-auto mb-6 flex max-w-[1120px] flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <Link href="/" className="inline-flex items-center gap-2 text-sm font-bold text-cyber-cyan">
          <ArrowLeft className="h-4 w-4" />
          New analysis
        </Link>
        <button
          type="button"
          onClick={() => downloadPdf(report)}
          className="inline-flex items-center justify-center gap-2 rounded-2xl bg-cyber-cyan px-5 py-3 font-black text-slate-950"
        >
          <Download className="h-4 w-4" />
          Download PDF report
        </button>
      </div>
      <TruthLensReport report={report} />
    </main>
  );
}
