import { classifyAiProbability, type AnalysisReport } from "@/lib/api";

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

function riskLevel(score: number) {
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

function baseTextReport(input: string, kind: "url" | "email", score: number, indicators: string[], verdict: string): AnalysisReport {
  const evidence = indicators
    .filter((indicator) => !indicator.startsWith("No "))
    .map((indicator) => ({ label: kind === "url" ? "URL Indicator" : "Email Indicator", detail: indicator, severity: riskLevel(score) }));
  return {
    id: crypto.randomUUID(),
    filename: kind === "url" ? input : "Pasted email / EML content",
    media_type: kind,
    uploaded_at: new Date().toISOString(),
    scores: { authenticity_score: 100 - score, deepfake_probability: 0, risk_level: riskLevel(score), confidence_score: 86, threat_score: score },
    metadata: { file_size_mb: kind === "email" ? Number((new Blob([input]).size / (1024 * 1024)).toFixed(4)) : 0, creation_date: new Date().toISOString(), codec: kind === "url" ? "URL indicator" : "Email text / EML", duration_seconds: null, tampering_indicators: indicators, camera_information: "Not applicable", editing_software: "Not applicable", exif_data: {} },
    face_analysis: {},
    lip_sync_analysis: {},
    audio_clone_detection: {},
    image_forensics: {},
    url_analysis: kind === "url" ? { indicators } : {},
    email_analysis: kind === "email" ? { indicators, highlight_terms: ["password", "urgent", "verify", "suspended", "invoice", "gift card"] } : {},
    suspicious_frames: [],
    evidence,
    verdict,
    ai_classification: classifyAiProbability(0),
    analysis_summary: `${kind.toUpperCase()} analysis completed using matched threat indicators.`,
    key_findings: evidence.length ? evidence.map((item) => item.detail) : ["No high-risk text indicators were detected."],
    conclusion: score >= 35 ? "Threat indicators were detected; verify through an independent channel." : "No high-risk indicators were detected.",
    reasons_for_decision: indicators,
    recommendations: kind === "url" ? ["Use official domains typed manually.", "Do not enter credentials on suspicious URLs.", "Report suspicious links."] : ["Do not click suspicious links or attachments.", "Verify the sender through a trusted channel.", "Report suspected phishing."],
    awareness_message: "Do not forward unverified media",
  };
}

export function analyzeUrlInput(rawUrl: string): AnalysisReport {
  const url = rawUrl.trim();
  const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return baseTextReport(url, "url", 90, ["Malformed URL structure detected."], "Likely Phishing");
  }
  const domain = parsed.hostname.toLowerCase();
  const indicators: string[] = [];
  let score = 0;
  if (parsed.protocol !== "https:") { indicators.push("URL does not use HTTPS."); score += 18; }
  if (url.includes("@")) { indicators.push("URL contains @ redirection syntax."); score += 25; }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) { indicators.push("Domain uses a raw IP address."); score += 25; }
  if (domain.split(".").filter(Boolean).length > 3) { indicators.push("Excessive subdomain depth detected."); score += 12; }
  if (/(login|verify|secure|account|update|wallet|reset)/i.test(url)) { indicators.push("Credential or account-verification keyword detected."); score += 18; }
  if (/(paypa1|g00gle|micros0ft|amaz0n|appleid|secure-bank)/i.test(domain)) { indicators.push("Potential typosquatting or brand impersonation detected."); score += 28; }
  if (domain.includes("-")) { indicators.push("Hyphenated domain structure detected."); score += 8; }
  if (!indicators.length) indicators.push("No phishing URL indicators detected.");
  const finalScore = clamp(score, 0, 100);
  return baseTextReport(url, "url", finalScore, indicators, finalScore >= 65 ? "Likely Phishing" : finalScore >= 35 ? "Suspicious URL" : "No URL Threat Detected");
}

export function analyzeEmailInput(rawEmail: string): AnalysisReport {
  const lowered = rawEmail.toLowerCase();
  const indicators: string[] = [];
  let score = 0;
  [
    ["Credential theft language detected.", /(password|verify your account|login immediately|reset your account)/i, 22],
    ["Urgency or threat pressure detected.", /(urgent|suspended|24 hours|immediately|final notice)/i, 22],
    ["Payment or reward lure detected.", /(prize|refund|invoice|wire transfer|gift card|crypto)/i, 22],
    ["Attachment or link risk detected.", /(\.exe|\.scr|bit\.ly|tinyurl|http:\/\/)/i, 22],
    ["Impersonation from consumer email domain detected.", /from:.*(support|security|admin).*@(gmail|outlook|yahoo)\./i, 22],
    ["Generic greeting often used in phishing.", /(dear customer|dear user)/i, 10],
  ].forEach(([label, regex, points]) => {
    if ((regex as RegExp).test(lowered)) {
      indicators.push(String(label));
      score += Number(points);
    }
  });
  if (!indicators.length) indicators.push("No scam or phishing indicators detected.");
  const finalScore = clamp(score, 0, 100);
  return baseTextReport(rawEmail, "email", finalScore, indicators, finalScore >= 65 ? "Likely Email Scam" : finalScore >= 35 ? "Suspicious Email" : "No Email Threat Detected");
}
