export type ScanStats = {
  total: number;
  image: number;
  video: number;
  audio: number;
  highRisk: number;
};

const STORAGE_KEY = "truthlens:scan-stats";

export const defaultStats: ScanStats = {
  total: 0,
  image: 0,
  video: 0,
  audio: 0,
  highRisk: 0,
};

export function readStats(): ScanStats {
  if (typeof window === "undefined") return defaultStats;
  try {
    return { ...defaultStats, ...JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}") };
  } catch {
    return defaultStats;
  }
}

export function recordScan(mediaType: string, riskLevel: string) {
  const next = readStats();
  next.total += 1;
  if (mediaType === "image") next.image += 1;
  if (mediaType === "video") next.video += 1;
  if (mediaType === "audio") next.audio += 1;
  if (riskLevel === "High" || riskLevel === "Critical") next.highRisk += 1;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  window.dispatchEvent(new CustomEvent("truthlens:stats", { detail: next }));
}
