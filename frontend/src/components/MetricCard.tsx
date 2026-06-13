import clsx from "clsx";

type MetricCardProps = {
  label: string;
  value: string;
  tone?: "cyan" | "green" | "amber" | "red";
};

const tones = {
  cyan: "text-cyber-cyan border-cyber-cyan/30",
  green: "text-cyber-green border-cyber-green/30",
  amber: "text-cyber-amber border-cyber-amber/30",
  red: "text-cyber-red border-cyber-red/30",
};

export function MetricCard({ label, value, tone = "cyan" }: MetricCardProps) {
  return (
    <div className={clsx("glass rounded-2xl border p-5", tones[tone])}>
      <p className="text-sm uppercase tracking-[0.28em] text-slate-400">{label}</p>
      <p className="mt-3 text-4xl font-black">{value}</p>
    </div>
  );
}
