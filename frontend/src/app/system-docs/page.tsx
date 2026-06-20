"use client";

import { useEffect, useState } from "react";
import { Download, Server, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { authRequest, useAuth } from "@/lib/auth";

type Documentation = {
  generated_at: string;
  source: string;
  frontend: Record<string, unknown>;
  backend: Record<string, unknown>;
  authentication: Record<string, unknown>;
  database: { provider: string; path: string; tables: Array<{ name: string; fields: Array<Record<string, unknown>> }>; logical_entities: Record<string, string> };
  integrations: Array<Record<string, string>>;
  pipelines: Record<string, string[]>;
  report_engine: Record<string, string>;
  deployment: Record<string, unknown>;
  health: Record<string, string>;
};

function renderValue(value: unknown) {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object" && value !== null) return JSON.stringify(value);
  return String(value);
}

function DetailSection({ title, data }: { title: string; data: Record<string, unknown> }) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-lg font-black text-slate-950">{title}</h2>
      <div className="mt-5 divide-y divide-slate-100">
        {Object.entries(data).map(([label, value]) => (
          <div key={label} className="grid gap-2 py-4 sm:grid-cols-[210px_1fr]">
            <p className="text-xs font-black uppercase tracking-wide text-slate-500">{label.replaceAll("_", " ")}</p>
            <p className="break-words text-sm leading-6 text-slate-700">{renderValue(value)}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function SystemDocumentationPage() {
  const { user } = useAuth();
  const [docs, setDocs] = useState<Documentation | null>(null);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    if (!user) return;
    if (user.role !== "administrator") {
      setError("Administrator access required.");
      return;
    }
    authRequest("/system/documentation", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error(response.status === 403 ? "Administrator access required." : "Unable to load system documentation.");
        setDocs(await response.json());
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load system documentation."));
  }, [user]);

  async function exportPdf() {
    setExporting(true);
    setError("");
    try {
      const response = await authRequest("/system/documentation/pdf", { cache: "no-store" });
      if (!response.ok) throw new Error("Documentation export failed.");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "truthlens-system-documentation.pdf";
      link.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Documentation export failed.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <AppShell title="System Documentation" subtitle="Administrator-only architecture reference generated from the running TruthLens implementation.">
      {error && <div className="rounded-2xl border border-red-200 bg-red-50 p-6 font-bold text-red-700">{error}</div>}
      {!error && !docs && <div className="rounded-2xl border border-slate-200 bg-white p-8 text-sm text-slate-500">Inspecting TruthLens architecture and configuration...</div>}
      {docs && (
        <div className="space-y-5">
          <section className="flex flex-col justify-between gap-5 rounded-2xl bg-[#07122B] p-6 text-white shadow-sm md:flex-row md:items-center">
            <div><div className="flex items-center gap-3"><ShieldCheck className="h-7 w-7 text-blue-400" /><h2 className="text-2xl font-black">TruthLens Architecture Reference</h2></div><p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">{docs.source}</p><p className="mt-2 text-xs text-slate-400">Generated {new Date(docs.generated_at).toLocaleString()}</p></div>
            <button onClick={exportPdf} disabled={exporting} className="flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-black hover:bg-blue-500 disabled:opacity-60"><Download className="h-5 w-5" />{exporting ? "Generating PDF..." : "Export System Documentation"}</button>
          </section>

          <div className="grid gap-5 xl:grid-cols-2">
            <DetailSection title="1. Frontend Stack" data={docs.frontend} />
            <DetailSection title="2. Backend Stack" data={docs.backend} />
            <DetailSection title="3. Authentication" data={docs.authentication} />
            <DetailSection title="4. Database" data={{ provider: docs.database.provider, path: docs.database.path, logical_entities: docs.database.logical_entities }} />
          </div>

          <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="text-lg font-black">Database Tables and Stored Fields</h2>
            <div className="mt-5 grid gap-4 lg:grid-cols-3">{docs.database.tables.map((table) => <div key={table.name} className="rounded-xl border border-slate-200 bg-slate-50 p-4"><p className="font-black text-blue-700">{table.name}</p><div className="mt-3 space-y-2">{table.fields.map((field) => <p key={String(field.name)} className="text-xs text-slate-600"><span className="font-black text-slate-900">{String(field.name)}</span> · {String(field.type)}{field.primary_key ? " · primary key" : ""}{field.required ? " · required" : ""}</p>)}</div></div>)}</div>
          </section>

          <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="text-lg font-black">5. API Integrations</h2>
            <div className="mt-5 grid gap-4 lg:grid-cols-2">{docs.integrations.map((integration) => <div key={integration.name} className="rounded-xl border border-slate-200 p-5"><div className="flex items-center justify-between gap-3"><p className="font-black">{integration.name}</p><span className={`rounded-full px-3 py-1 text-xs font-black ${["Operational", "Configured"].includes(integration.status) ? "bg-emerald-50 text-emerald-700" : integration.status === "Removed" ? "bg-slate-100 text-slate-600" : "bg-amber-50 text-amber-700"}`}>{integration.status}</span></div>{["purpose", "endpoint", "usage", "credentials"].map((key) => <p key={key} className="mt-3 text-sm leading-6 text-slate-600"><span className="font-black capitalize text-slate-900">{key}:</span> {integration[key]}</p>)}</div>)}</div>
          </section>

          <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="text-lg font-black">6–10. Forensic Pipelines</h2>
            <div className="mt-5 grid gap-5 lg:grid-cols-2">{Object.entries(docs.pipelines).map(([name, steps]) => <div key={name} className="rounded-xl bg-slate-50 p-5"><p className="font-black text-blue-700">{name} Pipeline</p><ol className="mt-4 space-y-3">{steps.map((step, index) => <li key={step} className="flex gap-3 text-sm leading-6 text-slate-700"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-blue-600 text-xs font-black text-white">{index + 1}</span>{step}</li>)}</ol></div>)}</div>
          </section>

          <div className="grid gap-5 xl:grid-cols-2">
            <DetailSection title="11. Report Engine" data={docs.report_engine} />
            <DetailSection title="12. Deployment" data={docs.deployment} />
          </div>

          <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center gap-3"><Server className="h-6 w-6 text-blue-600" /><h2 className="text-lg font-black">13. System Health</h2></div>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{Object.entries(docs.health).map(([name, status]) => <div key={name} className="rounded-xl border border-slate-200 p-4"><p className="text-sm font-black">{name}</p><p className={`mt-2 text-xs font-black ${status.includes("Operational") || status === "Configured" ? "text-emerald-600" : "text-amber-600"}`}>{status}</p></div>)}</div>
          </section>
        </div>
      )}
    </AppShell>
  );
}
