import { backendUrl, proxyResponse } from "../../../_utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await context.params;
    const response = await fetch(backendUrl(`/reports/${encodeURIComponent(id)}/pdf`), {
      cache: "no-store",
    });
    const proxied = await proxyResponse(response);
    proxied.headers.set("content-disposition", `attachment; filename="truthlens-${id}.pdf"`);
    return proxied;
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "TruthLens PDF proxy failed." },
      { status: 502 },
    );
  }
}
