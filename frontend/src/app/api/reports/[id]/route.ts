import { backendUrl, proxyResponse } from "../../_utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await context.params;
    const response = await fetch(backendUrl(`/reports/${encodeURIComponent(id)}`), {
      cache: "no-store",
    });
    return proxyResponse(response);
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "TruthLens report proxy failed." },
      { status: 502 },
    );
  }
}
