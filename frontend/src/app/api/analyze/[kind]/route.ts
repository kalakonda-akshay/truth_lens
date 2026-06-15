import { backendUrl, proxyResponse } from "../../_utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SUPPORTED_KINDS = new Set(["url", "email"]);

export async function POST(request: Request, context: { params: Promise<{ kind: string }> }) {
  try {
    const { kind } = await context.params;
    if (!SUPPORTED_KINDS.has(kind)) {
      return Response.json({ detail: "Unsupported analysis type." }, { status: 404 });
    }
    const body = await request.text();
    const response = await fetch(backendUrl(`/analyze/${kind}`), {
      method: "POST",
      headers: { "content-type": request.headers.get("content-type") ?? "application/json" },
      body,
    });
    return proxyResponse(response);
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "TruthLens text analysis proxy failed." },
      { status: 502 },
    );
  }
}
