import { backendUrl, proxyResponse } from "../_utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const response = await fetch(backendUrl("/analyze"), {
      method: "POST",
      body: form,
    });
    return proxyResponse(response);
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "TruthLens analysis proxy failed." },
      { status: 502 },
    );
  }
}
