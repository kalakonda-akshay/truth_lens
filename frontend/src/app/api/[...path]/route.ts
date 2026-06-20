import { backendUrl, proxyResponse } from "../_utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function forward(request: Request, context: { params: Promise<{ path: string[] }> }) {
  try {
    const { path } = await context.params;
    const contentType = request.headers.get("content-type") ?? "";
    const body = request.method === "GET" ? undefined : contentType.includes("multipart/form-data") ? await request.formData() : await request.text();
    const response = await fetch(backendUrl(`/${path.join("/")}`), {
      method: request.method,
      headers: {
        ...(contentType && !contentType.includes("multipart/form-data") ? { "content-type": contentType } : {}),
        ...(request.headers.get("authorization") ? { authorization: request.headers.get("authorization")! } : {}),
      },
      body,
      cache: "no-store",
    });
    return proxyResponse(response);
  } catch (error) {
    return Response.json({ detail: error instanceof Error ? error.message : "TruthLens API proxy failed." }, { status: 502 });
  }
}

export const GET = forward;
export const POST = forward;
