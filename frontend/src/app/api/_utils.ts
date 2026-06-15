const BACKEND_URL = (process.env.NEXT_PUBLIC_API_URL ?? process.env.API_URL ?? "").replace(/\/$/, "");

export function backendUrl(path: string) {
  if (!BACKEND_URL) {
    throw new Error("TruthLens backend URL is not configured.");
  }
  return `${BACKEND_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

export async function proxyResponse(response: Response) {
  const contentType = response.headers.get("content-type") ?? "application/json";
  const body = await response.arrayBuffer();
  return new Response(body, {
    status: response.status,
    headers: {
      "content-type": contentType,
    },
  });
}
