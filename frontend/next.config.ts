import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: path.join(__dirname),
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
};

export default nextConfig;
