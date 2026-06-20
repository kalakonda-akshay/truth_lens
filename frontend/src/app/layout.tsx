import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";

export const metadata: Metadata = {
  title: "TruthLens | Deepfake Verification",
  description: "AI-powered Deepfake and Synthetic Media Verification Platform for Cyberathon 2026",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased"><AuthProvider>{children}</AuthProvider></body>
    </html>
  );
}
