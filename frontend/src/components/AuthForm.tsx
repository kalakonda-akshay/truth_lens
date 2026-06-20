"use client";

import Link from "next/link";
import Script from "next/script";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { authRequest, AuthUser, useAuth } from "@/lib/auth";

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (options: { client_id: string; callback: (response: { credential: string }) => void }) => void;
          renderButton: (element: HTMLElement, options: Record<string, unknown>) => void;
        };
      };
    };
  }
}

export function AuthForm({ mode }: { mode: "login" | "signup" | "forgot" }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [googleReady, setGoogleReady] = useState(false);
  const { setSession } = useAuth();
  const router = useRouter();
  const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ?? "";

  const complete = useCallback(async (response: Response) => {
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Authentication failed.");
    setSession(data.user as AuthUser, data.token);
    router.push("/dashboard");
  }, [router, setSession]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (mode === "forgot") {
        const response = await authRequest("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail ?? "Recovery request failed.");
        setMessage(data.message);
      } else {
        const response = await authRequest(`/auth/${mode}`, { method: "POST", body: JSON.stringify({ name, email, password }) });
        await complete(response);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!googleClientId || !googleReady || !window.google || mode === "forgot") return;
    window.google.accounts.id.initialize({
      client_id: googleClientId,
      callback: async ({ credential }) => {
        setBusy(true);
        setError("");
        try {
          await complete(await authRequest("/auth/google", { method: "POST", body: JSON.stringify({ credential }) }));
        } catch (reason) {
          setError(reason instanceof Error ? reason.message : "Google Sign-In failed.");
        } finally {
          setBusy(false);
        }
      },
    });
    const target = document.getElementById("google-signin");
    if (target) window.google.accounts.id.renderButton(target, { theme: "outline", size: "large", width: 360 });
  }, [complete, googleClientId, googleReady, mode]);

  const title = mode === "login" ? "Analyst Login" : mode === "signup" ? "Create Analyst Account" : "Recover Account";

  return (
    <main className="grid min-h-screen place-items-center bg-[#07122B] px-5 py-12">
      {googleClientId && mode !== "forgot" && <Script src="https://accounts.google.com/gsi/client" strategy="afterInteractive" onLoad={() => setGoogleReady(true)} />}
      <section className="w-full max-w-md rounded-2xl bg-white p-7 shadow-2xl">
        <Link href="/" className="mb-7 flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl bg-[#07122B] text-white"><ShieldCheck /></div><div><p className="text-xl font-black">TruthLens AI</p><p className="text-xs text-slate-500">Secure Investigation Workspace</p></div></Link>
        <h1 className="text-2xl font-black">{title}</h1>
        <p className="mt-2 text-sm text-slate-500">Access user-linked cases, evidence and forensic reports.</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          {mode === "signup" && <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="Full name" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500" />}
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="Email address" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500" />
          {mode !== "forgot" && <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} placeholder="Password (8+ characters)" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500" />}
          {error && <p className="rounded-lg bg-red-50 p-3 text-sm font-semibold text-red-700">{error}</p>}
          {message && <p className="rounded-lg bg-emerald-50 p-3 text-sm font-semibold text-emerald-700">{message}</p>}
          <button disabled={busy} className="w-full rounded-xl bg-blue-600 px-5 py-3 font-black text-white hover:bg-blue-700 disabled:opacity-60">{busy ? "Please wait..." : title}</button>
        </form>
        {mode !== "forgot" && (
          <>
            <div className="my-5 flex items-center gap-3 text-xs text-slate-400"><span className="h-px flex-1 bg-slate-200" />OR<span className="h-px flex-1 bg-slate-200" /></div>
            {googleClientId ? <div id="google-signin" className="flex justify-center" /> : <p className="rounded-lg bg-amber-50 p-3 text-center text-xs font-semibold text-amber-700">Google Sign-In requires NEXT_PUBLIC_GOOGLE_CLIENT_ID.</p>}
          </>
        )}
        <div className="mt-6 flex justify-between text-sm font-bold text-blue-600">
          {mode === "login" ? <><Link href="/signup">Create account</Link><Link href="/forgot-password">Forgot password?</Link></> : <Link href="/login">Back to login</Link>}
        </div>
      </section>
    </main>
  );
}
