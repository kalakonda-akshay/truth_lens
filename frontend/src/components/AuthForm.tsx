"use client";

import Link from "next/link";
import Script from "next/script";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
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
  const [showPassword, setShowPassword] = useState(false);
  const [otp, setOtp] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [devOtp, setDevOtp] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [googleReady, setGoogleReady] = useState(false);
  const { setSession } = useAuth();
  const router = useRouter();
  const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ?? "";
  const otpStep = mode === "login" && Boolean(challengeId);

  const complete = useCallback(async (response: Response) => {
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Authentication failed.");
    setSession(data.user as AuthUser, data.token);
    router.push(data.user?.password_reset_required ? "/change-password" : "/dashboard");
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
      } else if (mode === "login" && challengeId) {
        const response = await authRequest("/auth/login/verify", { method: "POST", body: JSON.stringify({ challenge_id: challengeId, code: otp }) });
        await complete(response);
      } else if (mode === "login") {
        const response = await authRequest("/auth/login/request", { method: "POST", body: JSON.stringify({ email, password }) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail ?? "Login failed.");
        setChallengeId(data.challenge_id);
        setDevOtp(data.dev_otp ?? "");
        setMessage(data.message ?? "Enter the OTP to continue.");
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
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={otpStep} required placeholder="Email address" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500 disabled:bg-slate-100 disabled:text-slate-500" />
          {mode !== "forgot" && (
            <div className="relative">
              <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} disabled={otpStep} autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={8} placeholder="Password (8+ characters)" className="w-full rounded-xl border border-slate-200 px-4 py-3 pr-12 outline-none focus:border-blue-500 disabled:bg-slate-100 disabled:text-slate-500" />
              <button type="button" onClick={() => setShowPassword((value) => !value)} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg p-1 text-slate-500 hover:bg-slate-100" aria-label={showPassword ? "Hide password" : "Show password"}>
                {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
              </button>
            </div>
          )}
          {otpStep && <input inputMode="numeric" pattern="[0-9]*" value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} required minLength={6} maxLength={6} placeholder="Enter 6-digit OTP" className="w-full rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 font-bold tracking-widest outline-none focus:border-blue-500" />}
          {error && <p className="rounded-lg bg-red-50 p-3 text-sm font-semibold text-red-700">{error}</p>}
          {message && <p className="rounded-lg bg-emerald-50 p-3 text-sm font-semibold text-emerald-700">{message}</p>}
          {devOtp && <p className="rounded-lg bg-slate-100 p-3 text-center text-sm font-black text-slate-700">Prototype OTP: {devOtp}</p>}
          <button disabled={busy} className="relative w-full overflow-hidden rounded-xl bg-blue-600 px-5 py-3 font-black text-white hover:bg-blue-700 disabled:opacity-70">
            {busy && <span className="absolute inset-y-0 left-0 w-1/2 animate-login-slide bg-white/20" />}
            <span className="relative">{busy ? "Securing login..." : challengeId ? "Verify OTP" : title}</span>
          </button>
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
