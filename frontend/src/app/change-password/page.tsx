"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Eye, EyeOff, KeyRound, ShieldCheck } from "lucide-react";
import { authRequest, useAuth } from "@/lib/auth";

export default function ChangePasswordPage() {
  const { user, signOut } = useAuth();
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPasswords, setShowPasswords] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const response = await authRequest("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Password update failed.");
      signOut();
      router.replace("/login");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Password update failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-[#07122B] px-5 py-12">
      <section className="w-full max-w-lg rounded-2xl bg-white p-7 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-blue-50 text-blue-700"><ShieldCheck /></div>
          <div>
            <p className="text-2xl font-black">Set New Password</p>
            <p className="text-sm text-slate-500">Required before opening TruthLens.</p>
          </div>
        </div>
        <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm font-semibold text-amber-900">
          {user?.password_reset_required ? "Your account was reset by an administrator. Enter the temporary password, then choose a new password." : "You can update your password here."}
        </div>
        <form onSubmit={submit} className="space-y-4">
          <div className="relative">
            <input type={showPasswords ? "text" : "password"} value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required placeholder="Current or temporary password" className="w-full rounded-xl border border-slate-200 px-4 py-3 pr-12 outline-none focus:border-blue-500" />
            <button type="button" onClick={() => setShowPasswords((value) => !value)} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg p-1 text-slate-500 hover:bg-slate-100" aria-label={showPasswords ? "Hide passwords" : "Show passwords"}>
              {showPasswords ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
            </button>
          </div>
          <input type={showPasswords ? "text" : "password"} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required minLength={8} placeholder="New password (8+ characters)" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500" />
          <input type={showPasswords ? "text" : "password"} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required minLength={8} placeholder="Confirm new password" className="w-full rounded-xl border border-slate-200 px-4 py-3 outline-none focus:border-blue-500" />
          {error && <p className="rounded-lg bg-red-50 p-3 text-sm font-semibold text-red-700">{error}</p>}
          <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-3 font-black text-white hover:bg-blue-700 disabled:opacity-60">
            <KeyRound className="h-5 w-5" />{busy ? "Updating..." : "Update Password"}
          </button>
        </form>
      </section>
    </main>
  );
}
