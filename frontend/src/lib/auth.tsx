"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export type AuthUser = {
  id: string;
  email: string;
  name: string;
  avatar_url: string;
  provider: string;
};

type AuthContextValue = {
  user: AuthUser | null;
  token: string;
  ready: boolean;
  setSession: (user: AuthUser, token: string) => void;
  signOut: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

export function authToken() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("truthlens:token") ?? "";
}

export async function authRequest(path: string, init: RequestInit = {}) {
  const token = authToken();
  return fetch(`${BASE_PATH}/api${path}`, {
    ...init,
    headers: {
      ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const savedToken = localStorage.getItem("truthlens:token") ?? "";
    const savedUser = localStorage.getItem("truthlens:user");
    setToken(savedToken);
    if (savedUser) {
      try {
        setUser(JSON.parse(savedUser));
      } catch {
        localStorage.removeItem("truthlens:user");
      }
    }
    setReady(true);
  }, []);

  function setSession(nextUser: AuthUser, nextToken: string) {
    localStorage.setItem("truthlens:token", nextToken);
    localStorage.setItem("truthlens:user", JSON.stringify(nextUser));
    setUser(nextUser);
    setToken(nextToken);
  }

  function signOut() {
    void authRequest("/auth/logout", { method: "POST" });
    localStorage.removeItem("truthlens:token");
    localStorage.removeItem("truthlens:user");
    setUser(null);
    setToken("");
  }

  return <AuthContext.Provider value={{ user, token, ready, setSession, signOut }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && !user) router.replace("/login");
  }, [ready, router, user]);

  if (!ready || !user) {
    return <div className="grid min-h-screen place-items-center bg-[#07122B] text-sm font-bold text-white">Opening secure workspace...</div>;
  }
  return <>{children}</>;
}
