"use client";

import { useRouter } from "next/navigation";
import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, session } from "@/lib/api";
import type { User } from "@/types";

type AuthState = { user: User | null; ready: boolean; login: (email: string, password: string) => Promise<void>; logout: () => void };

const AuthContext = createContext<AuthState>({ user: null, ready: false, login: async () => {}, logout: () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const router = useRouter();

  useEffect(() => {
    setUser(session.get()?.user ?? null);
    setReady(true);
    const onLogout = () => {
      setUser(null);
      router.replace("/login");
    };
    window.addEventListener("ipsec:logout", onLogout);
    return () => window.removeEventListener("ipsec:logout", onLogout);
  }, [router]);

  const login = useCallback(async (email: string, password: string) => {
    const response = await api.login(email, password);
    session.set(response);
    setUser(response.user);
  }, []);

  const logout = useCallback(() => {
    session.clear();
    setUser(null);
    router.replace("/login");
  }, [router]);

  return <AuthContext.Provider value={{ user, ready, login, logout }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
