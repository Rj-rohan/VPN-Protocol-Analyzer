"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { ErrorBox } from "@/components/ui";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { user, ready, login } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (ready && user) router.replace("/");
  }, [ready, user, router]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center-screen">
      <form className="panel login-card" onSubmit={submit}>
        <div className="brand"><span className="brand-mark">◈</span>IPSEC / SCOPE</div>
        <div>
          <h1 style={{ margin: "6px 0 4px", fontSize: 28, letterSpacing: "-.03em" }}>Sign in</h1>
          <p className="muted" style={{ margin: 0, fontSize: 14 }}>IPsec VPN protocol analyzer and security assessment. Authorized personnel only.</p>
        </div>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" className="input" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <ErrorBox message={error} />
        <button className="btn" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="muted mono" style={{ fontSize: 11, margin: 0 }}>Capture files are sensitive security artifacts. All access is audited.</p>
      </form>
    </div>
  );
}
