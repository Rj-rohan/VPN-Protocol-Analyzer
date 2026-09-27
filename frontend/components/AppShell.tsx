"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect } from "react";
import { useAuth } from "@/lib/auth";

const LINKS = [
  { href: "/", label: "Dashboard", roles: ["admin", "analyst", "viewer"] },
  { href: "/upload", label: "Upload PCAP", roles: ["admin", "analyst"] },
  { href: "/live", label: "Live capture", roles: ["admin"] },
  { href: "/analyses", label: "Analyses", roles: ["admin", "analyst", "viewer"] },
  { href: "/admin", label: "Users & audit", roles: ["admin"] },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const { user, ready, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (ready && !user) router.replace("/login");
  }, [ready, user, router]);

  if (!ready || !user) return <div className="center-screen mono muted">Checking session…</div>;

  const active = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
  return (
    <div className="app">
      <aside className="sidebar">
        <Link href="/" className="brand"><span className="brand-mark">◈</span>IPSEC / SCOPE</Link>
        <nav className="nav" aria-label="Main">
          <span className="nav-label">Workspace</span>
          {LINKS.filter((link) => link.roles.includes(user.role)).map((link) => (
            <Link key={link.href} href={link.href} className={active(link.href) ? "active" : ""}>{link.label}</Link>
          ))}
        </nav>
        <div className="sidebar-foot">
          <small>SIGNED IN AS {user.role.toUpperCase()}</small>
          <span>{user.email}</span>
          <button className="btn secondary small" onClick={logout}>Sign out</button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
