"use client";

import { FormEvent, useEffect, useState } from "react";
import { ErrorBox, Loading, PageHead, Panel, when } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AuditEntry, Role, User } from "@/types";

export default function AdminPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ email: "", full_name: "", password: "", role: "analyst" as Role });
  const [saving, setSaving] = useState(false);

  const load = () => {
    api.users().then(setUsers).catch((e) => setError(e.message));
    api.audit(150).then(setAudit).catch((e) => setError(e.message));
  };
  useEffect(load, []);

  if (me && me.role !== "admin") return <ErrorBox message="Only administrators can manage users." />;

  async function create(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await api.createUser(form);
      setForm({ email: "", full_name: "", password: "", role: "analyst" });
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create the user.");
    } finally {
      setSaving(false);
    }
  }

  async function update(target: User, change: { role?: Role; is_active?: boolean }) {
    try {
      await api.updateUser(target.id, change);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed.");
    }
  }

  const emailById = Object.fromEntries((users ?? []).map((u) => [u.id, u.email]));
  return (
    <>
      <PageHead eyebrow="Administration" title="Users & audit" lede="Role-based access: analysts see their own captures, viewers read everything, administrators manage users." />
      <ErrorBox message={error} />
      <div className="grid cols-3" style={{ marginTop: 12 }}>
        <Panel title="Users" className="span-2">
          {!users ? <Loading /> : (
            <div className="table-wrap"><table className="data">
              <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Last login</th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td>{u.full_name || "—"}</td>
                    <td>
                      <select className="input" style={{ height: 32 }} value={u.role} disabled={u.id === me?.id} onChange={(e) => update(u, { role: e.target.value as Role })}>
                        <option value="admin">admin</option><option value="analyst">analyst</option><option value="viewer">viewer</option>
                      </select>
                    </td>
                    <td>
                      <button className="btn secondary small" disabled={u.id === me?.id} onClick={() => update(u, { is_active: !u.is_active })}>
                        {u.is_active ? "Active · disable" : "Disabled · enable"}
                      </button>
                    </td>
                    <td className="muted">{when(u.last_login_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </Panel>
        <Panel title="Add user">
          <form className="grid" style={{ gap: 12 }} onSubmit={create}>
            <div className="field"><label htmlFor="u-email">Email</label><input id="u-email" className="input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
            <div className="field"><label htmlFor="u-name">Full name</label><input id="u-name" className="input" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></div>
            <div className="field">
              <label htmlFor="u-pass">Initial password</label>
              <input id="u-pass" className="input" type="password" minLength={12} required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <span className="muted" style={{ fontSize: 12 }}>12+ characters, three of: lowercase, uppercase, digits, symbols.</span>
            </div>
            <div className="field">
              <label htmlFor="u-role">Role</label>
              <select id="u-role" className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                <option value="analyst">analyst</option><option value="viewer">viewer</option><option value="admin">admin</option>
              </select>
            </div>
            <button className="btn" type="submit" disabled={saving}>{saving ? "Creating…" : "Create user"}</button>
          </form>
        </Panel>
      </div>
      <Panel title="Audit log" aside={<span>latest 150 events</span>} className="" >
        {!audit ? <Loading /> : (
          <div className="table-wrap"><table className="data">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Outcome</th><th>Resource</th><th>IP</th><th>Detail</th></tr></thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td className="muted" style={{ whiteSpace: "nowrap" }}>{when(a.created_at)}</td>
                  <td>{a.user_id ? emailById[a.user_id] ?? a.user_id.slice(0, 8) : "—"}</td>
                  <td className="mono">{a.action}</td>
                  <td><span className={`badge ${a.outcome === "success" ? "st-completed" : "st-failed"}`}>{a.outcome}</span></td>
                  <td className="mono">{a.resource_type ? `${a.resource_type}:${(a.resource_id ?? "").slice(0, 12)}` : "—"}</td>
                  <td className="mono">{a.ip_address ?? "—"}</td>
                  <td className="evidence">{Object.entries(a.detail).map(([k, v]) => `${k}=${String(v)}`).join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Panel>
    </>
  );
}
