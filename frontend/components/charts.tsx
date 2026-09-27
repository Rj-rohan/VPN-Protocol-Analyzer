"use client";

import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITIES, SEVERITY_COLORS } from "@/components/ui";

const AXIS = { fontSize: 11, fontFamily: "DM Mono, monospace", fill: "#6b7a74" };
const INK = "#17211f";
const CATEGORY_COLORS = ["#17211f", "#ee794d", "#7fa82a", "#1f4fd1", "#a67c00", "#7a33c4", "#2f7d4f"];

export function SeverityBars({ data }: { data: Record<string, number> }) {
  const rows = SEVERITIES.map((level) => ({ level, count: data[level] ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="#e3e8df" />
        <XAxis dataKey="level" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={AXIS} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "#f1f3ed" }} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {rows.map((row) => <Cell key={row.level} fill={SEVERITY_COLORS[row.level]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryDonut({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  if (!rows.length) return <div className="empty">No predictions yet</div>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={rows} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2} stroke="none" isAnimationActive={false}>
          {rows.map((row, index) => <Cell key={row.name} fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]} />)}
        </Pie>
        <Tooltip />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function ProbabilityBars({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).map(([label, p]) => ({ label, percent: Math.round(p * 1000) / 10 }));
  return (
    <ResponsiveContainer width="100%" height={rows.length * 30 + 20}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 30, left: 10, bottom: 0 }}>
        <XAxis type="number" domain={[0, 100]} unit="%" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="label" width={96} tick={AXIS} axisLine={false} tickLine={false} />
        <Tooltip formatter={(value) => `${value}%`} cursor={{ fill: "#f1f3ed" }} />
        <Bar dataKey="percent" radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {rows.map((row, index) => <Cell key={row.label} fill={index === 0 ? "#ee794d" : "#c9d3c6"} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function SizeHistogram({ data }: { data: { range: string; packets: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="#e3e8df" />
        <XAxis dataKey="range" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={AXIS} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "#f1f3ed" }} />
        <Bar dataKey="packets" fill={INK} radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TrafficTimeline({ data }: { data: { t: number; bytes_up: number; bytes_down: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="#e3e8df" />
        <XAxis dataKey="t" unit="s" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} tickFormatter={(v) => (v >= 1024 ? `${(v / 1024).toFixed(1)}K` : String(v))} />
        <Tooltip formatter={(value: number, name) => [`${value.toLocaleString()} bytes`, name === "bytes_up" ? "Up (initiator → responder)" : "Down"]}
                 labelFormatter={(t) => `t = ${t}s`} />
        <Legend formatter={(name) => (name === "bytes_up" ? "Up" : "Down")} wrapperStyle={{ fontSize: 12 }} />
        <Area type="monotone" dataKey="bytes_up" stackId="1" stroke="#ee794d" fill="#ee794d" fillOpacity={0.35} isAnimationActive={false} />
        <Area type="monotone" dataKey="bytes_down" stackId="1" stroke={INK} fill={INK} fillOpacity={0.2} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
