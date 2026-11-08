// severity colours come from the active theme (index.css), so these are CSS variables, not hex
export const SEV = {
  critical: { label: "Critical", color: "var(--redline)", rank: 4 },
  high: { label: "High", color: "var(--marker)", rank: 3 },
  medium: { label: "Medium", color: "var(--highlight)", rank: 2 },
  low: { label: "Low", color: "var(--chalk)", rank: 1 },
};
export const SEV_ORDER = ["critical", "high", "medium", "low"];

export const sevForScore = (s) => (s >= 80 ? "critical" : s >= 60 ? "high" : s >= 40 ? "medium" : s > 0 ? "low" : "none");
export const colorForScore = (s) => SEV[sevForScore(s)]?.color ?? "var(--graphite)";

export function timeAgo(iso, now = Date.now()) {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const clock = (iso) => (iso && Number.isFinite(new Date(iso).getTime()) ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
export const stamp = (iso) => (iso && Number.isFinite(new Date(iso).getTime()) ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "");

export function bytes(n) {
  if (n == null || !Number.isFinite(Number(n))) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

export function midEllipsis(s, max = 44) {
  if (!s || s.length <= max) return s || "";
  const keep = max - 1;
  const head = Math.ceil(keep * 0.4);
  return `${s.slice(0, head)}…${s.slice(s.length - (keep - head))}`;
}

export const hex = (n) => `0x${Number(n).toString(16)}`;
export const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
export const baseName = (p) => (p || "").replace(/\\/g, "/").split("/").pop() || "";
export const dur = (s) => {
  if (s == null) return "";
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
};
