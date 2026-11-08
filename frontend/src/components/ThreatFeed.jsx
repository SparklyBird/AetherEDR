import { useMemo, useState } from "react";
import { useDebounced, useKeys, isTyping } from "../lib/hooks";
import { SEV, SEV_ORDER, clock, midEllipsis, plural, timeAgo } from "../lib/format";
import { Button, Empty, ErrorPanel, Input, RiskGauge, SevDot, Segmented, Select, Tag } from "./ui";

function Strip({ buckets = [] }) {
  const rows = (Array.isArray(buckets) ? buckets : []).map((b) => {
    const n = (b.critical || 0) + (b.high || 0) + (b.medium || 0) + (b.low || 0);
    const top = SEV_ORDER.find((s) => b[s] > 0);
    return { ...b, n, top };
  });
  const max = Math.max(1, ...rows.map((r) => r.n));
  const total = rows.reduce((n, r) => n + r.n, 0);
  return (
    <div role="img" aria-label={`${total} alerts in the last 24 hours`}>
      <div className="flex h-9 items-end gap-px border-b border-rule2">
        {rows.map((r, i) => (
          <div
            key={r.t || i}
            title={`${r.t ? new Date(r.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}: ${r.n} alert${r.n === 1 ? "" : "s"}`}
            className="flex-1"
            style={{ height: r.n ? `${Math.max(14, (r.n / max) * 100)}%` : 2, background: r.top ? SEV[r.top].color : "var(--rule)" }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[0.68rem] text-graphite tabular" aria-hidden>
        <span>24 h ago</span>
        <span>12 h</span>
        <span>now</span>
      </div>
    </div>
  );
}

export function groupAlerts(alerts) {
  const map = new Map();
  for (const a of alerts) {
    const key = `${a.host}:${a.pid ?? a.process_name}:${a.process_name}`;
    let g = map.get(key);
    if (!g) {
      g = { key, alerts: [], host_name: a.host_name, process: a.process, process_name: a.process_name, process_path: a.process_path, pid: a.pid };
      map.set(key, g);
    }
    g.alerts.push(a);
  }
  const groups = [...map.values()];
  for (const g of groups) {
    g.alerts.sort((x, y) => y.weight - x.weight || y.score - x.score);
    g.top = g.alerts[0];
    g.last = g.alerts.reduce((m, a) => (a.last_seen > m ? a.last_seen : m), "");
    g.score = Math.max(...g.alerts.map((a) => a.score));
    g.open = g.alerts.some((a) => a.status === "open");
    g.remote = g.alerts.find((a) => a.remote_ip);
    g.memory = g.alerts.some((a) => a.memory_flag);
    g.maxId = Math.max(...g.alerts.map((a) => a.id));
    g.sev = g.alerts.reduce((best, a) => (SEV[a.severity]?.rank > (SEV[best]?.rank || 0) ? a.severity : best), "low");
  }
  return groups;
}

const SHORT = { critical: "Crit", high: "High", medium: "Med", low: "Low" };

const SORTS = {
  newest: (a, b) => (a.last < b.last ? 1 : -1),
  risk: (a, b) => b.score - a.score || (a.last < b.last ? 1 : -1),
  name: (a, b) => String(a.process_name).localeCompare(String(b.process_name)) || b.score - a.score,
};

function Incident({ g, selected, checked, selecting, fresh, now, onSelect, onToggle, onStatus, onTrust }) {
  const [open, setOpen] = useState(false);
  const extra = g.alerts.length - 1;
  const resolved = !g.open;
  return (
    <li className={`relative border-b border-rule ${fresh ? "arrive" : ""} ${selected ? "bg-plate2" : ""} ${resolved ? "text-pencil" : ""}`} data-group={g.key}>
      {selected && <span className="absolute inset-y-0 left-0 w-[3px] bg-ink" aria-hidden />}
      <div className="flex items-start gap-2.5 pl-3 pr-3" style={{ paddingTop: "var(--pad)" }}>
        {selecting && (
          <input type="checkbox" checked={checked} onChange={() => onToggle(g.key)} aria-label={`Select ${g.process_name}`} className="mt-1.5 accent-[var(--ink)]" />
        )}
        <button
          type="button"
          onClick={() => g.process && onSelect(g.process)}
          className="flex min-w-0 flex-1 items-start gap-3 pb-1 text-left"
          aria-current={selected ? "true" : undefined}
        >
          <RiskGauge score={g.score} className="mt-0.5 w-[3.1rem]" />
          <span className="min-w-0 flex-1">
            <span className="flex items-baseline justify-between gap-2">
              <span className="truncate font-bold">{g.process_name || "Unknown process"}</span>
              <time className="shrink-0 text-xs text-graphite" dateTime={g.last} title={clock(g.last)}>
                {timeAgo(g.last, now)}
              </time>
            </span>
            <span className="mt-0.5 block leading-snug">{g.top.title}</span>
            <span className="mt-1 block truncate font-mono text-[0.7rem] text-graphite" title={g.process_path}>
              {midEllipsis(g.process_path || `PID ${g.pid}`, 46)}
            </span>
            <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
              <Tag>{g.host_name}</Tag>
              <Tag mono title="Rule that raised this">{g.top.rule_id}</Tag>
              {g.remote && <Tag tone="var(--chalk)" title="Remote address">{g.remote.remote_ip}</Tag>}
              {g.memory && <span className="hl text-xs" title="Executable memory without a backing file, or RWX regions">memory flagged</span>}
              {resolved && <Tag title={g.alerts[0].suppression ? "Closed because an exception covers it. Remove the exception on the Exceptions sheet to bring it back." : undefined}>{g.alerts[0].suppression ? "muted by exception" : g.alerts[0].status.replace("_", " ")}</Tag>}
            </span>
          </span>
        </button>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 pl-[4.9rem] pr-3 pt-0.5">
        {extra > 0 ? (
          <button type="button" className="text-xs text-pencil underline underline-offset-2 hover:text-ink" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
            {open ? "Hide" : "Show"} {plural(extra, "more detection")}
          </button>
        ) : (
          <span />
        )}
        <span className="flex flex-wrap gap-1">
          {g.open ? (
            <>
              <Button size="sm" onClick={() => onStatus(g.alerts, "ack")} title="Seen it. Keeps the alert, moves it out of the way. (a)">Acknowledge</Button>
              <Button size="sm" onClick={() => onStatus(g.alerts, "false_positive")} title="Not a threat. (x)">False positive</Button>
              <Button size="sm" variant="ghost" onClick={() => onTrust(g)} title="Stop alerting on this behaviour">Trust…</Button>
            </>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => onStatus(g.alerts, "open")}>Reopen</Button>
          )}
        </span>
      </div>
      {open && (
        <ul className="space-y-1 pb-3 pl-[4.9rem] pr-3">
          {g.alerts.slice(1).map((a) => (
            <li key={a.id} className="flex items-start gap-2 text-[0.8125rem] text-pencil">
              <SevDot sev={a.severity} className="mt-1.5" />
              <span className="min-w-0">
                <span className="text-ink">{a.title}</span>
                <span className="ml-1.5 font-mono text-xs text-graphite">{a.rule_id}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function ThreatFeed({ alerts, timeline, selectedProcess, onSelect, onStatus, onTrust, freshIds, now, loading, error, onRetry, onClear, sevFilter, setSevFilter }) {
  const [view, setView] = useState("active"); // active | open | resolved | all
  const [sort, setSort] = useState("newest");
  const [text, setText] = useState("");
  const [selecting, setSelecting] = useState(false);
  const [checked, setChecked] = useState(new Set());
  const q = useDebounced(text, 150).trim().toLowerCase();

  const counts = useMemo(() => {
    const c = { all: 0 };
    for (const a of alerts) if (a.status === "open" || a.status === "ack") (c.all++, (c[a.severity] = (c[a.severity] || 0) + 1));
    return c;
  }, [alerts]);

  const groups = useMemo(() => {
    const okStatus = {
      active: (a) => a.status === "open" || a.status === "ack",
      open: (a) => a.status === "open",
      resolved: (a) => a.status === "closed" || a.status === "false_positive",
      all: () => true,
    }[view];
    const visible = alerts.filter(
      (a) =>
        okStatus(a) &&
        (sevFilter === "all" || a.severity === sevFilter) &&
        (!q || `${a.process_name} ${a.title} ${a.rule_id} ${a.process_path} ${a.remote_ip} ${a.host_name} ${a.pid}`.toLowerCase().includes(q)),
    );
    return groupAlerts(visible).sort(SORTS[sort]);
  }, [alerts, view, sevFilter, sort, q]);

  const picked = groups.filter((g) => checked.has(g.key));
  const bulk = (status) => {
    onStatus(picked.flatMap((g) => g.alerts), status);
    setChecked(new Set());
  };

  useKeys(
    (e) => {
      if (isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || document.querySelector("dialog[open]")) return;
      const i = groups.findIndex((g) => g.process != null && g.process === selectedProcess);
      if (e.key === "j" || e.key === "k") {
        const next = groups[Math.max(0, Math.min(groups.length - 1, i + (e.key === "j" ? 1 : -1)))];
        if (next?.process != null) {
          onSelect(next.process);
          document.querySelector(`[data-group="${CSS.escape(next.key)}"]`)?.scrollIntoView({ block: "nearest" });
          e.preventDefault();
        }
      } else if ((e.key === "a" || e.key === "x") && i >= 0 && groups[i].open) {
        onStatus(groups[i].alerts, e.key === "a" ? "ack" : "false_positive");
        e.preventDefault();
      }
    },
    [groups, selectedProcess],
  );

  return (
    <section aria-label="Incident log" className="flex h-full min-h-0 flex-col bg-plate">
      <div className="space-y-2.5 border-b border-rule2 p-3">
        <div className="flex items-baseline justify-between">
          <h2 className="text-[0.9375rem] font-bold">Incident log</h2>
          <span className="flex items-baseline gap-3">
            {onClear && (
              <button type="button" onClick={onClear} title="Remove exited processes and old alerts" className="text-xs text-pencil underline underline-offset-2 hover:text-ink">
                Clear...
              </button>
            )}
            <button type="button" onClick={() => (setSelecting((s) => !s), setChecked(new Set()))} aria-pressed={selecting} className={`text-xs underline underline-offset-2 ${selecting ? "text-ink" : "text-pencil hover:text-ink"}`}>
              {selecting ? "Done selecting" : "Select"}
            </button>
          </span>
        </div>
        <Strip buckets={timeline} />
        <Input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter by process, rule, path or address" aria-label="Filter incident log" className="w-full !py-1" />
        <Segmented
          size="sm"
          label="Filter by severity"
          value={sevFilter}
          onChange={setSevFilter}
          className="w-full [&>button]:flex-1"
          options={[{ value: "all", label: "All", count: counts.all }, ...SEV_ORDER.map((s) => ({ value: s, label: SHORT[s], title: SEV[s].label, count: counts[s] || 0 }))]}
        />
        <div className="flex gap-2">
          <Select value={view} onChange={(e) => setView(e.target.value)} aria-label="Which alerts: active means open or acknowledged" title="Active means open or acknowledged" className="min-w-0 flex-1 !py-1 text-xs">
            <option value="active">Active</option>
            <option value="open">Open only</option>
            <option value="resolved">Resolved</option>
            <option value="all">Everything</option>
          </Select>
          <Select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort" className="min-w-0 flex-1 !py-1 text-xs">
            <option value="newest">Newest first</option>
            <option value="risk">Highest risk</option>
            <option value="name">Process name</option>
          </Select>
        </div>
        {selecting && (
          <div className="flex flex-wrap items-center gap-2 border border-rule2 px-2 py-1.5 text-xs">
            <span className="tabular">{picked.length} selected</span>
            <button className="underline underline-offset-2" onClick={() => setChecked(new Set(groups.map((g) => g.key)))}>All shown</button>
            <span className="ml-auto flex gap-1">
              <Button size="sm" disabled={!picked.length} onClick={() => bulk("ack")}>Acknowledge</Button>
              <Button size="sm" disabled={!picked.length} onClick={() => bulk("false_positive")}>False positive</Button>
            </span>
          </div>
        )}
      </div>

      {error && <ErrorPanel error={error} onRetry={onRetry} title="Could not load alerts" compact />}
      <ul className="min-h-0 flex-1 overflow-y-auto" aria-live="polite">
        {groups.map((g) => (
          <Incident
            key={g.key}
            g={g}
            now={now}
            selecting={selecting}
            checked={checked.has(g.key)}
            selected={g.process != null && g.process === selectedProcess}
            fresh={g.alerts.some((a) => freshIds.has(a.id))}
            onSelect={onSelect}
            onToggle={(k) => setChecked((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; })}
            onStatus={onStatus}
            onTrust={onTrust}
          />
        ))}
        {!groups.length && !error && (
          <Empty title={loading ? "Loading alerts" : alerts.length ? "Nothing matches these filters" : "No alerts yet"}>
            {loading ? "" : alerts.length ? "Clear the filter or widen the status." : "Detections appear here the moment they are raised."}
          </Empty>
        )}
      </ul>
      <div className="flex items-center justify-between border-t border-rule px-3 py-1.5 text-xs text-graphite">
        <span className="tabular">{plural(groups.length, "process", "processes")}</span>
      </div>
    </section>
  );
}
