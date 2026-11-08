import { useState } from "react";
import { api, explain } from "../lib/api";
import { SEV, bytes, midEllipsis, sevForScore, stamp, timeAgo } from "../lib/format";
import { usePolled } from "../lib/hooks";
import { baseName } from "../lib/format";
import { arr, copyText } from "../lib/safe";
import { toast } from "../lib/toast";
import MemoryView from "./MemoryView";
import YaraPanel from "./YaraPanel";
import { Button, ConfirmDialog, Empty, ErrorPanel, Popover, RiskGauge, Section, Spec, Spinner, Tabs, Tag } from "./ui";

function Copy({ text, label = "Copy" }) {
  if (!text) return null;
  return (
    <button
      type="button"
      className="ml-1.5 text-xs text-pencil underline underline-offset-2 hover:text-ink"
      onClick={async () => toast({ title: (await copyText(text)) ? "Copied" : "Copy failed", tone: "good", ms: 1800 })}
    >
      {label}
    </button>
  );
}

function Findings({ p, onTrust, onOpenSheet }) {
  const findings = arr(p.findings);
  const muted = arr(p.muted);
  return (
    <div>
      {!findings.length && <Empty title="Nothing suspicious found">{muted.length ? "Everything this process triggered is covered by an exception." : "No detection rule matched this process."}</Empty>}
      <ul className="divide-y divide-rule">
        {findings.map((f) => (
          <li key={f.rule_id + (f.suffix || "")} className="space-y-1.5 px-4 py-3">
            <div className="flex items-start justify-between gap-3">
              <p className="font-bold leading-snug">{f.title}</p>
              <span className="shrink-0 font-mono text-xs text-graphite">{f.rule_id}</span>
            </div>
            <div className="flex flex-wrap items-center gap-2" title={`Contributes ${f.weight} to the risk score`}>
              <span className="relative h-1.5 w-28 bg-rule" aria-hidden>
                <span className="absolute inset-y-0 left-0" style={{ width: `${Math.min(100, f.weight)}%`, background: SEV[sevForScore(f.weight)]?.color ?? "var(--graphite)" }} />
              </span>
              <span className="text-xs text-pencil tabular">weight {f.weight}</span>
              {f.tactic && <Tag>{f.tactic}</Tag>}
              {f.technique && <Tag mono>{f.technique}</Tag>}
              {f.memory && <span className="hl text-xs">memory</span>}
            </div>
            {f.description && <p className="text-[0.8125rem] text-pencil">{f.description}</p>}
            {f.evidence && Object.keys(f.evidence).length > 0 && (
              <details>
                <summary className="cursor-pointer text-xs text-pencil hover:text-ink">Evidence</summary>
                <pre className="mt-1.5 max-h-56 overflow-auto border border-rule2 bg-sheet p-2.5 font-mono text-[0.7rem] text-pencil">{JSON.stringify(f.evidence, null, 2)}</pre>
              </details>
            )}
          </li>
        ))}
      </ul>
      {findings.length > 0 && (
        <div className="border-t border-rule px-4 py-3">
          <Button size="sm" onClick={onTrust} title="Know why it does this? Stop alerting on it.">Trust these behaviours…</Button>
        </div>
      )}
      {muted.length > 0 && (
        <Section title={`Muted by exceptions (${muted.length})`} action={<button type="button" className="text-xs underline underline-offset-2" onClick={() => onOpenSheet("exceptions")}>Manage</button>}>
          <ul className="space-y-1 text-[0.8125rem] text-pencil">
            {muted.map((f) => (
              <li key={f.rule_id + (f.suffix || "")}>
                <span className="mr-1.5 font-mono text-xs text-graphite">{f.rule_id}</span>
                <span className="line-through decoration-rule2">{f.title}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function Network({ p }) {
  const conns = arr(p.connections);
  if (!conns.length) return <Empty title="No sockets seen">This process has not opened any network connections since the collector started tracking it.</Empty>;
  return (
    <div className="overflow-x-auto p-2">
      <table className="w-full text-left text-[0.8125rem]">
        <thead className="text-xs text-pencil">
          <tr>
            <th className="px-2 py-1.5 font-medium">Remote</th>
            <th className="px-2 py-1.5 font-medium">Where</th>
            <th className="px-2 py-1.5 font-medium">Seen</th>
          </tr>
        </thead>
        <tbody>
          {conns.map((c) => (
            <tr key={c.id} className="border-t border-rule align-top">
              <td className="px-2 py-1.5">
                <span className="font-mono text-xs">{c.direction === "listen" ? `listening :${c.lport}` : `${c.raddr}:${c.rport}`}</span>
                <span className="ml-1.5 text-xs text-graphite">{c.proto}</span>
                {c.hostname && <div className="font-mono text-xs text-pencil">{c.hostname}{c.entropy != null && <span className="text-graphite"> entropy {c.entropy}</span>}</div>}
              </td>
              <td className="px-2 py-1.5 text-xs text-pencil">{c.scope !== "public" ? c.scope : [c.country, c.asn ? `AS${c.asn}` : "", c.as_org].filter(Boolean).join(" ") || "unknown"}</td>
              <td className="whitespace-nowrap px-2 py-1.5 text-xs text-pencil">{timeAgo(c.first_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function History({ p }) {
  const alerts = arr(p.alerts);
  if (!alerts.length) return <Empty title="No alerts for this process" />;
  return (
    <ul className="divide-y divide-rule">
      {alerts.map((a) => (
        <li key={a.id} className="flex items-start gap-3 px-4 py-2.5">
          <span className="mt-1.5 size-2 shrink-0" style={{ background: SEV[a.severity]?.color }} aria-hidden />
          <div className="min-w-0 flex-1">
            <p className="leading-snug">{a.title}</p>
            <p className="text-xs text-pencil">
              <span className="font-mono text-graphite">{a.rule_id}</span>, {a.status.replace("_", " ")}{a.suppression ? " by exception" : ""}, first seen {timeAgo(a.first_seen)}
            </p>
          </div>
        </li>
      ))}
    </ul>
  );
}

const ACTIONS = {
  suspend: { title: "Suspend this process?", body: "Every thread freezes. The process stays in memory and can be resumed. Use it to stop damage while you investigate.", confirm: "Suspend", done: "Suspended" },
  terminate: { title: "Terminate this process?", body: "The process is ended and unsaved work in it is lost. Child processes are not touched. This is recorded in the action log.", confirm: "Terminate", done: "Terminated", danger: true },
  resume: { title: "Resume this process?", body: "", confirm: "Resume", done: "Resumed" },
};

export default function Inspector({ id, onSelect, onClose, onTrust, onFocus, onOpenSheet, onChanged, rev = 0 }) {
  const [tab, setTab] = useState("findings");
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);
  const { data: p, error, reload } = usePolled((signal) => api(`processes/${id}/`, { signal }), [id, rev], { interval: 8 });

  // new process, back to the findings tab
  const [lastId, setLastId] = useState(id);
  if (lastId !== id) {
    setLastId(id);
    setTab("findings");
  }

  async function respond(kind) {
    setBusy(true);
    try {
      await api(`processes/${id}/respond/`, { method: "POST", body: { action: kind } });
      toast({ title: ACTIONS[kind].done, body: `${p?.name} (PID ${p?.pid}). Recorded in the action log.`, tone: "good" });
      setConfirm(null);
      reload();
      onChanged?.();
    } catch (e) {
      explain(e, `Could not ${kind} this process`);
      setConfirm(null);
    } finally {
      setBusy(false);
    }
  }

  if (error && !p?.id) return <div className="p-3"><ErrorPanel error={error} onRetry={reload} title="Could not load this process" /><div className="px-3"><Button onClick={onClose}>Close</Button></div></div>;
  if (!p || p.id !== id) return <div className="grid h-full place-items-center bg-plate"><Spinner /></div>;

  const chain = [...arr(p.ancestors)].reverse();
  const children = arr(p.children);
  const sev = sevForScore(p.risk_score);
  const trustTarget = () => {
    const seen = new Set();
    const rules = arr(p.findings).filter((f) => !seen.has(f.rule_id) && seen.add(f.rule_id)).map((f) => ({ id: f.rule_id, title: f.title }));
    return { rules, exe: (p.exe || "").toLowerCase(), name: (p.name || baseName(p.exe)).toLowerCase() };
  };

  return (
    <aside aria-label="Process dossier" className="flex h-full min-h-0 flex-col bg-plate">
      <div className="space-y-3 border-b border-rule2 p-4">
        <div className="flex items-start gap-3">
          <RiskGauge score={p.risk_score} size="lg" />
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-base font-bold">{p.name}</h2>
            <p className="text-xs text-pencil">
              <span className="tabular">PID {p.pid}</span>, {p.alive ? <span className="text-ok">running</span> : "exited"} on {p.host_name}
              {sev !== "none" && <span style={{ color: SEV[sev].color }}>, {SEV[sev].label.toLowerCase()} risk</span>}
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close dossier">Close</Button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" onClick={() => onFocus(p.id)} title="Draw only this process's family on the lineage sheet">Show in lineage</Button>
          {p.risk_score > 0 && <Button size="sm" onClick={() => onTrust(trustTarget())}>Trust…</Button>}
          {p.alive && (
            <Popover label="Respond" align="left" width="w-64" buttonClass="!px-2 !py-1 !text-xs" variant="danger">
              {(close) => (
                <div className="space-y-1.5">
                  <p className="text-xs text-pencil">Acts on this computer only. Needs Administrator rights for other users' processes.</p>
                  <Button size="sm" className="w-full" onClick={() => (close(), setConfirm("suspend"))}>Suspend</Button>
                  <Button size="sm" className="w-full" onClick={() => (close(), respond("resume"))}>Resume</Button>
                  <Button size="sm" variant="danger" className="w-full" onClick={() => (close(), setConfirm("terminate"))}>Terminate…</Button>
                </div>
              )}
            </Popover>
          )}
        </div>

        {chain.length > 0 && (
          <nav aria-label="Parent chain" className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[0.8125rem]">
            {chain.map((a) => (
              <span key={a.id} className="flex items-center gap-1.5">
                <button type="button" onClick={() => onSelect(a.id)} className={`px-0.5 underline-offset-2 hover:underline ${a.risk_score >= 60 ? "text-redline" : "text-pencil hover:text-ink"}`}>{a.name}</button>
                <span className="text-graphite" aria-hidden>/</span>
              </span>
            ))}
            <span className="font-bold">{p.name}</span>
          </nav>
        )}
      </div>

      <Tabs
        label="Dossier sections"
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "findings", label: "Findings", count: arr(p.findings).length },
          { id: "details", label: "Details" },
          { id: "memory", label: "Memory", count: p.mem_summary?.flagged_regions ?? 0 },
          { id: "network", label: "Network", count: arr(p.connections).length },
          { id: "yara", label: "YARA", count: arr(p.yara_hits).length },
          { id: "history", label: "Alerts", count: arr(p.alerts).length },
        ]}
      />
      {error && <ErrorPanel error={error} onRetry={reload} compact />}
      <div className="min-h-0 flex-1 overflow-y-auto" role="tabpanel">
        {tab === "findings" && <Findings p={p} onTrust={() => onTrust(trustTarget())} onOpenSheet={onOpenSheet} />}
        {tab === "details" && (
          <div className="p-4">
            <Spec
              rows={[
                ["Path", <>{p.exe || "unknown"}{p.exe_deleted && <span className="text-redline"> (deleted)</span>}<Copy text={p.exe} /></>, { mono: true, title: p.exe }],
                ["Command", <>{midEllipsis(p.cmdline || "none", 240)}<Copy text={p.cmdline} /></>, { mono: true }],
                ["Working dir", p.cwd || "unknown", { mono: true }],
                ["User", p.username || "unknown"],
                ["Started", stamp(p.started_at)],
                p.ended_at && ["Exited", stamp(p.ended_at)],
                p.sha256 && ["SHA-256", <>{midEllipsis(p.sha256, 30)}<Copy text={p.sha256} /></>, { mono: true, title: p.sha256 }],
                ["Parent PID", p.ppid],
                ["Resources", p.last_rss ? `${bytes(p.last_rss)}, ${p.last_threads} threads` : "Not sampled yet"],
                ["Sockets", `${p.net_out} outbound, ${p.net_listen} listening`],
                p.anomaly != null && ["Baseline", p.anomaly >= 0.6 ? <span className="text-marker">Outlier, score {p.anomaly.toFixed(2)}</span> : `Typical, score ${p.anomaly.toFixed(2)}`],
              ]}
            />
            {children.length > 0 && (
              <div className="mt-4">
                <p className="mb-1.5 text-[0.8125rem] font-bold">Started {children.length} {children.length === 1 ? "process" : "processes"}</p>
                <div className="flex flex-wrap gap-1.5">
                  {children.slice(0, 24).map((c) => (
                    <button key={c.id} type="button" onClick={() => onSelect(c.id)} className={`rounded-xs border border-rule2 px-1.5 py-0.5 text-xs hover:bg-plate2 ${c.risk_score >= 60 ? "text-redline" : ""}`}>{c.name}</button>
                  ))}
                  {children.length > 24 && <span className="text-xs text-pencil">and {children.length - 24} more</span>}
                </div>
              </div>
            )}
          </div>
        )}
        {tab === "memory" && <MemoryView processId={p.id} />}
        {tab === "network" && <Network p={p} />}
        {tab === "yara" && <YaraPanel process={p} onFinished={reload} />}
        {tab === "history" && <History p={p} />}
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={confirm ? ACTIONS[confirm].title : ""}
        confirm={confirm ? ACTIONS[confirm].confirm : ""}
        danger={!!(confirm && ACTIONS[confirm].danger)}
        busy={busy}
        onConfirm={() => respond(confirm)}
        onClose={() => setConfirm(null)}
      >
        <p className="font-medium text-ink">{p.name} <span className="font-normal text-pencil">PID {p.pid}</span></p>
        <p className="mt-1.5">{confirm ? ACTIONS[confirm].body : ""}</p>
      </ConfirmDialog>
    </aside>
  );
}
