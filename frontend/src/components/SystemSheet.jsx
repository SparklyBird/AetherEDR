import { useState } from "react";
import { api } from "../lib/api";
import { bytes, clock, dur, stamp, timeAgo } from "../lib/format";
import { usePolled } from "../lib/hooks";
import { arr, copyText } from "../lib/safe";
import { toast } from "../lib/toast";
import { Button, Empty, ErrorPanel, Section, Spec, Spinner, Tag } from "./ui";

const yesno = (v) => (v ? "yes" : "no");

// how new processes are noticed: OS notifications when available, otherwise only the polling interval
function eventsText(e, shortLived) {
  if (!e) return false;
  if (e.active) {
    const kind = e.kind === "netlink" ? "kernel notifications" : e.kind === "wmi" ? "WMI notifications" : e.kind;
    return `${kind}, ${e.seen} announced${e.missed ? `, ${e.missed} gone before they could be read` : ""}${shortLived ? `, ${shortLived} short-lived recorded` : ""}`;
  }
  return `polling only${e.error ? `: ${e.error}` : ""}`;
}

// "412 readable, 6 protected, 2 no permission" for the processes running right now
function coverage(c) {
  if (!c) return false;
  const parts = [`${c.readable} readable`];
  if (c.protected) parts.push(`${c.protected} protected`);
  if (c.denied) parts.push(`${c.denied} no permission`);
  if (c.other) parts.push(`${c.other} unreadable`);
  if (c.pending) parts.push(`${c.pending} not scanned yet`);
  return parts.join(", ");
}

// a secret that stays hidden until asked for
function SecretRow({ value }) {
  const [reveal, setReveal] = useState(false);
  return (
    <>
      <span className="font-mono text-xs">{reveal ? value : "•".repeat(16)}</span>
      <button type="button" className="ml-2 text-xs underline underline-offset-2" onClick={() => setReveal((r) => !r)}>{reveal ? "Hide" : "Show"}</button>
      <button type="button" className="ml-2 text-xs underline underline-offset-2" onClick={async () => toast({ title: (await copyText(value)) ? "Key copied" : "Copy failed", tone: "good", ms: 2000 })}>Copy</button>
    </>
  );
}

export default function SystemSheet({ rev, onClear }) {
  const [ping, setPing] = useState(null);
  const sys = usePolled((signal) => api("system/", { signal }), [rev], { interval: 10 });
  const log = usePolled((signal) => api("actions/", { params: { limit: 50 }, signal }), [rev], { interval: 30 });
  const d = sys.data;
  const a = d?.agent || {};
  const secure = window.location.protocol === "https:";
  const local = ["127.0.0.1", "localhost", "[::1]", "::1"].includes(window.location.hostname);
  const actions = arr(log.data?.results);

  async function measure() {
    const t0 = performance.now();
    try {
      const h = await api("health/");
      setPing({ ms: Math.round(performance.now() - t0), ok: h.status === "ok", db: h.db });
    } catch (e) {
      setPing({ error: e.message });
    }
  }

  async function diagnostics() {
    if (!d) return;
    const { api_key, ...safe } = d; // keep the key out of copied bug reports
    const ok = await copyText(JSON.stringify({ ...safe, browser: navigator.userAgent, at: new Date().toISOString() }, null, 2));
    toast({ title: ok ? "Diagnostics copied" : "Copy failed", body: ok ? "The API key is left out." : "", tone: ok ? "good" : "bad", ms: 3000 });
  }

  if (!d && sys.error) return <ErrorPanel error={sys.error} onRetry={sys.reload} title="Could not load system information" />;
  if (!d) return <div className="grid h-full place-items-center bg-sheet"><Spinner /></div>;

  return (
    <div className="h-full overflow-y-auto bg-sheet">
      <div className="mx-auto grid max-w-5xl gap-x-10 py-2 md:grid-cols-2">
        <Section title="Collector">
          <Spec rows={[
            ["State", a.collector_running ? <span className="text-ok">running</span> : <span className="text-redline">stopped</span>],
            ["Mode", a.mode],
            ["Poll interval", a.interval != null && `${a.interval} s`],
            ["Last cycle", a.last_cycle_ms != null && `${a.last_cycle_ms} ms`],
            ["Last success", a.last_ok ? `${timeAgo(new Date(a.last_ok * 1000).toISOString())}` : "never"],
            ["Cycles", a.cycles != null && `${a.cycles} done, ${a.failures} failed, ${a.restarts} restarts`],
            ["Elevated", yesno(a.is_admin)],
            ["New processes seen by", eventsText(a.events, a.stats?.short_lived)],
            ["Memory introspection", yesno(a.memory_introspection)],
            ["Memory coverage", coverage(d.memory_coverage)],
            ["YARA", a.yara ? "available" : "not installed"],
            ["Baseline", a.baseline?.trained ? `trained on ${a.baseline.samples} samples` : "learning"],
            ["Running for", dur(a.uptime_s)],
          ].filter((r) => r[1] !== false && r[1] !== undefined && r[1] !== null)} />
          {a.last_error && <p className="mt-2 border-l-[3px] border-marker bg-plate2 px-3 py-2 font-mono text-xs text-pencil">Last error: {String(a.last_error)}</p>}
          {d.memory_coverage?.protected > 0 && (
            <p className="mt-2 text-xs text-graphite">
              Protected processes (for example lsass with RunAsPPL, csrss, System) refuse memory reads from every user-mode program, Administrator included. They are listed here so the gap is visible. Their start, parent, command line and connections are still recorded.
            </p>
          )}
          {!a.is_admin && a.mode === "standalone" && <p className="mt-2 text-xs text-marker">Not elevated. Windows hides other users' and protected processes' memory. Start AetherEDR.bat and accept the prompt.</p>}
        </Section>

        <Section title="This installation">
          <Spec rows={[
            ["Version", d.version],
            ["Python", d.python],
            ["Platform", d.platform, { mono: true }],
            ["Data folder", d.data_dir, { mono: true }],
            ["Active exceptions", d.counts.exceptions],
          ]} />
        </Section>

        <Section title="Stored history">
          <Spec rows={[
            ["Database size", bytes(d.db_bytes)],
            ["Processes", `${d.counts.alive} running, ${d.counts.ended ?? d.counts.processes - d.counts.alive} exited`],
            ["Alerts", d.counts.alerts],
            ["Connections", d.counts.connections],
            ["Automatic cleanup", `exited processes after ${d.settings.retention_days} days`],
          ]} />
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button size="sm" variant="danger" onClick={onClear} disabled={!onClear}>Clear history...</Button>
            <span className="text-xs text-graphite">All, or only what is older than a number of days.</span>
          </div>
        </Section>

        <Section title="Detection settings" action={<span className="text-xs text-graphite">environment variables</span>}>
          <Spec rows={[
            ["Alert threshold", <>{d.settings.alert_threshold}<span className="ml-1.5 text-xs text-graphite">AETHER_ALERT_THRESHOLD</span></>],
            ["Retention", <>{`${d.settings.retention_days} days`}<span className="ml-1.5 text-xs text-graphite">AETHER_RETENTION_DAYS</span></>],
            ["Poll seconds", d.settings.interval],
            ["Reverse DNS", d.settings.reverse_dns ? "on (emits DNS queries)" : "off"],
            ["Extra JIT allow-list", arr(d.settings.jit_allow).join(", ") || "none"],
            ["Shared-region check", d.settings.shared_region_min ? <>{`${d.settings.shared_region_min}+ programs`}<span className="ml-1.5 text-xs text-graphite">AETHER_SHARED_REGION_MIN</span></> : "off"],
            ["Watched countries", arr(d.settings.watch_countries).join(", ") || "none"],
          ]} />
        </Section>

        <Section title="Connection">
          <Spec rows={[
            ["Encryption", secure ? "HTTPS" : local ? "none, this PC only" : <span className="text-redline">none, keys cross the network in clear text</span>],
            ["API key", <SecretRow value={d.api_key} />],
            d.ingest_key && ["Agent key", <><SecretRow value={d.ingest_key} /><span className="mt-0.5 block text-xs text-graphite">For remote agents. It can only send data in.</span></>],
            ["Console to server", ping ? (ping.error ? <span className="text-redline">{ping.error}</span> : <>{ping.ms} ms, database {ping.db}</>) : "not measured"],
          ].filter(Boolean)} />
          <div className="mt-3 flex flex-wrap gap-2">
            <Button size="sm" onClick={measure}>Test connection</Button>
            <Button size="sm" onClick={diagnostics}>Copy diagnostics</Button>
          </div>
        </Section>

        <Section title="Response action log" className="md:col-span-2">
          {!actions.length ? (
            <Empty title="No response actions yet">Suspend, resume and terminate from the process dossier are recorded here.</Empty>
          ) : (
            <table className="w-full text-left text-[0.8125rem]">
              <thead className="text-xs text-pencil">
                <tr><th className="py-1.5 pr-3 font-medium">When</th><th className="px-2 py-1.5 font-medium">Action</th><th className="px-2 py-1.5 font-medium">Process</th><th className="px-2 py-1.5 font-medium">Result</th></tr>
              </thead>
              <tbody>
                {actions.map((x) => (
                  <tr key={x.id} className="border-t border-rule">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-pencil" title={stamp(x.ts)}>{clock(x.ts)}</td>
                    <td className="px-2 py-1.5 font-bold">{x.kind}</td>
                    <td className="px-2 py-1.5">{x.name} <span className="text-xs text-pencil tabular">{x.pid}</span></td>
                    <td className="px-2 py-1.5">{x.ok ? <Tag tone="var(--ok)">done</Tag> : <Tag tone="var(--redline)">failed</Tag>} <span className="text-xs text-pencil">{x.detail}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      </div>
    </div>
  );
}
