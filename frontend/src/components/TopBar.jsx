import ExportMenu from "./ExportMenu";
import { Button, Kbd, Mark, Select } from "./ui";
import { SEV, SEV_ORDER } from "../lib/format";

/** Open alerts as one proportional bar. Clicking a segment filters the incident log. */
function ThreatStrip({ stats, active, onPick }) {
  const counts = SEV_ORDER.map((s) => [s, Number(stats?.[s]) || 0]);
  const total = counts.reduce((n, [, c]) => n + c, 0);
  if (!total) {
    return (
      <div className="flex h-8 items-center gap-2 border border-rule2 px-3 text-[0.8125rem] text-pencil" title="No open alerts">
        <span className="size-2 bg-ok" style={{ borderRadius: 1 }} aria-hidden />
        {stats ? "No open alerts" : "Waiting for data"}
      </div>
    );
  }
  return (
    <div role="group" aria-label="Open alerts by severity" className="flex h-8 min-w-[15rem] max-w-[26rem] flex-1 overflow-hidden border border-rule2">
      {counts.map(([s, c]) =>
        c ? (
          <button
            key={s}
            type="button"
            onClick={() => onPick(active === s ? "all" : s)}
            aria-pressed={active === s}
            title={`${c} open ${SEV[s].label.toLowerCase()} alert${c === 1 ? "" : "s"}. Click to filter the log.`}
            style={{ flex: `${Math.max(c, total * 0.12)} 1 0`, background: `color-mix(in srgb, ${SEV[s].color} ${active === s ? 34 : 18}%, transparent)`, boxShadow: `inset 0 -3px 0 ${SEV[s].color}` }}
            className="flex min-w-0 items-center justify-center gap-1.5 border-r border-rule2 px-2 text-[0.8125rem] last:border-r-0 hover:brightness-125"
          >
            <span className="font-bold tabular">{c}</span>
            <span className="hidden truncate text-pencil sm:inline">{SEV[s].label.toLowerCase()}</span>
          </button>
        ) : null,
      )}
    </div>
  );
}

const STREAM = {
  live: ["bg-ok", "Live"],
  connecting: ["bg-highlight", "Connecting"],
  offline: ["bg-redline", "Reconnecting"],
};

export default function TopBar({ stats, agent, hosts, host, onHost, stream, sevFilter, onSev, onPalette, onSettings, onExit, unreachable }) {
  const [dot, text] = unreachable ? ["bg-redline", "No contact"] : STREAM[stream] || STREAM.connecting;
  const notElevated = agent?.mode === "standalone" && agent.is_admin === false;
  return (
    <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-rule2 bg-plate px-4 py-2">
      <div className="flex items-center gap-2.5">
        <Mark size={26} />
        <h1 className="text-base font-bold tracking-tight">AetherEDR</h1>
      </div>

      <label className="flex items-center gap-2 text-[0.8125rem] text-pencil">
        <span className="sr-only md:not-sr-only">Host</span>
        <Select value={host ?? ""} onChange={(e) => onHost(e.target.value || null)} className="max-w-48 !py-1">
          <option value="">All hosts</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.hostname}
            </option>
          ))}
        </Select>
      </label>

      <ThreatStrip stats={stats} active={sevFilter} onPick={onSev} />

      <div className="ml-auto flex flex-wrap items-center gap-3">
        {notElevated && (
          <span className="text-[0.8125rem] text-marker" title="Without Administrator rights Windows hides other users' and protected processes' memory. Start AetherEDR.bat and accept the prompt.">
            Not elevated: partial memory view
          </span>
        )}
        <span className="flex items-center gap-2 text-[0.8125rem] text-pencil" title={agent ? `Collector ${agent.collector_running ? "running" : "stopped"}, polling every ${agent.interval ?? "?"} s` : ""}>
          <span className={`size-2 ${dot}`} style={{ borderRadius: 1 }} aria-hidden />
          {text}
        </span>
        <Button onClick={onPalette} title="Search and commands" className="gap-2">
          Search <span className="hidden sm:inline"><Kbd>Ctrl K</Kbd></span>
        </Button>
        <ExportMenu host={host} />
        <Button onClick={onSettings} aria-label="Settings">
          Settings
        </Button>
        {agent?.can_stop && (
          <Button onClick={onExit} title="Stop AetherEDR" className="hover:!border-redline hover:!text-redline">
            Exit
          </Button>
        )}
      </div>
    </header>
  );
}
