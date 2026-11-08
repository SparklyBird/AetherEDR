import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, downloadAlerts, downloadProcesses, downloadReport, explain, getKey, initKey, openAlertStream } from "./lib/api";
import { clock } from "./lib/format";
import { isTyping, useKeys, usePolled } from "./lib/hooks";
import { arr, load, save } from "./lib/safe";
import { cycleTheme, THEME_LABELS, useSettings } from "./lib/settings";
import { toast } from "./lib/toast";
import AuthGate from "./components/AuthGate";
import CommandPalette from "./components/CommandPalette";
import ErrorBoundary from "./components/ErrorBoundary";
import ExceptionsSheet from "./components/ExceptionsSheet";
import Inspector from "./components/Inspector";
import LineageGraph from "./components/LineageGraph";
import RulesSheet from "./components/RulesSheet";
import SettingsDrawer from "./components/SettingsDrawer";
import SystemSheet from "./components/SystemSheet";
import { NetworkTable, ProcessTable } from "./components/Tables";
import ThreatFeed from "./components/ThreatFeed";
import TopBar from "./components/TopBar";
import ClearDataDialog from "./components/ClearDataDialog";
import ExitDialog from "./components/ExitDialog";
import StoppedScreen from "./components/StoppedScreen";
import TrustDialog from "./components/TrustDialog";
import { SheetTabs } from "./components/ui";

function useAlerts(host, authed, refresh, notify) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [fresh, setFresh] = useState(() => new Set());
  const [stream, setStream] = useState("connecting");
  const [stats, setStats] = useState(null);
  const loaded = useRef(false);
  const notifyRef = useRef(notify);
  notifyRef.current = notify;

  const merge = useCallback((incoming) => {
    setAlerts((cur) => {
      const m = new Map(cur.map((a) => [a.id, a]));
      for (const a of incoming) m.set(a.id, { ...m.get(a.id), ...a });
      return [...m.values()].sort((x, y) => y.id - x.id).slice(0, 800);
    });
  }, []);

  // replace=true drops alerts the server no longer has (after a clear), a plain refetch only adds and updates
  const refetch = useCallback(
    (replace = false) =>
      api("alerts/", { params: { host, limit: 400 } })
        .then((d) => ((replace === true ? setAlerts(arr(d?.results)) : merge(arr(d?.results))), setError(null), setLoading(false), (loaded.current = true)))
        .catch((e) => (setError(e), setLoading(false))),
    [host, merge],
  );

  useEffect(() => {
    if (!authed) return undefined;
    setAlerts([]);
    setLoading(true);
    loaded.current = false;
    refetch();
    const poll = refresh > 0 ? setInterval(() => !document.hidden && refetch(), Math.max(10, refresh) * 1000) : null; // score changes on existing alerts
    const close = openAlertStream({
      params: { host },
      onState: setStream,
      onStats: setStats,
      onAlert: (a) => {
        merge([a]);
        if (!loaded.current) return;
        setFresh((s) => new Set(s).add(a.id));
        setTimeout(() => setFresh((s) => (s.delete(a.id), new Set(s))), 3000);
        if (notifyRef.current && document.hidden && (a.severity === "critical" || a.severity === "high") && typeof Notification !== "undefined" && Notification.permission === "granted") {
          try {
            new Notification(`${a.severity === "critical" ? "Critical" : "High"} alert: ${a.process_name}`, { body: a.title, tag: `aether-${a.id}` });
          } catch {
            /* some browsers only allow notifications from a service worker */
          }
        }
      },
    });
    return () => {
      if (poll) clearInterval(poll);
      close();
    };
  }, [authed, host, refetch, merge, refresh]);

  const setStatus = useCallback(
    async (list, status) => {
      const ids = new Set(list.map((a) => a.id));
      setAlerts((cur) => cur.map((a) => (ids.has(a.id) ? { ...a, status } : a)));
      const results = await Promise.allSettled(list.map((a) => api(`alerts/${a.id}/`, { method: "PATCH", body: { status } })));
      const failed = results.filter((r) => r.status === "rejected");
      if (failed.length) {
        explain(failed[0].reason, failed.length === list.length ? "Could not update the alert" : `Could not update ${failed.length} of ${list.length} alerts`);
        refetch(); // roll back to server truth
      }
    },
    [refetch],
  );

  return { alerts, loading, error, fresh, stream, stats, setStatus, refetch };
}

const SHEET_IDS = ["lineage", "processes", "network", "rules", "exceptions", "system"];
const COLS = {
  "11": "lg:grid-cols-[23rem_minmax(0,1fr)_30rem]",
  "10": "lg:grid-cols-[23rem_minmax(0,1fr)]",
  "01": "lg:grid-cols-[minmax(0,1fr)_30rem]",
  "00": "lg:grid-cols-[minmax(0,1fr)]",
};

// After Exit the whole console is replaced, so no polling or live stream keeps trying a server that is gone.
export default function App() {
  const [stopped, setStopped] = useState(false);
  return stopped ? <StoppedScreen /> : <Console onStopped={() => setStopped(true)} />;
}

function Console({ onStopped }) {
  const s = useSettings();
  const [authed, setAuthed] = useState(() => !!initKey());
  const [host, setHost] = useState(null);
  const [selected, setSelected] = useState(null);
  const [focusId, setFocusId] = useState(null);
  const [sheet, setSheet] = useState(() => (SHEET_IDS.includes(load("aether.sheet", "")) ? load("aether.sheet", "") : "lineage"));
  const [feedOpen, setFeedOpen] = useState(() => load("aether.feed", true) !== false);
  const [pane, setPane] = useState("sheets"); // narrow screens: log | sheets | dossier
  const [sevFilter, setSevFilter] = useState("all");
  const [palette, setPalette] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [trust, setTrust] = useState(null);
  const [clearOpen, setClearOpen] = useState(false);
  const [exitOpen, setExitOpen] = useState(false);
  const [rev, setRev] = useState(0);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const out = () => setAuthed(false);
    window.addEventListener("aether:unauthorized", out);
    return () => window.removeEventListener("aether:unauthorized", out);
  }, []);
  useEffect(() => {
    const n = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(n);
  }, []);
  useEffect(() => {
    save("aether.sheet", sheet);
  }, [sheet]);
  useEffect(() => {
    save("aether.feed", feedOpen);
  }, [feedOpen]);
  useEffect(() => setFocusId(null), [host]);

  const { alerts, loading, error: alertError, fresh, stream, stats, setStatus, refetch } = useAlerts(host, authed, s.refresh, s.notify);
  const overview = usePolled((signal) => api("overview/", { signal }), [authed, host, rev], { interval: s.refresh, enabled: authed });
  const hostsQ = usePolled((signal) => api("hosts/", { signal }), [authed, rev], { interval: 30, enabled: authed });
  const exceptionsQ = usePolled((signal) => api("exceptions/", { signal }), [authed, rev], { interval: 60, enabled: authed });

  const hosts = arr(hostsQ.data?.results);
  const liveStats = useMemo(() => stats ?? overview.data?.stats, [stats, overview.data]);
  const unreachable = !!overview.error?.network;
  const exceptionCount = arr(exceptionsQ.data?.results ?? exceptionsQ.data).filter((e) => e.enabled).length;

  const bump = useCallback(() => {
    setRev((r) => r + 1);
    refetch();
  }, [refetch]);

  useEffect(() => {
    const open = liveStats?.open ?? 0;
    document.title = s.titleBadge && open > 0 ? `(${open}) AetherEDR` : "AetherEDR";
  }, [liveStats?.open, s.titleBadge]);

  const select = useCallback((id) => {
    setSelected(id);
    setPane("dossier");
  }, []);
  const closeDossier = useCallback(() => {
    setSelected(null);
    setPane("sheets");
  }, []);
  // after a clear: reload, and let go of anything that no longer exists
  const afterClear = useCallback(async () => {
    setRev((r) => r + 1);
    refetch(true);
    setFocusId(null);
    if (selected != null) {
      try {
        await api(`processes/${selected}/`);
      } catch (e) {
        if (e?.status === 404) closeDossier();
      }
    }
  }, [refetch, selected, closeDossier]);

  const goSheet = useCallback((id) => {
    setSheet(id);
    setPane("sheets");
  }, []);
  const focusLineage = useCallback((id) => {
    setFocusId(id);
    if (id != null) goSheet("lineage");
  }, [goSheet]);

  const trustGroup = useCallback((g) => {
    const seen = new Set();
    const rules = g.alerts.filter((a) => !seen.has(a.rule_id) && seen.add(a.rule_id)).map((a) => ({ id: a.rule_id, title: a.title }));
    setTrust({ rules, exe: (g.process_path || "").toLowerCase(), name: (g.process_name || "").toLowerCase() });
  }, []);

  const doExport = useCallback((label, fn) => async () => {
    try {
      await fn();
      toast({ title: "Export saved", body: label, tone: "good", ms: 3500 });
    } catch (e) {
      explain(e, `Could not export ${label.toLowerCase()}`);
    }
  }, []);

  const commands = useMemo(
    () => [
      ...[["lineage", "Lineage"], ["processes", "Processes"], ["network", "Network"], ["rules", "Rules"], ["exceptions", "Exceptions"], ["system", "System"]].map(([id, l], i) => ({
        id: `go-${id}`, label: `Go to ${l}`, hint: "sheet", keys: String(i + 1), run: () => goSheet(id),
      })),
      { id: "settings", label: "Open settings", keys: ",", run: () => setSettingsOpen(true) },
      { id: "theme", label: "Cycle theme", hint: `now ${THEME_LABELS[s.theme]}`, keys: "t", run: cycleTheme },
      { id: "feed", label: feedOpen ? "Hide incident log" : "Show incident log", keys: "l", run: () => setFeedOpen((o) => !o) },
      { id: "refresh", label: "Refresh everything", run: bump },
      { id: "clear", label: "Clear history...", hint: "exited processes and old alerts", run: () => setClearOpen(true) },
      { id: "exit", label: "Exit AetherEDR...", hint: "stops the collector and the console", when: !!overview.data?.agent?.can_stop, run: () => setExitOpen(true) },
      { id: "sev-crit", label: "Show critical alerts only", hint: "filter", run: () => setSevFilter("critical") },
      { id: "sev-high", label: "Show high alerts only", hint: "filter", run: () => setSevFilter("high") },
      { id: "sev-all", label: "Show all severities", hint: "filter", when: sevFilter !== "all", run: () => setSevFilter("all") },
      { id: "focus", label: "Focus lineage on selected process", when: selected != null, run: () => focusLineage(selected) },
      { id: "unfocus", label: "Show the whole lineage again", when: focusId != null, run: () => setFocusId(null) },
      { id: "close", label: "Close process dossier", when: selected != null, keys: "Esc", run: closeDossier },
      { id: "x-pdf", label: "Export report as PDF", hint: "last 24 hours", run: doExport("Report, PDF", () => downloadReport({ type: "pdf", hours: 24, host })) },
      { id: "x-docx", label: "Export report as Word", hint: "last 24 hours", run: doExport("Report, Word", () => downloadReport({ type: "docx", hours: 24, host })) },
      { id: "x-csv", label: "Export open alerts as CSV", run: doExport("Alerts, CSV", () => downloadAlerts({ type: "csv", hours: 168, host, status: "open,ack" })) },
      { id: "x-pjson", label: "Export flagged processes as JSON", hint: "full evidence", run: doExport("Flagged processes, JSON", () => downloadProcesses({ type: "json", host })) },
      { id: "x-pcsv", label: "Export flagged processes as CSV", hint: "one row per finding", run: doExport("Flagged processes, CSV", () => downloadProcesses({ type: "csv", host })) },
      { id: "x-json", label: "Export open alerts as JSON", run: doExport("Alerts, JSON", () => downloadAlerts({ type: "json", hours: 168, host, status: "open,ack" })) },
    ],
    [s.theme, feedOpen, sevFilter, selected, focusId, host, goSheet, bump, focusLineage, closeDossier, doExport, overview.data?.agent?.can_stop],
  );

  useKeys((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      setPalette((p) => !p);
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e) || document.querySelector("dialog[open]")) return;
    if (/^[1-6]$/.test(e.key)) goSheet(SHEET_IDS[+e.key - 1]);
    else if (e.key === "t") cycleTheme();
    else if (e.key === "l") setFeedOpen((o) => !o);
    else if (e.key === ",") setSettingsOpen(true);
    else if (e.key === "Escape" && selected != null) closeDossier();
  });

  if (!authed || !getKey()) return <AuthGate onAuthed={() => setAuthed(true)} />;

  const inspecting = selected != null;
  const hostName = hosts.find((h) => h.id === host)?.hostname;
  const tabs = [
    { id: "lineage", label: "Lineage", hint: "Process tree" },
    { id: "processes", label: "Processes", hint: "Every process the collector has seen" },
    { id: "network", label: "Network", hint: "Sockets and destinations" },
    { id: "rules", label: "Rules", hint: "What is detected and how heavily" },
    { id: "exceptions", label: "Exceptions", hint: "Behaviours you chose to trust", badge: exceptionCount },
    { id: "system", label: "System", hint: "Collector health, paths and settings" },
  ];
  const sheetNo = SHEET_IDS.indexOf(sheet) + 1;
  const common = { host, rev, onSelect: select };

  return (
    <div className="flex h-full flex-col">
      <TopBar
        stats={liveStats}
        agent={overview.data?.agent}
        hosts={hosts}
        host={host}
        onHost={setHost}
        stream={stream}
        sevFilter={sevFilter}
        onSev={setSevFilter}
        onPalette={() => setPalette(true)}
        onSettings={() => setSettingsOpen(true)}
        onExit={() => setExitOpen(true)}
        unreachable={unreachable}
      />
      {unreachable && (
        <p role="alert" className="border-b border-redline bg-[color-mix(in_srgb,var(--redline)_12%,transparent)] px-4 py-1.5 text-[0.8125rem]">
          <strong className="text-redline">Lost contact with AetherEDR.</strong> It may have stopped or restarted. The console keeps trying and shows the last data it received.
        </p>
      )}

      <div className="flex border-b border-rule2 bg-plate lg:hidden" role="tablist" aria-label="Panels">
        {[["log", "Incident log"], ["sheets", "Sheets"], ...(inspecting ? [["dossier", "Dossier"]] : [])].map(([v, l]) => (
          <button key={v} role="tab" aria-selected={pane === v} onClick={() => setPane(v)} className={`flex-1 border-b-2 py-2 text-[0.8125rem] font-medium ${pane === v ? "border-ink text-ink" : "border-transparent text-pencil"}`}>
            {l}
          </button>
        ))}
      </div>

      <main className={`grid min-h-0 flex-1 grid-cols-1 ${COLS[`${feedOpen ? 1 : 0}${inspecting ? 1 : 0}`]}`}>
        <div className={`${pane === "log" ? "block" : "hidden"} min-h-0 border-r border-rule2 ${feedOpen ? "lg:block" : "lg:hidden"}`}>
          <ErrorBoundary label="Incident log">
            <ThreatFeed
              alerts={alerts}
              timeline={overview.data?.timeline}
              selectedProcess={selected}
              onSelect={select}
              onStatus={setStatus}
              onTrust={trustGroup}
              freshIds={fresh}
              now={now}
              loading={loading}
              error={alertError && !alerts.length ? alertError : null}
              onRetry={() => refetch(true)}
              onClear={() => setClearOpen(true)}
              sevFilter={sevFilter}
              setSevFilter={setSevFilter}
            />
          </ErrorBoundary>
        </div>

        <div className={`${pane === "sheets" ? "flex" : "hidden"} min-h-0 min-w-0 flex-col lg:flex`}>
          <div className="min-h-0 flex-1">
            <ErrorBoundary label="This sheet" resetKey={sheet}>
              {sheet === "lineage" && <LineageGraph {...common} selectedId={selected} focusId={focusId} onFocus={focusLineage} />}
              {sheet === "processes" && <ProcessTable {...common} selectedId={selected} />}
              {sheet === "network" && <NetworkTable {...common} />}
              {sheet === "rules" && <RulesSheet rev={rev} onChanged={bump} />}
              {sheet === "exceptions" && <ExceptionsSheet rev={rev} onChanged={bump} />}
              {sheet === "system" && <SystemSheet rev={rev} onClear={() => setClearOpen(true)} />}
            </ErrorBoundary>
          </div>
          <SheetTabs
            tabs={tabs}
            value={sheet}
            onChange={goSheet}
            right={
              <div className="hidden shrink-0 items-center gap-4 border-l border-rule px-3 text-xs text-graphite @5xl:flex">
                <span>{hostName || "All hosts"}</span>
                <span className="tabular">Sheet {sheetNo} of {tabs.length}</span>
                <span className="tabular" title="When the lists last refreshed">{overview.at ? `Updated ${clock(new Date(overview.at).toISOString())}` : "Waiting"}</span>
                <button type="button" className="text-pencil underline underline-offset-2 hover:text-ink" onClick={() => setFeedOpen((o) => !o)} aria-pressed={!feedOpen}>
                  {feedOpen ? "Hide log" : "Show log"}
                </button>
              </div>
            }
          />
        </div>

        {inspecting && (
          <div className={`${pane === "dossier" ? "block" : "hidden"} min-h-0 border-l border-rule2 lg:block`}>
            <ErrorBoundary label="Process dossier" resetKey={selected}>
              <Inspector id={selected} rev={rev} onSelect={select} onClose={closeDossier} onTrust={setTrust} onFocus={focusLineage} onOpenSheet={goSheet} onChanged={bump} />
            </ErrorBoundary>
          </div>
        )}
      </main>

      <CommandPalette open={palette} onClose={() => setPalette(false)} commands={commands} host={host} onPickProcess={select} />
      <SettingsDrawer open={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <TrustDialog target={trust} onClose={() => setTrust(null)} onDone={bump} />
      <ClearDataDialog open={clearOpen} onClose={() => setClearOpen(false)} onDone={afterClear} host={host} />
      <ExitDialog open={exitOpen} onClose={() => setExitOpen(false)} onStopped={onStopped} remoteAgents={overview.data?.agent?.mode === "server"} />
    </div>
  );
}
