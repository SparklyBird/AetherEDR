import { useEffect, useState } from "react";
import { api, explain } from "../lib/api";
import { toast } from "../lib/toast";
import { Button, Dialog, Input, Select, Spinner, Switch } from "./ui";

const AGES = [
  ["all", "Everything that has ended"],
  ["1", "Older than 1 day"],
  ["3", "Older than 3 days"],
  ["7", "Older than 7 days"],
  ["14", "Older than 14 days"],
  ["30", "Older than 30 days"],
  ["custom", "Older than a number of days..."],
];

const n = (v) => Number(v || 0).toLocaleString();

/** Deletes ended processes and the alerts that belong to nothing running. Shows the exact counts first. */
export default function ClearDataDialog({ open, onClose, onDone, host }) {
  const [age, setAge] = useState("7");
  const [custom, setCustom] = useState("30");
  const [withAlerts, setWithAlerts] = useState(true);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  let days = null;
  let invalid = false;
  if (age === "custom") {
    days = Number.parseInt(custom, 10);
    invalid = !Number.isInteger(days) || days < 1 || days > 3650;
  } else if (age !== "all") {
    days = Number(age);
  }

  // count what would go, every time the choice changes
  useEffect(() => {
    if (!open || invalid) {
      setPreview(null);
      return undefined;
    }
    const ctl = new AbortController();
    setPreview(null);
    setError(null);
    const t = setTimeout(() => {
      api("maintenance/clear/", { method: "POST", body: { older_than_days: days, alerts: withAlerts, host: host || null, dry_run: true }, signal: ctl.signal })
        .then((r) => setPreview(r.counts))
        .catch((e) => !ctl.signal.aborted && setError(e));
    }, 250);
    return () => {
      clearTimeout(t);
      ctl.abort();
    };
  }, [open, days, withAlerts, host, invalid]);

  async function run() {
    setBusy(true);
    try {
      const r = await api("maintenance/clear/", { method: "POST", body: { older_than_days: days, alerts: withAlerts, host: host || null, confirm: true }, timeout: 120000 });
      const c = r.counts;
      toast({ title: "History cleared", body: `Removed ${n(c.processes)} processes${withAlerts ? ` and ${n(c.alerts)} alerts` : ""}.`, tone: "good", ms: 5000 });
      onDone?.();
      onClose();
    } catch (e) {
      explain(e, "Could not clear the history");
    } finally {
      setBusy(false);
    }
  }

  const nothing = preview && preview.processes + (withAlerts ? preview.alerts : 0) === 0;
  const label = preview && !nothing ? `Clear ${n(preview.processes)} processes${withAlerts ? ` and ${n(preview.alerts)} alerts` : ""}` : "Clear";

  return (
    <Dialog open={open} onClose={onClose} title="Clear history">
      <div className="space-y-4 p-4">
        <p className="text-[0.8125rem] text-pencil">
          Removes processes that have exited, with their connections, memory scans and YARA jobs. Running processes are never touched
          {host ? ", and only the selected host is cleaned" : ""}.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <Select value={age} onChange={(e) => setAge(e.target.value)} aria-label="Which history to clear" className="min-w-0 flex-1">
            {AGES.map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </Select>
          {age === "custom" && (
            <label className="flex items-center gap-2 text-[0.8125rem]">
              <Input type="number" min={1} max={3650} step={1} value={custom} onChange={(e) => setCustom(e.target.value)} aria-label="Days" aria-invalid={invalid} className="w-24 tabular" />
              days
            </label>
          )}
        </div>
        {invalid && <p className="-mt-2 text-xs text-redline">Enter a whole number of days from 1 to 3650.</p>}

        <Switch checked={withAlerts} onChange={setWithAlerts} label="Also remove their alerts" hint="Alerts of running processes always stay." />

        <div className="border border-rule bg-sheet px-3 py-2.5 text-[0.8125rem]" aria-live="polite">
          {error ? (
            <span className="text-redline">Could not count: {error.message}</span>
          ) : invalid ? (
            <span className="text-graphite">Pick a number of days.</span>
          ) : !preview ? (
            <span className="inline-flex items-center gap-2 text-graphite"><Spinner /> Counting</span>
          ) : nothing ? (
            <span className="text-pencil">Nothing to remove.</span>
          ) : (
            <dl className="grid grid-cols-[1fr_auto] gap-x-6 gap-y-0.5">
              <dt className="text-pencil">Exited processes</dt><dd className="tabular text-right font-bold">{n(preview.processes)}</dd>
              {withAlerts && (<><dt className="text-pencil">Alerts</dt><dd className="tabular text-right font-bold">{n(preview.alerts)}</dd></>)}
              <dt className="text-pencil">Connection records</dt><dd className="tabular text-right">{n(preview.connections)}</dd>
              <dt className="text-pencil">Memory scans</dt><dd className="tabular text-right">{n(preview.memory_scans)}</dd>
            </dl>
          )}
          {preview && (
            <p className="mt-2 border-t border-rule pt-2 text-xs text-graphite">
              Kept: {n(preview.running_kept)} running
              {preview.lineage_kept ? `, ${n(preview.lineage_kept)} exited ${preview.lineage_kept === 1 ? "parent" : "parents"} of running processes` : ""}, exceptions and the response log.
            </p>
          )}
        </div>

        <p className="text-xs text-graphite">This cannot be undone. Export first if you may need the records.</p>
        <div className="flex flex-wrap justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" onClick={run} disabled={busy || invalid || !preview || nothing}>
            {busy && <Spinner />} {label}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
