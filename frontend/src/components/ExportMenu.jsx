import { useState } from "react";
import { downloadAlerts, downloadProcesses, downloadReport } from "../lib/api";
import { toast } from "../lib/toast";
import { Button, ErrorNote, Popover, Segmented, Select, Spinner } from "./ui";

const RANGES = [
  { v: 24, label: "Last 24 hours" },
  { v: 168, label: "Last 7 days" },
  { v: 720, label: "Last 30 days" },
];

const LEVELS = [
  { v: "", label: "Medium and up (all flagged)" },
  { v: "60", label: "High and Critical" },
  { v: "80", label: "Critical only" },
  { v: "1", label: "Any finding at all" },
];

export default function ExportMenu({ host }) {
  const [kind, setKind] = useState("report"); // report | data | procs
  const [type, setType] = useState("pdf");
  const [hours, setHours] = useState(24);
  const [status, setStatus] = useState("open");
  const [level, setLevel] = useState("");
  const [alive, setAlive] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const formats = kind === "report" ? [{ value: "pdf", label: "PDF" }, { value: "docx", label: "Word" }] : kind === "procs" ? [{ value: "json", label: "JSON (full)" }, { value: "csv", label: "CSV" }] : [{ value: "csv", label: "CSV" }, { value: "json", label: "JSON" }];

  function pick(k) {
    setKind(k);
    setType(k === "report" ? "pdf" : k === "procs" ? "json" : "csv");
    setError(null);
  }

  async function go(close) {
    setBusy(true);
    setError(null);
    try {
      if (kind === "report") await downloadReport({ type, hours, host });
      else if (kind === "procs") await downloadProcesses({ type, host, minScore: level || undefined, alive: alive || undefined });
      else await downloadAlerts({ type, hours, host, status: status === "all" ? undefined : status === "open" ? "open,ack" : status });
      toast({ title: "Export saved", body: "Check your downloads folder.", tone: "good", ms: 3500 });
      close();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Popover label="Export" width="w-80">
      {(close) => (
        <div className="space-y-3">
          <Segmented label="What to export" value={kind} onChange={pick} className="w-full [&>button]:flex-1" options={[{ value: "report", label: "Report" }, { value: "data", label: "Alerts" }, { value: "procs", label: "Processes" }]} />
          <div>
            <p className="mb-1 text-[0.8125rem] font-bold">Format</p>
            <Segmented label="Format" value={type} onChange={setType} options={formats} />
          </div>
          {kind !== "procs" && (
          <label className="block">
            <span className="mb-1 block text-[0.8125rem] font-bold">Time range</span>
            <Select value={hours} onChange={(e) => setHours(+e.target.value)} className="w-full">
              {RANGES.map((r) => (
                <option key={r.v} value={r.v}>
                  {r.label}
                </option>
              ))}
            </Select>
          </label>
          )}
          {kind === "procs" && (
            <>
              <label className="block">
                <span className="mb-1 block text-[0.8125rem] font-bold">Risk level</span>
                <Select value={level} onChange={(e) => setLevel(e.target.value)} className="w-full">
                  {LEVELS.map((r) => (
                    <option key={r.v} value={r.v}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="block">
                <span className="mb-1 block text-[0.8125rem] font-bold">State</span>
                <Select value={alive} onChange={(e) => setAlive(e.target.value)} className="w-full">
                  <option value="">Running and ended</option>
                  <option value="1">Running now</option>
                  <option value="0">Ended only</option>
                </Select>
              </label>
            </>
          )}
          {kind === "data" && (
            <label className="block">
              <span className="mb-1 block text-[0.8125rem] font-bold">Alerts</span>
              <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-full">
                <option value="open">Open and acknowledged</option>
                <option value="all">Everything, including resolved</option>
                <option value="false_positive">False positives only</option>
              </Select>
            </label>
          )}
          <p className="text-xs text-graphite">
            {host ? "Covers the selected host." : "Covers all hosts."} Built on this machine; nothing is uploaded.
            {kind === "procs" && " Includes command lines, paths, rule IDs, weights, evidence and silenced findings. Review before sharing."}
          </p>
          <ErrorNote error={error} />
          <Button variant="primary" className="w-full" onClick={() => go(close)} disabled={busy}>
            {busy ? <Spinner /> : null}
            {busy ? "Preparing" : kind === "report" ? `Download ${type === "pdf" ? "PDF" : "Word"} report` : kind === "procs" ? `Download flagged processes (${type.toUpperCase()})` : `Download ${type.toUpperCase()}`}
          </Button>
        </div>
      )}
    </Popover>
  );
}
